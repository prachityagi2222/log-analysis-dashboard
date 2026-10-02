// Prevents an extra console window from appearing alongside the app on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Windows process creation flag that gives the console-mode backend process
/// no visible console window while keeping its stdout/stderr pipes intact.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Port the backend falls back to when no free port is found.
const DEFAULT_PORT: u16 = 8080;

/// Handle to the PyInstaller backend process so it can be terminated on exit.
struct BackendProcess(Mutex<Option<Child>>);

/// Set while the app is shutting down so a late-spawning backend is not leaked.
struct ShuttingDown(AtomicBool);

/// Best-effort console logging. Writing to stdout never panics, which matters
/// because release builds run under the Windows GUI subsystem (no console).
fn log(message: &str) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{message}");
}

/// Locate the PyInstaller-built backend executable.
///
/// * Packaged application: Tauri copies `log-backend[.exe]` next to the main
///   binary, so look in the directory of the running executable first.
/// * Development (`tauri dev`): the binary lives in `src-tauri/binaries/` and
///   must keep the `-<target-triple>` suffix Tauri requires for external bins.
fn resolve_backend_path() -> Option<PathBuf> {
    let file_name = if cfg!(windows) { "log-backend.exe" } else { "log-backend" };

    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let bundled = dir.join(file_name);
            if bundled.is_file() {
                return Some(bundled);
            }
        }
    }

    let binaries_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries");

    let plain = binaries_dir.join(file_name);
    if plain.is_file() {
        return Some(plain);
    }

    let suffixed = binaries_dir.join(format!("log-backend-{}", env!("TARGET_TRIPLE")));
    #[cfg(windows)]
    let suffixed = suffixed.with_extension("exe");
    if suffixed.is_file() {
        return Some(suffixed);
    }

    None
}

/// Spawn the backend and block until it prints its readiness handshake
/// (`SERVER_READY:http://127.0.0.1:<port>`), returning the URL to load.
fn spawn_backend(app: &tauri::AppHandle) -> Result<String, String> {
    let path = resolve_backend_path().ok_or_else(|| {
        "Could not find the bundled backend executable (log-backend). Build it with \
         PyInstaller into src-tauri/binaries/ before starting the app."
            .to_string()
    })?;

    log(&format!("[tauri] launching backend: {}", path.display()));

    let mut command = Command::new(&path);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // The backend picks its own free port and reports it via the handshake, so
    // no port argument is passed here (forcing one could collide with 8080).
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);

    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to start backend at {}: {e}", path.display()))?;

    let stdout = child.stdout.take().ok_or("Backend stdout was not captured")?;
    let stderr = child.stderr.take().ok_or("Backend stderr was not captured")?;

    // Drain stderr on its own thread: a full pipe would block the backend.
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            log(&format!("[backend] {line}"));
        }
    });

    // Wait for the SERVER_READY line. When the backend dies early the pipe
    // closes and read_line returns 0, so this loop always terminates.
    let mut reader = BufReader::new(stdout);
    let mut url = None;
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|e| format!("Failed to read backend output: {e}"))?;
        if read == 0 {
            break;
        }

        let trimmed = line.trim();
        log(&format!("[backend] {trimmed}"));

        if let Some(rest) = trimmed.strip_prefix("SERVER_READY:") {
            url = Some(rest.trim().to_string());
            break;
        }
    }

    // Keep draining the remaining stdout so the backend never blocks on write.
    if url.is_some() {
        std::thread::spawn(move || {
            for line in reader.lines().map_while(Result::ok) {
                log(&format!("[backend] {line}"));
            }
        });
    }

    // Register the child for shutdown, unless the app is already exiting.
    if app.state::<ShuttingDown>().0.load(Ordering::SeqCst) {
        kill_backend(child.id(), &mut child);
        return Err("application is shutting down".to_string());
    }
    app.state::<BackendProcess>().0.lock().unwrap().replace(child);

    url.ok_or_else(|| "Backend exited before reporting SERVER_READY".to_string())
}

/// Terminate the backend and any process it spawned.
///
/// A PyInstaller one-file bundle runs a small bootloader parent that starts the
/// real interpreter as a child process. Killing only the parent would leave that
/// child alive, still holding the listening port, so tear down the whole tree.
fn kill_backend(pid: u32, child: &mut Child) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    #[cfg(not(windows))]
    let _ = (pid, child);

    let _ = child.kill();
    let _ = child.wait();
}

fn main() {
    tauri::Builder::default()
        .manage(BackendProcess(Mutex::new(None)))
        .manage(ShuttingDown(AtomicBool::new(false)))
        .setup(|app| {
            let handle = app.handle().clone();

            // Show the splash screen straight away: PyInstaller one-file
            // extraction plus the FastAPI/sklearn import can take a few seconds
            // on the first launch.
            WebviewWindowBuilder::new(&handle, "main", WebviewUrl::App("splash.html".into()))
                .title("Log Analysis Dashboard")
                .inner_size(1440.0, 900.0)
                .min_inner_size(1024.0, 640.0)
                .center()
                .build()?;

            // Boot the backend off the main thread, then swap the splash for
            // the real UI once the server is listening.
            std::thread::spawn(move || {
                let target = match spawn_backend(&handle) {
                    Ok(url) => url,
                    Err(err) => {
                        log(&format!(
                            "[tauri] {err} Falling back to http://127.0.0.1:{DEFAULT_PORT}"
                        ));
                        format!("http://127.0.0.1:{DEFAULT_PORT}")
                    }
                };

                let parsed = match target.parse::<tauri::Url>() {
                    Ok(url) => url,
                    Err(err) => {
                        log(&format!("[tauri] invalid backend url '{target}': {err}"));
                        return;
                    }
                };

                let window_handle = handle.clone();
                if let Err(err) = handle.run_on_main_thread(move || {
                    match window_handle.get_webview_window("main") {
                        Some(window) => {
                            if let Err(err) = window.navigate(parsed) {
                                log(&format!("[tauri] navigation failed: {err}"));
                            }
                        }
                        None => log("[tauri] main window no longer exists"),
                    }
                }) {
                    log(&format!("[tauri] could not dispatch navigation: {err}"));
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the Log Analysis Dashboard application")
        .run(|app_handle, event| {
            if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
                app_handle
                    .state::<ShuttingDown>()
                    .0
                    .store(true, Ordering::SeqCst);

                let child = app_handle.state::<BackendProcess>().0.lock().unwrap().take();

                if let Some(mut child) = child {
                    kill_backend(child.id(), &mut child);
                }
            }
        });
}