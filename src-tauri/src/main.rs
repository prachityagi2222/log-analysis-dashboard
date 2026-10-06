// Prevents an extra console window from appearing alongside the app on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Windows process creation flag that gives the console-mode backend process
/// no visible console window while keeping its stdout/stderr pipes intact.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Upper bound for how long we wait for the backend to print SERVER_READY.
/// A PyInstaller one-file bundle can spend several seconds extracting and
/// importing sklearn, but it should never take this long; if it does, the
/// process is almost certainly blocked (antivirus) or missing a runtime.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Handle to the PyInstaller backend process so it can be terminated on exit.
struct BackendProcess(Mutex<Option<Child>>);

/// Set while the app is shutting down so a late-spawning backend is not leaked.
struct ShuttingDown(AtomicBool);

/// Directory where startup logs are persisted. Release builds run under the
/// Windows GUI subsystem, so stdout is a null device; a file under APPDATA is
/// the only place the backend's stderr (Python tracebacks, missing-DLL errors)
/// can survive on a machine that has no console attached.
fn log_file_path() -> Option<PathBuf> {
    let appdata = std::env::var("APPDATA").ok()?;
    let dir = PathBuf::from(appdata).join("LogDashboard").join("logs");
    let _ = std::fs::create_dir_all(&dir);
    Some(dir.join("tauri.log"))
}

/// Best-effort logging. Writes to stdout (visible during `tauri dev`) and, when
/// possible, appends to %APPDATA%\LogDashboard\logs\tauri.log so release builds
/// remain diagnosable on machines without a console.
fn log(message: &str) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{message}");

    if let Some(path) = log_file_path() {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(file, "{message}");
        }
    }
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
///
/// The wait is bounded by STARTUP_TIMEOUT so a backend that hangs during
/// PyInstaller extraction (for example under antivirus scanning) cannot block
/// the app forever. If the backend exits or times out, the process tree is
/// torn down and the real cause (already captured on stderr) is reported.
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
    // Every line is persisted to the log file, so a Python traceback or a
    // missing-DLL error is visible even in GUI-subsystem release builds.
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            log(&format!("[backend] {line}"));
        }
    });

    // Pump stdout through a channel so the readiness wait can be bounded by a
    // timeout instead of blocking on read_line forever.
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    // Wait for the SERVER_READY line, bounded by STARTUP_TIMEOUT.
    // recv_deadline is unstable, so poll with recv_timeout against a
    // hard deadline instead.
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut url = None;
    let mut timed_out = false;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                let trimmed = line.trim().to_string();
                log(&format!("[backend] {trimmed}"));

                if let Some(rest) = trimmed.strip_prefix("SERVER_READY:") {
                    url = Some(rest.trim().to_string());
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                timed_out = true;
                break;
            }
            Err(RecvTimeoutError::Disconnected) => {
                // The stdout pump finished: the backend closed its stdout
                // (it exited or crashed before announcing readiness).
                break;
            }
        }
    }

    if url.is_none() {
        // The backend either crashed or hung. Tear down the process tree so it
        // is not leaked, then report the failure. The detailed cause (traceback,
        // DLL error, etc.) is already in the log file via the stderr drain.
        kill_backend(child.id(), &mut child);
        let log_hint = log_file_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unavailable>".to_string());
        if timed_out {
            return Err(format!(
                "Backend did not report readiness within {} seconds. It may be blocked \
                 by antivirus or missing a system runtime. Startup output was written to: {log_hint}",
                STARTUP_TIMEOUT.as_secs()
            ));
        }
        return Err(format!(
            "Backend exited before reporting SERVER_READY. Startup output was written to: {log_hint}"
        ));
    }

    // Keep draining the remaining stdout so the backend never blocks on write.
    std::thread::spawn(move || {
        for line in rx.iter() {
            log(&format!("[backend] {line}"));
        }
    });

    // Register the child for shutdown, unless the app is already exiting.
    if app.state::<ShuttingDown>().0.load(Ordering::SeqCst) {
        kill_backend(child.id(), &mut child);
        return Err("application is shutting down".to_string());
    }
    app.state::<BackendProcess>().0.lock().unwrap().replace(child);

    // url is guaranteed Some here: we returned early above whenever it was None.
    Ok(url.expect("readiness URL was set"))
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

/// Percent-encode a string for safe inclusion in a data: URL.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// Escape a string for safe inclusion in HTML text content.
fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#039;"),
            _ => out.push(c),
        }
    }
    out
}

/// Build a self-contained error page shown when the backend cannot start.
/// The page carries a short plain-language message plus the log-file location;
/// the full technical detail (traceback, DLL error) lives in the log file.
fn backend_error_url(message: &str) -> tauri::Url {
    let log_path = log_file_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "%APPDATA%\\LogDashboard\\logs\\tauri.log".to_string());
    let escaped_log_path = html_escape(&log_path);
    let escaped_message = html_escape(message);
    let html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">\
         <title>Log Analysis Dashboard</title>\
         <style>\
         body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e17;color:#e2e8f0;\
         display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}\
         .box{{max-width:560px;padding:32px;border:1px solid rgba(239,68,68,.4);border-radius:12px;\
         background:#111827;text-align:center}}\
         h1{{color:#ef4444;font-size:1.25rem;margin:0 0 12px}}\
         p{{color:#94a3b8;line-height:1.5;margin:0 0 8px}}\
         code{{color:#f87171;font-size:.8rem;word-break:break-all}}\
         </style></head>\
         <body><div class=\"box\">\
         <h1>Local analysis engine failed to start</h1>\
         <p>The backend process could not be launched. This is usually caused by antivirus \
         software blocking the bundled engine, or a missing system component.</p>\
         <p>Please try restarting the application. If the problem persists, the startup log \
         may help: <code>{escaped_log_path}</code></p>\
         <code>{escaped_message}</code>\
         </div></body></html>",
    );
    format!("data:text/html;charset=utf-8,{}", percent_encode(&html))
        .parse()
        .expect("error page data URL is valid")
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
                let target: tauri::Url = match spawn_backend(&handle) {
                    Ok(url) => match url.parse() {
                        Ok(parsed) => parsed,
                        Err(err) => {
                            let msg = format!("Backend reported an invalid URL '{url}': {err}");
                            log(&format!("[tauri] {msg}"));
                            backend_error_url(&msg)
                        }
                    },
                    Err(err) => {
                        // Do NOT fall back to a hard-coded localhost port: that
                        // produces an opaque "refused to connect" and hides the
                        // real failure. Show a clear error page instead, and keep
                        // the technical detail in the log file.
                        log(&format!("[tauri] backend startup failed: {err}"));
                        backend_error_url(&err)
                    }
                };

                let window_handle = handle.clone();
                if let Err(err) = handle.run_on_main_thread(move || {
                    match window_handle.get_webview_window("main") {
                        Some(window) => {
                            if let Err(err) = window.navigate(target) {
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
