fn main() {
    // Expose the active target triple to the crate so we can locate the
    // architecture-suffixed sidecar binary (e.g. log-backend-x86_64-pc-windows-gnu.exe)
    // while running under `tauri dev`.
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=TARGET_TRIPLE={target}");
    }

    tauri_build::build();
}