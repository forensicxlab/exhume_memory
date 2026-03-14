#[cfg(target_os = "macos")]
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::cli::LogLevel;

pub fn init_logging(level: LogLevel) {
    let level_filter = match level {
        LogLevel::Error => log::LevelFilter::Error,
        LogLevel::Warn => log::LevelFilter::Warn,
        LogLevel::Info => log::LevelFilter::Info,
        LogLevel::Debug => log::LevelFilter::Debug,
        LogLevel::Trace => log::LevelFilter::Trace,
    };

    let mut builder = env_logger::Builder::new();
    builder
        .filter_level(level_filter)
        .filter_module("memflow_rawmem", log::LevelFilter::Warn);
    builder.init();
}

pub fn configure_runtime_paths() {
    #[cfg(target_os = "macos")]
    {
        if let Some(runtime_dir) = find_macos_runtime_dir() {
            ensure_macos_driver_aliases(&runtime_dir);
            set_env_path("DYLD_LIBRARY_PATH", &runtime_dir);
            set_env_path("DYLD_FALLBACK_LIBRARY_PATH", &runtime_dir);
            preload_macos_runtime_libraries(&runtime_dir);
            log::info!("using LeechCore runtime dir: {}", runtime_dir.display());
        } else {
            log::warn!(
                "could not auto-locate LeechCore runtime dir. expected binaries/bin-macos/LeechCore/runtime, binaries/bin-macos/PCILeech/runtime, or lc-runtime containing leechcore_ft601_driver_macos.dylib"
            );
        }
    }
}

#[cfg(target_os = "macos")]
const MACOS_RUNTIME_RELATIVE_DIRS: &[&str] = &[
    "binaries/bin-macos/LeechCore/runtime",
    "src-tauri/binaries/bin-macos/LeechCore/runtime",
    "Resources/binaries/bin-macos/LeechCore/runtime",
    "binaries/bin-macos/PCILeech/runtime",
    "src-tauri/binaries/bin-macos/PCILeech/runtime",
    "Resources/binaries/bin-macos/PCILeech/runtime",
    "lc-runtime",
    "src-tauri/lc-runtime",
    "Resources/lc-runtime",
    "",
];

#[cfg(target_os = "macos")]
fn find_macos_runtime_dir() -> Option<PathBuf> {
    let mut candidates = Vec::<PathBuf>::new();

    if let Ok(dir) = std::env::var("LEECHCORE_RUNTIME_DIR") {
        candidates.push(PathBuf::from(dir));
    }

    if let Ok(cwd) = std::env::current_dir() {
        extend_macos_runtime_candidates(&mut candidates, &cwd);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            extend_macos_runtime_candidates(&mut candidates, exe_dir);
            if let Some(contents_dir) = exe_dir.parent() {
                extend_macos_runtime_candidates(&mut candidates, contents_dir);
                extend_macos_runtime_candidates(&mut candidates, &contents_dir.join("Resources"));
            }
        }
    }

    let mut seen = HashSet::new();
    candidates.into_iter().find(|dir| {
        seen.insert(dir.clone())
            && (dir.join("leechcore_ft601_driver_macos.dylib").is_file()
                || dir.join("leechcore_driver.dylib").is_file())
    })
}

#[cfg(target_os = "macos")]
fn extend_macos_runtime_candidates(candidates: &mut Vec<PathBuf>, base: &Path) {
    for ancestor in base.ancestors().take(6) {
        for relative_dir in MACOS_RUNTIME_RELATIVE_DIRS {
            if relative_dir.is_empty() {
                candidates.push(ancestor.to_path_buf());
            } else {
                candidates.push(ancestor.join(relative_dir));
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn set_env_path(key: &str, path: &Path) {
    let value = path.to_string_lossy().to_string();
    // Rust 2024 marks env mutation as unsafe because it is process-global.
    unsafe {
        std::env::set_var(key, value);
    }
}

#[cfg(target_os = "macos")]
fn ensure_macos_driver_aliases(runtime_dir: &Path) {
    use std::os::unix::fs::symlink;

    let generic_driver = runtime_dir.join("leechcore_driver.dylib");
    let legacy_driver = runtime_dir.join("leechcore.dylib");

    if generic_driver.exists() || !legacy_driver.exists() {
        return;
    }

    match symlink(&legacy_driver, &generic_driver) {
        Ok(()) => {
            log::info!(
                "created compatibility symlink: {} -> {}",
                generic_driver.display(),
                legacy_driver.display()
            );
        }
        Err(err) => {
            log::warn!(
                "failed to create compatibility symlink {} -> {}: {}",
                generic_driver.display(),
                legacy_driver.display(),
                err
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn preload_macos_runtime_libraries(runtime_dir: &Path) {
    use std::sync::OnceLock;

    static PRELOAD_DONE: OnceLock<()> = OnceLock::new();

    if PRELOAD_DONE.get().is_some() {
        return;
    }

    let candidates = [
        "libftd3xx.dylib",
        "libMSCompression.dylib",
        "leechcore.dylib",
        "leechcore_driver.dylib",
        "leechcore_ft601_driver_macos.dylib",
    ];

    let mut loaded = 0usize;

    for name in candidates {
        let path = runtime_dir.join(name);
        if !path.is_file() {
            continue;
        }

        match unsafe { libloading::Library::new(&path) } {
            Ok(library) => {
                // Keep the image loaded for the process lifetime.
                std::mem::forget(library);
                loaded += 1;
                log::debug!("preloaded {}", path.display());
            }
            Err(err) => {
                log::warn!("failed to preload {}: {}", path.display(), err);
            }
        }
    }

    let _ = PRELOAD_DONE.set(());

    if loaded == 0 {
        log::warn!(
            "no LeechCore runtime libraries were preloaded from {}",
            runtime_dir.display()
        );
    }
}
