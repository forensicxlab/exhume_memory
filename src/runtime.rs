use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

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

/// Locate and preload the optional LeechCore DMA runtime shipped beside an
/// application. The setup is process-wide and therefore runs at most once.
///
/// `exhume_memory` links the LeechCore core statically. Only the platform DMA
/// driver libraries need to be discovered at runtime.
pub fn configure_runtime_paths() {
    static CONFIGURED_RUNTIME: OnceLock<Option<PathBuf>> = OnceLock::new();

    CONFIGURED_RUNTIME.get_or_init(|| {
        let Some(runtime_dir) = find_runtime_dir() else {
            log::warn!(
                "could not auto-locate the LeechCore runtime directory; expected one of [{}] in leechcore-runtime or set LEECHCORE_RUNTIME_DIR",
                runtime_driver_names().join(", ")
            );
            return None;
        };

        configure_loader_search_path(&runtime_dir);
        let preload = preload_runtime_libraries(&runtime_dir);
        if !preload.driver_loaded {
            log::warn!(
                "found LeechCore runtime directory {}, but no DMA driver could be preloaded ({} supporting libraries loaded)",
                runtime_dir.display(),
                preload.libraries.len()
            );
        } else {
            log::info!(
                "using LeechCore runtime directory {} ({} libraries preloaded)",
                runtime_dir.display(),
                preload.libraries.len()
            );
        }

        Some(runtime_dir)
    });
}

const RUNTIME_RELATIVE_DIRS: &[&str] = &[
    "leechcore-runtime",
    "runtime/leechcore",
    "binaries/LeechCore/runtime",
    // Legacy Thanatology development layout.
    "binaries/bin-macos/LeechCore/runtime",
    "src-tauri/binaries/bin-macos/LeechCore/runtime",
    "Resources/leechcore-runtime",
    "Resources/binaries/bin-macos/LeechCore/runtime",
    "",
];

fn find_runtime_dir() -> Option<PathBuf> {
    let override_dir = std::env::var_os("LEECHCORE_RUNTIME_DIR").map(PathBuf::from);
    // Current-directory discovery is convenient for development, but a
    // release build must not load native libraries from an investigator's
    // working directory.
    let cwd = if cfg!(debug_assertions) {
        std::env::current_dir().ok()
    } else {
        None
    };
    let executable = std::env::current_exe().ok();

    find_runtime_dir_from(override_dir, cwd.as_deref(), executable.as_deref())
}

fn find_runtime_dir_from(
    override_dir: Option<PathBuf>,
    cwd: Option<&Path>,
    executable: Option<&Path>,
) -> Option<PathBuf> {
    let mut candidates = Vec::<PathBuf>::new();

    if let Some(dir) = override_dir {
        candidates.push(dir);
    }

    if let Some(dir) = cwd {
        extend_runtime_candidates(&mut candidates, dir);
    }

    if let Some(executable) = executable
        && let Some(executable_dir) = executable.parent()
    {
        extend_runtime_candidates(&mut candidates, executable_dir);
        extend_linux_resource_candidates(&mut candidates, executable_dir, executable);
    }

    let mut seen = HashSet::new();
    candidates.into_iter().find_map(|candidate| {
        if !seen.insert(candidate.clone()) || !runtime_dir_is_valid(&candidate) {
            return None;
        }

        Some(std::fs::canonicalize(&candidate).unwrap_or(candidate))
    })
}

fn extend_runtime_candidates(candidates: &mut Vec<PathBuf>, base: &Path) {
    for ancestor in base.ancestors().take(8) {
        for relative_dir in RUNTIME_RELATIVE_DIRS {
            if relative_dir.is_empty() {
                candidates.push(ancestor.to_path_buf());
            } else {
                candidates.push(ancestor.join(relative_dir));
            }
        }
    }
}

fn extend_linux_resource_candidates(
    candidates: &mut Vec<PathBuf>,
    executable_dir: &Path,
    executable: &Path,
) {
    #[cfg(target_os = "linux")]
    if let Some(executable_name) = executable.file_name() {
        // Tauri places resources in ../lib/<executable-name> for development,
        // AppImage, deb and rpm layouts.
        candidates.push(
            executable_dir
                .join("../lib")
                .join(executable_name)
                .join("leechcore-runtime"),
        );
        candidates.push(
            Path::new("/usr/lib")
                .join(executable_name)
                .join("leechcore-runtime"),
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (candidates, executable_dir, executable);
    }
}

fn runtime_dir_is_valid(dir: &Path) -> bool {
    runtime_driver_names()
        .iter()
        .any(|name| dir.join(name).is_file())
}

#[cfg(target_os = "macos")]
fn runtime_driver_names() -> &'static [&'static str] {
    &["leechcore_ft601_driver_macos.dylib"]
}

#[cfg(target_os = "linux")]
fn runtime_driver_names() -> &'static [&'static str] {
    &["leechcore_driver.so", "leechcore_ft601_driver_linux.so"]
}

#[cfg(target_os = "windows")]
fn runtime_driver_names() -> &'static [&'static str] {
    &["leechcore_driver.dll", "FTD3XXWU.dll", "FTD3XX.dll"]
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn runtime_driver_names() -> &'static [&'static str] {
    &[]
}

fn configure_loader_search_path(runtime_dir: &Path) {
    #[cfg(target_os = "macos")]
    for key in ["DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH"] {
        prepend_env_path(key, runtime_dir);
    }

    #[cfg(target_os = "linux")]
    prepend_env_path("LD_LIBRARY_PATH", runtime_dir);

    #[cfg(target_os = "windows")]
    prepend_env_path("PATH", runtime_dir);
}

fn prepend_env_path(key: &str, path: &Path) {
    let Some(value) = prepended_search_path(path, std::env::var_os(key).as_deref()) else {
        log::warn!("failed to add {} to {}", path.display(), key);
        return;
    };

    // Rust 2024 marks environment mutation as unsafe because it is
    // process-global. configure_runtime_paths serializes this one-time setup.
    unsafe {
        std::env::set_var(key, value);
    }
}

fn prepended_search_path(path: &Path, current: Option<&OsStr>) -> Option<OsString> {
    let mut paths = vec![path.to_path_buf()];
    if let Some(current) = current {
        paths.extend(std::env::split_paths(current));
    }

    let mut seen = HashSet::new();
    paths.retain(|entry| seen.insert(entry.clone()));
    std::env::join_paths(paths).ok()
}

struct PreloadedRuntime {
    libraries: Vec<libloading::Library>,
    driver_loaded: bool,
}

fn preload_runtime_libraries(runtime_dir: &Path) -> &'static PreloadedRuntime {
    static PRELOADED_RUNTIME: OnceLock<PreloadedRuntime> = OnceLock::new();

    PRELOADED_RUNTIME.get_or_init(|| {
        let mut libraries = Vec::new();
        let mut driver_loaded = false;

        for name in preload_library_names() {
            let path = runtime_dir.join(name);
            if !path.is_file() {
                continue;
            }

            match unsafe { libloading::Library::new(&path) } {
                Ok(library) => {
                    log::debug!("preloaded {}", path.display());
                    driver_loaded |= runtime_driver_names().contains(name);
                    libraries.push(library);
                }
                Err(err) => {
                    log::warn!("failed to preload {}: {}", path.display(), err);
                }
            }
        }

        PreloadedRuntime {
            libraries,
            driver_loaded,
        }
    })
}

#[cfg(target_os = "macos")]
fn preload_library_names() -> &'static [&'static str] {
    &["libftd3xx.dylib", "leechcore_ft601_driver_macos.dylib"]
}

#[cfg(target_os = "linux")]
fn preload_library_names() -> &'static [&'static str] {
    &["leechcore_driver.so", "leechcore_ft601_driver_linux.so"]
}

#[cfg(target_os = "windows")]
fn preload_library_names() -> &'static [&'static str] {
    &[
        "vcruntime140.dll",
        "leechcore_driver.dll",
        "FTD3XXWU.dll",
        "FTD3XX.dll",
    ]
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn preload_library_names() -> &'static [&'static str] {
    &[]
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let nonce = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "exhume-memory-runtime-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create runtime test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn add_runtime_marker(dir: &Path) {
        fs::create_dir_all(dir).expect("create marker directory");
        fs::write(dir.join(runtime_driver_names()[0]), b"fixture").expect("write runtime marker");
    }

    #[test]
    fn explicit_runtime_directory_takes_priority() {
        let fixture = TestDir::new("override");
        let override_dir = fixture.path().join("explicit");
        let discovered_dir = fixture.path().join("leechcore-runtime");
        add_runtime_marker(&override_dir);
        add_runtime_marker(&discovered_dir);

        let selected =
            find_runtime_dir_from(Some(override_dir.clone()), Some(fixture.path()), None)
                .expect("runtime directory");

        assert_eq!(selected, fs::canonicalize(override_dir).unwrap());
    }

    #[test]
    fn discovers_runtime_beside_the_executable() {
        let fixture = TestDir::new("executable");
        let executable_dir = fixture.path().join("bin");
        let runtime_dir = executable_dir.join("leechcore-runtime");
        add_runtime_marker(&runtime_dir);

        let selected = find_runtime_dir_from(None, None, Some(&executable_dir.join("thanatology")))
            .expect("runtime directory");

        assert_eq!(selected, fs::canonicalize(runtime_dir).unwrap());
    }

    #[test]
    fn discovers_runtime_in_a_macos_style_resources_directory() {
        let fixture = TestDir::new("resources");
        let contents = fixture.path().join("Thanatology.app/Contents");
        let runtime_dir = contents.join("Resources/leechcore-runtime");
        add_runtime_marker(&runtime_dir);

        let selected = find_runtime_dir_from(None, None, Some(&contents.join("MacOS/thanatology")))
            .expect("runtime directory");

        assert_eq!(selected, fs::canonicalize(runtime_dir).unwrap());
    }

    #[test]
    fn prepending_search_path_preserves_entries_without_duplicates() {
        let runtime = Path::new("/runtime");
        let current = std::env::join_paths([Path::new("/existing"), runtime]).unwrap();
        let updated = prepended_search_path(runtime, Some(&current)).unwrap();
        let entries = std::env::split_paths(&updated).collect::<Vec<_>>();

        assert_eq!(entries, vec![runtime, Path::new("/existing")]);
    }
}
