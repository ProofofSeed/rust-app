// SPDX-License-Identifier: LGPL-3.0-or-later

//! Exclusive, mode-0600 file creation, and panic-output suppression around
//! verification.

/// Runs a closure with the panic output suppressed, restoring the previous hook
/// afterwards.
pub fn quietly<T>(f: impl FnOnce() -> T) -> T {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = f();
    let _ = std::panic::take_hook();
    std::panic::set_hook(previous);
    result
}

/// Creates a new file mode 0600, refusing to overwrite one or to follow a symlink.
pub fn create_new_0600(path: &std::path::Path) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e} (refusing to overwrite)", path.display()))
}
