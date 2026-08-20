// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared file-creation helper: create a new file mode 0600, refusing to
//! overwrite. `create_new` (O_CREAT|O_EXCL) also refuses to follow a pre-planted
//! symlink at the path, so a sidecar or proof cannot be redirected into a
//! shared directory.

/// Runs `f` with the panic output suppressed, restoring the previous hook after.
/// The stream verifier turns a malformed proof into `false` via `catch_unwind`,
/// but the default hook still prints a panic trace — including the binary's build
/// path — to stderr on the way. The CLI is single-threaded, so swapping the
/// process-global hook for the duration of one verification is race-free here.
pub fn quietly<T>(f: impl FnOnce() -> T) -> T {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = f();
    let _ = std::panic::take_hook();
    std::panic::set_hook(previous);
    result
}

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
