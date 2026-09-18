//! Carries setup payloads to helpers without exceeding the Windows command-line limit.
//!
//! A setup payload grows with the user's profile contents, so inline Base64 eventually passes the
//! 32,767 UTF-16 code-unit command line that `CreateProcessW` accepts. Two length-independent
//! transports cover the launch paths:
//!
//! - A `@file:` argument backed by a private file, for launches that the producer waits on. The
//!   producer keeps an open handle that denies writers and deleters until the helper has read the
//!   file, so the path cannot be substituted, and deletes the file through that handle afterwards.
//! - A `@stdin` argument, for a `Command` child the producer does not wait on. The producer writes
//!   the payload and closes stdin before returning, so no file lifetime spans the child.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO;
use windows_sys::Win32::Storage::FileSystem::FileDispositionInfo;
use windows_sys::Win32::Storage::FileSystem::SetFileInformationByHandle;

use crate::file_write::create_temporary_file;
use crate::logging::log_note;

/// Prefix for an argument whose value is a path to a file holding the Base64 payload.
const PAYLOAD_FILE_PREFIX: &str = "@file:";

/// Argument that tells the helper to read its Base64 payload from stdin to EOF.
const PAYLOAD_STDIN_ARG: &str = "@stdin";

/// Base64 characters that still fit inline alongside `exe` without approaching the command-line
/// limit. Base64 uses only `[A-Za-z0-9+/=]`, so quoting never expands it.
fn inline_payload_budget(exe: &Path) -> usize {
    const WINDOWS_COMMAND_LINE_LIMIT: usize = 32_767;
    let exe_units = exe.to_string_lossy().encode_utf16().count();
    WINDOWS_COMMAND_LINE_LIMIT.saturating_sub(exe_units + 8 + 16)
}

/// The payload argument for a setup-helper launch.
///
/// Large payloads are backed by a private file. The file stays open, and therefore cannot be
/// renamed, deleted, or rewritten by another process, until this value is dropped.
pub(crate) struct SetupPayloadArg {
    arg: String,
    // Held only so the backing file outlives the launch; never read.
    _payload_file: Option<SetupPayloadFile>,
}

struct SetupPayloadFile {
    file: File,
    // Retained so the pinned sandbox directory cannot be swapped while the helper reads.
    _directory: OwnedHandle,
    path: PathBuf,
    sandbox_dir: PathBuf,
}

impl SetupPayloadArg {
    /// Chooses an inline argument or a private backing file for `payload_b64`.
    pub(crate) fn prepare(payload_b64: &str, exe: &Path, sandbox_dir: &Path) -> Result<Self> {
        if payload_b64.len() <= inline_payload_budget(exe) {
            return Ok(Self {
                arg: payload_b64.to_string(),
                _payload_file: None,
            });
        }
        let (file, directory, path) =
            create_temporary_file(sandbox_dir, ".b64").context("create setup payload file")?;
        // The guard owns the still-open, undeletable file. A failed write drops it here, which
        // schedules deletion through the handle, so partial payloads cannot leak.
        let mut payload_file = SetupPayloadFile {
            file,
            _directory: directory,
            path,
            sandbox_dir: sandbox_dir.to_path_buf(),
        };
        payload_file
            .file
            .write_all(payload_b64.as_bytes())
            .context("write setup payload file")?;
        payload_file
            .file
            .flush()
            .context("flush setup payload file")?;
        Ok(Self {
            arg: format!("{PAYLOAD_FILE_PREFIX}{}", payload_file.path.display()),
            _payload_file: Some(payload_file),
        })
    }

    /// The single argument to hand to the setup helper.
    pub(crate) fn as_str(&self) -> &str {
        &self.arg
    }
}

impl Drop for SetupPayloadFile {
    fn drop(&mut self) {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
        // Delete through the retained handle: the directory entry may already be gone, and
        // deleting by name could remove a replacement. The file is unlinked once every open
        // handle, including the helper's read handle, has closed.
        let scheduled = unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle() as HANDLE,
                FileDispositionInfo,
                (&raw const disposition).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if scheduled == 0 {
            // Drop cannot return an error; report best effort so a failed cleanup is visible.
            let error = unsafe { GetLastError() };
            log_note(
                &format!(
                    "setup payload: failed to schedule deletion of {} (os error {error})",
                    self.path.display()
                ),
                Some(&self.sandbox_dir),
            );
        }
    }
}

/// Resolves argv[1] to the Base64 payload.
///
/// `@file:` reads a file the producer owns; `@stdin` reads `stdin` to EOF; anything else is inline
/// Base64. Consumers never delete a payload file.
pub fn resolve_payload_argument(args: &[String], stdin: &mut impl Read) -> Result<String> {
    if args.len() != 2 {
        bail!("expected payload argument");
    }
    let arg = args[1].as_str();
    if arg == PAYLOAD_STDIN_ARG {
        let mut payload = String::new();
        stdin
            .read_to_string(&mut payload)
            .context("failed to read payload from stdin")?;
        return Ok(payload);
    }
    match arg.strip_prefix(PAYLOAD_FILE_PREFIX) {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read payload file {path}")),
        None => Ok(arg.to_string()),
    }
}

/// Spawns `command` with a `@stdin` payload, writes `payload_b64` to the child's stdin, and closes
/// stdin so the child sees EOF.
///
/// Returns once the bytes are handed off, without waiting for the child's full work, so callers can
/// start a long-running helper child. The payload has no on-disk lifetime across the child.
pub fn spawn_with_stdin_payload(command: &mut Command, payload_b64: &str) -> Result<()> {
    command.arg(PAYLOAD_STDIN_ARG).stdin(Stdio::piped());
    let mut child = command.spawn().context("spawn setup helper")?;
    let mut stdin = child.stdin.take().context("open setup helper stdin")?;
    stdin
        .write_all(payload_b64.as_bytes())
        .context("write setup payload to helper stdin")?;
    stdin
        .flush()
        .context("flush setup payload to helper stdin")?;
    drop(stdin);
    // The child owns the buffered payload now. Do not wait for the full operation, and do not keep
    // the process handle open; dropping it does not affect the running child.
    drop(child);
    Ok(())
}

#[cfg(test)]
#[path = "setup_payload_tests.rs"]
mod tests;
