//! Carries large setup payloads to helpers without exceeding the Windows command-line limit.
//!
//! A setup payload grows with the user's profile contents, so inline Base64 eventually passes the
//! 32,767 UTF-16 code-unit command line that `CreateProcessW` accepts. Large payloads travel
//! through a private file instead. The producer keeps an open handle that denies writers and
//! deleters until the helper has read the file, so the path cannot be substituted in between, and
//! deletes the file through that same handle once the launch is finished.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use std::fs::File;
use std::io::Write;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO;
use windows_sys::Win32::Storage::FileSystem::FileDispositionInfo;
use windows_sys::Win32::Storage::FileSystem::SetFileInformationByHandle;

use crate::file_write::create_temporary_file;

/// Prefix marking an argument whose value is the path to a file holding the Base64 payload.
pub const PAYLOAD_FILE_PREFIX: &str = "@file:";

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
pub struct SetupPayloadArg {
    arg: String,
    payload_file: Option<SetupPayloadFile>,
}

struct SetupPayloadFile {
    file: File,
    // Retained so the pinned sandbox directory cannot be swapped while the helper reads.
    _directory: OwnedHandle,
}

impl Drop for SetupPayloadFile {
    fn drop(&mut self) {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
        // Delete through the retained handle: the directory entry may already be gone, and
        // deleting by name could remove a replacement. The file is unlinked once every open
        // handle, including the helper's read handle, has closed.
        unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle() as HANDLE,
                FileDispositionInfo,
                (&raw const disposition).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            );
        }
    }
}

impl SetupPayloadArg {
    /// Chooses an inline argument or a private backing file for `payload_b64`.
    pub fn prepare(payload_b64: &str, exe: &Path, sandbox_dir: &Path) -> Result<Self> {
        if payload_b64.len() <= inline_payload_budget(exe) {
            return Ok(Self {
                arg: payload_b64.to_string(),
                payload_file: None,
            });
        }
        let (file, directory, path) =
            create_temporary_file(sandbox_dir, ".b64").context("create setup payload file")?;
        // The guard owns the still-open, undeletable file. A failed write drops it here, which
        // schedules deletion through the handle, so partial payloads cannot leak.
        let mut payload_file = SetupPayloadFile {
            file,
            _directory: directory,
        };
        payload_file
            .file
            .write_all(payload_b64.as_bytes())
            .context("write setup payload file")?;
        payload_file.file.flush().context("flush setup payload file")?;
        Ok(Self {
            arg: format!("{PAYLOAD_FILE_PREFIX}{}", path.display()),
            payload_file: Some(payload_file),
        })
    }

    /// The single argument to hand to the setup helper.
    pub fn as_str(&self) -> &str {
        &self.arg
    }
}

/// Resolves argv[1] to the Base64 payload, reading a `@file:` payload file when present.
///
/// The producer owns the file. Consumers must never delete it.
pub fn resolve_payload_argument(args: &[String]) -> Result<String> {
    if args.len() != 2 {
        bail!("expected payload argument");
    }
    match args[1].strip_prefix(PAYLOAD_FILE_PREFIX) {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read payload file {path}")),
        None => Ok(args[1].clone()),
    }
}

#[cfg(test)]
#[path = "setup_payload_tests.rs"]
mod tests;
