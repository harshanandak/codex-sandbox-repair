//! Checks payload transport selection, byte-exact delivery, and cleanup on every exit path.

use super::PAYLOAD_FILE_PREFIX;
use super::PAYLOAD_STDIN_ARG;
use super::SetupPayloadArg;
use super::inline_payload_budget;
use super::resolve_payload_argument;
use super::spawn_with_stdin_payload;
use anyhow::Result;
use anyhow::bail;
use pretty_assertions::assert_eq;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;

fn helper_exe() -> PathBuf {
    PathBuf::from(r"C:\very\long\helper\path\codex-windows-sandbox-setup.exe")
}

fn oversized_payload() -> String {
    "A".repeat(38_136)
}

/// Receiver fixture for the `@stdin` handoff. PowerShell only treats a trailing `@stdin` as a
/// literal positional argument under `-File`; under `-Command` it parses as a splat and fails.
const STDIN_RECEIVER_SCRIPT: &str = r#"param([string]$transport)
if ($transport -ne '@stdin') {
    [Console]::Error.WriteLine("unexpected transport argument: $transport")
    exit 2
}
$output = [IO.File]::Create($env:CODEX_TEST_PAYLOAD_OUT)
[Console]::OpenStandardInput().CopyTo($output)
$output.Dispose()
"#;

fn file_path(arg: &SetupPayloadArg) -> &str {
    arg.as_str()
        .strip_prefix(PAYLOAD_FILE_PREFIX)
        .expect("file payload argument")
}

#[test]
fn small_payload_stays_inline() -> Result<()> {
    let temp = tempfile::tempdir()?;

    let arg = SetupPayloadArg::prepare("QUJD", &helper_exe(), temp.path())?;

    assert_eq!(arg.as_str(), "QUJD");
    assert_eq!(fs::read_dir(temp.path())?.count(), 0);
    Ok(())
}

#[test]
fn inline_budget_leaves_command_line_headroom() {
    let exe = helper_exe();
    let budget = inline_payload_budget(&exe);
    let exe_units = exe.to_string_lossy().encode_utf16().count();
    assert!(budget + exe_units + 8 <= 32_767);
}

#[test]
fn oversized_payload_round_trips_through_a_file() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let payload = oversized_payload();
    assert!(payload.len() > inline_payload_budget(&helper_exe()));

    let arg = SetupPayloadArg::prepare(&payload, &helper_exe(), temp.path())?;

    assert!(arg.as_str().len() < 1_024, "file argument must stay short");
    // Exactly what a waiting helper does: read by path while the producer still holds the file.
    assert_eq!(fs::read_to_string(file_path(&arg))?, payload);
    Ok(())
}

#[test]
fn held_payload_file_resists_rewrite_and_replacement() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let arg = SetupPayloadArg::prepare(&oversized_payload(), &helper_exe(), temp.path())?;
    let path = Path::new(file_path(&arg));

    assert!(fs::write(path, b"tampered").is_err());
    assert!(fs::remove_file(path).is_err());
    assert!(fs::rename(path, temp.path().join("moved")).is_err());
    assert!(path.exists());
    Ok(())
}

#[test]
fn payload_file_is_removed_when_a_launch_is_abandoned() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let arg = SetupPayloadArg::prepare(&oversized_payload(), &helper_exe(), temp.path())?;
    let path = PathBuf::from(file_path(&arg));
    assert!(path.exists());

    // A launch that fails before the helper reads the payload drops the argument exactly here.
    drop(arg);

    assert!(!path.exists(), "abandoned payload file must be removed");
    assert_eq!(fs::read_dir(temp.path())?.count(), 0);
    Ok(())
}

#[test]
fn file_transport_supports_unicode_and_space_directories() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let sandbox = temp.path().join("payload dir ünïcode");
    fs::create_dir(&sandbox)?;
    let payload = oversized_payload();

    let arg = SetupPayloadArg::prepare(&payload, &helper_exe(), &sandbox)?;
    let path = file_path(&arg);

    assert!(path.contains('ü'));
    assert_eq!(fs::read_to_string(path)?, payload);
    Ok(())
}

#[test]
fn concurrent_large_payloads_use_distinct_files() -> Result<()> {
    let temp = tempfile::tempdir()?;

    let first = SetupPayloadArg::prepare(&oversized_payload(), &helper_exe(), temp.path())?;
    let second = SetupPayloadArg::prepare(&oversized_payload(), &helper_exe(), temp.path())?;

    assert_ne!(first.as_str(), second.as_str());
    assert_eq!(fs::read_dir(temp.path())?.count(), 2);
    Ok(())
}

#[test]
fn missing_sandbox_directory_fails_without_leaving_a_file() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing");

    let err = SetupPayloadArg::prepare(&oversized_payload(), &helper_exe(), &missing)
        .err()
        .expect("missing directory must fail");

    assert!(err.to_string().contains("create setup payload file"));
    assert_eq!(fs::read_dir(temp.path())?.count(), 0);
    Ok(())
}

#[test]
fn resolve_reads_inline_and_file_payloads() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let payload = oversized_payload();
    let arg = SetupPayloadArg::prepare(&payload, &helper_exe(), temp.path())?;
    let mut empty = std::io::empty();

    assert_eq!(
        resolve_payload_argument(&["setup".to_string(), arg.as_str().to_string()], &mut empty)?,
        payload
    );
    assert_eq!(
        resolve_payload_argument(&["setup".to_string(), "QUJD".to_string()], &mut empty)?,
        "QUJD"
    );
    Ok(())
}

#[test]
fn resolve_reads_stdin_payload() -> Result<()> {
    let payload = oversized_payload();
    let mut stdin = std::io::Cursor::new(payload.clone().into_bytes());

    assert_eq!(
        resolve_payload_argument(
            &["setup".to_string(), PAYLOAD_STDIN_ARG.to_string()],
            &mut stdin
        )?,
        payload
    );
    Ok(())
}

#[test]
fn resolve_rejects_malformed_arguments() {
    let mut empty = std::io::empty();
    assert!(resolve_payload_argument(&[], &mut empty).is_err());
    assert!(
        resolve_payload_argument(
            &["setup".to_string(), "a".to_string(), "b".to_string()],
            &mut empty
        )
        .is_err()
    );

    let missing = format!("{PAYLOAD_FILE_PREFIX}C:\\missing\\payload.b64");
    let err = resolve_payload_argument(&["setup".to_string(), missing], &mut empty).unwrap_err();

    assert!(err.to_string().contains("failed to read payload file"));
}

#[test]
fn stdin_payload_reaches_a_child_after_the_producer_returns() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let script = temp.path().join("receiver.ps1");
    let out = temp.path().join("received.b64");
    fs::write(&script, STDIN_RECEIVER_SCRIPT)?;
    let payload = oversized_payload();
    let mut command = Command::new("powershell.exe");
    command
        .env("CODEX_TEST_PAYLOAD_OUT", &out)
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(&script);

    // Returns after handing the bytes off; it does not wait for the child.
    spawn_with_stdin_payload(&mut command, &payload)?;

    assert_eq!(
        read_until_len(&out, payload.len(), Duration::from_secs(30))?,
        payload.as_bytes()
    );
    // The stdin handoff creates no payload file: exactly the receiver and its output remain.
    let mut names = fs::read_dir(temp.path())?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<Vec<String>>>()?;
    names.sort();
    assert_eq!(
        names,
        vec!["received.b64".to_string(), "receiver.ps1".to_string()]
    );
    Ok(())
}

fn read_until_len(path: &Path, expected: usize, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(bytes) = fs::read(path)
            && bytes.len() == expected
        {
            return Ok(bytes);
        }
        if Instant::now() >= deadline {
            bail!("child did not write {expected} bytes to {} in time", path.display());
        }
        sleep(Duration::from_millis(50));
    }
}
