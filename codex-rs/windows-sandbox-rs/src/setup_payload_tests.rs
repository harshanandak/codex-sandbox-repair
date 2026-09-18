//! Checks the setup payload transport: budget selection, byte-exact file round-trip, path
//! substitution resistance, and cleanup on every exit path.

use super::PAYLOAD_FILE_PREFIX;
use super::SetupPayloadArg;
use super::inline_payload_budget;
use super::resolve_payload_argument;
use anyhow::Result;
use pretty_assertions::assert_eq;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

fn helper_exe() -> PathBuf {
    PathBuf::from(r"C:\very\long\helper\path\codex-windows-sandbox-setup.exe")
}

fn oversized_payload() -> String {
    "A".repeat(38_136)
}

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
    // Exactly what the helper does: read by path while the producer still holds the file.
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

    assert_eq!(
        resolve_payload_argument(&["setup".to_string(), arg.as_str().to_string()])?,
        payload
    );
    assert_eq!(
        resolve_payload_argument(&["setup".to_string(), "QUJD".to_string()])?,
        "QUJD"
    );
    Ok(())
}

#[test]
fn resolve_rejects_malformed_arguments() {
    assert!(resolve_payload_argument(&[]).is_err());
    assert!(
        resolve_payload_argument(&["setup".to_string(), "a".to_string(), "b".to_string()])
            .is_err()
    );

    let missing = format!("{PAYLOAD_FILE_PREFIX}C:\\missing\\payload.b64");
    let err = resolve_payload_argument(&["setup".to_string(), missing]).unwrap_err();

    assert!(err.to_string().contains("failed to read payload file"));
}
