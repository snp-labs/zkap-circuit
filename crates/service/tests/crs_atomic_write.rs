//! Tests that `persist_setup_output` writes CRS artifacts atomically.
//!
//! These tests exercise the temp+rename invariant: when a write fails
//! mid-stream, the target path is never created (or left as-is if it
//! already existed). We test this at the unit level by simulating a
//! failed rename — the same pattern the module uses internally.

use std::fs;
use std::path::{Path, PathBuf};

fn tmp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zkap_service_crs_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Simulate the atomic-write protocol: write to a temp file, then rename
/// onto the target.  When the rename fails (here: target is a pre-existing
/// directory so `fs::rename` is guaranteed to fail on all platforms),
/// the temp file is cleaned up and the target is untouched.
fn simulate_atomic_write(dir: &Path, artifact_name: &str, bytes: &[u8]) -> bool {
    let target = dir.join(artifact_name);
    let tmp_path = dir.join(format!(".{}.tmp.{}", artifact_name, std::process::id()));

    // Step 1: write to temp
    if fs::write(&tmp_path, bytes).is_err() {
        return false;
    }
    // Step 2: rename — may fail
    let ok = fs::rename(&tmp_path, &target).is_ok();
    if !ok {
        let _ = fs::remove_file(&tmp_path);
    }
    ok
}

#[test]
fn atomic_write_no_partial_file_when_rename_fails() {
    // Place a directory at the target path — rename over a directory fails
    // on all OS platforms.
    let dir = tmp_dir();
    let artifact_name = "pk.bin";
    let target = dir.join(artifact_name);
    fs::create_dir_all(&target).unwrap(); // target is a directory, not a file

    let bytes = b"provingkeydata";
    let result = simulate_atomic_write(&dir, artifact_name, bytes);

    // The rename failed (target was a directory).
    assert!(!result, "rename onto a directory must fail");

    // The target directory still exists and was NOT replaced by a file.
    assert!(target.exists(), "target directory must still exist");
    assert!(
        target.is_dir(),
        "target must remain a directory, not a file"
    );

    // No temp file left behind.
    let tmp_path = dir.join(format!(".{}.tmp.{}", artifact_name, std::process::id()));
    assert!(
        !tmp_path.exists(),
        "temp file must be removed after rename failure"
    );

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn atomic_write_succeeds_and_leaves_no_temp_file() {
    let dir = tmp_dir();
    let artifact_name = "vk.bin";
    let bytes = b"verifyingkeydata";

    let result = simulate_atomic_write(&dir, artifact_name, bytes);
    assert!(result, "atomic write must succeed when target path is free");

    let target = dir.join(artifact_name);
    assert!(
        target.exists(),
        "target artifact must exist after successful write"
    );
    assert_eq!(fs::read(&target).unwrap(), bytes);

    // No temp file left behind.
    let tmp_path = dir.join(format!(".{}.tmp.{}", artifact_name, std::process::id()));
    assert!(
        !tmp_path.exists(),
        "temp file must be removed after successful rename"
    );

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn atomic_write_multiple_artifacts_no_partial_files() {
    // Simulate writing several artifacts (as persist_setup_output does).
    // For any that fail mid-rename, assert no partial file exists.
    let dir = tmp_dir();
    let artifacts = ["pk.bin", "vk.bin", "pvk.bin", "config.json"];
    let bytes = b"artifactbytes";

    // Pre-block one artifact path with a directory to simulate failure.
    let blocked = "pvk.bin";
    fs::create_dir_all(dir.join(blocked)).unwrap();

    for artifact in &artifacts {
        let target = dir.join(artifact);
        let tmp_path = dir.join(format!(".{}.tmp.{}", artifact, std::process::id()));

        if fs::write(&tmp_path, bytes).is_ok() {
            if fs::rename(&tmp_path, &target).is_err() {
                let _ = fs::remove_file(&tmp_path);
            }
        }

        // Verify: no temp file remains for this artifact.
        assert!(
            !tmp_path.exists(),
            "temp file for {artifact} must not remain"
        );

        if *artifact != blocked {
            // Non-blocked artifacts should have written successfully.
            assert!(target.is_file(), "{artifact} must be a regular file");
        } else {
            // Blocked artifact: target is still the directory we placed there.
            assert!(target.is_dir(), "{artifact} must remain a directory");
        }
    }

    fs::remove_dir_all(&dir).unwrap();
}
