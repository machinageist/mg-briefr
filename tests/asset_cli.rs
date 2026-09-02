use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Output};

fn run(db: &Path, artifacts: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mg-brief"))
        .arg("--db")
        .arg(db)
        .arg("--artifact-root")
        .arg(artifacts)
        .args(args)
        .output()
        .expect("run mg-brief")
}

fn provenance(observed_at: &str) -> Value {
    json!({
        "references": [{
            "source_id": "local-inventory",
            "locator": "/private/inventory/packages.json",
            "content_sha256": null,
            "retrieved_at": observed_at,
            "source_version": "fixture-1"
        }],
        "confidence": "high",
        "observed_at": observed_at
    })
}

fn asset(id: &str, kind: &str, label: &str, created_at: &str) -> Value {
    json!({
        "id": id,
        "kind": kind,
        "label": label,
        "created_at": created_at,
        "provenance": provenance(created_at)
    })
}

#[allow(clippy::too_many_arguments)]
fn observation(
    id: &str,
    asset_id: &str,
    origin_kind: &str,
    observed_at: &str,
    coverage: &str,
    stale_after: Option<&str>,
    corrects: Option<&str>,
    raw_identifier: &str,
    candidates: Value,
) -> Value {
    json!({
        "id": id,
        "asset_id": asset_id,
        "origin": {"kind": origin_kind, "name": "fixture"},
        "raw_identifier": raw_identifier,
        "normalized_candidates": candidates,
        "coverage": coverage,
        "observed_at": observed_at,
        "stale_after": stale_after,
        "corrects_observation_id": corrects,
        "evidence": ["bounded fixture evidence"],
        "provenance": provenance(observed_at)
    })
}

#[test]
fn asset_cli_import_list_and_inspect_preserve_uncertainty_and_corrections() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("catalog.sqlite");
    let artifacts = directory.path().join("artifacts");
    let input = directory.path().join("assets.json");
    let document = json!({
        "schema": "mg-brief.asset-import/v1",
        "entries": [
            {
                "asset": asset("asset-hardware", "hardware", "lab adapter", "2024-01-01T00:00:00Z"),
                "observation": observation(
                    "obs-hardware-1", "asset-hardware", "collector", "2024-01-01T00:00:00Z",
                    "unknown", None, None, "USB VID_1234&PID_5678",
                    json!([{"kind":"model", "value":"VID_1234:PID_5678", "confidence":"low"}])
                )
            },
            {
                "asset": asset("asset-openssl", "software", "TLS library", "2024-01-01T00:00:00Z"),
                "observation": observation(
                    "obs-openssl-1", "asset-openssl", "collector", "2024-01-01T00:00:00Z",
                    "incomplete", Some("2024-02-01T00:00:00Z"), None, "openssl 3.0.0-1",
                    json!([
                        {"kind":"package", "value":"openssl", "confidence":"high"},
                        {"kind":"version", "value":"3.0.0-1", "confidence":"medium"}
                    ])
                )
            }
        ]
    });
    std::fs::write(&input, serde_json::to_vec(&document).unwrap()).unwrap();

    let imported = run(
        &db,
        &artifacts,
        &["asset", "import", "--input", input.to_str().unwrap()],
    );
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let imported_value: Value = serde_json::from_slice(&imported.stdout).unwrap();
    assert_eq!(imported_value["schema"], "mg-brief/v1");
    assert_eq!(imported_value["inserted_assets"], 2);
    assert_eq!(imported_value["inserted_observations"], 2);
    assert!(!String::from_utf8_lossy(&imported.stdout).contains("/private/"));

    let correction_input = directory.path().join("correction.json");
    let correction = json!({
        "schema": "mg-brief.asset-import/v1",
        "entries": [{
            "asset": asset("asset-openssl", "software", "TLS library", "2024-01-01T00:00:00Z"),
            "observation": observation(
                "obs-openssl-correction", "asset-openssl", "user_correction", "2024-01-02T00:00:00Z",
                "complete", Some("2024-03-01T00:00:00Z"), Some("obs-openssl-1"), "OpenSSL from package database",
                json!([
                    {"kind":"package", "value":"openssl", "confidence":"high"},
                    {"kind":"version", "value":"3.0.1-1", "confidence":"high"}
                ])
            )
        }]
    });
    std::fs::write(&correction_input, serde_json::to_vec(&correction).unwrap()).unwrap();
    let corrected = run(
        &db,
        &artifacts,
        &[
            "asset",
            "import",
            "--input",
            correction_input.to_str().unwrap(),
        ],
    );
    assert!(corrected.status.success());

    let collector_input = directory.path().join("collector-later.json");
    let collector = json!({
        "schema": "mg-brief.asset-import/v1",
        "entries": [{
            "asset": asset("asset-openssl", "software", "TLS library", "2024-01-01T00:00:00Z"),
            "observation": observation(
                "obs-openssl-2", "asset-openssl", "collector", "2024-01-03T00:00:00Z",
                "complete", Some("2024-04-01T00:00:00Z"), None, "openssl 9.9.9",
                json!([{"kind":"version", "value":"9.9.9", "confidence":"low"}])
            )
        }]
    });
    std::fs::write(&collector_input, serde_json::to_vec(&collector).unwrap()).unwrap();
    let collected = run(
        &db,
        &artifacts,
        &[
            "asset",
            "import",
            "--input",
            collector_input.to_str().unwrap(),
        ],
    );
    assert!(collected.status.success());

    let listed = run(
        &db,
        &artifacts,
        &[
            "asset",
            "list",
            "--as-of",
            "2024-03-15T00:00:00Z",
            "--limit",
            "10",
        ],
    );
    assert!(listed.status.success());
    let listed_value: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed_value["items"].as_array().unwrap().len(), 2);
    assert_eq!(listed_value["items"][0]["asset"]["id"], "asset-hardware");
    assert_eq!(listed_value["items"][0]["inventory_status"], "unknown");
    assert_eq!(listed_value["items"][1]["inventory_status"], "stale");
    assert_eq!(
        listed_value["items"][1]["effective_observation"]["id"],
        "obs-openssl-correction"
    );
    assert_eq!(listed_value["items"][1]["observation_count"], 3);
    let output = String::from_utf8(listed.stdout).unwrap();
    assert!(output.contains("candidate_only"));
    assert!(!output.contains("/private/"));

    let inspected = run(
        &db,
        &artifacts,
        &[
            "asset",
            "inspect",
            "asset-openssl",
            "--as-of",
            "2024-02-15T00:00:00Z",
            "--observation-limit",
            "2",
        ],
    );
    assert!(inspected.status.success());
    let inspected_value: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(inspected_value["inventory_status"], "fresh");
    assert_eq!(
        inspected_value["effective_observation"]["id"],
        "obs-openssl-correction"
    );
    assert_eq!(inspected_value["observations"].as_array().unwrap().len(), 2);
    assert_eq!(inspected_value["observation_count"], 3);
    assert_eq!(inspected_value["observations_truncated"], true);
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("openssl 9.9.9"));

    let replay = run(
        &db,
        &artifacts,
        &[
            "asset",
            "import",
            "--input",
            correction_input.to_str().unwrap(),
        ],
    );
    assert!(replay.status.success());
    let replay: Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["inserted_assets"], 0);
    assert_eq!(replay["inserted_observations"], 0);
    assert_eq!(replay["replayed_entries"], 1);
}

#[test]
fn asset_cli_rejects_invalid_corrections_bounds_and_immutable_conflicts_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("catalog.sqlite");
    let artifacts = directory.path().join("artifacts");
    let input = directory.path().join("invalid.json");
    let document = json!({
        "schema": "mg-brief.asset-import/v1",
        "entries": [{
            "asset": asset("asset-a", "software", "A", "2024-01-01T00:00:00Z"),
            "observation": observation(
                "obs-a", "asset-a", "user_correction", "2024-01-01T00:00:00Z",
                "complete", None, Some("missing-observation"), "pkg 1", json!([])
            )
        }]
    });
    std::fs::write(&input, serde_json::to_vec(&document).unwrap()).unwrap();
    let rejected = run(
        &db,
        &artifacts,
        &["asset", "import", "--input", input.to_str().unwrap()],
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("corrected observation"));

    let listed = run(
        &db,
        &artifacts,
        &["asset", "list", "--as-of", "2024-01-01T00:00:00Z"],
    );
    assert!(listed.status.success());
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert!(listed["items"].as_array().unwrap().is_empty());

    let too_large_limit = run(
        &db,
        &artifacts,
        &[
            "asset",
            "list",
            "--as-of",
            "2024-01-01T00:00:00Z",
            "--limit",
            "101",
        ],
    );
    assert!(!too_large_limit.status.success());
    assert!(String::from_utf8_lossy(&too_large_limit.stderr)
        .contains("asset list limit must be between 1 and 100"));

    let oversized = directory.path().join("oversized.json");
    let file = std::fs::File::create(&oversized).unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap();
    let rejected = run(
        &db,
        &artifacts,
        &["asset", "import", "--input", oversized.to_str().unwrap()],
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("unavailable or too large"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let target = directory.path().join("target.json");
        std::fs::write(&target, b"{}").unwrap();
        let link = directory.path().join("linked.json");
        symlink(&target, &link).unwrap();
        let rejected = run(
            &db,
            &artifacts,
            &["asset", "import", "--input", link.to_str().unwrap()],
        );
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("unavailable or too large"));
    }
}
