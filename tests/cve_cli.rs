use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::{Command, Output};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

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

fn ingest_document(artifact: &Path, revision: &str, version_id: &str, timestamp: &str) -> Value {
    let digest = hex(&Sha256::digest(std::fs::read(artifact).unwrap()));
    let locator = "/private/nvd/raw.json";
    let provenance = json!({
        "references": [{
            "source_id": "nvd",
            "locator": locator,
            "content_sha256": digest,
            "retrieved_at": timestamp,
            "source_version": revision
        }],
        "confidence": "exact",
        "observed_at": timestamp
    });
    json!({
        "record": {
            "id": "CVE-2024-1234",
            "aliases": [],
            "descriptions": {"en": format!("revision {revision}")},
            "cna": "example",
            "published_at": "2024-01-01T00:00:00Z",
            "modified_at": timestamp,
            "withdrawn_at": null,
            "provenance": provenance
        },
        "version": {
            "id": version_id,
            "cve_id": "CVE-2024-1234",
            "revision": revision,
            "modified_at": timestamp,
            "fields": {"state": "published"},
            "provenance": provenance
        },
        "artifacts": [{
            "source_id": "nvd",
            "locator": locator,
            "path": artifact,
            "media_type": "application/json"
        }]
    })
}

#[test]
fn cve_cli_ingest_current_history_pagination_and_redaction() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("catalog.sqlite");
    let artifact_root = directory.path().join("artifacts");
    let artifact = directory.path().join("raw.json");
    std::fs::write(&artifact, br#"{"source":"nvd"}"#).unwrap();

    for (revision, id, timestamp) in [
        ("1", "CVE-2024-1234:nvd:1", "2024-01-01T00:00:01Z"),
        ("2", "CVE-2024-1234:nvd:2", "2024-01-01T00:00:02Z"),
    ] {
        let document = directory.path().join(format!("ingest-{revision}.json"));
        std::fs::write(
            &document,
            serde_json::to_vec(&ingest_document(&artifact, revision, id, timestamp)).unwrap(),
        )
        .unwrap();
        let output = run(
            &db,
            &artifact_root,
            &["cve", "ingest", "--input", document.to_str().unwrap()],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schema"], "mg-brief/v1");
        assert_eq!(value["revision"], revision);
        assert!(value["inserted"].as_bool().unwrap());
        let encoded = String::from_utf8(output.stdout).unwrap();
        assert!(!encoded.contains("/private/nvd/raw.json"));
        assert!(!encoded.contains(artifact.to_str().unwrap()));
    }

    let current = run(&db, &artifact_root, &["cve", "current", "CVE-2024-1234"]);
    assert!(current.status.success());
    let current_value: Value = serde_json::from_slice(&current.stdout).unwrap();
    assert_eq!(current_value["version"]["revision"], "2");
    let current_text = String::from_utf8(current.stdout).unwrap();
    assert!(!current_text.contains("/private/nvd/raw.json"));
    assert!(!current_text.contains(artifact.to_str().unwrap()));

    let first = run(
        &db,
        &artifact_root,
        &["cve", "history", "CVE-2024-1234", "--limit", "1"],
    );
    assert!(first.status.success());
    let first_value: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first_value["items"][0]["version"]["revision"], "2");
    assert_eq!(
        first_value["items"][0]["record"]["descriptions"]["en"],
        "revision 2"
    );
    let cursor = first_value["next_cursor"].as_str().unwrap();
    let second = run(
        &db,
        &artifact_root,
        &[
            "cve",
            "history",
            "CVE-2024-1234",
            "--limit",
            "1",
            "--cursor",
            cursor,
        ],
    );
    assert!(second.status.success());
    let second_value: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second_value["items"][0]["version"]["revision"], "1");
    assert_eq!(
        second_value["items"][0]["record"]["descriptions"]["en"],
        "revision 1"
    );
    assert!(second_value["next_cursor"].is_null());

    let export = run(&db, &artifact_root, &["export", "--json"]);
    assert!(export.status.success());
    let export_value: Value = serde_json::from_slice(&export.stdout).unwrap();
    let revisions = export_value["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["origin"]["kind"] == "cve_revision")
        .collect::<Vec<_>>();
    assert_eq!(revisions.len(), 2);
    assert_eq!(
        revisions[0]["payload"]["record"]["descriptions"]["en"],
        "revision 1"
    );
    assert_eq!(revisions[0]["payload"]["version"]["revision"], "1");
    assert_eq!(
        revisions[1]["payload"]["record"]["descriptions"]["en"],
        "revision 2"
    );
    assert_eq!(revisions[1]["payload"]["version"]["revision"], "2");

    let malformed = run(
        &db,
        &artifact_root,
        &[
            "cve",
            "history",
            "CVE-2024-1234",
            "--cursor",
            "not-a-cursor",
        ],
    );
    assert!(!malformed.status.success());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("malformed history cursor"));
}

#[test]
fn cve_cli_imports_authoritative_cve_json5_and_preserves_raw_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("catalog.sqlite");
    let artifact_root = directory.path().join("artifacts");
    let input = directory.path().join("CVE-2024-9999.json");
    let raw = br#"{
        "dataType":"CVE_RECORD",
        "dataVersion":"5.1",
        "cveMetadata":{
            "cveId":"CVE-2024-9999",
            "assignerOrgId":"11111111-2222-3333-4444-555555555555",
            "assignerShortName":"example",
            "state":"PUBLISHED",
            "datePublished":"2024-02-01T00:00:00Z",
            "dateUpdated":"2024-02-02T00:00:00Z",
            "serial":3
        },
        "containers":{"cna":{"descriptions":[{"lang":"en","value":"adapter fixture"}]}}
    }"#;
    std::fs::write(&input, raw).unwrap();
    let locator = "https://cveawg.mitre.org/api/cve/CVE-2024-9999";

    let output = run(
        &db,
        &artifact_root,
        &[
            "cve",
            "import-cve5",
            "--input",
            input.to_str().unwrap(),
            "--locator",
            locator,
            "--retrieved-at",
            "2024-02-03T00:00:00Z",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let imported: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(imported["cve_id"], "CVE-2024-9999");
    assert_eq!(imported["revision"], "3");
    assert!(imported["current"].as_bool().unwrap());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(locator));

    let current = run(&db, &artifact_root, &["cve", "current", "CVE-2024-9999"]);
    assert!(current.status.success());
    let current: Value = serde_json::from_slice(&current.stdout).unwrap();
    assert_eq!(current["record"]["descriptions"]["en"], "adapter fixture");
    assert_eq!(current["version"]["fields"]["state"], "PUBLISHED");
    assert_eq!(current["version"]["fields"]["data_version"], "5.1");
    assert_eq!(current["version"]["id"], "CVE-2024-9999:cve-program:3");
    let digest = hex(&Sha256::digest(raw));
    let stored = artifact_root
        .join("sha256")
        .join(&digest[..2])
        .join(&digest);
    assert_eq!(std::fs::read(stored).unwrap(), raw);

    let future_dated = run(
        &db,
        &artifact_root,
        &[
            "cve",
            "import-cve5",
            "--input",
            input.to_str().unwrap(),
            "--locator",
            locator,
            "--retrieved-at",
            "2024-02-01T00:00:00Z",
        ],
    );
    assert!(!future_dated.status.success());
    assert!(String::from_utf8_lossy(&future_dated.stderr)
        .contains("dateUpdated is later than retrieval time"));
}
