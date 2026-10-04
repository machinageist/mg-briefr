use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::path::Path;

const MAX_FINDINGS: usize = 64;
const MAX_FINDING_CHARS: usize = 240;

#[derive(Debug, Serialize)]
pub struct IntegrityReport {
    schema: &'static str,
    status: &'static str,
    findings: Vec<String>,
    truncated: bool,
}

impl IntegrityReport {
    pub fn is_healthy(&self) -> bool {
        self.status == "healthy"
    }

    pub fn status_name(&self) -> &'static str {
        self.status
    }

    pub fn findings(&self) -> &[String] {
        &self.findings
    }
}

// Inspect an application-owned snapshot without migrations or recovery
pub fn inspect(path: &Path) -> IntegrityReport {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return report("unconfigured", vec![], false);
        }
        Err(error) => {
            return report("unavailable", vec![safe_text(&error.to_string())], false);
        }
    };
    if !metadata.file_type().is_file() {
        return report(
            "unavailable",
            vec!["catalog path is not a regular file".into()],
            false,
        );
    }

    let connection = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(connection) => connection,
        Err(error) => {
            return report("unavailable", vec![safe_text(&error.to_string())], false);
        }
    };
    let mut statement = match connection.prepare("PRAGMA integrity_check") {
        Ok(statement) => statement,
        Err(error) => {
            return report("corrupt", vec![safe_text(&error.to_string())], false);
        }
    };
    let mut rows = match statement.query([]) {
        Ok(rows) => rows,
        Err(error) => {
            return report("corrupt", vec![safe_text(&error.to_string())], false);
        }
    };

    let mut findings = Vec::new();
    let mut truncated = false;
    loop {
        match rows.next() {
            Ok(Some(row)) => {
                let message = match row.get::<_, String>(0) {
                    Ok(message) => message,
                    Err(error) => {
                        if findings.len() < MAX_FINDINGS {
                            findings.push(safe_text(&error.to_string()));
                        } else {
                            truncated = true;
                        }
                        break;
                    }
                };
                if findings.len() == MAX_FINDINGS {
                    truncated = true;
                    break;
                }
                findings.push(safe_text(&message));
            }
            Ok(None) => break,
            Err(error) => {
                if findings.len() < MAX_FINDINGS {
                    findings.push(safe_text(&error.to_string()));
                } else {
                    truncated = true;
                }
                break;
            }
        }
    }

    let status = if findings.as_slice() == ["ok"] {
        "healthy"
    } else if findings.is_empty() {
        findings.push("integrity_check returned no result".into());
        "unavailable"
    } else {
        "corrupt"
    };
    report(status, findings, truncated)
}

// Build one bounded report envelope
fn report(status: &'static str, findings: Vec<String>, truncated: bool) -> IntegrityReport {
    IntegrityReport {
        schema: "mg.brief.integrity/1",
        status,
        findings,
        truncated,
    }
}

// Keep diagnostics short and free of terminal control characters
fn safe_text(value: &str) -> String {
    let mut output = String::new();
    let mut characters = value.chars();
    for _ in 0..MAX_FINDING_CHARS {
        let Some(character) = characters.next() else {
            return output;
        };
        output.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    if characters.next().is_some() {
        output.pop();
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn missing_catalog_is_reported_without_creating_it() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("missing.sqlite");

        let result = inspect(&path);

        assert_eq!(result.status, "unconfigured");
        assert!(!path.exists());
    }

    #[test]
    fn wal_integrity_check_reads_a_private_snapshot_without_touching_the_source() {
        use std::collections::{BTreeMap, BTreeSet};

        let directory = tempdir().unwrap();
        let path = directory.path().join("catalog with spaces.sqlite");
        let setup = Connection::open(&path).unwrap();
        setup
            .execute_batch(
                "CREATE TABLE sample (id INTEGER PRIMARY KEY); INSERT INTO sample VALUES (1);",
            )
            .unwrap();
        drop(setup);
        let connection = Connection::open(&path).unwrap();
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "wal");
        connection
            .execute("INSERT INTO sample VALUES (2)", [])
            .unwrap();
        let wal = Path::new(&format!("{}-wal", path.display())).to_path_buf();
        let shm = Path::new(&format!("{}-shm", path.display())).to_path_buf();
        assert!(wal.is_file());
        assert!(shm.is_file());
        let source_files = [&path, &wal, &shm]
            .into_iter()
            .map(|entry| (entry.to_path_buf(), std::fs::read(entry).unwrap()))
            .collect::<BTreeMap<_, _>>();
        let before_names = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();

        let snapshot = super::super::recovery::snapshot_for_integrity(&path, true).unwrap();
        let result = inspect(snapshot.database_path());
        let reader =
            Connection::open_with_flags(snapshot.database_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let rows: i64 = reader
            .query_row("SELECT COUNT(*) FROM sample", [], |row| row.get(0))
            .unwrap();
        drop(reader);
        drop(snapshot);
        let after_names = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        let after_files = [&path, &wal, &shm]
            .into_iter()
            .map(|entry| (entry.to_path_buf(), std::fs::read(entry).unwrap()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(result.schema, "mg.brief.integrity/1");
        assert_eq!(result.status, "healthy");
        assert_eq!(result.findings, ["ok"]);
        assert!(!result.truncated);
        assert_eq!(rows, 2);
        assert_eq!(after_files, source_files);
        assert_eq!(after_names, before_names);
        drop(connection);
    }

    #[test]
    fn diagnostics_are_control_safe_and_limited_to_the_configured_character_count() {
        let input = format!("a\n{}", "b".repeat(MAX_FINDING_CHARS));
        let output = safe_text(&input);

        assert_eq!(output.chars().count(), MAX_FINDING_CHARS);
        assert!(output.ends_with('…'));
        assert!(!output.chars().any(char::is_control));
    }

    #[test]
    fn malformed_catalog_is_reported_without_modifying_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("catalog.sqlite");
        let malformed = b"not a sqlite catalog";
        std::fs::write(&path, malformed).unwrap();

        let result = inspect(&path);

        assert!(matches!(result.status, "corrupt" | "unavailable"));
        assert!(!result.findings.is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), malformed);
    }

    #[cfg(unix)]
    #[test]
    fn catalog_symlinks_are_not_followed() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let target = directory.path().join("target.sqlite");
        let link = directory.path().join("catalog.sqlite");
        let connection = Connection::open(&target).unwrap();
        connection
            .execute_batch("CREATE TABLE sample (id INTEGER);")
            .unwrap();
        drop(connection);
        symlink(&target, &link).unwrap();

        let result = inspect(&link);

        assert_eq!(result.status, "unavailable");
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
