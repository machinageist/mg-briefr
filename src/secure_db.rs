use std::{
    ffi::{OsStr, OsString},
    io,
    path::{Component, Path},
};

#[cfg(unix)]
use rusqlite::OpenFlags;

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PERMISSION_BITS: u32 = 0o7777;
const SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

// Prepare the database leaf and its owned private directory before SQLite opens either one
pub(crate) fn prepare_database_path(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let (parent, name) = open_database_parent(path, true)?;
        ensure_private_file(&parent, &name, true)?;
        ensure_database_sidecars_at(&parent, &name)
    }
    #[cfg(not(unix))]
    {
        prepare_database_path_without_unix_descriptors(path)
    }
}

// Recheck SQLite's auxiliary files after a journal-mode change creates them
pub(crate) fn ensure_database_sidecars(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let (parent, name) = open_database_parent(path, true)?;
        ensure_database_sidecars_at(&parent, &name)
    }
    #[cfg(not(unix))]
    {
        ensure_database_sidecars_without_unix_descriptors(path)
    }
}

// Accept an explicit database override only beneath an existing private parent directory
pub(crate) fn validate_database_override(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let (parent, _) = open_database_parent(path, false)?;
        require_private_directory(&parent)
    }
    #[cfg(not(unix))]
    {
        if !path.is_absolute() || path.file_name().filter(|name| !name.is_empty()).is_none() {
            return Err(invalid_path("database path must be an absolute file"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| invalid_path("database path must have a parent"))?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(insecure_path("database directory"));
        }
        Ok(())
    }
}

// Open SQLite with its Unix no-follow protection when the platform provides it
pub(crate) fn open_database(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    #[cfg(unix)]
    {
        rusqlite::Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
    }
    #[cfg(not(unix))]
    {
        rusqlite::Connection::open(path)
    }
}

#[cfg(unix)]
fn open_database_parent(
    path: &Path,
    create_missing_directories: bool,
) -> io::Result<(rustix::fd::OwnedFd, OsString)> {
    use rustix::fs::{mkdirat, open, openat, Mode, OFlags};

    if !path.is_absolute() {
        return Err(invalid_path("database path must be absolute"));
    }
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid_path("database path must name a file"))?
        .to_os_string();
    let parent = path
        .parent()
        .filter(|parent| parent.is_absolute())
        .ok_or_else(|| invalid_path("database path must have an absolute parent"))?;
    let components = parent
        .components()
        .map(|component| match component {
            Component::RootDir => Ok(None),
            Component::Normal(name) => Ok(Some(name.to_os_string())),
            _ => Err(invalid_path(
                "database path contains a non-normal component",
            )),
        })
        .collect::<io::Result<Vec<_>>>()?;
    let components = components.into_iter().flatten();
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current = open("/", directory_flags, Mode::empty()).map_err(map_directory_error)?;
    for component in components {
        match openat(&current, &component, directory_flags, Mode::empty()) {
            Ok(next) => current = next,
            Err(error) if create_missing_directories && error == rustix::io::Errno::NOENT => {
                match mkdirat(
                    &current,
                    &component,
                    Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE),
                ) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(map_directory_error(error)),
                }
                current = openat(&current, &component, directory_flags, Mode::empty())
                    .map_err(map_directory_error)?;
            }
            Err(error) => return Err(map_directory_error(error)),
        }
    }
    if create_missing_directories {
        validate_private_directory(&current)?;
    }
    Ok((current, name))
}

#[cfg(unix)]
fn require_private_directory(directory: &rustix::fd::OwnedFd) -> io::Result<()> {
    use rustix::fs::{fstat, FileType};

    let metadata = fstat(directory).map_err(map_directory_error)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & PERMISSION_BITS != PRIVATE_DIRECTORY_MODE
    {
        return Err(insecure_path("database directory"));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_database_sidecars_at(parent: &rustix::fd::OwnedFd, name: &OsStr) -> io::Result<()> {
    for suffix in SIDECAR_SUFFIXES {
        let mut sidecar = name.to_os_string();
        sidecar.push(suffix);
        ensure_private_file(parent, &sidecar, false)?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_file(parent: &rustix::fd::OwnedFd, name: &OsStr, create: bool) -> io::Result<()> {
    use rustix::fs::{fchmod, fstat, openat, FileType, Mode, OFlags};

    let existing_flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let created_flags = existing_flags | OFlags::RDWR | OFlags::CREATE | OFlags::EXCL;
    let file = match openat(
        parent,
        name,
        if create {
            created_flags
        } else {
            existing_flags
        },
        Mode::from_raw_mode(PRIVATE_FILE_MODE),
    ) {
        Ok(file) => file,
        Err(error) if create && error == rustix::io::Errno::EXIST => {
            openat(parent, name, existing_flags, Mode::empty()).map_err(map_file_error)?
        }
        Err(error) if !create && error == rustix::io::Errno::NOENT => return Ok(()),
        Err(error) => return Err(map_file_error(error)),
    };
    let metadata = fstat(&file).map_err(map_file_error)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || metadata.st_nlink != 1
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(insecure_path("database file"));
    }
    if metadata.st_mode & PERMISSION_BITS != PRIVATE_FILE_MODE {
        fchmod(&file, Mode::from_raw_mode(PRIVATE_FILE_MODE)).map_err(map_file_error)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory(directory: &rustix::fd::OwnedFd) -> io::Result<()> {
    use rustix::fs::{fchmod, fstat, FileType, Mode};

    let metadata = fstat(directory).map_err(map_directory_error)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(insecure_path("database directory"));
    }
    if metadata.st_mode & PERMISSION_BITS != PRIVATE_DIRECTORY_MODE {
        fchmod(directory, Mode::from_raw_mode(PRIVATE_DIRECTORY_MODE))
            .map_err(map_directory_error)?;
    }
    Ok(())
}

#[cfg(unix)]
fn map_directory_error(error: rustix::io::Errno) -> io::Error {
    match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => insecure_path("database directory"),
        _ => io::Error::from(error),
    }
}

#[cfg(unix)]
fn map_file_error(error: rustix::io::Errno) -> io::Error {
    match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => insecure_path("database file"),
        _ => io::Error::from(error),
    }
}

#[cfg(not(unix))]
fn prepare_database_path_without_unix_descriptors(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(invalid_path("database path must be absolute"));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| invalid_path("database path must have a parent"))?;
    std::fs::create_dir_all(parent)?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(insecure_path("database directory"));
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_file() => Ok(()),
        Ok(_) => Err(insecure_path("database file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn ensure_database_sidecars_without_unix_descriptors(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_path("database path must have a parent"))?;
    for suffix in SIDECAR_SUFFIXES {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = std::path::PathBuf::from(sidecar);
        if sidecar.parent() != Some(parent) {
            return Err(invalid_path("database sidecar escaped its parent"));
        }
        if let Ok(metadata) = std::fs::symlink_metadata(sidecar) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(insecure_path("database sidecar"));
            }
        }
    }
    Ok(())
}

fn invalid_path(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn insecure_path(kind: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("insecure {kind}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        )
        .expect("private temporary directory");
        directory
    }

    #[test]
    fn bare_relative_database_paths_are_rejected() {
        let error = prepare_database_path(Path::new("catalog.sqlite")).expect_err("relative path");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn intermediate_symlinked_directory_is_rejected() {
        let directory = private_tempdir();
        let target = directory.path().join("target");
        let alias = directory.path().join("alias");
        fs::create_dir(&target).expect("target directory");
        symlink(&target, &alias).expect("symlink");
        assert!(prepare_database_path(&alias.join("catalog.sqlite")).is_err());
    }

    #[test]
    fn missing_ancestor_directories_are_created_for_first_run() {
        let directory = private_tempdir();
        let database = directory
            .path()
            .join("xdg")
            .join("data")
            .join("mg-briefr")
            .join("catalog.sqlite");
        prepare_database_path(&database).expect("first-run database hierarchy");
        assert!(database.is_file());
        assert_eq!(
            fs::metadata(database.parent().expect("database parent"))
                .expect("database parent metadata")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_DIRECTORY_MODE
        );
    }

    #[test]
    fn existing_database_parent_is_repaired_on_its_held_descriptor() {
        let directory = private_tempdir();
        let shared = directory.path().join("shared");
        fs::create_dir(&shared).expect("shared directory");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).expect("shared mode");
        prepare_database_path(&shared.join("catalog.sqlite")).expect("repair database parent");
        assert_eq!(
            fs::metadata(&shared)
                .expect("shared metadata")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_DIRECTORY_MODE
        );
    }

    #[test]
    fn explicit_override_requires_an_existing_private_parent() {
        let directory = private_tempdir();
        assert!(validate_database_override(&directory.path().join("catalog.sqlite")).is_ok());
        let shared = directory.path().join("shared");
        fs::create_dir(&shared).expect("shared directory");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).expect("shared mode");
        assert!(validate_database_override(&shared.join("catalog.sqlite")).is_err());
    }
}
