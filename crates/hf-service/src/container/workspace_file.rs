//! Host writes to a workspace that a sandbox may have modified.

use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

fn components(relative: &Path) -> io::Result<(Vec<OsString>, OsString)> {
    let mut parts = relative
        .components()
        .map(|part| match part {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "workspace file path must be relative and contain only normal components",
            )),
        })
        .collect::<io::Result<Vec<_>>>()?;
    let leaf = parts.pop().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "workspace file path is empty")
    })?;
    Ok((parts, leaf))
}

/// Replace a file without following a link left by a sandbox at its destination
/// or in its parent directories.
pub(super) fn replace_workspace_file(
    workspace: &Path,
    relative: &Path,
    mut source: impl Read,
    permissions: Option<std::fs::Permissions>,
) -> io::Result<PathBuf> {
    let (parents, leaf) = components(relative)?;
    replace_workspace_file_impl(workspace, &parents, &leaf, &mut source, permissions)?;
    Ok(workspace.join(relative))
}

#[cfg(unix)]
fn replace_workspace_file_impl(
    workspace: &Path,
    parents: &[OsString],
    leaf: &std::ffi::OsStr,
    source: &mut impl Read,
    permissions: Option<std::fs::Permissions>,
) -> io::Result<()> {
    use rustix::fs::{mkdirat, open, openat, renameat, unlinkat, AtFlags, Mode, OFlags};
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt;

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(open(workspace, directory_flags, Mode::empty())?);
    for parent in parents {
        let next = match openat(&directory, parent, directory_flags, Mode::empty()) {
            Ok(next) => next,
            Err(rustix::io::Errno::NOENT) => {
                match mkdirat(&directory, parent, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(error.into()),
                }
                openat(&directory, parent, directory_flags, Mode::empty())?
            }
            Err(error) => return Err(error.into()),
        };
        directory = File::from(next);
    }

    let temporary = format!(".oxfuzz-stage-{}.tmp", uuid::Uuid::new_v4());
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = File::from(openat(
        &directory,
        temporary.as_str(),
        flags,
        Mode::RUSR | Mode::WUSR,
    )?);
    let result = io::copy(source, &mut file).map(|_| ()).and_then(|()| {
        file.set_permissions(
            permissions.unwrap_or_else(|| std::fs::Permissions::from_mode(0o644)),
        )?;
        renameat(&directory, temporary.as_str(), &directory, leaf).map_err(Into::into)
    });
    if result.is_err() {
        // The temp entry is disposable after a failed copy or rename.
        let _cleanup_failed = unlinkat(&directory, temporary.as_str(), AtFlags::empty());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::replace_workspace_file;

    #[test]
    fn existing_workspace_file_is_replaced() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("input.c");
        std::fs::write(&path, "old").unwrap();

        replace_workspace_file(
            workspace.path(),
            std::path::Path::new("input.c"),
            std::io::Cursor::new("new"),
            None,
        )
        .unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "new");
    }
}

#[cfg(windows)]
fn replace_workspace_file_impl(
    workspace: &Path,
    parents: &[OsString],
    leaf: &std::ffi::OsStr,
    source: &mut impl Read,
    permissions: Option<std::fs::Permissions>,
) -> io::Result<()> {
    use cap_primitives::fs::{
        create_dir, open, open_ambient, open_dir_nofollow, remove_file, rename, DirOptions,
        OpenOptions, OpenOptionsExt,
    };
    use std::fs::File;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let mut root_options = OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let mut directory = open_ambient(
        workspace,
        &root_options,
        cap_primitives::ambient_authority(),
    )?;
    if !directory.metadata()?.is_dir()
        || std::fs::symlink_metadata(workspace)?
            .file_type()
            .is_symlink()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace root is not a regular directory",
        ));
    }
    for parent in parents {
        let name = Path::new(parent);
        directory = match open_dir_nofollow(&directory, name) {
            Ok(next) => next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match create_dir(&directory, name, &DirOptions::new()) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                open_dir_nofollow(&directory, name)?
            }
            Err(error) => return Err(error),
        };
    }

    let temporary = format!(".oxfuzz-stage-{}.tmp", uuid::Uuid::new_v4());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file: File = open(&directory, Path::new(&temporary), &options)?;
    let result = io::copy(source, &mut file).map(|_| ()).and_then(|()| {
        if let Some(permissions) = permissions {
            file.set_permissions(permissions)?;
        }
        match rename(
            &directory,
            Path::new(&temporary),
            &directory,
            Path::new(leaf),
        ) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
                ) =>
            {
                remove_file(&directory, Path::new(leaf))?;
                rename(
                    &directory,
                    Path::new(&temporary),
                    &directory,
                    Path::new(leaf),
                )
            }
            Err(error) => Err(error),
        }
    });
    if result.is_err() {
        // The temp entry is disposable after a failed copy or rename.
        let _cleanup_failed = remove_file(&directory, Path::new(&temporary));
    }
    result
}

#[cfg(not(any(unix, windows)))]
fn replace_workspace_file_impl(
    _workspace: &Path,
    _parents: &[OsString],
    _leaf: &std::ffi::OsStr,
    _source: &mut impl Read,
    _permissions: Option<std::fs::Permissions>,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative workspace writes are unavailable on this platform",
    ))
}
