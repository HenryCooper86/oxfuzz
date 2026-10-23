//! Open an already-authorized canonical path without following replacement links.

use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

pub(super) fn open_regular_file(path: &Path) -> io::Result<File> {
    let mut anchor = PathBuf::new();
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => anchor.push(component.as_os_str()),
            Component::Normal(name) => names.push(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected a canonical file path",
                ))
            }
        }
    }
    if !anchor.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an absolute file path",
        ));
    }
    let (leaf, parents) = names.split_last().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "cannot read a filesystem root")
    })?;
    let file = open_from_anchor(&anchor, parents, leaf)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot read a non-regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn open_from_anchor(
    anchor: &Path,
    parents: &[&std::ffi::OsStr],
    leaf: &std::ffi::OsStr,
) -> io::Result<File> {
    use rustix::fs::{open, openat, Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(open(anchor, flags, Mode::empty())?);
    for parent in parents {
        directory = File::from(openat(&directory, *parent, flags, Mode::empty())?);
    }
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    Ok(File::from(openat(&directory, leaf, flags, Mode::empty())?))
}

#[cfg(windows)]
fn open_from_anchor(
    anchor: &Path,
    parents: &[&std::ffi::OsStr],
    leaf: &std::ffi::OsStr,
) -> io::Result<File> {
    use cap_primitives::fs::{open, open_ambient, open_dir_nofollow, OpenOptions, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let mut directory = open_ambient(anchor, &options, cap_primitives::ambient_authority())?;
    for parent in parents {
        directory = open_dir_nofollow(&directory, Path::new(parent))?;
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    open(&directory, Path::new(leaf), &options)
}

#[cfg(not(any(unix, windows)))]
fn open_from_anchor(
    _anchor: &Path,
    _parents: &[&std::ffi::OsStr],
    _leaf: &std::ffi::OsStr,
) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "confined file reads are unavailable on this platform",
    ))
}
