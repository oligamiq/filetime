use crate::FileTime;
use libc::{time_t, timespec};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::wasi::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;

pub fn from_last_modification_time(meta: &fs::Metadata) -> FileTime {
    let duration = meta
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    FileTime {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos(),
    }
}

pub fn from_last_access_time(meta: &fs::Metadata) -> FileTime {
    let duration = meta
        .accessed()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    FileTime {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos(),
    }
}

pub fn from_creation_time(meta: &fs::Metadata) -> Option<FileTime> {
    let duration = meta
        .created()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(FileTime {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos(),
    })
}

pub fn to_timespec(ft: &Option<FileTime>) -> timespec {
    let mut ts: timespec = unsafe { std::mem::zeroed() };
    if let Some(ft) = ft {
        ts.tv_sec = ft.seconds;
        ts.tv_nsec = ft.nanos as _;
    } else {
        ts.tv_sec = 0;
        ts.tv_nsec = -2;
    }

    ts
}

pub fn set_file_times(p: &Path, atime: FileTime, mtime: FileTime) -> io::Result<()> {
    set_times(p, Some(atime), Some(mtime), false)
}

pub fn set_file_mtime(p: &Path, mtime: FileTime) -> io::Result<()> {
    set_times(p, None, Some(mtime), false)
}

pub fn set_file_atime(p: &Path, atime: FileTime) -> io::Result<()> {
    set_times(p, Some(atime), None, false)
}

pub fn set_file_handle_times(
    f: &fs::File,
    atime: Option<FileTime>,
    mtime: Option<FileTime>,
) -> io::Result<()> {
    // Attempt to use the `utimensat` syscall, but if it's not supported by the
    // current kernel then fall back to an older syscall.
    static INVALID: AtomicBool = AtomicBool::new(false);
    if !INVALID.load(SeqCst) {
        let times = [to_timespec(&atime), to_timespec(&mtime)];

        // However, on musl, we call the musl libc function instead. This is because
        // on newer musl versions starting with musl 1.2, `timespec` is always a 64-bit
        // value even on 32-bit targets. As a result, musl internally converts their
        // `timespec` values to the correct ABI before invoking the syscall. Since we
        // use `timespec` from the libc crate, it matches musl's definition and not
        // the Linux kernel's version (for some platforms) so we must use musl's
        // `utimensat` function to properly convert the value. musl's `utimensat`
        // function allows file descriptors in the path argument so this is fine.
        let rc = unsafe {
            libc::utimensat(
                f.as_raw_fd(),
                ptr::null::<libc::c_char>(),
                times.as_ptr(),
                0,
            )
        };

        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            INVALID.store(true, SeqCst);
        } else {
            return Err(err);
        }
    }

    let (atime, mtime) = match get_times(atime, mtime, || f.metadata())? {
        Some(pair) => pair,
        None => return Ok(()),
    };
    let times = [to_timespec(&Some(atime)), to_timespec(&Some(mtime))];
    let rc =
        unsafe { libc::__wasilibc_nocwd_utimensat(f.as_raw_fd(), ptr::null(), times.as_ptr(), 0) };
    return if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
}

fn get_times(
    atime: Option<FileTime>,
    mtime: Option<FileTime>,
    current: impl FnOnce() -> io::Result<fs::Metadata>,
) -> io::Result<Option<(FileTime, FileTime)>> {
    let pair = match (atime, mtime) {
        (Some(a), Some(b)) => (a, b),
        (None, None) => return Ok(None),
        (Some(a), None) => {
            let meta = current()?;
            (a, FileTime::from_last_modification_time(&meta))
        }
        (None, Some(b)) => {
            let meta = current()?;
            (FileTime::from_last_access_time(&meta), b)
        }
    };
    Ok(Some(pair))
}

fn to_timeval(ft: &FileTime) -> libc::timeval {
    libc::timeval {
        tv_sec: ft.seconds() as libc::time_t,
        tv_usec: (ft.nanoseconds() / 1000) as libc::suseconds_t,
    }
}

pub fn set_symlink_file_times(p: &Path, atime: FileTime, mtime: FileTime) -> io::Result<()> {
    set_times(p, Some(atime), Some(mtime), true)
}

fn set_times(
    p: &Path,
    atime: Option<FileTime>,
    mtime: Option<FileTime>,
    symlink: bool,
) -> io::Result<()> {
    let flags = if symlink {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };

    // Same as the `if` statement above.
    static INVALID: AtomicBool = AtomicBool::new(false);
    if !INVALID.load(SeqCst) {
        let p = CString::new(p.as_os_str().as_bytes())?;
        let times = [to_timespec(&atime), to_timespec(&mtime)];
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, p.as_ptr(), times.as_ptr(), flags) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            INVALID.store(true, SeqCst);
        } else {
            return Err(err);
        }
    }

    return Err(io::Error::from_raw_os_error(libc::ENOSYS));
}
