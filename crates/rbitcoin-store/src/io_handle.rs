//! Portable positional file handle for completion-driven store IO.
//!
//! Unix: raw fd. Windows: `HANDLE`. The session never closes the handle.

/// Borrowed OS handle for one positional pread/pwrite. Copy, not an owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct IoHandle {
    #[cfg(unix)]
    pub fd: std::os::fd::RawFd,
    #[cfg(windows)]
    pub handle: isize,
}

impl IoHandle {
    #[cfg(unix)]
    #[inline]
    pub fn from_raw_fd(fd: std::os::fd::RawFd) -> Self {
        Self { fd }
    }

    #[cfg(unix)]
    #[inline]
    pub fn as_raw_fd(self) -> std::os::fd::RawFd {
        self.fd
    }

    #[cfg(windows)]
    #[inline]
    pub fn from_raw_handle(handle: isize) -> Self {
        Self { handle }
    }

    #[cfg(windows)]
    #[inline]
    pub fn as_raw_handle(self) -> isize {
        self.handle
    }

    /// Borrow a positional handle from an open file (does not take ownership).
    pub fn from_file(file: &std::fs::File) -> Self {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            Self::from_raw_fd(file.as_raw_fd())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            Self::from_raw_handle(file.as_raw_handle() as isize)
        }
    }

    /// One-shot positional read. Returns bytes transferred or negated errno.
    pub fn pread(self, offset: u64, buf: &mut [u8]) -> i32 {
        if buf.is_empty() {
            return 0;
        }
        #[cfg(unix)]
        {
            // SAFETY: `buf` is the caller's mutable slice. `self.fd` is open.
            let n = unsafe {
                libc::pread(
                    self.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    offset as libc::off_t,
                )
            };
            if n < 0 {
                -std::io::Error::last_os_error().raw_os_error().unwrap_or(5)
            } else {
                n as i32
            }
        }
        #[cfg(windows)]
        {
            win_pread(self.handle, offset, buf)
        }
    }

    /// One-shot positional write. Returns bytes transferred or negated errno.
    pub fn pwrite(self, offset: u64, buf: &[u8]) -> i32 {
        if buf.is_empty() {
            return 0;
        }
        // A tip-connect test arms one body fd. The prefix is a real pwrite;
        // the error is what a full filesystem returns after that prefix.
        // Eight-byte HWM updates stay real unless `arm_fail_hwm_pwrites` is set.
        // An armed one fails before any byte is stored, so a header retry
        // cannot observe a short length.
        #[cfg(debug_assertions)]
        if buf.len() == 8 && take_fail_hwm(self) {
            return -disk_full_errno();
        }
        #[cfg(debug_assertions)]
        if buf.len() > 8 && short_pwrite_armed(self) {
            let n = self.pwrite_sys(offset, &buf[..8]);
            if n < 0 {
                return n;
            }
            return -disk_full_errno();
        }
        self.pwrite_sys(offset, buf)
    }

    fn pwrite_sys(self, offset: u64, buf: &[u8]) -> i32 {
        #[cfg(unix)]
        {
            // SAFETY: `buf` is the caller's slice. `self.fd` is open.
            let n = unsafe {
                libc::pwrite(
                    self.fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    offset as libc::off_t,
                )
            };
            if n < 0 {
                -std::io::Error::last_os_error().raw_os_error().unwrap_or(5)
            } else {
                n as i32
            }
        }
        #[cfg(windows)]
        {
            win_pwrite(self.handle, offset, buf)
        }
    }
}

/// Process-wide: tip connect runs on the tip-accept thread, not the test thread.
#[cfg(debug_assertions)]
static SHORT_PWRITE: std::sync::Mutex<Vec<IoHandle>> = std::sync::Mutex::new(Vec::new());

/// Next N eight-byte pwrites on these fds fail before any byte is stored.
#[cfg(debug_assertions)]
static FAIL_HWM: std::sync::Mutex<Vec<(IoHandle, u32)>> = std::sync::Mutex::new(Vec::new());

#[cfg(debug_assertions)]
fn disk_full_errno() -> i32 {
    #[cfg(unix)]
    {
        libc::ENOSPC
    }
    #[cfg(windows)]
    {
        112
    }
}

/// Arm `handle` so later pwrites longer than the HWM unit write 8 bytes and
/// return disk-full. Stays armed until [`disarm_short_pwrite`].
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn arm_short_pwrite(handle: IoHandle) {
    let mut slots = SHORT_PWRITE.lock().unwrap_or_else(|e| e.into_inner());
    if !slots.contains(&handle) {
        slots.push(handle);
    }
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn disarm_short_pwrite() {
    SHORT_PWRITE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    FAIL_HWM.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Drop one fd's arms. A process-wide clear races another test in this binary.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn disarm_pwrite(handle: IoHandle) {
    SHORT_PWRITE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|h| *h != handle);
    FAIL_HWM
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(h, _)| *h != handle);
}

/// Fail the next `n` eight-byte pwrites on `handle` without storing a byte.
///
/// A shrink retries the high-water persist. The first failure must not count
/// as a stored length.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn arm_fail_hwm_pwrites(handle: IoHandle, n: u32) {
    let mut slots = FAIL_HWM.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(slot) = slots.iter_mut().find(|(h, _)| *h == handle) {
        slot.1 = n;
    } else {
        slots.push((handle, n));
    }
}

#[cfg(debug_assertions)]
fn take_fail_hwm(handle: IoHandle) -> bool {
    let mut slots = FAIL_HWM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(i) = slots.iter().position(|(h, _)| *h == handle) else {
        return false;
    };
    if slots[i].1 == 0 {
        slots.swap_remove(i);
        return false;
    }
    slots[i].1 -= 1;
    if slots[i].1 == 0 {
        slots.swap_remove(i);
    }
    true
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn would_short_pwrite(handle: IoHandle, len: usize) -> bool {
    len > 8 && short_pwrite_armed(handle)
}

#[cfg(debug_assertions)]
fn short_pwrite_armed(handle: IoHandle) -> bool {
    SHORT_PWRITE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&handle)
}

#[cfg(unix)]
impl From<std::os::fd::RawFd> for IoHandle {
    fn from(fd: std::os::fd::RawFd) -> Self {
        Self::from_raw_fd(fd)
    }
}

#[cfg(windows)]
#[doc(hidden)]
pub fn win_pread(handle: isize, offset: u64, buf: &mut [u8]) -> i32 {
    win_xfer(handle, offset, buf.as_mut_ptr(), buf.len(), false)
}

#[cfg(windows)]
#[doc(hidden)]
pub fn win_pwrite(handle: isize, offset: u64, buf: &[u8]) -> i32 {
    win_xfer(handle, offset, buf.as_ptr() as *mut u8, buf.len(), true)
}

#[cfg(windows)]
#[doc(hidden)]
pub struct PositionalXferEvent(*mut core::ffi::c_void);

#[cfg(windows)]
impl Drop for PositionalXferEvent {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        extern "system" {
            fn CloseHandle(h: *mut core::ffi::c_void) -> i32;
        }
        // SAFETY: `self.0` is the event handle this guard owns.
        unsafe {
            CloseHandle(self.0);
        }
        self.0 = core::ptr::null_mut();
    }
}

#[cfg(windows)]
thread_local! {
    static POSITIONAL_XFER_EVENT: PositionalXferEvent = {
        use std::ptr::{null, null_mut};
        extern "system" {
            fn CreateEventW(
                sec: *mut core::ffi::c_void,
                manual_reset: i32,
                initial: i32,
                name: *const u16,
            ) -> *mut core::ffi::c_void;
        }
        // SAFETY: manual-reset unnamed event. The thread-local drops it.
        PositionalXferEvent(unsafe { CreateEventW(null_mut(), 1, 0, null()) })
    };
}

#[cfg(windows)]
#[doc(hidden)]
pub fn win_xfer(handle: isize, offset: u64, ptr: *mut u8, len: usize, write: bool) -> i32 {
    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        off: u32,
        off_high: u32,
        event: *mut core::ffi::c_void,
    }
    extern "system" {
        fn ReadFile(
            h: *mut core::ffi::c_void,
            buf: *mut u8,
            n: u32,
            got: *mut u32,
            ov: *mut core::ffi::c_void,
        ) -> i32;
        fn WriteFile(
            h: *mut core::ffi::c_void,
            buf: *const u8,
            n: u32,
            got: *mut u32,
            ov: *mut core::ffi::c_void,
        ) -> i32;
        fn GetOverlappedResult(
            h: *mut core::ffi::c_void,
            ov: *mut core::ffi::c_void,
            got: *mut u32,
            wait: i32,
        ) -> i32;
        fn ResetEvent(h: *mut core::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
    }
    const ERROR_IO_PENDING: u32 = 997;
    // A read at EOF returns 38 even on a synchronous handle. std `read_at`
    // turns that into `Ok(0)`. Callers treat `rc == 0` as a short read.
    const ERROR_HANDLE_EOF: u32 = 38;
    POSITIONAL_XFER_EVENT.with(|event| {
        let event = event.0;
        if event.is_null() {
            // SAFETY: reads the Win32 last-error for this thread.
            return -(unsafe { GetLastError() } as i32);
        }
        // SAFETY: `event` is the thread-local manual-reset event.
        unsafe {
            ResetEvent(event);
        }
        // SAFETY: this OVERLAPPED is stack-local. If the handle is bound to an
        // IOCP, a NULL hEvent queues the packet to the port and harvest
        // `Box::from_raw`s it (STATUS_HEAP_CORRUPTION). The low bit of hEvent
        // tells Windows not to queue (GetOverlappedResult still waits).
        let mut ov = Overlapped {
            internal: 0,
            internal_high: 0,
            off: offset as u32,
            off_high: (offset >> 32) as u32,
            event: ((event as usize) | 1) as *mut core::ffi::c_void,
        };
        let mut got: u32 = 0;
        let h = handle as *mut core::ffi::c_void;
        let ovp = (&mut ov) as *mut Overlapped as *mut core::ffi::c_void;
        let ok = if write {
            // SAFETY: `ptr`/`len` is the caller buffer. `ov` is stack-local with the low event bit set.
            unsafe { WriteFile(h, ptr, len as u32, &mut got, ovp) }
        } else {
            // SAFETY: same overlapped transfer as the write arm, into the caller buffer.
            unsafe { ReadFile(h, ptr, len as u32, &mut got, ovp) }
        };
        if ok == 0 {
            // SAFETY: reads the Win32 last-error for this thread.
            let err = unsafe { GetLastError() };
            if err == ERROR_IO_PENDING {
                // SAFETY: `ov` is the stack overlapped passed to ReadFile/WriteFile. Wait is on.
                if unsafe { GetOverlappedResult(h, ovp, &mut got, 1) } == 0 {
                    // SAFETY: reads the Win32 last-error for this thread.
                    let err = unsafe { GetLastError() };
                    if !write && err == ERROR_HANDLE_EOF {
                        return 0;
                    }
                    return -(err as i32);
                }
            } else if !write && err == ERROR_HANDLE_EOF {
                return 0;
            } else {
                return -(err as i32);
            }
        }
        got as i32
    })
}

/// Resize an overlapped file without `SetFilePointer` / std `Seek`.
///
/// `FILE_FLAG_OVERLAPPED` handles reject `WriteFile`/`ReadFile` with a NULL
/// `OVERLAPPED` (Windows ERROR_INVALID_PARAMETER / os error 87). `File::set_len`
/// on current rustc already uses this API; keep an explicit path so table grow
/// does not regress if std changes.
#[cfg(windows)]
pub fn win_set_eof(file: &std::fs::File, new_len: u64) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    struct FileEndOfFileInfo {
        end_of_file: i64,
    }
    extern "system" {
        fn SetFileInformationByHandle(
            h: *mut core::ffi::c_void,
            class: u32,
            info: *const core::ffi::c_void,
            size: u32,
        ) -> i32;
        fn GetLastError() -> u32;
    }
    const FILE_END_OF_FILE_INFO: u32 = 6;
    let info = FileEndOfFileInfo {
        end_of_file: new_len as i64,
    };
    // SAFETY: `info` is a local end-of-file struct. `file` is open.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as *mut core::ffi::c_void,
            FILE_END_OF_FILE_INFO,
            (&info as *const FileEndOfFileInfo).cast(),
            std::mem::size_of::<FileEndOfFileInfo>() as u32,
        )
    };
    if ok == 0 {
        Err(std::io::Error::from_raw_os_error(
            // SAFETY: reads the Win32 last-error for this thread.
            unsafe { GetLastError() } as i32,
        ))
    } else {
        Ok(())
    }
}
