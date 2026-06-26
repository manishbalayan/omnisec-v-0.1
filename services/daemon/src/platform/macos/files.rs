//! macOS file system monitoring via kqueue(2) / kevent(2)
//!
//! Watches open file descriptors for vnode events using EVFILT_VNODE.
//! Supports NOTE_WRITE, NOTE_DELETE, NOTE_ATTRIB, and NOTE_RENAME.
//!
//! Usage:
//!   let engine = FileMonitorEngine::new();
//!   engine.watch("/etc/hosts");
//!   for event in engine.events() { ... }

use super::super::FileSysEvent;
use libc::{
    c_int, kevent, kqueue, EVFILT_VNODE, EV_ADD, EV_CLEAR, EV_ENABLE,
    NOTE_ATTRIB, NOTE_DELETE, NOTE_RENAME, NOTE_WRITE,
};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::os::unix::io::IntoRawFd;
use std::sync::{Arc, Mutex};

pub struct FileMonitorEngine {
    kq: c_int,
    watched: Arc<Mutex<HashMap<c_int, String>>>, // fd → path
}

impl FileMonitorEngine {
    pub fn new() -> Self {
        let kq = unsafe { kqueue() };
        if kq < 0 {
            tracing::warn!("kqueue: failed to create queue (errno {})", errno());
        }
        FileMonitorEngine {
            kq,
            watched: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Add a path to the watch list.
    pub fn watch(&self, path: &str) -> bool {
        if self.kq < 0 {
            return false;
        }

        let fd = match OpenOptions::new().read(true).open(path) {
            Ok(f) => f.into_raw_fd(),
            Err(e) => {
                tracing::warn!("kqueue: cannot open '{}': {}", path, e);
                return false;
            }
        };

        let fflags = (NOTE_WRITE | NOTE_DELETE | NOTE_ATTRIB | NOTE_RENAME) as u32;

        let change = kevent {
            ident: fd as usize,
            filter: EVFILT_VNODE as i16,
            flags: (EV_ADD | EV_ENABLE | EV_CLEAR) as u16,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
        };

        let ret = unsafe {
            libc::kevent(
                self.kq,
                &change as *const kevent,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };

        if ret < 0 {
            tracing::warn!("kqueue: kevent EV_ADD failed for '{}' (errno {})", path, errno());
            unsafe { libc::close(fd) };
            return false;
        }

        self.watched.lock().unwrap().insert(fd, path.to_string());
        tracing::debug!("kqueue: watching '{}'", path);
        true
    }

    /// Poll for pending vnode events with a timeout.
    pub fn poll(&self, timeout_ms: u64) -> Vec<FileSysEvent> {
        if self.kq < 0 {
            return Vec::new();
        }

        let ts = libc::timespec {
            tv_sec: (timeout_ms / 1000) as libc::time_t,
            tv_nsec: ((timeout_ms % 1000) * 1_000_000) as libc::c_long,
        };

        let mut evlist: [kevent; 32] = unsafe { std::mem::zeroed() };

        let nev = unsafe {
            libc::kevent(
                self.kq,
                std::ptr::null(),
                0,
                evlist.as_mut_ptr(),
                32,
                &ts as *const libc::timespec,
            )
        };

        if nev <= 0 {
            return Vec::new();
        }

        let watched = self.watched.lock().unwrap();
        (0..nev as usize)
            .filter_map(|i| {
                let ev = &evlist[i];
                let fd = ev.ident as c_int;
                let path = watched.get(&fd)?.clone();
                let action = vnode_flags_to_action(ev.fflags);
                Some(FileSysEvent {
                    path,
                    action,
                    real_event: true,
                })
            })
            .collect()
    }
}

impl Drop for FileMonitorEngine {
    fn drop(&mut self) {
        if self.kq >= 0 {
            // Close all watched fds.
            let watched = self.watched.lock().unwrap();
            for &fd in watched.keys() {
                unsafe { libc::close(fd) };
            }
            unsafe { libc::close(self.kq) };
        }
    }
}

fn vnode_flags_to_action(fflags: u32) -> String {
    let mut parts = Vec::new();
    if fflags & NOTE_WRITE != 0 {
        parts.push("write");
    }
    if fflags & NOTE_DELETE != 0 {
        parts.push("delete");
    }
    if fflags & NOTE_RENAME != 0 {
        parts.push("rename");
    }
    if fflags & NOTE_ATTRIB != 0 {
        parts.push("attrib");
    }
    if parts.is_empty() {
        "unknown".to_string()
    } else {
        parts.join("|")
    }
}

fn errno() -> i32 {
    unsafe { *libc::__error() }
}
