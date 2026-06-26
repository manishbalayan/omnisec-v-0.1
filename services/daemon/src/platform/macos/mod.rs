//! macOS platform implementation
//!
//! Native APIs used:
//! - sysctl(CTL_KERN, KERN_PROC_ALL)  → process enumeration
//! - sysctl(CTL_KERN, KERN_PROCARGS2) → full command-line retrieval
//! - kqueue(2) / kevent(2)            → file system event monitoring (EVFILT_VNODE)
//! - pfctl(8) PF anchor               → network-level packet filtering
//! - POSIX kill(2)                    → process signal delivery (SIGSTOP/CONT/KILL)
//! - launchctl(1)                     → service management (keepalive via plist)

pub mod process;
pub mod network;
pub mod files;
pub mod service;
