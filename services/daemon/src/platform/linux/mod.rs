//! Linux platform implementation
//!
//! Native APIs used:
//! - /proc filesystem  → process enumeration, command-line reading
//! - inotify(7)        → file system event monitoring
//! - nftables (nft 1)  → network-level blocking
//! - Netlink / /proc/net → connection tracking
//! - NOTIFY_SOCKET     → systemd sd_notify watchdog

pub mod process;
pub mod network;
pub mod files;
pub mod service;
