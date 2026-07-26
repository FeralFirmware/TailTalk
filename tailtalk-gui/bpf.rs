//! Whether this process can open a BPF device, which is what EtherTalk needs
//! before the GUI is willing to offer an Ethernet interface at all.
//!
//! libpcap captures and injects through a `/dev/bpf*` character device, opened
//! read/write since we put AARP/DDP frames on the wire rather than only
//! sniffing. Those devices are root-only as shipped; Wireshark's ChmodBPF
//! package is the usual fix, creating an `access_bpf` group, handing the
//! devices to it and adding the console user.
//!
//! So the check is whether that group exists and whether we are in it.
//! Membership comes from `getgroups`, the login session's group list, which is
//! what the kernel consults when pcap opens the device. A fresh ChmodBPF
//! install therefore reads as unavailable until the user logs out and back in,
//! which is when it genuinely starts working.

/// True when this process should be able to open a BPF device for capture and
/// injection.
#[cfg(target_os = "macos")]
pub fn capture_permitted() -> bool {
    // SAFETY: takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return true; // root opens the devices regardless of group membership.
    }

    // SAFETY: the name is NUL-terminated. `getgrnam` returns a pointer into a
    // static buffer valid until the next getgr* call; we read it immediately.
    let entry = unsafe { libc::getgrnam(c"access_bpf".as_ptr()) };
    if entry.is_null() {
        tracing::debug!("No access_bpf group: Wireshark's ChmodBPF package is not installed");
        return false;
    }
    in_group(unsafe { (*entry).gr_gid })
}

/// Whether this process's group list includes `gid`.
#[cfg(target_os = "macos")]
fn in_group(gid: libc::gid_t) -> bool {
    // SAFETY: no arguments, cannot fail.
    if unsafe { libc::getegid() } == gid {
        return true;
    }

    // SAFETY: a size of 0 asks for the count only, and permits a null buffer.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return false;
    }

    let mut groups = vec![0; count as usize];
    // SAFETY: the buffer holds `count` gid_t, matching the size we pass.
    let filled = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if filled < 0 {
        return false;
    }
    groups[..filled as usize].contains(&gid)
}

/// Non-macOS platforms have no ChmodBPF equivalent to gate on: EtherTalk is a
/// deliberate opt-in there, so never hide what the user asked to compile in.
#[cfg(not(target_os = "macos"))]
pub fn capture_permitted() -> bool {
    true
}
