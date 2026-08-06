//! NT path model + the Mount Manager (spec §7, §13).
//!
//! A mount point maps a namespace prefix to a file-system volume device. [`MountManager`]
//! resolves a full NT path to a volume-relative path by longest-prefix match (spec §13.3).

use alloc::string::String;
use alloc::vec::Vec;

/// The v0.1 volume device (spec §6.3).
pub const MEMFS_VOLUME: &str = r"\Device\MemFsVolume0";

/// One namespace mount: `prefix` → `target` (a volume-device-relative root) (spec §6.4).
struct Mount {
    prefix: String,
    target: String,
}

/// The Mount Manager (spec §13): resolves an NT path to a volume + volume-relative path.
pub struct MountManager {
    mounts: Vec<Mount>,
}

impl Default for MountManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MountManager {
    /// A Mount Manager with the required v0.1 mounts (spec §13.2): `\SystemRoot` →
    /// `\Device\MemFsVolume0\Windows`, `\??\C:` → `\Device\MemFsVolume0`.
    pub fn new() -> Self {
        let mut m = MountManager { mounts: Vec::new() };
        m.mount(r"\SystemRoot", &alloc::format!("{MEMFS_VOLUME}\\Windows"));
        m.mount(r"\??\C:", MEMFS_VOLUME);
        m.mount(r"\DosDevices\C:", MEMFS_VOLUME); // optional alias (spec §6.4)
        m
    }

    pub fn mount(&mut self, prefix: &str, target: &str) {
        self.mounts
            .retain(|m| !m.prefix.eq_ignore_ascii_case(prefix));
        self.mounts.push(Mount {
            prefix: prefix.into(),
            target: target.into(),
        });
    }

    /// Resolve a full NT path to `(volume_device, volume_relative_path)` by longest-prefix match
    /// (spec §13.3). `volume_relative_path` starts with `\` and uses normalized separators.
    pub fn resolve(&self, path: &str) -> Option<(String, String)> {
        let norm = normalize_separators(path);
        // Longest matching mount prefix wins.
        let mut best: Option<&Mount> = None;
        for m in &self.mounts {
            if path_has_prefix(&norm, &m.prefix)
                && best
                    .map(|b| m.prefix.len() > b.prefix.len())
                    .unwrap_or(true)
            {
                best = Some(m);
            }
        }
        let m = best?;
        // The mount target is `\Device\<vol>[\<sub>]`; split off the volume device.
        let rest = &norm[m.prefix.len()..];
        let full_target = alloc::format!("{}{}", m.target, rest);
        split_volume(&full_target)
    }
}

/// Collapse `/` → `\` and any run of separators to a single `\`.
pub fn normalize_separators(path: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for ch in path.chars() {
        let c = if ch == '/' { '\\' } else { ch };
        if c == '\\' {
            if !prev_sep {
                out.push('\\');
            }
            prev_sep = true;
        } else {
            out.push(c);
            prev_sep = false;
        }
    }
    // Drop a trailing separator (except a lone root).
    if out.len() > 1 && out.ends_with('\\') {
        out.pop();
    }
    out
}

/// Whether an NT object path names the named-pipe filesystem, case-insensitively.
pub fn is_named_pipe_path(path: &[u16]) -> bool {
    const DOS_PIPE: &[u8] = b"\\??\\pipe\\";
    const DOS_DEVICES_PIPE: &[u8] = b"\\dosdevices\\pipe\\";
    const DEVICE_PIPE: &[u8] = b"\\device\\namedpipe\\";

    fn starts_ascii_case_insensitive(path: &[u16], prefix: &[u8]) -> bool {
        path.len() >= prefix.len()
            && path
                .iter()
                .zip(prefix)
                .all(|(&unit, &byte)| unit <= 0x7f && (unit as u8).eq_ignore_ascii_case(&byte))
    }

    starts_ascii_case_insensitive(path, DOS_PIPE)
        || starts_ascii_case_insensitive(path, DOS_DEVICES_PIPE)
        || starts_ascii_case_insensitive(path, DEVICE_PIPE)
}

/// Translate the local NT/DOS path forms used by user-mode file opens into a lowercase,
/// root-relative path for the executive's mounted FAT volume.
fn push_relative_component(out: &mut [u8], len: &mut usize, component: &[u8]) -> Option<()> {
    if component.is_empty() || component == b"." {
        return Some(());
    }
    if component == b".." || component.contains(&b':') {
        return None;
    }
    if *len != 0 {
        if *len >= out.len() {
            return None;
        }
        out[*len] = b'\\';
        *len += 1;
    }
    if out.len().saturating_sub(*len) < component.len() {
        return None;
    }
    for &byte in component {
        out[*len] = byte.to_ascii_lowercase();
        *len += 1;
    }
    Some(())
}

fn push_relative_suffix(out: &mut [u8], len: &mut usize, suffix: &[u8]) -> Option<()> {
    for component in suffix.split(|byte| *byte == b'\\') {
        push_relative_component(out, len, component)?;
    }
    Some(())
}

pub fn nt_path_to_volume_relative_into(
    path: &[u16],
    system_root: &[u8],
    folded: &mut [u8],
    out: &mut [u8],
) -> Option<usize> {
    if system_root.is_empty()
        || system_root
            .iter()
            .any(|byte| !byte.is_ascii() || matches!(byte, b'\\' | b'/' | b':'))
    {
        return None;
    }
    if folded.len() < path.len() {
        return None;
    }
    let mut folded_len = 0usize;
    let mut previous_separator = false;
    for &unit in path {
        if unit > 0x7f {
            return None;
        }
        let mut byte = (unit as u8).to_ascii_lowercase();
        if byte == b'/' {
            byte = b'\\';
        }
        if byte == b'\\' {
            if previous_separator {
                continue;
            }
            previous_separator = true;
        } else {
            previous_separator = false;
        }
        folded[folded_len] = byte;
        folded_len += 1;
    }
    let folded = &folded[..folded_len];

    let system_prefix = b"\\systemroot";
    let dos_prefix = b"\\??\\c:\\";
    let dos_devices_prefix = b"\\dosdevices\\c:\\";
    let drive_prefix = b"c:\\";

    let mut out_len = 0usize;
    if folded.starts_with(system_prefix)
        && folded
            .get(system_prefix.len())
            .is_none_or(|byte| *byte == b'\\')
    {
        push_relative_component(out, &mut out_len, system_root)?;
        push_relative_suffix(out, &mut out_len, &folded[system_prefix.len()..])?;
    } else if folded.starts_with(dos_prefix) {
        push_drive_relative_into(system_root, &folded[dos_prefix.len()..], out, &mut out_len)?;
    } else if folded.starts_with(dos_devices_prefix) {
        push_drive_relative_into(
            system_root,
            &folded[dos_devices_prefix.len()..],
            out,
            &mut out_len,
        )?;
    } else if folded.starts_with(drive_prefix) {
        push_drive_relative_into(
            system_root,
            &folded[drive_prefix.len()..],
            out,
            &mut out_len,
        )?;
    } else {
        return None;
    }
    Some(out_len)
}

fn push_drive_relative_into(
    system_root: &[u8],
    relative: &[u8],
    out: &mut [u8],
    out_len: &mut usize,
) -> Option<()> {
    // The hosted PEB exposes the canonical DOS SystemRoot as C:\Windows while the ReactOS tree is
    // mounted under system_root on the FAT volume. Resolve both spellings to the same directory.
    if relative == b"windows" || relative.starts_with(b"windows\\") {
        push_relative_component(out, out_len, system_root)?;
        push_relative_suffix(out, out_len, &relative[b"windows".len()..])
    } else {
        push_relative_suffix(out, out_len, relative)
    }
}

pub fn nt_path_to_volume_relative(path: &[u16], system_root: &[u8]) -> Option<Vec<u8>> {
    let mut folded = alloc::vec![0u8; path.len()];
    let mut out = alloc::vec![0u8; path.len().saturating_add(system_root.len())];
    let len = nt_path_to_volume_relative_into(path, system_root, &mut folded, &mut out)?;
    out.truncate(len);
    Some(out)
}

/// Whether `volume_relative` (the output of [`nt_path_to_volume_relative`] — lowercase, no leading
/// separator) is AT or UNDER one of `prefixes` (each itself a lowercase volume-relative path).
///
/// This is the general "writable mount at prefix P" test (spec §13.4): a namespace subtree is
/// declared writable, and every path inside it — at any depth — belongs to the writable volume.
/// Component-wise, so `profiles2` is NOT under `profiles`.
pub fn is_under_prefix(volume_relative: &[u8], prefixes: &[&[u8]]) -> bool {
    prefixes.iter().any(|prefix| {
        !prefix.is_empty()
            && volume_relative.len() >= prefix.len()
            && volume_relative[..prefix.len()] == **prefix
            && volume_relative
                .get(prefix.len())
                .is_none_or(|byte| *byte == b'\\')
    })
}

/// Resolve an NT path to the WRITABLE volume's relative path, or `None` when the path is outside
/// every writable mount prefix (in which case the caller's read-only namespace still owns it).
///
/// The writable volume shares the read-only volume's namespace convention — the same
/// [`nt_path_to_volume_relative`] canonicalisation — so swapping the backing store (RAM today,
/// FAT write-through later) needs no change above this seam.
pub fn writable_mount_relative(
    path: &[u16],
    system_root: &[u8],
    prefixes: &[&[u8]],
) -> Option<Vec<u8>> {
    let relative = nt_path_to_volume_relative(path, system_root)?;
    is_under_prefix(&relative, prefixes).then_some(relative)
}

pub fn writable_mount_relative_into(
    path: &[u16],
    system_root: &[u8],
    prefixes: &[&[u8]],
    folded: &mut [u8],
    out: &mut [u8],
) -> Option<usize> {
    let len = nt_path_to_volume_relative_into(path, system_root, folded, out)?;
    is_under_prefix(&out[..len], prefixes).then_some(len)
}

/// Case-insensitive component-wise prefix test.
fn path_has_prefix(path: &str, prefix: &str) -> bool {
    let p: Vec<&str> = path.split('\\').filter(|c| !c.is_empty()).collect();
    let q: Vec<&str> = prefix.split('\\').filter(|c| !c.is_empty()).collect();
    q.len() <= p.len() && q.iter().zip(&p).all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Split `\Device\MemFsVolume0\A\B` into (`\Device\MemFsVolume0`, `\A\B`).
fn split_volume(full: &str) -> Option<(String, String)> {
    let comps: Vec<&str> = full.split('\\').filter(|c| !c.is_empty()).collect();
    // Expect `Device`, `<VolumeName>`, then the relative components.
    if comps.len() < 2 || !comps[0].eq_ignore_ascii_case("Device") {
        return None;
    }
    let volume = alloc::format!("\\{}\\{}", comps[0], comps[1]);
    let mut rel = String::new();
    for c in &comps[2..] {
        rel.push('\\');
        rel.push_str(c);
    }
    if rel.is_empty() {
        rel.push('\\');
    }
    Some((volume, rel))
}
