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
pub fn nt_path_to_volume_relative(path: &[u16], system_root: &[u8]) -> Option<Vec<u8>> {
    if system_root.is_empty()
        || system_root
            .iter()
            .any(|byte| !byte.is_ascii() || matches!(byte, b'\\' | b'/' | b':'))
    {
        return None;
    }
    let mut folded = Vec::with_capacity(path.len());
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
        folded.push(byte);
    }

    let system_prefix = b"\\systemroot";
    let dos_prefix = b"\\??\\c:\\";
    let dos_devices_prefix = b"\\dosdevices\\c:\\";
    let drive_prefix = b"c:\\";
    let mut relative = Vec::new();
    if folded.starts_with(system_prefix)
        && folded
            .get(system_prefix.len())
            .is_none_or(|byte| *byte == b'\\')
    {
        relative.extend(system_root.iter().map(u8::to_ascii_lowercase));
        relative.extend_from_slice(&folded[system_prefix.len()..]);
    } else if folded.starts_with(dos_prefix) {
        relative.extend_from_slice(&folded[dos_prefix.len()..]);
    } else if folded.starts_with(dos_devices_prefix) {
        relative.extend_from_slice(&folded[dos_devices_prefix.len()..]);
    } else if folded.starts_with(drive_prefix) {
        relative.extend_from_slice(&folded[drive_prefix.len()..]);
    } else {
        return None;
    }

    let mut normalized = Vec::with_capacity(relative.len());
    for component in relative.split(|byte| *byte == b'\\') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." || component.contains(&b':') {
            return None;
        }
        if !normalized.is_empty() {
            normalized.push(b'\\');
        }
        normalized.extend_from_slice(component);
    }
    Some(normalized)
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
