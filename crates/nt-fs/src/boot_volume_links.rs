//! Canonical drive and SystemRoot symbolic links for the registered boot volume.
//!
//! Every target is derived from the registered mounted-volume Device's own name and the
//! validated installation root; nothing names a volume, drive or root directory literally.

use alloc::{format, string::String, vec::Vec};

use crate::BootPaths;

/// The Object Manager directory that holds a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDirectory {
    /// The namespace root `\`.
    Root,
    /// The global DOS device directory `\??`, which `\DosDevices` aliases.
    DosDevices,
    /// `\GLOBAL??`, the global DOS device directory spelled for per-session callers.
    GlobalDosDevices,
}

impl LinkDirectory {
    pub fn name(self) -> &'static str {
        match self {
            Self::Root => "",
            Self::DosDevices => "??",
            Self::GlobalDosDevices => "Global??",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeLink {
    pub directory: LinkDirectory,
    pub leaf: String,
    pub target: String,
}

impl VolumeLink {
    /// The absolute link name.
    pub fn path(&self) -> String {
        match self.directory {
            LinkDirectory::Root => format!("\\{}", self.leaf),
            directory => format!("\\{}\\{}", directory.name(), self.leaf),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootVolumeLinkError {
    /// The registered name is not a single `\Device\<name>` component.
    InvalidDevice,
}

/// The links to publish and the absolute names that must then resolve to the registered
/// Device with `system32_suffix` as the device-relative remainder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootVolumeLinks {
    pub links: Vec<VolumeLink>,
    pub probes: Vec<String>,
    pub system32_suffix: String,
}

pub fn boot_volume_links(
    device_name: &str,
    paths: &BootPaths,
) -> Result<BootVolumeLinks, BootVolumeLinkError> {
    let leaf = device_name.strip_prefix("\\Device\\").ok_or(BootVolumeLinkError::InvalidDevice)?;
    if leaf.is_empty()
        || leaf.bytes().any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'\\' | b'/'))
    {
        return Err(BootVolumeLinkError::InvalidDevice);
    }
    // `BootPaths` admitted only ASCII drive and root spellings.
    let drive = core::str::from_utf8(paths.drive()).map_err(|_| BootVolumeLinkError::InvalidDevice)?;
    let root_suffix = core::str::from_utf8(&paths.system_root()[2..])
        .map_err(|_| BootVolumeLinkError::InvalidDevice)?;
    let drive_link = |directory| VolumeLink {
        directory, leaf: String::from(drive), target: String::from(device_name),
    };
    let links = alloc::vec![
        drive_link(LinkDirectory::DosDevices),
        drive_link(LinkDirectory::GlobalDosDevices),
        VolumeLink {
            directory: LinkDirectory::Root,
            leaf: String::from("SystemRoot"),
            target: format!("{device_name}{root_suffix}"),
        },
    ];
    let mut probes: Vec<String> = links.iter().map(|link| match link.directory {
        LinkDirectory::Root => format!("{}\\System32", link.path()),
        _ => format!("{}{root_suffix}\\System32", link.path()),
    }).collect();
    probes.push(format!("\\DosDevices\\{drive}{root_suffix}\\System32"));
    Ok(BootVolumeLinks { links, probes, system32_suffix: format!("{root_suffix}\\System32") })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InstalledRoot;
    use alloc::vec;

    fn paths(drive: u8, root: &str) -> BootPaths {
        BootPaths::new(drive, &InstalledRoot { name: root.encode_utf16().collect(), first_cluster: 9 })
            .unwrap()
    }

    #[test]
    fn links_derive_from_the_registered_device_and_discovered_root() {
        let device = r"\Device\Volume{0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0}";
        let links = boot_volume_links(device, &paths(b'C', "LiberNT")).unwrap();
        assert_eq!(links.links, vec![
            VolumeLink { directory: LinkDirectory::DosDevices, leaf: "C:".into(), target: device.into() },
            VolumeLink { directory: LinkDirectory::GlobalDosDevices, leaf: "C:".into(), target: device.into() },
            VolumeLink { directory: LinkDirectory::Root, leaf: "SystemRoot".into(),
                target: format!("{device}\\LiberNT") },
        ]);
        assert_eq!(links.links.iter().map(VolumeLink::path).collect::<Vec<_>>(),
            vec![r"\??\C:", r"\Global??\C:", r"\SystemRoot"]);
        assert_eq!(links.system32_suffix, r"\LiberNT\System32");
        assert_eq!(links.probes, vec![
            r"\??\C:\LiberNT\System32", r"\Global??\C:\LiberNT\System32",
            r"\SystemRoot\System32", r"\DosDevices\C:\LiberNT\System32",
        ], "every published spelling, and the DosDevices alias, must reach the same Device");
    }

    #[test]
    fn no_drive_or_root_identity_is_hardcoded() {
        let device = r"\Device\HarddiskVolume7";
        let links = boot_volume_links(device, &paths(b'e', "w")).unwrap();
        assert_eq!(links.links[0].leaf, "E:");
        assert_eq!(links.links[2].target, r"\Device\HarddiskVolume7\w");
        assert!(links.links.iter().all(|link| !link.target.contains("reactos")
            && !link.target.contains("Windows")));
        assert_eq!(links.system32_suffix, r"\w\System32");
    }

    #[test]
    fn only_a_single_registered_device_component_is_a_link_target() {
        for name in ["", r"\Device", r"\Device\", r"\Device\a\b", r"Device\x", r"\??\C:",
            "\\Device\\Vol\u{e9}", "\\Device\\a\0b", r"\Device\a/b"]
        {
            assert_eq!(boot_volume_links(name, &paths(b'C', "LiberNT")),
                Err(BootVolumeLinkError::InvalidDevice), "{name:?}");
        }
    }
}
