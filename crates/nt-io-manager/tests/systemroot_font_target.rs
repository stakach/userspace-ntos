//! A win32k `\SystemRoot\Fonts\...` open names the registered mounted-volume Device. The links
//! are the ones `nt_fs::boot_volume_links` derives, published into a real Object Manager, and
//! the provider CREATE route takes the resolved Device and untouched remaining name as is.

use nt_object_manager::{ComponentId, ObjectManager};
use nt_types::{CaseSensitivity, NtPath, UnicodeString};

const CI: CaseSensitivity = CaseSensitivity::CaseInsensitive;
const DEVICE: &str = r"\Device\Volume{4c1d7e3a-0b92-4f5e-8a6d-1f2e3d4c5b6a}";

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn mounted_namespace(root: &str) -> (ObjectManager, nt_types::ObjectId, nt_fs::BootVolumeLinks) {
    let mut om = ObjectManager::new();
    om.bootstrap_namespace().unwrap();
    let devices = om.lookup_path(&NtPath::parse_str(r"\Device").unwrap(), CI).unwrap();
    let leaf = DEVICE.rsplit('\\').next().unwrap();
    let volume = om.create_device(&devices, &UnicodeString::from_str(leaf), ComponentId(9), 1, true)
        .unwrap();
    let paths = nt_fs::BootPaths::new(b'C', &nt_fs::InstalledRoot {
        name: units(root), first_cluster: 12,
    }).unwrap();
    let links = nt_fs::boot_volume_links(DEVICE, &paths).unwrap();
    for link in &links.links {
        let parent = match link.directory {
            nt_fs::LinkDirectory::Root => r"\".to_string(),
            directory => format!(r"\{}", directory.name()),
        };
        let parent = om.lookup_path(&NtPath::parse_str(&parent).unwrap(), CI).unwrap();
        om.create_symbolic_link_target(&parent, &UnicodeString::from_str(&link.leaf),
            UnicodeString::from_str(&link.target), true).unwrap();
    }
    (om, volume.id(), links)
}

#[test]
fn systemroot_font_names_resolve_to_the_registered_volume_with_the_exact_remainder() {
    let (om, volume, _) = mounted_namespace("LiberNT");
    for (name, remaining) in [
        (r"\SystemRoot\Fonts\arial.ttf", r"\LiberNT\Fonts\arial.ttf"),
        (r"\SystemRoot\Fonts\", r"\LiberNT\Fonts\"),
        (r"\??\C:\LiberNT\Fonts\tahoma.ttf", r"\LiberNT\Fonts\tahoma.ttf"),
        (r"\GLOBAL??\C:\LiberNT\Fonts\tahoma.ttf", r"\LiberNT\Fonts\tahoma.ttf"),
        (r"\DosDevices\C:\LiberNT\Fonts\marlett.ttf", r"\LiberNT\Fonts\marlett.ttf"),
    ] {
        let target = om.resolve_file_target(&units(name), CI).unwrap();
        assert_eq!(target.device_object, volume, "{name}");
        assert_eq!(target.remaining_name, units(remaining), "{name}");
        let resolved: Result<(u64, Vec<u16>), u32> =
            Ok((target.device_object.0, target.remaining_name));
        assert_eq!(nt_fs::ResolvedFileTarget::classify(Some(&resolved), |id| id == volume.0),
            nt_fs::ResolvedFileTarget::FilesystemChild,
            "the registered kernel filesystem owns the name: {name}");
    }
}

#[test]
fn every_derived_probe_reaches_the_volume_and_the_root_is_not_assumed() {
    let (om, volume, links) = mounted_namespace("w");
    for probe in &links.probes {
        let target = om.resolve_file_target(&units(probe), CI).unwrap();
        assert_eq!((target.device_object, target.remaining_name),
            (volume, units(&links.system32_suffix)), "{probe}");
    }
    let target = om.resolve_file_target(&units(r"\SystemRoot\Fonts\arial.ttf"), CI).unwrap();
    assert_eq!(target.remaining_name, units(r"\w\Fonts\arial.ttf"),
        "the discovered installation root, not a fixed directory name");
}
