//! Bootstrap hosted-process image policy.
//!
//! This is the remaining executive-owned seed while the boot loader does not yet hand us a dynamic
//! initial native-image manifest. Runtime handlers consume catalogs populated here; they do not
//! reach back into the historical descriptor table.
#![allow(clippy::all)]

pub(crate) fn smss_bootstrap_image() -> nt_exe_image::OwnedHostedProcessImage {
    nt_exe_image::OwnedHostedProcessImage::new(
        0,
        nt_exe_image::SMSS_TOP_BADGE,
        b"smss.exe",
        b"smss.exe",
        nt_exe_image::HostedProcessRole::NativeSession,
        b"\\SystemRoot\\System32\\smss.exe",
        b"smss.exe",
        nt_exe_image::HostedImageRoot::System32,
        b"",
    )
    .expect("SMSS bootstrap image descriptor is static and validated")
}

pub(crate) fn seed_hosted_exe_image_catalog(
    catalog: &mut nt_exe_image::OwnedHostedImageCatalog<8>,
    smss_pe: &nt_pe_loader::PeFile,
    csrss_pe: &Option<nt_pe_loader::PeFile<'static>>,
    winlogon_pe: &Option<nt_pe_loader::PeFile<'static>>,
    services_pe: &Option<nt_pe_loader::PeFile<'static>>,
    lsass_pe: &Option<nt_pe_loader::PeFile<'static>>,
    userinit_pe: &Option<nt_pe_loader::PeFile<'static>>,
    explorer_pe: &Option<nt_pe_loader::PeFile<'static>>,
) {
    let loaded = [
        (b"smss.exe" as &[u8], !smss_pe.bytes().is_empty()),
        (b"csrss.exe" as &[u8], csrss_pe.is_some()),
        (b"winlogon.exe" as &[u8], winlogon_pe.is_some()),
        (b"services.exe" as &[u8], services_pe.is_some()),
        (b"lsass.exe" as &[u8], lsass_pe.is_some()),
        (b"userinit.exe" as &[u8], userinit_pe.is_some()),
        (b"explorer.exe" as &[u8], explorer_pe.is_some()),
    ];
    for image in nt_exe_image::HOSTED_PROCESS_IMAGES {
        if loaded
            .iter()
            .any(|(leaf, present)| *present && leaf.eq_ignore_ascii_case(image.leaf))
            && catalog.get_by_leaf(image.leaf).is_none()
        {
            let _ = catalog.register_ref(nt_exe_image::HostedProcessImageRef::from(image));
        }
    }
}
