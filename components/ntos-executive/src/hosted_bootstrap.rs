//! Bootstrap hosted-process image policy.
//!
//! This is the remaining executive-owned seed while the boot loader does not yet hand us a dynamic
//! initial native-image manifest. Runtime handlers consume catalogs populated here; they do not
//! reach back into the historical descriptor table.
#![allow(clippy::all)]

fn hosted_bootstrap_image(
    pi: usize,
    top_badge: u64,
    leaf: &[u8],
    role: nt_exe_image::HostedProcessRole,
    nt_image_path: &[u8],
    command_line: &[u8],
    image_root: nt_exe_image::HostedImageRoot,
    probe_fragment: &[u8],
) -> nt_exe_image::OwnedHostedProcessImage {
    nt_exe_image::OwnedHostedProcessImage::new(
        pi,
        top_badge,
        leaf,
        leaf,
        role,
        nt_image_path,
        command_line,
        image_root,
        probe_fragment,
    )
    .expect("hosted bootstrap image descriptor is static and validated")
}

#[derive(Clone, Copy)]
pub(crate) struct HostedBootstrapLoadSpec {
    pub(crate) disk_path: &'static [u8],
    pub(crate) stem: &'static [u8],
    pub(crate) image: nt_exe_image::OwnedHostedProcessImage,
}

fn hosted_bootstrap_load_spec(
    disk_path: &'static [u8],
    stem: &'static [u8],
    image: nt_exe_image::OwnedHostedProcessImage,
) -> HostedBootstrapLoadSpec {
    HostedBootstrapLoadSpec {
        disk_path,
        stem,
        image,
    }
}

pub(crate) fn smss_bootstrap_image() -> nt_exe_image::OwnedHostedProcessImage {
    hosted_bootstrap_image(
        0,
        nt_exe_image::SMSS_TOP_BADGE,
        b"smss.exe",
        nt_exe_image::HostedProcessRole::NativeSession,
        b"\\SystemRoot\\System32\\smss.exe",
        b"smss.exe",
        nt_exe_image::HostedImageRoot::System32,
        b"",
    )
}

fn csrss_bootstrap_image() -> nt_exe_image::OwnedHostedProcessImage {
    hosted_bootstrap_image(
        1,
        nt_exe_image::CSRSS_TOP_BADGE,
        b"csrss.exe",
        nt_exe_image::HostedProcessRole::Win32Subsystem,
        b"\\SystemRoot\\System32\\csrss.exe",
        b"csrss.exe ObjectDirectory=\\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16",
        nt_exe_image::HostedImageRoot::System32,
        b"csrss",
    )
}

pub(crate) fn csrss_bootstrap_load_spec() -> HostedBootstrapLoadSpec {
    hosted_bootstrap_load_spec(
        b"reactos\\system32\\csrss.exe",
        b"csrss.exe",
        csrss_bootstrap_image(),
    )
}

fn winlogon_bootstrap_image() -> nt_exe_image::OwnedHostedProcessImage {
    hosted_bootstrap_image(
        2,
        nt_exe_image::WINLOGON_TOP_BADGE,
        b"winlogon.exe",
        nt_exe_image::HostedProcessRole::InteractiveLogon,
        b"\\SystemRoot\\System32\\winlogon.exe",
        b"winlogon.exe",
        nt_exe_image::HostedImageRoot::System32,
        b"winlogon",
    )
}

pub(crate) fn winlogon_bootstrap_load_spec() -> HostedBootstrapLoadSpec {
    hosted_bootstrap_load_spec(
        b"reactos\\system32\\winlogon.exe",
        b"winlogon.exe",
        winlogon_bootstrap_image(),
    )
}

fn services_bootstrap_image() -> nt_exe_image::OwnedHostedProcessImage {
    hosted_bootstrap_image(
        3,
        nt_exe_image::SERVICES_TOP_BADGE,
        b"services.exe",
        nt_exe_image::HostedProcessRole::NonInteractiveService,
        b"\\SystemRoot\\System32\\services.exe",
        b"services.exe",
        nt_exe_image::HostedImageRoot::System32,
        b"services",
    )
}

pub(crate) fn services_bootstrap_load_spec() -> HostedBootstrapLoadSpec {
    hosted_bootstrap_load_spec(
        b"reactos\\system32\\services.exe",
        b"services.exe",
        services_bootstrap_image(),
    )
}

fn lsass_bootstrap_image() -> nt_exe_image::OwnedHostedProcessImage {
    hosted_bootstrap_image(
        4,
        nt_exe_image::LSASS_TOP_BADGE,
        b"lsass.exe",
        nt_exe_image::HostedProcessRole::NonInteractiveService,
        b"\\SystemRoot\\System32\\lsass.exe",
        b"lsass.exe",
        nt_exe_image::HostedImageRoot::System32,
        b"lsass",
    )
}

pub(crate) fn lsass_bootstrap_load_spec() -> HostedBootstrapLoadSpec {
    hosted_bootstrap_load_spec(
        b"reactos\\system32\\lsass.exe",
        b"lsass.exe",
        lsass_bootstrap_image(),
    )
}

fn userinit_bootstrap_image() -> nt_exe_image::OwnedHostedProcessImage {
    hosted_bootstrap_image(
        5,
        nt_exe_image::USERINIT_TOP_BADGE,
        b"userinit.exe",
        nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
        b"\\SystemRoot\\System32\\userinit.exe",
        b"userinit.exe",
        nt_exe_image::HostedImageRoot::System32,
        b"userinit",
    )
}

pub(crate) fn userinit_bootstrap_load_spec() -> HostedBootstrapLoadSpec {
    hosted_bootstrap_load_spec(
        br"reactos\system32\userinit.exe",
        b"userinit.exe",
        userinit_bootstrap_image(),
    )
}

fn explorer_bootstrap_image() -> nt_exe_image::OwnedHostedProcessImage {
    hosted_bootstrap_image(
        6,
        nt_exe_image::EXPLORER_TOP_BADGE,
        b"explorer.exe",
        nt_exe_image::HostedProcessRole::InteractiveShell,
        b"\\SystemRoot\\explorer.exe",
        b"explorer.exe",
        nt_exe_image::HostedImageRoot::SystemRoot,
        b"explorer",
    )
}

pub(crate) fn explorer_bootstrap_load_spec() -> HostedBootstrapLoadSpec {
    hosted_bootstrap_load_spec(
        br"reactos\explorer.exe",
        b"explorer.exe",
        explorer_bootstrap_image(),
    )
}

pub(crate) fn register_loaded_hosted_image(
    catalog: &mut nt_exe_image::OwnedHostedImageCatalog<8>,
    image: nt_exe_image::OwnedHostedProcessImage,
    loaded: bool,
) -> Result<(), nt_exe_image::HostedImageRegistrationError> {
    if loaded {
        catalog.register(image)?;
    }
    Ok(())
}
