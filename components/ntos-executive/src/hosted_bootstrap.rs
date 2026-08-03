//! Bootstrap hosted-process image policy.
//!
//! This is the remaining executive-owned seed while the boot loader does not yet hand us a dynamic
//! initial native-image manifest. Runtime handlers consume catalogs populated here; they do not
//! reach back into the historical descriptor table.
#![allow(clippy::all)]

use crate::{
    csrss_process_runtime, explorer_process_runtime, lsass_process_runtime,
    register_hosted_process_runtime, services_process_runtime, userinit_process_runtime,
    winlogon_process_runtime, HostedProcessRuntime,
};

#[derive(Clone, Copy)]
pub(crate) struct HostedBootstrapLoadSpec {
    pub(crate) disk_path: &'static [u8],
    pub(crate) stem: &'static [u8],
    pub(crate) image: nt_exe_image::OwnedHostedProcessImage,
    pub(crate) runtime: HostedProcessRuntime,
}

#[derive(Clone, Copy)]
struct HostedBootstrapManifestEntry {
    disk_path: &'static [u8],
    stem: &'static [u8],
    pi: usize,
    top_badge: u64,
    leaf: &'static [u8],
    role: nt_exe_image::HostedProcessRole,
    nt_image_path: &'static [u8],
    command_line: &'static [u8],
    image_root: nt_exe_image::HostedImageRoot,
    probe_fragment: &'static [u8],
    runtime: fn() -> HostedProcessRuntime,
}

impl HostedBootstrapManifestEntry {
    fn image(self) -> nt_exe_image::OwnedHostedProcessImage {
        nt_exe_image::OwnedHostedProcessImage::new(
            self.pi,
            self.top_badge,
            self.leaf,
            self.leaf,
            self.role,
            self.nt_image_path,
            self.command_line,
            self.image_root,
            self.probe_fragment,
        )
        .expect("hosted bootstrap image manifest entry is static and validated")
    }

    fn load_spec(self) -> HostedBootstrapLoadSpec {
        HostedBootstrapLoadSpec {
            disk_path: self.disk_path,
            stem: self.stem,
            image: self.image(),
            runtime: (self.runtime)(),
        }
    }
}

const SMSS_BOOTSTRAP_MANIFEST: HostedBootstrapManifestEntry = HostedBootstrapManifestEntry {
    disk_path: b"reactos\\system32\\smss.exe",
    stem: b"smss.exe",
    pi: 0,
    top_badge: nt_exe_image::SMSS_TOP_BADGE,
    leaf: b"smss.exe",
    role: nt_exe_image::HostedProcessRole::NativeSession,
    nt_image_path: b"\\SystemRoot\\System32\\smss.exe",
    command_line: b"smss.exe",
    image_root: nt_exe_image::HostedImageRoot::System32,
    probe_fragment: b"",
    runtime: crate::smss_process_runtime,
};

const HOSTED_BOOTSTRAP_MANIFEST: [HostedBootstrapManifestEntry; 6] = [
    HostedBootstrapManifestEntry {
        disk_path: b"reactos\\system32\\csrss.exe",
        stem: b"csrss.exe",
        pi: 1,
        top_badge: nt_exe_image::CSRSS_TOP_BADGE,
        leaf: b"csrss.exe",
        role: nt_exe_image::HostedProcessRole::Win32Subsystem,
        nt_image_path: b"\\SystemRoot\\System32\\csrss.exe",
        command_line: b"csrss.exe ObjectDirectory=\\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"csrss",
        runtime: csrss_process_runtime,
    },
    HostedBootstrapManifestEntry {
        disk_path: b"reactos\\system32\\winlogon.exe",
        stem: b"winlogon.exe",
        pi: 2,
        top_badge: nt_exe_image::WINLOGON_TOP_BADGE,
        leaf: b"winlogon.exe",
        role: nt_exe_image::HostedProcessRole::InteractiveLogon,
        nt_image_path: b"\\SystemRoot\\System32\\winlogon.exe",
        command_line: b"winlogon.exe",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"winlogon",
        runtime: winlogon_process_runtime,
    },
    HostedBootstrapManifestEntry {
        disk_path: b"reactos\\system32\\services.exe",
        stem: b"services.exe",
        pi: 3,
        top_badge: nt_exe_image::SERVICES_TOP_BADGE,
        leaf: b"services.exe",
        role: nt_exe_image::HostedProcessRole::NonInteractiveService,
        nt_image_path: b"\\SystemRoot\\System32\\services.exe",
        command_line: b"services.exe",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"services",
        runtime: services_process_runtime,
    },
    HostedBootstrapManifestEntry {
        disk_path: b"reactos\\system32\\lsass.exe",
        stem: b"lsass.exe",
        pi: 4,
        top_badge: nt_exe_image::LSASS_TOP_BADGE,
        leaf: b"lsass.exe",
        role: nt_exe_image::HostedProcessRole::NonInteractiveService,
        nt_image_path: b"\\SystemRoot\\System32\\lsass.exe",
        command_line: b"lsass.exe",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"lsass",
        runtime: lsass_process_runtime,
    },
    HostedBootstrapManifestEntry {
        disk_path: br"reactos\system32\userinit.exe",
        stem: b"userinit.exe",
        pi: 5,
        top_badge: nt_exe_image::USERINIT_TOP_BADGE,
        leaf: b"userinit.exe",
        role: nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
        nt_image_path: b"\\SystemRoot\\System32\\userinit.exe",
        command_line: b"userinit.exe",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"userinit",
        runtime: userinit_process_runtime,
    },
    HostedBootstrapManifestEntry {
        disk_path: br"reactos\explorer.exe",
        stem: b"explorer.exe",
        pi: 6,
        top_badge: nt_exe_image::EXPLORER_TOP_BADGE,
        leaf: b"explorer.exe",
        role: nt_exe_image::HostedProcessRole::InteractiveShell,
        nt_image_path: b"\\SystemRoot\\explorer.exe",
        command_line: b"explorer.exe",
        image_root: nt_exe_image::HostedImageRoot::SystemRoot,
        probe_fragment: b"explorer",
        runtime: explorer_process_runtime,
    },
];

pub(crate) const HOSTED_BOOTSTRAP_LOAD_COUNT: usize = HOSTED_BOOTSTRAP_MANIFEST.len();

pub(crate) fn smss_bootstrap_image() -> nt_exe_image::OwnedHostedProcessImage {
    SMSS_BOOTSTRAP_MANIFEST.image()
}

pub(crate) fn hosted_bootstrap_load_specs() -> [HostedBootstrapLoadSpec; HOSTED_BOOTSTRAP_LOAD_COUNT]
{
    core::array::from_fn(|i| HOSTED_BOOTSTRAP_MANIFEST[i].load_spec())
}

pub(crate) fn register_loaded_hosted_image(
    catalog: &mut nt_exe_image::OwnedHostedImageCatalog<8>,
    image: nt_exe_image::OwnedHostedProcessImage,
    runtime: HostedProcessRuntime,
    loaded: bool,
) -> Result<(), nt_exe_image::HostedImageRegistrationError> {
    if loaded {
        catalog.register(image)?;
        register_hosted_process_runtime(runtime)
            .expect("hosted process runtime layout must register once when image is loaded");
    }
    Ok(())
}
