//! Bootstrap hosted-process image policy.
//!
//! This is the remaining executive-owned seed while the boot loader does not yet hand us a dynamic
//! initial native-image manifest. Runtime handlers consume catalogs populated here; they do not
//! reach back into the historical descriptor table.
#![allow(clippy::all)]

use crate::{
    hosted_process_runtime_for_pi, register_hosted_process_runtime_for_image,
    HOSTED_PROCESS_IMAGE_CAP,
};

#[derive(Clone, Copy)]
pub(crate) struct HostedBootstrapLoadSpec {
    pub(crate) disk_path: &'static [u8],
    pub(crate) stem: &'static [u8],
    pub(crate) image: nt_exe_image::HostedProcessImageRef<'static>,
}

#[derive(Clone, Copy)]
struct HostedBootstrapManifestEntry {
    disk_path: &'static [u8],
    stem: &'static [u8],
    top_badge: u64,
    leaf: &'static [u8],
    role: nt_exe_image::HostedProcessRole,
    nt_image_path: &'static [u8],
    command_line: &'static [u8],
    image_root: nt_exe_image::HostedImageRoot,
    probe_fragment: &'static [u8],
}

impl HostedBootstrapManifestEntry {
    fn image(self, pi: usize) -> nt_exe_image::HostedProcessImageRef<'static> {
        nt_exe_image::HostedProcessImageRef {
            pi,
            top_badge: self.top_badge,
            generation: 1,
            leaf: self.leaf,
            process_name: core::str::from_utf8(self.leaf)
                .expect("hosted bootstrap image manifest leaf is ASCII"),
            role: self.role,
            nt_image_path: self.nt_image_path,
            command_line: self.command_line,
            image_root: self.image_root,
            probe_fragment: self.probe_fragment,
        }
    }

    fn load_spec(self, pi: usize) -> HostedBootstrapLoadSpec {
        HostedBootstrapLoadSpec {
            disk_path: self.disk_path,
            stem: self.stem,
            image: self.image(pi),
        }
    }
}

const SMSS_BOOTSTRAP_MANIFEST: HostedBootstrapManifestEntry = HostedBootstrapManifestEntry {
    disk_path: b"reactos\\system32\\smss.exe",
    stem: b"smss.exe",
    top_badge: nt_exe_image::SMSS_TOP_BADGE,
    leaf: b"smss.exe",
    role: nt_exe_image::HostedProcessRole::NativeSession,
    nt_image_path: b"\\SystemRoot\\System32\\smss.exe",
    command_line: b"smss.exe",
    image_root: nt_exe_image::HostedImageRoot::System32,
    probe_fragment: b"",
};

const HOSTED_BOOTSTRAP_MANIFEST: [HostedBootstrapManifestEntry; 6] = [
    HostedBootstrapManifestEntry {
        disk_path: b"reactos\\system32\\csrss.exe",
        stem: b"csrss.exe",
        top_badge: nt_exe_image::CSRSS_TOP_BADGE,
        leaf: b"csrss.exe",
        role: nt_exe_image::HostedProcessRole::Win32Subsystem,
        nt_image_path: b"\\SystemRoot\\System32\\csrss.exe",
        command_line: b"csrss.exe ObjectDirectory=\\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"csrss",
    },
    HostedBootstrapManifestEntry {
        disk_path: b"reactos\\system32\\winlogon.exe",
        stem: b"winlogon.exe",
        top_badge: nt_exe_image::WINLOGON_TOP_BADGE,
        leaf: b"winlogon.exe",
        role: nt_exe_image::HostedProcessRole::InteractiveLogon,
        nt_image_path: b"\\SystemRoot\\System32\\winlogon.exe",
        command_line: b"winlogon.exe",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"winlogon",
    },
    HostedBootstrapManifestEntry {
        disk_path: b"reactos\\system32\\services.exe",
        stem: b"services.exe",
        top_badge: nt_exe_image::SERVICES_TOP_BADGE,
        leaf: b"services.exe",
        role: nt_exe_image::HostedProcessRole::ServiceControlManager,
        nt_image_path: b"\\SystemRoot\\System32\\services.exe",
        command_line: b"services.exe",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"services",
    },
    HostedBootstrapManifestEntry {
        disk_path: b"reactos\\system32\\lsass.exe",
        stem: b"lsass.exe",
        top_badge: nt_exe_image::LSASS_TOP_BADGE,
        leaf: b"lsass.exe",
        role: nt_exe_image::HostedProcessRole::LocalSecurityAuthority,
        nt_image_path: b"\\SystemRoot\\System32\\lsass.exe",
        command_line: b"lsass.exe",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"lsass",
    },
    HostedBootstrapManifestEntry {
        disk_path: br"reactos\system32\userinit.exe",
        stem: b"userinit.exe",
        top_badge: nt_exe_image::USERINIT_TOP_BADGE,
        leaf: b"userinit.exe",
        role: nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
        nt_image_path: b"\\SystemRoot\\System32\\userinit.exe",
        command_line: b"userinit.exe",
        image_root: nt_exe_image::HostedImageRoot::System32,
        probe_fragment: b"userinit",
    },
    HostedBootstrapManifestEntry {
        disk_path: br"reactos\explorer.exe",
        stem: b"explorer.exe",
        top_badge: nt_exe_image::EXPLORER_TOP_BADGE,
        leaf: b"explorer.exe",
        role: nt_exe_image::HostedProcessRole::InteractiveShell,
        nt_image_path: b"\\SystemRoot\\explorer.exe",
        command_line: b"explorer.exe",
        image_root: nt_exe_image::HostedImageRoot::SystemRoot,
        probe_fragment: b"explorer",
    },
];

pub(crate) const HOSTED_BOOTSTRAP_LOAD_COUNT: usize = HOSTED_BOOTSTRAP_MANIFEST.len();
pub(crate) const HOSTED_PROCESS_MANAGER_SEED_COUNT: usize = 3;

pub(crate) fn smss_bootstrap_image() -> nt_exe_image::HostedProcessImageRef<'static> {
    SMSS_BOOTSTRAP_MANIFEST.image(0)
}

pub(crate) fn hosted_process_manager_seed_image(
    index: usize,
) -> Option<nt_exe_image::HostedProcessImageRef<'static>> {
    if index == 0 {
        Some(smss_bootstrap_image())
    } else {
        HOSTED_BOOTSTRAP_MANIFEST
            .get(index - 1)
            .copied()
            .map(|entry| entry.image(index))
    }
    .filter(|image| index < HOSTED_PROCESS_MANAGER_SEED_COUNT && image.pi == index)
}

pub(crate) fn hosted_bootstrap_load_spec(index: usize) -> Option<HostedBootstrapLoadSpec> {
    HOSTED_BOOTSTRAP_MANIFEST
        .get(index)
        .copied()
        .map(|entry| entry.load_spec(index + 1))
}

pub(crate) fn register_loaded_hosted_image(
    catalog: &mut nt_exe_image::OwnedHostedImageCatalog<HOSTED_PROCESS_IMAGE_CAP>,
    image: nt_exe_image::HostedProcessImageRef<'_>,
    loaded: bool,
) -> Result<(), nt_exe_image::HostedImageRegistrationError> {
    if loaded {
        catalog.register_ref(image)?;
        if hosted_process_runtime_for_pi(image.pi).is_none() {
            register_hosted_process_runtime_for_image(image)
                .expect("hosted process runtime layout must register once when image is loaded");
        }
    }
    Ok(())
}
