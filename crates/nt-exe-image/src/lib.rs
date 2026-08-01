//! Pure executable-image identity and spawn-state tracking for hosted NT processes.
//!
//! NT handles are process-local, so every lookup is keyed by `(owner_pi, handle)`. The effectful
//! executive owns PE bytes, seL4 caps, EPROCESS objects, and publication; this table only validates
//! the ordered `NtOpenFile -> NtCreateSection -> NtCreateProcessEx -> publish` decisions.

#![no_std]

pub const MAX_EXE_LEAF: usize = 64;
pub const SMSS_TOP_BADGE: u64 = 0;
pub const CSRSS_TOP_BADGE: u64 = 2;
pub const WINLOGON_TOP_BADGE: u64 = 4;
pub const SERVICES_TOP_BADGE: u64 = 6;
pub const LSASS_TOP_BADGE: u64 = 8;
pub const USERINIT_TOP_BADGE: u64 = 27;
pub const EXPLORER_TOP_BADGE: u64 = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageMetadata {
    pub pool_va: u64,
    pub file_size: u64,
    pub image_size: u64,
    pub entry_rva: u32,
    pub subsystem: u16,
    pub subsystem_major: u16,
    pub subsystem_minor: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageState {
    Empty,
    Opened,
    Sectioned,
    SpawnReserved,
    Published,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    InvalidPath,
    InvalidHandle,
    InvalidMetadata,
    Full,
    HandleCollision,
    NotFound,
    InvalidState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpawnRequest {
    pub slot: usize,
    pub creator_pi: usize,
    pub desired_access: u32,
    pub process_handle_out: u64,
    leaf: [u8; MAX_EXE_LEAF],
    leaf_len: u8,
}

impl SpawnRequest {
    pub fn leaf(&self) -> &[u8] {
        &self.leaf[..self.leaf_len as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedImageRoot {
    System32,
    SystemRoot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedProcessRole {
    NativeSession,
    Win32Subsystem,
    InteractiveLogon,
    NonInteractiveService,
    InteractiveShellBootstrap,
    InteractiveShell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedProcessImage {
    pub pi: usize,
    pub top_badge: u64,
    pub leaf: &'static [u8],
    pub process_name: &'static str,
    pub role: HostedProcessRole,
    pub nt_image_path: &'static [u8],
    pub command_line: &'static [u8],
    pub image_root: HostedImageRoot,
    pub probe_fragment: &'static [u8],
}

pub const HOSTED_PROCESS_IMAGES: &[HostedProcessImage] = &[
    HostedProcessImage {
        pi: 0,
        top_badge: SMSS_TOP_BADGE,
        leaf: b"smss.exe",
        process_name: "smss.exe",
        role: HostedProcessRole::NativeSession,
        nt_image_path: b"\\SystemRoot\\System32\\smss.exe",
        command_line: b"smss.exe",
        image_root: HostedImageRoot::System32,
        probe_fragment: b"",
    },
    HostedProcessImage {
        pi: 1,
        top_badge: CSRSS_TOP_BADGE,
        leaf: b"csrss.exe",
        process_name: "csrss.exe",
        role: HostedProcessRole::Win32Subsystem,
        nt_image_path: b"\\SystemRoot\\System32\\csrss.exe",
        command_line: b"csrss.exe ObjectDirectory=\\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16",
        image_root: HostedImageRoot::System32,
        probe_fragment: b"csrss",
    },
    HostedProcessImage {
        pi: 2,
        top_badge: WINLOGON_TOP_BADGE,
        leaf: b"winlogon.exe",
        process_name: "winlogon.exe",
        role: HostedProcessRole::InteractiveLogon,
        nt_image_path: b"\\SystemRoot\\System32\\winlogon.exe",
        command_line: b"winlogon.exe",
        image_root: HostedImageRoot::System32,
        probe_fragment: b"winlogon",
    },
    HostedProcessImage {
        pi: 3,
        top_badge: SERVICES_TOP_BADGE,
        leaf: b"services.exe",
        process_name: "services.exe",
        role: HostedProcessRole::NonInteractiveService,
        nt_image_path: b"\\SystemRoot\\System32\\services.exe",
        command_line: b"services.exe",
        image_root: HostedImageRoot::System32,
        probe_fragment: b"services",
    },
    HostedProcessImage {
        pi: 4,
        top_badge: LSASS_TOP_BADGE,
        leaf: b"lsass.exe",
        process_name: "lsass.exe",
        role: HostedProcessRole::NonInteractiveService,
        nt_image_path: b"\\SystemRoot\\System32\\lsass.exe",
        command_line: b"lsass.exe",
        image_root: HostedImageRoot::System32,
        probe_fragment: b"lsass",
    },
    HostedProcessImage {
        pi: 5,
        top_badge: USERINIT_TOP_BADGE,
        leaf: b"userinit.exe",
        process_name: "userinit.exe",
        role: HostedProcessRole::InteractiveShellBootstrap,
        nt_image_path: b"\\SystemRoot\\System32\\userinit.exe",
        command_line: b"userinit.exe",
        image_root: HostedImageRoot::System32,
        probe_fragment: b"userinit",
    },
    HostedProcessImage {
        pi: 6,
        top_badge: EXPLORER_TOP_BADGE,
        leaf: b"explorer.exe",
        process_name: "explorer.exe",
        role: HostedProcessRole::InteractiveShell,
        nt_image_path: b"\\SystemRoot\\explorer.exe",
        command_line: b"explorer.exe",
        image_root: HostedImageRoot::SystemRoot,
        probe_fragment: b"explorer",
    },
];

pub fn hosted_image_for_pi(pi: usize) -> Option<&'static HostedProcessImage> {
    HOSTED_PROCESS_IMAGES.iter().find(|image| image.pi == pi)
}

pub fn hosted_image_for_leaf(leaf: &[u8]) -> Option<&'static HostedProcessImage> {
    HOSTED_PROCESS_IMAGES
        .iter()
        .find(|image| eq_ascii_case(image.leaf, leaf))
}

pub fn hosted_image_for_path(path: &[u8]) -> Option<&'static HostedProcessImage> {
    hosted_image_for_leaf(canonical_exe_leaf(path)?)
}

pub fn hosted_image_for_top_badge(top_badge: u64) -> Option<&'static HostedProcessImage> {
    HOSTED_PROCESS_IMAGES
        .iter()
        .find(|image| image.top_badge == top_badge)
}

pub fn hosted_process_name_for_pi(pi: usize) -> Option<&'static str> {
    hosted_image_for_pi(pi).map(|image| image.process_name)
}

pub fn hosted_top_badge_for_pi(pi: usize) -> Option<u64> {
    hosted_image_for_pi(pi).map(|image| image.top_badge)
}

pub fn hosted_pi_for_leaf(leaf: &[u8]) -> Option<usize> {
    hosted_image_for_leaf(leaf).map(|image| image.pi)
}

pub fn hosted_process_role_for_path(path: &[u8]) -> Option<HostedProcessRole> {
    hosted_image_for_path(path).map(|image| image.role)
}

pub fn hosted_path_is_noninteractive_service(path: &[u8]) -> bool {
    hosted_process_role_for_path(path) == Some(HostedProcessRole::NonInteractiveService)
}

pub fn hosted_pi_for_top_badge(top_badge: u64) -> Option<usize> {
    hosted_image_for_top_badge(top_badge).map(|image| image.pi)
}

pub fn hosted_spawn_allowed(_creator_pi: usize, leaf: &[u8]) -> bool {
    hosted_image_for_leaf(leaf).is_some()
}

pub fn hosted_probe_image(folded_path: &[u8], is_sxs: bool) -> Option<&'static HostedProcessImage> {
    if is_sxs {
        return None;
    }
    HOSTED_PROCESS_IMAGES
        .iter()
        .filter(|image| !image.probe_fragment.is_empty())
        .find(|image| contains_ascii_case(folded_path, image.probe_fragment))
}

pub fn hosted_probe_leaf(folded_path: &[u8], is_sxs: bool) -> Option<&'static [u8]> {
    hosted_probe_image(folded_path, is_sxs).map(|image| image.leaf)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseOutcome {
    NotFound,
    Retained(usize),
    Released(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageSlot {
    leaf: [u8; MAX_EXE_LEAF],
    leaf_len: u8,
    pub owner_pi: usize,
    pub metadata: ImageMetadata,
    pub file_handle: u64,
    pub section_handle: u64,
    pub desired_access: u32,
    pub process_handle_out: u64,
    pub process_handle: u64,
    pub state: ImageState,
}

const EMPTY_METADATA: ImageMetadata = ImageMetadata {
    pool_va: 0,
    file_size: 0,
    image_size: 0,
    entry_rva: 0,
    subsystem: 0,
    subsystem_major: 0,
    subsystem_minor: 0,
};

const EMPTY_SLOT: ImageSlot = ImageSlot {
    leaf: [0; MAX_EXE_LEAF],
    leaf_len: 0,
    owner_pi: 0,
    metadata: EMPTY_METADATA,
    file_handle: 0,
    section_handle: 0,
    desired_access: 0,
    process_handle_out: 0,
    process_handle: 0,
    state: ImageState::Empty,
};

impl ImageSlot {
    pub fn leaf(&self) -> &[u8] {
        &self.leaf[..self.leaf_len as usize]
    }

    pub fn spawn_request(&self, slot: usize) -> Option<SpawnRequest> {
        if self.state != ImageState::SpawnReserved {
            return None;
        }
        let mut leaf = [0u8; MAX_EXE_LEAF];
        leaf[..self.leaf_len as usize].copy_from_slice(self.leaf());
        Some(SpawnRequest {
            slot,
            creator_pi: self.owner_pi,
            desired_access: self.desired_access,
            process_handle_out: self.process_handle_out,
            leaf,
            leaf_len: self.leaf_len,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageTable<const N: usize> {
    slots: [ImageSlot; N],
}

impl<const N: usize> Default for ImageTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ImageTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [EMPTY_SLOT; N],
        }
    }

    pub fn get(&self, slot: usize) -> Option<&ImageSlot> {
        self.slots
            .get(slot)
            .filter(|slot| slot.state != ImageState::Empty)
    }

    pub fn active_len(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.state != ImageState::Empty)
            .count()
    }

    pub fn open(
        &mut self,
        owner_pi: usize,
        path: &[u8],
        file_handle: u64,
        metadata: ImageMetadata,
    ) -> Result<usize, ImageError> {
        if file_handle == 0 {
            return Err(ImageError::InvalidHandle);
        }
        if metadata.pool_va == 0 || metadata.file_size == 0 || metadata.image_size == 0 {
            return Err(ImageError::InvalidMetadata);
        }
        let leaf = canonical_exe_leaf(path).ok_or(ImageError::InvalidPath)?;
        if let Some((index, existing)) = self.slots.iter().enumerate().find(|(_, slot)| {
            slot.state != ImageState::Empty
                && slot.owner_pi == owner_pi
                && (slot.file_handle == file_handle || slot.section_handle == file_handle)
        }) {
            return if existing.file_handle == file_handle
                && eq_ascii_case(existing.leaf(), leaf)
                && existing.metadata == metadata
            {
                Ok(index)
            } else {
                Err(ImageError::HandleCollision)
            };
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.state == ImageState::Empty)
            .ok_or(ImageError::Full)?;
        let mut slot = EMPTY_SLOT;
        slot.leaf[..leaf.len()].copy_from_slice(leaf);
        for byte in &mut slot.leaf[..leaf.len()] {
            *byte = byte.to_ascii_lowercase();
        }
        slot.leaf_len = leaf.len() as u8;
        slot.owner_pi = owner_pi;
        slot.metadata = metadata;
        slot.file_handle = file_handle;
        slot.state = ImageState::Opened;
        self.slots[index] = slot;
        Ok(index)
    }

    pub fn index_for_file(&self, owner_pi: usize, file_handle: u64) -> Option<usize> {
        (file_handle != 0).then_some(())?;
        self.slots.iter().position(|slot| {
            slot.state != ImageState::Empty
                && slot.owner_pi == owner_pi
                && slot.file_handle == file_handle
        })
    }

    pub fn index_for_section(&self, owner_pi: usize, section_handle: u64) -> Option<usize> {
        (section_handle != 0).then_some(())?;
        self.slots.iter().position(|slot| {
            slot.state != ImageState::Empty
                && slot.owner_pi == owner_pi
                && slot.section_handle == section_handle
        })
    }

    pub fn create_section(
        &mut self,
        owner_pi: usize,
        file_handle: u64,
        section_handle: u64,
    ) -> Result<usize, ImageError> {
        if section_handle == 0 {
            return Err(ImageError::InvalidHandle);
        }
        let index = self
            .index_for_file(owner_pi, file_handle)
            .ok_or(ImageError::NotFound)?;
        if self.slots[index].state == ImageState::Sectioned
            && self.slots[index].section_handle == section_handle
        {
            return Ok(index);
        }
        if self.index_for_section(owner_pi, section_handle).is_some() {
            return Err(ImageError::HandleCollision);
        }
        let slot = &mut self.slots[index];
        match slot.state {
            ImageState::Opened => {
                slot.section_handle = section_handle;
                slot.state = ImageState::Sectioned;
                Ok(index)
            }
            ImageState::Sectioned if slot.section_handle == section_handle => Ok(index),
            _ => Err(ImageError::InvalidState),
        }
    }

    pub fn reserve_spawn(
        &mut self,
        owner_pi: usize,
        section_handle: u64,
        desired_access: u32,
        process_handle_out: u64,
    ) -> Result<SpawnRequest, ImageError> {
        if process_handle_out == 0 {
            return Err(ImageError::InvalidHandle);
        }
        let index = self
            .index_for_section(owner_pi, section_handle)
            .ok_or(ImageError::NotFound)?;
        let slot = &mut self.slots[index];
        match slot.state {
            ImageState::Sectioned => {
                slot.desired_access = desired_access;
                slot.process_handle_out = process_handle_out;
                slot.state = ImageState::SpawnReserved;
            }
            ImageState::SpawnReserved
                if slot.desired_access == desired_access
                    && slot.process_handle_out == process_handle_out => {}
            _ => return Err(ImageError::InvalidState),
        }
        Ok(slot.spawn_request(index).unwrap())
    }

    pub fn rollback_spawn(&mut self, request: SpawnRequest) -> Result<(), ImageError> {
        let slot = self
            .slots
            .get_mut(request.slot)
            .ok_or(ImageError::NotFound)?;
        if slot.spawn_request(request.slot) != Some(request) {
            return Err(ImageError::InvalidState);
        }
        slot.desired_access = 0;
        slot.process_handle_out = 0;
        slot.state = ImageState::Sectioned;
        Ok(())
    }

    pub fn publish(
        &mut self,
        request: SpawnRequest,
        process_handle: u64,
    ) -> Result<(), ImageError> {
        if process_handle == 0 {
            return Err(ImageError::InvalidHandle);
        }
        let slot = self
            .slots
            .get_mut(request.slot)
            .ok_or(ImageError::NotFound)?;
        if slot.spawn_request(request.slot) != Some(request) {
            return Err(ImageError::InvalidState);
        }
        slot.process_handle = process_handle;
        slot.state = ImageState::Published;
        Ok(())
    }

    pub fn close(&mut self, owner_pi: usize, handle: u64) -> CloseOutcome {
        if handle == 0 {
            return CloseOutcome::NotFound;
        }
        let Some(index) = self.slots.iter().position(|slot| {
            slot.state != ImageState::Empty
                && slot.owner_pi == owner_pi
                && (slot.file_handle == handle || slot.section_handle == handle)
        }) else {
            return CloseOutcome::NotFound;
        };
        let slot = &mut self.slots[index];
        if slot.file_handle == handle {
            slot.file_handle = 0;
        }
        if slot.section_handle == handle {
            slot.section_handle = 0;
        }
        if slot.file_handle == 0
            && slot.section_handle == 0
            && !matches!(
                slot.state,
                ImageState::SpawnReserved | ImageState::Published
            )
        {
            *slot = EMPTY_SLOT;
            CloseOutcome::Released(index)
        } else {
            CloseOutcome::Retained(index)
        }
    }
}

/// Return the exact final `.exe` component of a folded or mixed-case NT/DOS path.
///
/// SxS probes and malformed/overlong leaves are rejected. Matching is component-exact: `userinit2`
/// cannot alias `userinit`, and a directory containing `.exe` is irrelevant.
pub fn canonical_exe_leaf(path: &[u8]) -> Option<&[u8]> {
    if path.is_empty()
        || contains_ascii_case(path, b".local")
        || contains_ascii_case(path, b".manifest")
        || contains_ascii_case(path, b".config")
    {
        return None;
    }
    let start = path
        .iter()
        .rposition(|byte| matches!(byte, b'\\' | b'/'))
        .map_or(0, |position| position + 1);
    let leaf = &path[start..];
    if leaf.len() <= 4 || leaf.len() > MAX_EXE_LEAF || !ends_with_ascii_case(leaf, b".exe") {
        return None;
    }
    if !leaf
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return None;
    }
    Some(leaf)
}

fn contains_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn ends_with_ascii_case(value: &[u8], suffix: &[u8]) -> bool {
    value.len() >= suffix.len()
        && value[value.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn eq_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

#[cfg(test)]
mod tests {
    use super::*;

    const META: ImageMetadata = ImageMetadata {
        pool_va: 0x1000_1500_0000,
        file_size: 0x28_000,
        image_size: 0x50_000,
        entry_rva: 0x1234,
        subsystem: 2,
        subsystem_major: 5,
        subsystem_minor: 1,
    };

    #[test]
    fn exact_leaf_resolution_accepts_nt_dos_and_systemroot_paths() {
        assert_eq!(
            canonical_exe_leaf(br"\??\C:\Windows\System32\USERINIT.EXE"),
            Some(b"USERINIT.EXE" as &[u8])
        );
        assert_eq!(
            canonical_exe_leaf(br"\SystemRoot/System32/services.exe"),
            Some(b"services.exe" as &[u8])
        );
        assert_eq!(
            canonical_exe_leaf(b"userinit2.exe"),
            Some(b"userinit2.exe" as &[u8])
        );
    }

    #[test]
    fn malformed_and_sxs_paths_are_rejected() {
        assert_eq!(canonical_exe_leaf(b"userinit.dll"), None);
        assert_eq!(canonical_exe_leaf(br"x\userinit.exe.local"), None);
        assert_eq!(canonical_exe_leaf(br"x\userinit.exe.manifest"), None);
        assert_eq!(canonical_exe_leaf(br"x\bad name.exe"), None);
        assert_eq!(canonical_exe_leaf(br"x\"), None);
    }

    #[test]
    fn hosted_catalog_resolves_current_boot_images() {
        assert_eq!(hosted_process_name_for_pi(0), Some("smss.exe"));
        assert_eq!(hosted_process_name_for_pi(6), Some("explorer.exe"));
        assert_eq!(hosted_top_badge_for_pi(0), Some(SMSS_TOP_BADGE));
        assert_eq!(hosted_top_badge_for_pi(6), Some(EXPLORER_TOP_BADGE));
        assert_eq!(hosted_pi_for_leaf(b"SERVICES.EXE"), Some(3));
        assert_eq!(hosted_pi_for_top_badge(SERVICES_TOP_BADGE), Some(3));
        assert_eq!(hosted_pi_for_leaf(b"userinit2.exe"), None);
        assert_eq!(hosted_pi_for_top_badge(13), None);
    }

    #[test]
    fn hosted_catalog_classifies_noninteractive_service_images_by_path() {
        assert_eq!(
            hosted_process_role_for_path(br"\SystemRoot\System32\SERVICES.EXE"),
            Some(HostedProcessRole::NonInteractiveService)
        );
        assert_eq!(
            hosted_process_role_for_path(br"\??\C:\ReactOS\System32\lsass.exe"),
            Some(HostedProcessRole::NonInteractiveService)
        );
        assert!(hosted_path_is_noninteractive_service(b"services.exe"));
        assert!(hosted_path_is_noninteractive_service(b"LSASS.EXE"));
        assert!(!hosted_path_is_noninteractive_service(b"winlogon.exe"));
        assert!(!hosted_path_is_noninteractive_service(b"explorer.exe"));
        assert!(!hosted_path_is_noninteractive_service(
            b"service-helper.exe"
        ));
    }

    #[test]
    fn hosted_catalog_records_boot_paths_and_locations() {
        let services = hosted_image_for_pi(3).unwrap();
        assert_eq!(services.top_badge, SERVICES_TOP_BADGE);
        assert_eq!(services.role, HostedProcessRole::NonInteractiveService);
        assert_eq!(
            services.nt_image_path,
            b"\\SystemRoot\\System32\\services.exe"
        );
        assert_eq!(services.command_line, b"services.exe");
        assert_eq!(services.image_root, HostedImageRoot::System32);

        let explorer = hosted_image_for_leaf(b"EXPLORER.EXE").unwrap();
        assert_eq!(explorer.role, HostedProcessRole::InteractiveShell);
        assert_eq!(explorer.nt_image_path, b"\\SystemRoot\\explorer.exe");
        assert_eq!(explorer.command_line, b"explorer.exe");
        assert_eq!(explorer.image_root, HostedImageRoot::SystemRoot);
    }

    #[test]
    fn hosted_probe_classifier_preserves_boot_quirks() {
        assert_eq!(
            hosted_probe_leaf(br"\??\C:\Windowsservices.exe", false),
            Some(b"services.exe" as &[u8])
        );
        assert_eq!(
            hosted_probe_leaf(br"\SystemRoot\explorer.exe", false),
            Some(b"explorer.exe" as &[u8])
        );
        assert_eq!(
            hosted_probe_leaf(br"\SystemRoot\System32\smss.exe", false),
            None
        );
        assert_eq!(
            hosted_probe_leaf(br"\SystemRoot\System32\lsasrv.dll", false),
            None
        );
        assert_eq!(
            hosted_probe_leaf(br"\SystemRoot\System32\userinit.exe.manifest", true),
            None
        );
    }

    #[test]
    fn hosted_catalog_is_not_parent_policy() {
        assert!(hosted_spawn_allowed(0, b"csrss.exe"));
        assert!(hosted_spawn_allowed(0, b"winlogon.exe"));
        assert!(hosted_spawn_allowed(2, b"services.exe"));
        assert!(hosted_spawn_allowed(2, b"lsass.exe"));
        assert!(hosted_spawn_allowed(2, b"userinit.exe"));
        assert!(hosted_spawn_allowed(5, b"explorer.exe"));
        assert!(hosted_spawn_allowed(2, b"explorer.exe"));
        assert!(hosted_spawn_allowed(5, b"userinit.exe"));
        assert!(hosted_spawn_allowed(0, b"explorer.exe"));
        assert!(!hosted_spawn_allowed(2, b"calc.exe"));
    }

    #[test]
    fn owner_local_handle_collisions_do_not_cross_processes() {
        let mut table = ImageTable::<4>::new();
        let a = table.open(2, b"services.exe", 0x44, META).unwrap();
        let b = table.open(4, b"userinit.exe", 0x44, META).unwrap();
        assert_ne!(a, b);
        assert_eq!(table.index_for_file(2, 0x44), Some(a));
        assert_eq!(table.index_for_file(4, 0x44), Some(b));
        assert_eq!(
            table.open(2, b"other.exe", 0x44, META),
            Err(ImageError::HandleCollision)
        );
    }

    #[test]
    fn ordered_lifecycle_is_idempotent_and_publish_is_transactional() {
        let mut table = ImageTable::<2>::new();
        let slot = table.open(2, b"userinit.exe", 0x40, META).unwrap();
        assert_eq!(table.create_section(2, 0x40, 0x44), Ok(slot));
        assert_eq!(table.create_section(2, 0x40, 0x44), Ok(slot));
        let request = table.reserve_spawn(2, 0x44, 0x1fffff, 0x1000).unwrap();
        assert_eq!(request.leaf(), b"userinit.exe");
        assert_eq!(table.reserve_spawn(2, 0x44, 0x1fffff, 0x1000), Ok(request));
        assert_eq!(table.get(slot).unwrap().state, ImageState::SpawnReserved);
        assert_eq!(table.publish(request, 0), Err(ImageError::InvalidHandle));
        assert_eq!(table.get(slot).unwrap().state, ImageState::SpawnReserved);
        table.publish(request, 0x48).unwrap();
        assert_eq!(table.get(slot).unwrap().state, ImageState::Published);
        assert_eq!(table.get(slot).unwrap().process_handle, 0x48);
    }

    #[test]
    fn failed_spawn_can_roll_back_without_losing_the_section() {
        let mut table = ImageTable::<1>::new();
        let slot = table.open(2, b"userinit.exe", 0x40, META).unwrap();
        table.create_section(2, 0x40, 0x44).unwrap();
        let request = table.reserve_spawn(2, 0x44, 1, 0x1000).unwrap();
        table.rollback_spawn(request).unwrap();
        assert_eq!(table.get(slot).unwrap().state, ImageState::Sectioned);
        assert_eq!(table.index_for_section(2, 0x44), Some(slot));
    }

    #[test]
    fn close_removes_stale_handle_bindings_and_releases_unpublished_slots() {
        let mut table = ImageTable::<1>::new();
        let slot = table.open(2, b"userinit.exe", 0x40, META).unwrap();
        table.create_section(2, 0x40, 0x44).unwrap();
        assert_eq!(table.close(2, 0x40), CloseOutcome::Retained(slot));
        assert_eq!(table.index_for_file(2, 0x40), None);
        assert_eq!(table.close(2, 0x44), CloseOutcome::Released(slot));
        assert_eq!(table.active_len(), 0);
        assert_eq!(table.open(2, b"explorer.exe", 0x40, META), Ok(slot));
    }

    #[test]
    fn fixed_capacity_refuses_without_mutating_existing_slots() {
        let mut table = ImageTable::<1>::new();
        table.open(2, b"services.exe", 0x40, META).unwrap();
        assert_eq!(
            table.open(2, b"lsass.exe", 0x44, META),
            Err(ImageError::Full)
        );
        assert_eq!(table.active_len(), 1);
        assert_eq!(table.get(0).unwrap().leaf(), b"services.exe");
    }
}
