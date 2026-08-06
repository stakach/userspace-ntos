//! Pure executable-image identity and spawn-state tracking for hosted NT processes.
//!
//! NT handles are process-local, so every lookup is keyed by `(owner_pi, handle)`. The effectful
//! executive owns PE bytes, seL4 caps, EPROCESS objects, and publication; this table only validates
//! the ordered `NtOpenFile -> NtCreateSection -> NtCreateProcessEx -> publish` decisions.

#![no_std]

pub const MAX_EXE_LEAF: usize = 64;
pub const MAX_NT_IMAGE_PATH: usize = 192;
pub const MAX_COMMAND_LINE: usize = 384;
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
    pub target: Option<SpawnTarget>,
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

impl HostedProcessRole {
    pub fn uses_win32_client_gdi(self) -> bool {
        matches!(
            self,
            Self::Win32Subsystem
                | Self::InteractiveLogon
                | Self::NonInteractiveService
                | Self::InteractiveShellBootstrap
                | Self::InteractiveShell
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpawnTarget {
    pub pi: usize,
    pub top_badge: u64,
    pub role: HostedProcessRole,
}

impl SpawnTarget {
    pub fn from_image(image: HostedProcessImageRef<'_>) -> Self {
        Self {
            pi: image.pi,
            top_badge: image.top_badge,
            role: image.role,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedProcessImageRef<'a> {
    pub pi: usize,
    pub top_badge: u64,
    pub leaf: &'a [u8],
    pub process_name: &'a str,
    pub role: HostedProcessRole,
    pub nt_image_path: &'a [u8],
    pub command_line: &'a [u8],
    pub image_root: HostedImageRoot,
    pub probe_fragment: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedImageRegistrationError {
    InvalidPath,
    InvalidProcessName,
    FieldTooLong,
    DuplicatePi,
    DuplicateTopBadge,
    DuplicateLeaf,
    Full,
}

fn validate_hosted_image_ref(
    image: HostedProcessImageRef<'_>,
) -> Result<(), HostedImageRegistrationError> {
    let Some(leaf) = canonical_exe_leaf(image.leaf) else {
        return Err(HostedImageRegistrationError::InvalidPath);
    };
    let Some(path_leaf) = canonical_exe_leaf(image.nt_image_path) else {
        return Err(HostedImageRegistrationError::InvalidPath);
    };
    if image.top_badge >= 64
        || image.leaf.is_empty()
        || image.leaf.len() > MAX_EXE_LEAF
        || image.nt_image_path.is_empty()
        || image.command_line.is_empty()
        || !eq_ascii_case(leaf, image.leaf)
        || !eq_ascii_case(path_leaf, image.leaf)
    {
        return Err(HostedImageRegistrationError::InvalidPath);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedImageCatalog<'a, const N: usize> {
    entries: [Option<HostedProcessImageRef<'a>>; N],
}

impl<'a, const N: usize> Default for HostedImageCatalog<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, const N: usize> HostedImageCatalog<'a, N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn register(
        &mut self,
        image: HostedProcessImageRef<'a>,
    ) -> Result<usize, HostedImageRegistrationError> {
        validate_hosted_image_ref(image)?;
        if self.get_by_pi(image.pi).is_some() {
            return Err(HostedImageRegistrationError::DuplicatePi);
        }
        if self.get_by_top_badge(image.top_badge).is_some() {
            return Err(HostedImageRegistrationError::DuplicateTopBadge);
        }
        if self.get_by_leaf(image.leaf).is_some() {
            return Err(HostedImageRegistrationError::DuplicateLeaf);
        }
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(HostedImageRegistrationError::Full)?;
        self.entries[index] = Some(image);
        Ok(index)
    }

    pub fn count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    pub fn mask(&self) -> u64 {
        self.entries
            .iter()
            .filter_map(|entry| entry.map(|image| image.pi))
            .filter(|&pi| pi < 64)
            .fold(0, |mask, pi| mask | (1u64 << pi))
    }

    pub fn get_by_pi(&self, pi: usize) -> Option<HostedProcessImageRef<'a>> {
        self.entries
            .iter()
            .copied()
            .flatten()
            .find(|image| image.pi == pi)
    }

    pub fn get_by_leaf(&self, leaf: &[u8]) -> Option<HostedProcessImageRef<'a>> {
        self.entries
            .iter()
            .copied()
            .flatten()
            .find(|image| eq_ascii_case(image.leaf, leaf))
    }

    pub fn get_by_path(&self, path: &[u8]) -> Option<HostedProcessImageRef<'a>> {
        self.get_by_leaf(canonical_exe_leaf(path)?)
    }

    pub fn get_by_top_badge(&self, top_badge: u64) -> Option<HostedProcessImageRef<'a>> {
        self.entries
            .iter()
            .copied()
            .flatten()
            .find(|image| image.top_badge == top_badge)
    }

    pub fn process_name_for_pi(&self, pi: usize) -> Option<&'a str> {
        self.get_by_pi(pi).map(|image| image.process_name)
    }

    pub fn top_badge_for_pi(&self, pi: usize) -> Option<u64> {
        self.get_by_pi(pi).map(|image| image.top_badge)
    }

    pub fn pi_for_leaf(&self, leaf: &[u8]) -> Option<usize> {
        self.get_by_leaf(leaf).map(|image| image.pi)
    }

    pub fn pi_for_top_badge(&self, top_badge: u64) -> Option<usize> {
        self.get_by_top_badge(top_badge).map(|image| image.pi)
    }

    pub fn role_for_path(&self, path: &[u8]) -> Option<HostedProcessRole> {
        self.get_by_path(path).map(|image| image.role)
    }

    pub fn path_is_noninteractive_service(&self, path: &[u8]) -> bool {
        self.role_for_path(path) == Some(HostedProcessRole::NonInteractiveService)
    }

    pub fn probe_image(
        &self,
        folded_path: &[u8],
        is_sxs: bool,
    ) -> Option<HostedProcessImageRef<'a>> {
        if is_sxs {
            return None;
        }
        self.entries
            .iter()
            .copied()
            .flatten()
            .filter(|image| !image.probe_fragment.is_empty())
            .find(|image| contains_ascii_case(folded_path, image.probe_fragment))
    }

    pub fn probe_leaf(&self, folded_path: &[u8], is_sxs: bool) -> Option<&'a [u8]> {
        self.probe_image(folded_path, is_sxs)
            .map(|image| image.leaf)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedBytes<const N: usize> {
    bytes: [u8; N],
    len: u16,
}

impl<const N: usize> FixedBytes<N> {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, HostedImageRegistrationError> {
        let mut fixed = Self::empty();
        fixed.set_from_slice(bytes)?;
        Ok(fixed)
    }

    fn set_from_slice(&mut self, bytes: &[u8]) -> Result<(), HostedImageRegistrationError> {
        if bytes.len() > N || bytes.len() > u16::MAX as usize {
            return Err(HostedImageRegistrationError::FieldTooLong);
        }
        self.bytes = [0; N];
        self.bytes[..bytes.len()].copy_from_slice(bytes);
        self.len = bytes.len() as u16;
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedHostedProcessImage {
    pub pi: usize,
    pub top_badge: u64,
    leaf: FixedBytes<MAX_EXE_LEAF>,
    process_name: FixedBytes<MAX_EXE_LEAF>,
    pub role: HostedProcessRole,
    nt_image_path: FixedBytes<MAX_NT_IMAGE_PATH>,
    command_line: FixedBytes<MAX_COMMAND_LINE>,
    pub image_root: HostedImageRoot,
    probe_fragment: FixedBytes<MAX_EXE_LEAF>,
}

impl OwnedHostedProcessImage {
    const fn empty() -> Self {
        Self {
            pi: 0,
            top_badge: 0,
            leaf: FixedBytes::empty(),
            process_name: FixedBytes::empty(),
            role: HostedProcessRole::NativeSession,
            nt_image_path: FixedBytes::empty(),
            command_line: FixedBytes::empty(),
            image_root: HostedImageRoot::System32,
            probe_fragment: FixedBytes::empty(),
        }
    }

    pub fn new(
        pi: usize,
        top_badge: u64,
        leaf: &[u8],
        process_name: &[u8],
        role: HostedProcessRole,
        nt_image_path: &[u8],
        command_line: &[u8],
        image_root: HostedImageRoot,
        probe_fragment: &[u8],
    ) -> Result<Self, HostedImageRegistrationError> {
        let process_name = core::str::from_utf8(process_name)
            .map_err(|_| HostedImageRegistrationError::InvalidProcessName)?;
        let mut image = Self::empty();
        image.copy_from_ref(HostedProcessImageRef {
            pi,
            top_badge,
            leaf,
            process_name,
            role,
            nt_image_path,
            command_line,
            image_root,
            probe_fragment,
        })?;
        Ok(image)
    }

    fn copy_from_ref(
        &mut self,
        image: HostedProcessImageRef<'_>,
    ) -> Result<(), HostedImageRegistrationError> {
        validate_hosted_image_ref(image)?;
        self.pi = image.pi;
        self.top_badge = image.top_badge;
        self.leaf.set_from_slice(image.leaf)?;
        self.process_name
            .set_from_slice(image.process_name.as_bytes())?;
        self.role = image.role;
        self.nt_image_path.set_from_slice(image.nt_image_path)?;
        self.command_line.set_from_slice(image.command_line)?;
        self.image_root = image.image_root;
        self.probe_fragment.set_from_slice(image.probe_fragment)?;
        Ok(())
    }

    pub fn as_ref(&self) -> HostedProcessImageRef<'_> {
        HostedProcessImageRef {
            pi: self.pi,
            top_badge: self.top_badge,
            leaf: self.leaf.as_slice(),
            process_name: self.process_name_str(),
            role: self.role,
            nt_image_path: self.nt_image_path.as_slice(),
            command_line: self.command_line.as_slice(),
            image_root: self.image_root,
            probe_fragment: self.probe_fragment.as_slice(),
        }
    }

    fn process_name_str(&self) -> &str {
        // SAFETY: `process_name` is private and only populated through `copy_from_ref`, which
        // receives a Rust `&str`, or `empty`, which stores an empty byte string.
        unsafe { core::str::from_utf8_unchecked(self.process_name.as_slice()) }
    }

    pub fn leaf(&self) -> &[u8] {
        self.leaf.as_slice()
    }

    pub fn nt_image_path(&self) -> &[u8] {
        self.nt_image_path.as_slice()
    }

    pub fn command_line(&self) -> &[u8] {
        self.command_line.as_slice()
    }

    pub fn probe_fragment(&self) -> &[u8] {
        self.probe_fragment.as_slice()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedHostedImageCatalog<const N: usize> {
    entries: [OwnedHostedProcessImage; N],
    used: [bool; N],
}

impl<const N: usize> Default for OwnedHostedImageCatalog<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> OwnedHostedImageCatalog<N> {
    pub const fn new() -> Self {
        Self {
            entries: [OwnedHostedProcessImage::empty(); N],
            used: [false; N],
        }
    }

    pub fn clear(&mut self) {
        self.used.fill(false);
    }

    pub fn register(
        &mut self,
        image: OwnedHostedProcessImage,
    ) -> Result<usize, HostedImageRegistrationError> {
        validate_hosted_image_ref(image.as_ref())?;
        if self.get_by_pi(image.pi).is_some() {
            return Err(HostedImageRegistrationError::DuplicatePi);
        }
        if self.get_by_top_badge(image.top_badge).is_some() {
            return Err(HostedImageRegistrationError::DuplicateTopBadge);
        }
        if self.get_by_leaf(image.leaf()).is_some() {
            return Err(HostedImageRegistrationError::DuplicateLeaf);
        }
        let index = self
            .used
            .iter()
            .position(|used| !*used)
            .ok_or(HostedImageRegistrationError::Full)?;
        self.entries[index] = image;
        self.used[index] = true;
        Ok(index)
    }

    pub fn register_ref(
        &mut self,
        image: HostedProcessImageRef<'_>,
    ) -> Result<usize, HostedImageRegistrationError> {
        validate_hosted_image_ref(image)?;
        if self.get_by_pi(image.pi).is_some() {
            return Err(HostedImageRegistrationError::DuplicatePi);
        }
        if self.get_by_top_badge(image.top_badge).is_some() {
            return Err(HostedImageRegistrationError::DuplicateTopBadge);
        }
        if self.get_by_leaf(image.leaf).is_some() {
            return Err(HostedImageRegistrationError::DuplicateLeaf);
        }
        let index = self
            .used
            .iter()
            .position(|used| !*used)
            .ok_or(HostedImageRegistrationError::Full)?;
        self.entries[index].copy_from_ref(image)?;
        self.used[index] = true;
        Ok(index)
    }

    pub fn count(&self) -> usize {
        self.used.iter().filter(|used| **used).count()
    }

    pub fn mask(&self) -> u64 {
        self.entries
            .iter()
            .zip(self.used.iter())
            .filter(|(_, used)| **used)
            .map(|(image, _)| image.pi)
            .filter(|&pi| pi < 64)
            .fold(0, |mask, pi| mask | (1u64 << pi))
    }

    pub fn get_by_pi(&self, pi: usize) -> Option<HostedProcessImageRef<'_>> {
        self.entries
            .iter()
            .zip(self.used.iter())
            .filter(|(_, used)| **used)
            .map(|(image, _)| image)
            .find(|image| image.pi == pi)
            .map(OwnedHostedProcessImage::as_ref)
    }

    pub fn get_owned_by_pi(&self, pi: usize) -> Option<&OwnedHostedProcessImage> {
        self.entries
            .iter()
            .zip(self.used.iter())
            .filter(|(_, used)| **used)
            .map(|(image, _)| image)
            .find(|image| image.pi == pi)
    }

    pub fn get_by_leaf(&self, leaf: &[u8]) -> Option<HostedProcessImageRef<'_>> {
        self.entries
            .iter()
            .zip(self.used.iter())
            .filter(|(_, used)| **used)
            .map(|(image, _)| image)
            .find(|image| eq_ascii_case(image.leaf(), leaf))
            .map(OwnedHostedProcessImage::as_ref)
    }

    pub fn get_by_path(&self, path: &[u8]) -> Option<HostedProcessImageRef<'_>> {
        self.get_by_leaf(canonical_exe_leaf(path)?)
    }

    pub fn get_by_top_badge(&self, top_badge: u64) -> Option<HostedProcessImageRef<'_>> {
        self.entries
            .iter()
            .zip(self.used.iter())
            .filter(|(_, used)| **used)
            .map(|(image, _)| image)
            .find(|image| image.top_badge == top_badge)
            .map(OwnedHostedProcessImage::as_ref)
    }

    pub fn process_name_for_pi(&self, pi: usize) -> Option<&str> {
        self.get_by_pi(pi).map(|image| image.process_name)
    }

    pub fn top_badge_for_pi(&self, pi: usize) -> Option<u64> {
        self.get_by_pi(pi).map(|image| image.top_badge)
    }

    pub fn pi_for_leaf(&self, leaf: &[u8]) -> Option<usize> {
        self.get_by_leaf(leaf).map(|image| image.pi)
    }

    pub fn pi_for_top_badge(&self, top_badge: u64) -> Option<usize> {
        self.get_by_top_badge(top_badge).map(|image| image.pi)
    }

    pub fn role_for_path(&self, path: &[u8]) -> Option<HostedProcessRole> {
        self.get_by_path(path).map(|image| image.role)
    }

    pub fn path_is_noninteractive_service(&self, path: &[u8]) -> bool {
        self.role_for_path(path) == Some(HostedProcessRole::NonInteractiveService)
    }

    pub fn probe_image(
        &self,
        folded_path: &[u8],
        is_sxs: bool,
    ) -> Option<HostedProcessImageRef<'_>> {
        if is_sxs {
            return None;
        }
        self.entries
            .iter()
            .zip(self.used.iter())
            .filter(|(_, used)| **used)
            .map(|(image, _)| image)
            .filter(|image| !image.probe_fragment().is_empty())
            .find(|image| contains_ascii_case(folded_path, image.probe_fragment()))
            .map(OwnedHostedProcessImage::as_ref)
    }

    pub fn probe_leaf(&self, folded_path: &[u8], is_sxs: bool) -> Option<&[u8]> {
        self.probe_image(folded_path, is_sxs)
            .map(|image| image.leaf)
    }
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
        self.spawn_request_with_target(slot, None)
    }

    fn spawn_request_with_target(
        &self,
        slot: usize,
        target: Option<SpawnTarget>,
    ) -> Option<SpawnRequest> {
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
            target,
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
        self.reserve_spawn_with_target(
            owner_pi,
            section_handle,
            desired_access,
            process_handle_out,
            None,
        )
    }

    pub fn reserve_spawn_registered<'a, const M: usize>(
        &mut self,
        catalog: &HostedImageCatalog<'a, M>,
        owner_pi: usize,
        section_handle: u64,
        desired_access: u32,
        process_handle_out: u64,
    ) -> Result<SpawnRequest, ImageError> {
        let index = self
            .index_for_section(owner_pi, section_handle)
            .ok_or(ImageError::NotFound)?;
        let image = catalog
            .get_by_leaf(self.slots[index].leaf())
            .ok_or(ImageError::InvalidPath)?;
        self.reserve_spawn_with_target(
            owner_pi,
            section_handle,
            desired_access,
            process_handle_out,
            Some(SpawnTarget::from_image(image)),
        )
    }

    pub fn reserve_spawn_owned_registered<const M: usize>(
        &mut self,
        catalog: &OwnedHostedImageCatalog<M>,
        owner_pi: usize,
        section_handle: u64,
        desired_access: u32,
        process_handle_out: u64,
    ) -> Result<SpawnRequest, ImageError> {
        let index = self
            .index_for_section(owner_pi, section_handle)
            .ok_or(ImageError::NotFound)?;
        let image = catalog
            .get_by_leaf(self.slots[index].leaf())
            .ok_or(ImageError::InvalidPath)?;
        self.reserve_spawn_with_target(
            owner_pi,
            section_handle,
            desired_access,
            process_handle_out,
            Some(SpawnTarget::from_image(image)),
        )
    }

    fn reserve_spawn_with_target(
        &mut self,
        owner_pi: usize,
        section_handle: u64,
        desired_access: u32,
        process_handle_out: u64,
        target: Option<SpawnTarget>,
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
        Ok(slot.spawn_request_with_target(index, target).unwrap())
    }

    pub fn rollback_spawn(&mut self, request: SpawnRequest) -> Result<(), ImageError> {
        let slot = self
            .slots
            .get_mut(request.slot)
            .ok_or(ImageError::NotFound)?;
        if slot.spawn_request_with_target(request.slot, request.target) != Some(request) {
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
        if slot.spawn_request_with_target(request.slot, request.target) != Some(request) {
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

    fn catalog_image(
        pi: usize,
        top_badge: u64,
        leaf: &'static [u8],
        nt_image_path: &'static [u8],
        role: HostedProcessRole,
        image_root: HostedImageRoot,
        probe_fragment: &'static [u8],
    ) -> HostedProcessImageRef<'static> {
        HostedProcessImageRef {
            pi,
            top_badge,
            leaf,
            process_name: "registered.exe",
            role,
            nt_image_path,
            command_line: leaf,
            image_root,
            probe_fragment,
        }
    }

    fn owned_catalog_image(
        pi: usize,
        top_badge: u64,
        leaf: &[u8],
        nt_image_path: &[u8],
        role: HostedProcessRole,
        image_root: HostedImageRoot,
        probe_fragment: &[u8],
    ) -> OwnedHostedProcessImage {
        OwnedHostedProcessImage::new(
            pi,
            top_badge,
            leaf,
            b"registered.exe",
            role,
            nt_image_path,
            leaf,
            image_root,
            probe_fragment,
        )
        .unwrap()
    }

    fn boot_owned_catalog() -> OwnedHostedImageCatalog<7> {
        let mut catalog = OwnedHostedImageCatalog::<7>::new();
        let mut register = |pi,
                            top_badge,
                            leaf: &'static [u8],
                            role,
                            nt_image_path: &'static [u8],
                            command_line: &'static [u8],
                            image_root,
                            probe_fragment: &'static [u8]| {
            catalog
                .register(
                    OwnedHostedProcessImage::new(
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
                    .unwrap(),
                )
                .unwrap();
        };

        register(
            0,
            SMSS_TOP_BADGE,
            b"smss.exe",
            HostedProcessRole::NativeSession,
            b"\\SystemRoot\\System32\\smss.exe",
            b"smss.exe",
            HostedImageRoot::System32,
            b"",
        );
        register(
            1,
            CSRSS_TOP_BADGE,
            b"csrss.exe",
            HostedProcessRole::Win32Subsystem,
            b"\\SystemRoot\\System32\\csrss.exe",
            b"csrss.exe ObjectDirectory=\\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16",
            HostedImageRoot::System32,
            b"csrss",
        );
        register(
            2,
            WINLOGON_TOP_BADGE,
            b"winlogon.exe",
            HostedProcessRole::InteractiveLogon,
            b"\\SystemRoot\\System32\\winlogon.exe",
            b"winlogon.exe",
            HostedImageRoot::System32,
            b"winlogon",
        );
        register(
            3,
            SERVICES_TOP_BADGE,
            b"services.exe",
            HostedProcessRole::NonInteractiveService,
            b"\\SystemRoot\\System32\\services.exe",
            b"services.exe",
            HostedImageRoot::System32,
            b"services",
        );
        register(
            4,
            LSASS_TOP_BADGE,
            b"lsass.exe",
            HostedProcessRole::NonInteractiveService,
            b"\\SystemRoot\\System32\\lsass.exe",
            b"lsass.exe",
            HostedImageRoot::System32,
            b"lsass",
        );
        register(
            5,
            USERINIT_TOP_BADGE,
            b"userinit.exe",
            HostedProcessRole::InteractiveShellBootstrap,
            b"\\SystemRoot\\System32\\userinit.exe",
            b"userinit.exe",
            HostedImageRoot::System32,
            b"userinit",
        );
        register(
            6,
            EXPLORER_TOP_BADGE,
            b"explorer.exe",
            HostedProcessRole::InteractiveShell,
            b"\\SystemRoot\\explorer.exe",
            b"explorer.exe",
            HostedImageRoot::SystemRoot,
            b"explorer",
        );

        catalog
    }

    #[test]
    fn dynamic_catalog_registers_and_resolves_images() {
        let mut catalog = HostedImageCatalog::<4>::new();
        let userinit = catalog_image(
            5,
            USERINIT_TOP_BADGE,
            b"userinit.exe",
            b"\\SystemRoot\\System32\\userinit.exe",
            HostedProcessRole::InteractiveShellBootstrap,
            HostedImageRoot::System32,
            b"userinit",
        );
        let explorer = catalog_image(
            6,
            EXPLORER_TOP_BADGE,
            b"explorer.exe",
            b"\\SystemRoot\\explorer.exe",
            HostedProcessRole::InteractiveShell,
            HostedImageRoot::SystemRoot,
            b"explorer",
        );

        assert_eq!(catalog.register(userinit), Ok(0));
        assert_eq!(catalog.register(explorer), Ok(1));
        assert_eq!(catalog.count(), 2);
        assert_eq!(catalog.mask(), (1u64 << 5) | (1u64 << 6));
        assert_eq!(catalog.get_by_pi(5), Some(userinit));
        assert_eq!(catalog.get_by_leaf(b"USERINIT.EXE"), Some(userinit));
        assert_eq!(
            catalog.get_by_path(b"\\??\\C:\\ReactOS\\explorer.exe"),
            Some(explorer)
        );
        assert_eq!(catalog.top_badge_for_pi(6), Some(EXPLORER_TOP_BADGE));
        assert_eq!(catalog.pi_for_top_badge(USERINIT_TOP_BADGE), Some(5));
        assert_eq!(
            catalog.role_for_path(b"\\SystemRoot\\explorer.exe"),
            Some(HostedProcessRole::InteractiveShell)
        );
        assert_eq!(
            catalog.probe_leaf(b"\\SystemRoot\\System32\\USERINIT.EXE", false),
            Some(b"userinit.exe" as &[u8])
        );
    }

    #[test]
    fn dynamic_catalog_rejects_duplicate_identity() {
        let mut catalog = HostedImageCatalog::<4>::new();
        let userinit = catalog_image(
            5,
            USERINIT_TOP_BADGE,
            b"userinit.exe",
            b"\\SystemRoot\\System32\\userinit.exe",
            HostedProcessRole::InteractiveShellBootstrap,
            HostedImageRoot::System32,
            b"userinit",
        );
        catalog.register(userinit).unwrap();

        assert_eq!(
            catalog.register(catalog_image(
                5,
                EXPLORER_TOP_BADGE,
                b"explorer.exe",
                b"\\SystemRoot\\explorer.exe",
                HostedProcessRole::InteractiveShell,
                HostedImageRoot::SystemRoot,
                b"explorer",
            )),
            Err(HostedImageRegistrationError::DuplicatePi)
        );
        assert_eq!(
            catalog.register(catalog_image(
                6,
                USERINIT_TOP_BADGE,
                b"explorer.exe",
                b"\\SystemRoot\\explorer.exe",
                HostedProcessRole::InteractiveShell,
                HostedImageRoot::SystemRoot,
                b"explorer",
            )),
            Err(HostedImageRegistrationError::DuplicateTopBadge)
        );
        assert_eq!(
            catalog.register(catalog_image(
                6,
                EXPLORER_TOP_BADGE,
                b"USERINIT.EXE",
                b"\\SystemRoot\\System32\\userinit.exe",
                HostedProcessRole::InteractiveShellBootstrap,
                HostedImageRoot::System32,
                b"userinit",
            )),
            Err(HostedImageRegistrationError::DuplicateLeaf)
        );
    }

    #[test]
    fn dynamic_catalog_rejects_invalid_registration_paths() {
        let mut catalog = HostedImageCatalog::<2>::new();
        assert_eq!(
            catalog.register(catalog_image(
                5,
                USERINIT_TOP_BADGE,
                b"userinit.exe.local",
                b"\\SystemRoot\\System32\\userinit.exe.local",
                HostedProcessRole::InteractiveShellBootstrap,
                HostedImageRoot::System32,
                b"userinit",
            )),
            Err(HostedImageRegistrationError::InvalidPath)
        );
        assert_eq!(
            catalog.register(catalog_image(
                5,
                USERINIT_TOP_BADGE,
                b"userinit.exe",
                b"\\SystemRoot\\System32\\explorer.exe",
                HostedProcessRole::InteractiveShellBootstrap,
                HostedImageRoot::System32,
                b"userinit",
            )),
            Err(HostedImageRegistrationError::InvalidPath)
        );
    }

    #[test]
    fn dynamic_catalog_capacity_is_explicit() {
        let mut catalog = HostedImageCatalog::<1>::new();
        catalog
            .register(catalog_image(
                5,
                USERINIT_TOP_BADGE,
                b"userinit.exe",
                b"\\SystemRoot\\System32\\userinit.exe",
                HostedProcessRole::InteractiveShellBootstrap,
                HostedImageRoot::System32,
                b"userinit",
            ))
            .unwrap();
        assert_eq!(
            catalog.register(catalog_image(
                6,
                EXPLORER_TOP_BADGE,
                b"explorer.exe",
                b"\\SystemRoot\\explorer.exe",
                HostedProcessRole::InteractiveShell,
                HostedImageRoot::SystemRoot,
                b"explorer",
            )),
            Err(HostedImageRegistrationError::Full)
        );
    }

    #[test]
    fn dynamic_catalog_probe_keeps_sxs_out() {
        let mut catalog = HostedImageCatalog::<1>::new();
        let explorer = catalog_image(
            6,
            EXPLORER_TOP_BADGE,
            b"explorer.exe",
            b"\\SystemRoot\\explorer.exe",
            HostedProcessRole::InteractiveShell,
            HostedImageRoot::SystemRoot,
            b"explorer",
        );
        catalog.register(explorer).unwrap();
        assert_eq!(
            catalog.probe_leaf(b"\\SystemRoot\\explorer.exe", false),
            Some(b"explorer.exe" as &[u8])
        );
        assert_eq!(
            catalog.probe_leaf(b"\\SystemRoot\\explorer.exe", true),
            None
        );
    }

    #[test]
    fn owned_dynamic_catalog_registers_runtime_backed_images() {
        let mut catalog = OwnedHostedImageCatalog::<2>::new();
        let userinit = owned_catalog_image(
            5,
            USERINIT_TOP_BADGE,
            b"userinit.exe",
            b"\\SystemRoot\\System32\\userinit.exe",
            HostedProcessRole::InteractiveShellBootstrap,
            HostedImageRoot::System32,
            b"userinit",
        );
        let explorer = owned_catalog_image(
            6,
            EXPLORER_TOP_BADGE,
            b"explorer.exe",
            b"\\SystemRoot\\explorer.exe",
            HostedProcessRole::InteractiveShell,
            HostedImageRoot::SystemRoot,
            b"explorer",
        );

        assert_eq!(catalog.register(userinit), Ok(0));
        assert_eq!(catalog.register(explorer), Ok(1));
        assert_eq!(catalog.count(), 2);
        assert_eq!(catalog.mask(), (1u64 << 5) | (1u64 << 6));
        assert_eq!(catalog.get_by_pi(5), Some(userinit.as_ref()));
        assert_eq!(
            catalog.get_by_leaf(b"EXPLORER.EXE"),
            Some(explorer.as_ref())
        );
        assert_eq!(
            catalog.get_by_path(b"\\??\\C:\\ReactOS\\System32\\USERINIT.EXE"),
            Some(userinit.as_ref())
        );
        assert_eq!(catalog.get_owned_by_pi(6), Some(&explorer));
        assert_eq!(catalog.process_name_for_pi(5), Some("registered.exe"));
        assert_eq!(
            catalog.probe_leaf(b"\\SystemRoot\\explorer.exe", false),
            Some(b"explorer.exe" as &[u8])
        );
        assert_eq!(
            catalog.probe_leaf(b"\\SystemRoot\\explorer.exe", true),
            None
        );
    }

    #[test]
    fn owned_dynamic_catalog_rejects_invalid_runtime_registration() {
        assert_eq!(
            OwnedHostedProcessImage::new(
                5,
                USERINIT_TOP_BADGE,
                b"userinit.exe",
                &[0xff],
                HostedProcessRole::InteractiveShellBootstrap,
                b"\\SystemRoot\\System32\\userinit.exe",
                b"userinit.exe",
                HostedImageRoot::System32,
                b"userinit",
            ),
            Err(HostedImageRegistrationError::InvalidProcessName)
        );
        assert_eq!(
            OwnedHostedProcessImage::new(
                5,
                USERINIT_TOP_BADGE,
                b"userinit.exe",
                b"userinit.exe",
                HostedProcessRole::InteractiveShellBootstrap,
                b"\\SystemRoot\\System32\\explorer.exe",
                b"userinit.exe",
                HostedImageRoot::System32,
                b"userinit",
            ),
            Err(HostedImageRegistrationError::InvalidPath)
        );
        assert_eq!(
            FixedBytes::<4>::from_slice(b"12345"),
            Err(HostedImageRegistrationError::FieldTooLong)
        );
    }

    #[test]
    fn spawn_reservation_can_bind_to_dynamic_catalog_target() {
        let mut catalog = HostedImageCatalog::<1>::new();
        catalog
            .register(catalog_image(
                5,
                USERINIT_TOP_BADGE,
                b"userinit.exe",
                b"\\SystemRoot\\System32\\userinit.exe",
                HostedProcessRole::InteractiveShellBootstrap,
                HostedImageRoot::System32,
                b"userinit",
            ))
            .unwrap();
        let mut table = ImageTable::<1>::new();
        let slot = table.open(2, b"userinit.exe", 0x40, META).unwrap();
        table.create_section(2, 0x40, 0x44).unwrap();

        let request = table
            .reserve_spawn_registered(&catalog, 2, 0x44, 0x1fffff, 0x1000)
            .unwrap();

        assert_eq!(request.slot, slot);
        assert_eq!(
            request.target,
            Some(SpawnTarget {
                pi: 5,
                top_badge: USERINIT_TOP_BADGE,
                role: HostedProcessRole::InteractiveShellBootstrap,
            })
        );
        assert_eq!(
            table.reserve_spawn_registered(&catalog, 2, 0x44, 0x1fffff, 0x1000),
            Ok(request)
        );
        table.publish(request, 0x48).unwrap();
        assert_eq!(table.get(slot).unwrap().state, ImageState::Published);
    }

    #[test]
    fn spawn_reservation_rejects_unregistered_images() {
        let catalog = HostedImageCatalog::<1>::new();
        let mut table = ImageTable::<1>::new();
        table.open(2, b"calc.exe", 0x40, META).unwrap();
        table.create_section(2, 0x40, 0x44).unwrap();

        assert_eq!(
            table.reserve_spawn_registered(&catalog, 2, 0x44, 0x1fffff, 0x1000),
            Err(ImageError::InvalidPath)
        );
        assert_eq!(table.get(0).unwrap().state, ImageState::Sectioned);
    }

    #[test]
    fn spawn_reservation_can_bind_to_owned_catalog_target() {
        let mut catalog = OwnedHostedImageCatalog::<1>::new();
        catalog
            .register(owned_catalog_image(
                6,
                EXPLORER_TOP_BADGE,
                b"explorer.exe",
                b"\\SystemRoot\\explorer.exe",
                HostedProcessRole::InteractiveShell,
                HostedImageRoot::SystemRoot,
                b"explorer",
            ))
            .unwrap();
        let mut table = ImageTable::<1>::new();
        table.open(5, b"explorer.exe", 0x40, META).unwrap();
        table.create_section(5, 0x40, 0x44).unwrap();

        let request = table
            .reserve_spawn_owned_registered(&catalog, 5, 0x44, 0x1fffff, 0x1000)
            .unwrap();

        assert_eq!(
            request.target,
            Some(SpawnTarget {
                pi: 6,
                top_badge: EXPLORER_TOP_BADGE,
                role: HostedProcessRole::InteractiveShell,
            })
        );
    }

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
    fn explicit_catalog_resolves_boot_images() {
        let catalog = boot_owned_catalog();

        assert_eq!(catalog.process_name_for_pi(0), Some("smss.exe"));
        assert_eq!(catalog.process_name_for_pi(6), Some("explorer.exe"));
        assert_eq!(catalog.top_badge_for_pi(0), Some(SMSS_TOP_BADGE));
        assert_eq!(catalog.top_badge_for_pi(6), Some(EXPLORER_TOP_BADGE));
        assert_eq!(catalog.pi_for_leaf(b"SERVICES.EXE"), Some(3));
        assert_eq!(catalog.pi_for_top_badge(SERVICES_TOP_BADGE), Some(3));
        assert_eq!(catalog.pi_for_leaf(b"userinit2.exe"), None);
        assert_eq!(catalog.pi_for_top_badge(13), None);
    }

    #[test]
    fn explicit_catalog_classifies_noninteractive_service_images_by_path() {
        let catalog = boot_owned_catalog();

        assert_eq!(
            catalog.role_for_path(br"\SystemRoot\System32\SERVICES.EXE"),
            Some(HostedProcessRole::NonInteractiveService)
        );
        assert_eq!(
            catalog.role_for_path(br"\??\C:\ReactOS\System32\lsass.exe"),
            Some(HostedProcessRole::NonInteractiveService)
        );
        assert!(catalog.path_is_noninteractive_service(b"services.exe"));
        assert!(catalog.path_is_noninteractive_service(b"LSASS.EXE"));
        assert!(!catalog.path_is_noninteractive_service(b"winlogon.exe"));
        assert!(!catalog.path_is_noninteractive_service(b"explorer.exe"));
        assert!(!catalog.path_is_noninteractive_service(b"service-helper.exe"));
    }

    #[test]
    fn hosted_roles_advertise_win32_client_gdi_capability() {
        assert!(!HostedProcessRole::NativeSession.uses_win32_client_gdi());
        assert!(HostedProcessRole::Win32Subsystem.uses_win32_client_gdi());
        assert!(HostedProcessRole::InteractiveLogon.uses_win32_client_gdi());
        assert!(HostedProcessRole::NonInteractiveService.uses_win32_client_gdi());
        assert!(HostedProcessRole::InteractiveShellBootstrap.uses_win32_client_gdi());
        assert!(HostedProcessRole::InteractiveShell.uses_win32_client_gdi());
    }

    #[test]
    fn explicit_catalog_records_boot_paths_and_locations() {
        let catalog = boot_owned_catalog();

        let services = catalog.get_by_pi(3).unwrap();
        assert_eq!(services.top_badge, SERVICES_TOP_BADGE);
        assert_eq!(services.role, HostedProcessRole::NonInteractiveService);
        assert_eq!(
            services.nt_image_path,
            b"\\SystemRoot\\System32\\services.exe"
        );
        assert_eq!(services.command_line, b"services.exe");
        assert_eq!(services.image_root, HostedImageRoot::System32);

        let explorer = catalog.get_by_leaf(b"EXPLORER.EXE").unwrap();
        assert_eq!(explorer.role, HostedProcessRole::InteractiveShell);
        assert_eq!(explorer.nt_image_path, b"\\SystemRoot\\explorer.exe");
        assert_eq!(explorer.command_line, b"explorer.exe");
        assert_eq!(explorer.image_root, HostedImageRoot::SystemRoot);
    }

    #[test]
    fn explicit_catalog_probe_classifier_preserves_boot_quirks() {
        let catalog = boot_owned_catalog();

        assert_eq!(
            catalog.probe_leaf(br"\??\C:\Windowsservices.exe", false),
            Some(b"services.exe" as &[u8])
        );
        assert_eq!(
            catalog.probe_leaf(br"\SystemRoot\explorer.exe", false),
            Some(b"explorer.exe" as &[u8])
        );
        assert_eq!(
            catalog.probe_leaf(br"\SystemRoot\System32\smss.exe", false),
            None
        );
        assert_eq!(
            catalog.probe_leaf(br"\SystemRoot\System32\lsasrv.dll", false),
            None
        );
        assert_eq!(
            catalog.probe_leaf(br"\SystemRoot\System32\userinit.exe.manifest", true),
            None
        );
    }

    #[test]
    fn explicit_catalog_is_not_parent_policy() {
        let catalog = boot_owned_catalog();

        for leaf in [
            b"csrss.exe" as &[u8],
            b"winlogon.exe",
            b"services.exe",
            b"lsass.exe",
            b"userinit.exe",
            b"explorer.exe",
        ] {
            assert!(catalog.get_by_leaf(leaf).is_some());
        }
        assert!(catalog.get_by_leaf(b"calc.exe").is_none());
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
