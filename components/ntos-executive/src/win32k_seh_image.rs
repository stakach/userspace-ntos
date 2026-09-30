//! Admitted exception linkage image for the isolated win32k provider.

use alloc::vec::Vec;
use core::cell::RefCell;
use core::ptr::{copy_nonoverlapping, read_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

use nt_unwind::exception_images::{AdmittedExceptionImage, ExceptionImageCatalog};
use nt_unwind::seh_linkage_image::SehLinkageImage;

use crate::{driver_launch::hosted_seh_component, RO_NX};

pub(crate) const IMAGE_VA: u64 = crate::win32k_subsystem::WIN32K_CODE_VA
    + crate::win32k_subsystem::WIN32K_IMAGE_FRAMES * 0x1000;
pub(crate) const MAX_FRAMES: usize = 16;
const RX: u64 = 2;
const SUPPORT_PATH: &[u8] = b"reactos\\system32\\nt-seh-linkage.dll";

struct Published {
    pml4: u64,
    provider: nt_provider_wait::ProviderDomainIdentity,
    linkage: SehLinkageImage,
    catalog: RefCell<ExceptionImageCatalog>,
}

static PUBLISHED: AtomicBool = AtomicBool::new(false);
static mut STATE: Option<Published> = None;
static RIGHTS_READY: AtomicBool = AtomicBool::new(false);
static mut FRAME_RIGHTS: [u64; MAX_FRAMES] = [RO_NX; MAX_FRAMES];
static IMPORTS_READY: AtomicBool = AtomicBool::new(false);
static mut IMPORT_LINKAGE: Option<SehLinkageImage> = None;

pub(crate) struct Prepared {
    bytes: Vec<u8>,
    rights: [u64; MAX_FRAMES],
    frames: u64,
    linkage: SehLinkageImage,
}

impl Prepared {
    pub(crate) fn frame_count(&self) -> u64 {
        self.frames
    }

    pub(crate) unsafe fn publish_frame_rights(&self) -> Option<&'static [u64]> {
        if RIGHTS_READY.load(Ordering::Acquire) {
            return None;
        }
        core::ptr::addr_of_mut!(FRAME_RIGHTS).write(self.rights);
        RIGHTS_READY.store(true, Ordering::Release);
        Some(&(&*core::ptr::addr_of!(FRAME_RIGHTS))[..self.frames as usize])
    }

    pub(crate) fn linkage(&self) -> SehLinkageImage {
        self.linkage
    }

    /// The root mapping must cover precisely the frame run selected by `frame_count`.
    pub(crate) unsafe fn install(&mut self) -> Option<()> {
        let length = self.bytes.len();
        let frame_bytes = self.frames.checked_mul(0x1000)?;
        if length == 0 || length as u64 > frame_bytes {
            return None;
        }
        let slots = [
            (
                self.linkage.dispatch_slot_rva,
                hosted_seh_component::raise_dispatch as *const () as usize as u64,
            ),
            (
                self.linkage.unwind_dispatch_slot_rva,
                hosted_seh_component::unwind_dispatch as *const () as usize as u64,
            ),
            (
                self.linkage.fault_dispatch_slot_rva,
                hosted_seh_component::fault_dispatch as *const () as usize as u64,
            ),
        ];
        for (rva, _) in slots {
            let offset = rva as usize;
            let slot = self.bytes.get(offset..offset.checked_add(8)?)?;
            if slot.iter().any(|byte| *byte != 0) {
                return None;
            }
        }
        for (rva, target) in slots {
            let offset = rva as usize;
            let slot = self.bytes.get_mut(offset..offset + 8)?;
            slot.copy_from_slice(&target.to_le_bytes());
        }
        copy_nonoverlapping(self.bytes.as_ptr(), IMAGE_VA as *mut u8, length);
        for (rva, target) in slots {
            if read_volatile((IMAGE_VA + u64::from(rva)) as *const u64) != target {
                return None;
            }
        }
        Some(())
    }

    pub(crate) unsafe fn publish_imports(&self) -> Option<()> {
        if IMPORTS_READY.load(Ordering::Acquire) || self.frames == 0 {
            return None;
        }
        for (rva, expected) in [
            (
                self.linkage.dispatch_slot_rva,
                hosted_seh_component::raise_dispatch as *const () as usize as u64,
            ),
            (
                self.linkage.unwind_dispatch_slot_rva,
                hosted_seh_component::unwind_dispatch as *const () as usize as u64,
            ),
            (
                self.linkage.fault_dispatch_slot_rva,
                hosted_seh_component::fault_dispatch as *const () as usize as u64,
            ),
        ] {
            if read_volatile((IMAGE_VA + u64::from(rva)) as *const u64) != expected {
                return None;
            }
        }
        *core::ptr::addr_of_mut!(IMPORT_LINKAGE) = Some(self.linkage);
        IMPORTS_READY.store(true, Ordering::Release);
        Some(())
    }

    pub(crate) fn into_snapshot(self) -> Option<nt_unwind::exception_images::AdmittedExceptionImage> {
        nt_unwind::exception_images::AdmittedExceptionImage::from_mapped_image(
            IMAGE_VA,
            self.bytes.into_boxed_slice(),
        )
        .ok()
    }
}

pub(crate) fn prepare(source: &[u8]) -> Option<Prepared> {
    let pe = nt_pe_loader::PeFile::parse(source).ok()?;
    nt_pe_loader::immutable_support_image::validate(&pe).ok()?;
    let size = pe.size_of_image() as u64;
    let frames = size.checked_add(0xfff)?.checked_div(0x1000)?;
    if frames == 0 || frames > MAX_FRAMES as u64 {
        return None;
    }
    let mapped = pe.map(IMAGE_VA).ok()?;
    if mapped.bytes.len() as u64 != size {
        return None;
    }
    let linkage = nt_unwind::seh_linkage_image::admit(&pe, &mapped).ok()?;
    let mut rights = [RO_NX; MAX_FRAMES];
    for section in pe.sections() {
        let span = u64::from(section.virtual_size.max(section.size_of_raw_data));
        if span == 0 {
            continue;
        }
        let start = u64::from(section.virtual_address);
        let end = start.checked_add(span)?.checked_add(0xfff)? & !0xfff;
        if start & 0xfff != 0 || end > (size.checked_add(0xfff)? & !0xfff) {
            return None;
        }
        if section.is_executable() {
            for right in rights.get_mut((start / 0x1000) as usize..(end / 0x1000) as usize)? {
                *right = RX;
            }
        }
    }
    Some(Prepared { bytes: mapped.bytes, rights, frames, linkage })
}

pub(crate) fn admitted_imports() -> Option<SehLinkageImage> {
    if !IMPORTS_READY.load(Ordering::Acquire) {
        return None;
    }
    unsafe { *core::ptr::addr_of!(IMPORT_LINKAGE) }
}

pub(crate) unsafe fn load_from_os(fs: &crate::Fat32) -> Option<Prepared> {
    let (source_va, source_len) = crate::fs_loader::load_file_to_pool(fs, SUPPORT_PATH)?;
    let source = core::slice::from_raw_parts(source_va as *const u8, source_len as usize);
    prepare(source)
}

pub(crate) unsafe fn primary_image_size(source_va: u64, source_len: usize) -> Option<u32> {
    if source_va == 0 || source_len == 0 {
        return None;
    }
    let source = core::slice::from_raw_parts(source_va as *const u8, source_len);
    let size = nt_pe_loader::PeFile::parse(source).ok()?.size_of_image();
    (size != 0 && u64::from(size) <= crate::win32k_subsystem::WIN32K_IMAGE_FRAMES * 0x1000)
        .then_some(size)
}

fn validate_image_rights(bytes: &[u8], mapped_rights: &[u64]) -> Option<()> {
    let pe = nt_pe_loader::PeFile::parse(bytes).ok()?;
    if pe.size_of_image() as usize != bytes.len() {
        return None;
    }
    let header_pages = (u64::from(pe.headers().size_of_headers) + 0xfff) / 0x1000;
    if mapped_rights.get(..header_pages as usize)?.iter().any(|right| *right != RO_NX) {
        return None;
    }
    for section in pe.sections() {
        let span = u64::from(section.virtual_size.max(section.size_of_raw_data));
        if span == 0 {
            continue;
        }
        let begin = u64::from(section.virtual_address);
        let end = begin.checked_add(span)?.checked_add(0xfff)? & !0xfff;
        if begin & 0xfff != 0 || end > bytes.len() as u64 {
            return None;
        }
        let expected = match nt_pe_loader::Protection::from_section_characteristics(
            section.characteristics,
        ) {
            nt_pe_loader::Protection::ReadExecute => RX,
            nt_pe_loader::Protection::ReadWrite => crate::RW_NX,
            nt_pe_loader::Protection::ReadOnly => RO_NX,
        };
        if mapped_rights.get((begin / 0x1000) as usize..(end / 0x1000) as usize)?
            .iter()
            .any(|right| *right != expected)
        {
            return None;
        }
    }
    Some(())
}

/// Capture the already patched primary image before any provider thread runs. The owned catalog
/// remains valid even when win32k later writes its data section.
pub(crate) unsafe fn publish(
    pml4: u64,
    support: Prepared,
    primary_size: u32,
) -> Option<()> {
    if PUBLISHED.load(Ordering::Acquire) || pml4 == 0 || primary_size == 0 {
        return None;
    }
    let provider = crate::current_win32k_provider_domain()?;
    let linkage = support.linkage();
    let support = support.into_snapshot()?;
    let size = primary_size as usize;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).ok()?;
    bytes.resize(size, 0);
    copy_nonoverlapping(
        crate::win32k_subsystem::WIN32K_CODE_VA as *const u8,
        bytes.as_mut_ptr(),
        size,
    );
    validate_image_rights(&bytes, crate::win32k_subsystem::code_rights())?;
    let primary = AdmittedExceptionImage::from_mapped_image(
        crate::win32k_subsystem::WIN32K_CODE_VA,
        bytes.into_boxed_slice(),
    )
    .ok()?;
    let catalog = ExceptionImageCatalog::new(alloc::vec![primary, support]).ok()?;
    if catalog.image_count() != 2 {
        return None;
    }
    *core::ptr::addr_of_mut!(STATE) = Some(Published {
        pml4,
        provider,
        linkage,
        catalog: RefCell::new(catalog),
    });
    PUBLISHED.store(true, Ordering::Release);
    Some(())
}

fn authenticated(
    channel: &crate::spawn_hosts::PumpChannel,
    reply: u64,
) -> Option<(nt_component_suspension::LaneHandle, &'static Published)> {
    if !PUBLISHED.load(Ordering::Acquire) {
        return None;
    }
    let lane = unsafe {
        crate::win32k_glue::win32k_physical_lane_for_channel(
            channel.tcb,
            channel.fault_ep,
            reply,
        )?
    };
    let state = unsafe { (&*core::ptr::addr_of!(STATE)).as_ref()? };
    if channel.pml4 != state.pml4 || !crate::win32k_provider_domain_is_current(state.provider) {
        return None;
    }
    Some((lane, state))
}

pub(crate) fn linkage(
    channel: &crate::spawn_hosts::PumpChannel,
    reply: u64,
) -> Option<SehLinkageImage> {
    authenticated(channel, reply).map(|(_, state)| state.linkage)
}

pub(crate) fn with_catalog<R>(
    channel: &crate::spawn_hosts::PumpChannel,
    reply: u64,
    use_catalog: impl FnOnce(&ExceptionImageCatalog) -> R,
) -> Option<R> {
    let (lane, state) = authenticated(channel, reply)?;
    let catalog = state.catalog.try_borrow().ok()?;
    let result = use_catalog(&catalog);
    (authenticated(channel, reply)?.0 == lane).then_some(result)
}

/// Admit a newly loaded helper/display image before installing executable mappings for its
/// component frames. The catalog borrow is exclusive and refuses reentrant mutation while an
/// exception reader owns the previous catalog view.
pub(crate) unsafe fn register_dynamic_image(
    pml4: u64,
    image_va: u64,
    image_size: u32,
    rights: &[u64],
) -> Option<()> {
    if !PUBLISHED.load(Ordering::Acquire)
        || image_va == 0
        || image_va & 0xfff != 0
        || image_size == 0
        || u64::from(image_size) > rights.len() as u64 * 0x1000
    {
        return None;
    }
    let state = (&*core::ptr::addr_of!(STATE)).as_ref()?;
    if state.pml4 != pml4 || !crate::win32k_provider_domain_is_current(state.provider) {
        return None;
    }
    let mut catalog = state.catalog.try_borrow_mut().ok()?;
    let size = image_size as usize;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).ok()?;
    bytes.resize(size, 0);
    copy_nonoverlapping(image_va as *const u8, bytes.as_mut_ptr(), size);
    validate_image_rights(&bytes, rights)?;
    let image = AdmittedExceptionImage::from_mapped_image(image_va, bytes.into_boxed_slice()).ok()?;
    catalog.append(image).ok()
}
