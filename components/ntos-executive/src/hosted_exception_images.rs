//! Immutable x64 unwind metadata for one physically owned hosted-driver domain.
//!
//! Image admission is only metadata validation. No exception is dispatched here.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use nt_io_manager::HostedDomainIdentity;
use nt_unwind::exception_images::{
    AdmittedExceptionImage, ExceptionImageCatalog, ImageAdmissionError,
};
use nt_unwind::exception_snapshot::{self, SealedExceptionView, SnapshotImage};

pub(super) const COMPONENT_SNAPSHOT_VA: u64 = 0x0000_0100_0F40_0000;
const COMPONENT_SNAPSHOT_LIMIT: u64 = crate::WORK_CLUSTER_BASE;
const EXEC_SCRATCH_VA: u64 = 0x0000_0101_5100_0000;
const EXEC_SCRATCH_LIMIT: u64 = 0x0000_0101_5200_0000;
const _: () = assert!(
    COMPONENT_SNAPSHOT_LIMIT - COMPONENT_SNAPSHOT_VA == EXEC_SCRATCH_LIMIT - EXEC_SCRATCH_VA
);
const _: () = assert!(EXEC_SCRATCH_VA > super::FSD_EXEC_LIMIT);
const _: () = assert!(EXEC_SCRATCH_LIMIT <= 0x0000_0101_6000_0000);
static SCRATCH_IN_USE: AtomicBool = AtomicBool::new(false);

/// Validate the actual component mapping before any driver code runs. The view retains no image
/// table or heap allocation; exception dispatch can reconstruct it on the current thread later.
pub(super) unsafe fn validate_component_mapping() -> bool {
    let length = core::ptr::read_unaligned((COMPONENT_SNAPSHOT_VA + 16) as *const u64);
    let Ok(length) = usize::try_from(length) else {
        return false;
    };
    if length < 24 || length > (COMPONENT_SNAPSHOT_LIMIT - COMPONENT_SNAPSHOT_VA) as usize {
        return false;
    }
    let bytes = core::slice::from_raw_parts(COMPONENT_SNAPSHOT_VA as *const u8, length);
    let Ok(view) = SealedExceptionView::parse(bytes) else {
        return false;
    };
    super::print_str(b"[driver-exception-image] component-verified images=");
    super::print_u64(view.image_count() as u64);
    super::print_str(b" bytes=");
    super::print_u64(length as u64);
    super::print_str(b"\n");
    true
}

/// The exact scratch cap and whether page_map has completed. This local ledger is populated
/// before each native map effect; an uncertain unmap cannot release the scratch lane.
struct ScratchAlias {
    cap: u64,
    mapped: bool,
}

unsafe fn clear_scratch(aliases: &mut Vec<ScratchAlias>) {
    for alias in aliases.drain(..).rev() {
        if alias.mapped && crate::page_unmap_r(alias.cap) != 0 {
            super::print_str(b"[driver-exception-image] scratch unmap uncertain\n");
            super::park();
        }
        if crate::cnode_delete_recycle_r(alias.cap) != 0 {
            super::print_str(b"[driver-exception-image] scratch cap release uncertain\n");
            super::park();
        }
    }
    SCRATCH_IN_USE.store(false, Ordering::Release);
}

/// Called only after the primary route has enrolled, before its suspended TCB is resumed.
/// The per-instance retirement journal owns every new root frame and mapped component cap.
pub(super) unsafe fn project_sealed(
    instance: usize,
    domain: HostedDomainIdentity,
    catalog: &ExceptionImageCatalog,
) -> Result<(), nt_status::NtStatus> {
    let mut images = Vec::new();
    images
        .try_reserve_exact(catalog.image_count())
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    for image in catalog.images() {
        images.push(SnapshotImage {
            base: image.base(),
            bytes: image.mapped_bytes(),
        });
    }
    let bytes = exception_snapshot::encoded_len(&images)
        .map_err(|_| nt_status::NtStatus::INVALID_IMAGE_FORMAT)?;
    if bytes == 0 || bytes > (COMPONENT_SNAPSHOT_LIMIT - COMPONENT_SNAPSHOT_VA) as usize {
        return Err(nt_status::NtStatus::INVALID_IMAGE_FORMAT);
    }
    let count = bytes.div_ceil(0x1000) as u64;
    let mut aliases = Vec::new();
    aliases
        .try_reserve_exact(count as usize)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    if SCRATCH_IN_USE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let Some(base) = super::alloc_driver_frame_run(instance, b"exception-snapshot", count) else {
        SCRATCH_IN_USE.store(false, Ordering::Release);
        return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    };
    {
        let Some(inst) = super::driver_instances_mut().get_mut(instance) else {
            super::park();
        };
        inst.exception_snapshot_frame_base = base;
        inst.exception_snapshot_frames = count;
        inst.exception_snapshot_bytes = bytes as u64;
    }
    let mut error = None;
    for index in 0..count {
        let va = EXEC_SCRATCH_VA + index * 0x1000;
        if index % 512 == 0 && !crate::ensure_executive_paging(va) {
            error = Some(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
            break;
        }
        let (cap, copy_error) = crate::copy_cap_r(base + index);
        if copy_error != 0 {
            error = Some(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
            break;
        }
        aliases.push(ScratchAlias { cap, mapped: false });
        if crate::page_map_r(cap, va, crate::RW_NX, crate::CAP_INIT_THREAD_VSPACE) != 0 {
            // The kernel may have entered the mapping effect despite an uncertain result.
            // Keep the scratch lease and all caps retained; no component can run from here.
            super::print_str(b"[driver-exception-image] scratch map uncertain\n");
            super::park();
        }
        aliases.last_mut().unwrap().mapped = true;
    }
    if error.is_none() {
        let output = core::slice::from_raw_parts_mut(EXEC_SCRATCH_VA as *mut u8, bytes);
        if exception_snapshot::encode(&images, output).ok() != Some(bytes) {
            error = Some(nt_status::NtStatus::INVALID_IMAGE_FORMAT);
        }
    }
    clear_scratch(&mut aliases);
    if let Some(status) = error {
        return Err(status);
    }

    let pml4 = super::driver_instances_mut()[instance].pml4;
    for index in 0..count {
        let va = COMPONENT_SNAPSHOT_VA + index * 0x1000;
        if !super::ensure_paging(va, pml4, domain) {
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        }
        let (cap, copy_error) = crate::copy_cap_r(base + index);
        if copy_error != 0 {
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        }
        crate::spawn_hosts::component_map_cap_bank_store(
            &mut super::driver_instances_mut()[instance].map_cap_bank,
            cap,
        );
        if crate::page_map_r(cap, va, crate::RO_NX, pml4) != 0 {
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        }
    }
    super::print_str(b"[driver-exception-image] sealed instance=");
    super::print_u64(instance as u64);
    super::print_str(b" bytes=");
    super::print_u64(bytes as u64);
    super::print_str(b" frames=");
    super::print_u64(count);
    super::print_str(b" rights=RO_NX\n");
    Ok(())
}

struct Row {
    domain: HostedDomainIdentity,
    catalog: ExceptionImageCatalog,
}

pub(super) enum PublishError {
    InsufficientResources,
    Occupied,
}

static mut CATALOGS: Option<Vec<Option<Row>>> = None;

fn admission_error_name(error: ImageAdmissionError) -> &'static [u8] {
    match error {
        ImageAdmissionError::Pe(_) => b"Pe",
        ImageAdmissionError::EmptyCatalog => b"EmptyCatalog",
        ImageAdmissionError::ImageOrder => b"ImageOrder",
        ImageAdmissionError::NotExecutable => b"NotExecutable",
        ImageAdmissionError::SnapshotSize => b"SnapshotSize",
        ImageAdmissionError::AddressRange => b"AddressRange",
        ImageAdmissionError::HeaderExtent => b"HeaderExtent",
        ImageAdmissionError::SectionExtent => b"SectionExtent",
        ImageAdmissionError::SectionOverlap => b"SectionOverlap",
        ImageAdmissionError::ExceptionDirectory => b"ExceptionDirectory",
        ImageAdmissionError::FunctionTable => b"FunctionTable",
        ImageAdmissionError::UnwindMetadata => b"UnwindMetadata",
        ImageAdmissionError::ImageOverlap => b"ImageOverlap",
    }
}

fn admission_failed(instance: usize, run_va: u64, reason: &[u8]) {
    crate::print_str(b"[driver-exception-image] admission failed instance=");
    crate::print_u64(instance as u64);
    crate::print_str(b" base=0x");
    super::print_hex64(run_va);
    crate::print_str(b" reason=");
    crate::print_str(reason);
    crate::print_str(b"\n");
}

/// Capture the exact already-relocated and import-patched mapped PE, not its source file.
/// The executive alias remains readable even when the component's mapping is RX.
pub(super) unsafe fn capture(
    instance: usize,
    exec_va: u64,
    run_va: u64,
    image_len: u32,
) -> Option<AdmittedExceptionImage> {
    let mut bytes = Vec::new();
    if image_len == 0 || bytes.try_reserve_exact(image_len as usize).is_err() {
        admission_failed(instance, run_va, b"SnapshotAllocation");
        return None;
    }
    bytes.extend_from_slice(core::slice::from_raw_parts(
        exec_va as *const u8,
        image_len as usize,
    ));
    match AdmittedExceptionImage::from_mapped_image(run_va, bytes.into_boxed_slice()) {
        Ok(image) => Some(image),
        Err(error) => {
            admission_failed(instance, run_va, admission_error_name(error));
            None
        }
    }
}

pub(super) fn catalog(
    instance: usize,
    images: Vec<AdmittedExceptionImage>,
) -> Option<ExceptionImageCatalog> {
    match ExceptionImageCatalog::new(images) {
        Ok(catalog) => Some(catalog),
        Err(error) => {
            admission_failed(instance, 0, admission_error_name(error));
            None
        }
    }
}

/// Publish only into the exact reserved instance. Physical retirement is the only removal path.
pub(super) fn publish(
    instance: usize,
    domain: HostedDomainIdentity,
    catalog: ExceptionImageCatalog,
) -> Result<(), PublishError> {
    let image_count = catalog.image_count();
    unsafe {
        let rows = (&mut *core::ptr::addr_of_mut!(CATALOGS)).get_or_insert_with(Vec::new);
        if rows.len() <= instance {
            let needed = instance
                .checked_add(1)
                .ok_or(PublishError::InsufficientResources)?;
            rows.try_reserve_exact(needed - rows.len())
                .map_err(|_| PublishError::InsufficientResources)?;
            rows.resize_with(needed, || None);
        }
        if rows[instance].is_some() {
            admission_failed(instance, 0, b"InstanceAlreadyPublished");
            return Err(PublishError::Occupied);
        }
        rows[instance] = Some(Row { domain, catalog });
    }
    crate::print_str(b"[driver-exception-image] admitted instance=");
    crate::print_u64(instance as u64);
    crate::print_str(b" images=");
    crate::print_u64(image_count as u64);
    crate::print_str(b"\n");
    Ok(())
}

/// Borrow only the catalog sealed for this exact live domain. The borrow cannot outlive the
/// closure, so retirement or instance-slot reuse cannot leave an unowned catalog reference.
pub(super) fn with_catalog<R>(
    instance: usize,
    domain: HostedDomainIdentity,
    use_catalog: impl for<'a> FnOnce(&'a ExceptionImageCatalog) -> R,
) -> Option<R> {
    unsafe {
        let row = (&*core::ptr::addr_of!(CATALOGS))
            .as_ref()?
            .get(instance)?
            .as_ref()?;
        (row.domain == domain).then(|| use_catalog(&row.catalog))
    }
}

pub(super) fn retire(instance: usize, domain: HostedDomainIdentity) {
    unsafe {
        let Some(row) = (&mut *core::ptr::addr_of_mut!(CATALOGS))
            .as_mut()
            .and_then(|rows| rows.get_mut(instance))
        else {
            return;
        };
        if row.as_ref().is_some_and(|owner| owner.domain == domain) {
            *row = None;
        }
    }
}
