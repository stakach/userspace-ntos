//! Immutable x64 unwind metadata for one physically owned hosted-driver domain.
//!
//! Image admission is only metadata validation. No exception is dispatched here.

use alloc::vec::Vec;
use nt_io_manager::HostedDomainIdentity;
use nt_unwind::exception_images::{
    AdmittedExceptionImage, ExceptionImageCatalog, ImageAdmissionError,
};

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
