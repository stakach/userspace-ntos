//! Process-owned mapped PE snapshots for an authenticated user frame walk.
//!
//! This is a per-PC source for `OnDemandUserImageCatalog`. Numeric image VAs are never enough:
//! the active process generation, committed IMAGE allocation and exact loader/Section view owner
//! must all agree before and after the checked memory read.

use alloc::vec::Vec;
use nt_unwind::{
    exception_images::AdmittedExceptionImage,
    exception_walk::ExceptionImageError,
};

const MAX_USER_IMAGE_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UserImageOwner {
    Main(nt_exe_image::SpawnTarget),
    Ntdll,
    BootstrapDll(usize),
    NativeView(crate::exec_handler::native_image_view::NativeImageViewDescriptor),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UserImageMapping {
    owner: UserImageOwner,
    base: u64,
    size: usize,
}

unsafe fn mapping_for_pc(
    handler: &crate::ExecNtHandler,
    caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
    pc: u64,
) -> Option<UserImageMapping> {
    let pi = caller.pi();
    if !handler.validate_provider_logical_caller(caller)
        || handler.capture_process_identity(pi) != Some(caller.process())
    {
        return None;
    }
    let ctx = handler.loop_ctx?.for_process(pi)?;
    let allocation = crate::process_committed_image_allocation(pi as u64, pc)?;
    let info = crate::process_committed_mapping_basic_information(pi as u64, pc)?;
    if info.type_ != nt_address_space::MEM_IMAGE
        || info.state != nt_address_space::MEM_COMMIT
        || info.protect & nt_address_space::PAGE_GUARD != 0
    {
        return None;
    }
    let base = allocation.allocation_base;
    let size = usize::try_from(allocation.allocation_end.checked_sub(base)?).ok()?;
    if size == 0 || size > MAX_USER_IMAGE_SNAPSHOT_BYTES {
        return None;
    }
    let owner = if base == ctx.img_base && allocation.allocation_end == ctx.img_end {
        let image = (&*ctx.exe_image_catalog).get_by_pi(pi)?;
        let target = nt_exe_image::SpawnTarget::from_image(image);
        let pe = (&*ctx.hosted_loaded_images).pe_by_pi(pi)?;
        (pe.size_of_image() as usize == size).then_some(UserImageOwner::Main(target))?
    } else if base == ctx.nt_base && allocation.allocation_end == ctx.nt_end {
        let pe = ctx.ntdll_pe.as_ref()?;
        (pe.size_of_image() as usize == size).then_some(UserImageOwner::Ntdll)?
    } else if let Some((slot, _)) = (&*ctx.reg).dll_for_page(pi, pc) {
        let dll = (&*ctx.reg).get(slot)?;
        let pe = ctx.dll_pes().get(slot)?.as_ref()?;
        (dll.base == base && dll.image_size == size as u64
            && pe.size_of_image() as usize == size)
            .then_some(UserImageOwner::BootstrapDll(slot))?
    } else {
        let view = handler.native_image_view_for_page(pi, pc).ok()??;
        let source = handler.image_sections.source_for_view(view.view)?;
        (view.base == base && view.size == size as u64
            && view.section_offset == 0 && source.layout.size_of_image() as usize == size)
            .then_some(UserImageOwner::NativeView(view))?
    };
    Some(UserImageMapping { owner, base, size })
}

/// Snapshot one positively owned image. The caller must retain and revalidate the same paused
/// user dispatch and physical win32k lane through the subsequent stack walk.
pub(super) unsafe fn image_for_user_pc(
    handler_ptr: *mut crate::ExecNtHandler,
    caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
    pc: u64,
) -> Result<AdmittedExceptionImage, ExceptionImageError> {
    let handler = handler_ptr.as_ref().ok_or(ExceptionImageError::UnreadableImage)?;
    let mapping = mapping_for_pc(handler, caller, pc).ok_or(ExceptionImageError::UnknownImage)?;
    // A main EXE's retained source may be retired only after its exact read scope drains. The
    // scope is held while checked process reads can fault in pages from that source.
    let _image_scope = if let UserImageOwner::Main(target) = mapping.owner {
        let ctx = handler.loop_ctx.and_then(|ctx| ctx.for_process(caller.pi()))
            .ok_or(ExceptionImageError::UnreadableImage)?;
        Some(crate::hosted_loaded_images::HostedImageReadScope::capture(
            ctx.hosted_loaded_images, target,
        ).map_err(|_| ExceptionImageError::UnreadableImage)?)
    } else {
        None
    };
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(mapping.size).map_err(|_| ExceptionImageError::UnreadableImage)?;
    bytes.resize(mapping.size, 0);
    (&mut *handler_ptr)
        .process_memory_read_status(caller.pi(), mapping.base, &mut bytes)
        .map_err(|_| ExceptionImageError::UnreadableImage)?;
    if mapping_for_pc(&*handler_ptr, caller, pc) != Some(mapping) {
        return Err(ExceptionImageError::UnreadableImage);
    }
    AdmittedExceptionImage::from_mapped_image(mapping.base, bytes.into_boxed_slice())
        .map_err(|_| ExceptionImageError::UnreadableImage)
}
