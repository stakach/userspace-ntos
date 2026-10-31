//! Authenticated native win32k process query and exact shared-pool response publication.

use super::*;
use crate::process_information_bridge::{
    decode_request, encode_response, HEADER_SIZE, MAX_OUTPUT_BYTES,
};
use crate::process_information_capture::{capture_process_information, ProcessImageEvidence};

const INVALID_HANDLE: u32 = nt_process::STATUS_INVALID_HANDLE;
const INVALID_PARAMETER: u32 = nt_process::STATUS_INVALID_PARAMETER;
const DEVICE_NOT_READY: u32 = 0xC000_00A3;

unsafe fn image_evidence_for_process<'a>(
    handler: &'a ExecNtHandler,
    target_pid: nt_process::ProcessId,
) -> Option<ProcessImageEvidence<'a>> {
    let mut selected = None;
    for pi in 0..MAX_PI {
        if handler.pm_pid_for_pi(pi) == Some(target_pid) {
            if selected.replace(pi).is_some() {
                return None;
            }
        }
    }
    let pi = selected?;
    let image = handler.hosted_process_image(pi)?;
    let generation = handler.hosted_process_generation(pi)?;
    if generation == 0 || image.pi != pi || image.generation != generation || image.top_badge == 0 {
        return None;
    }
    let ctx = handler.loop_ctx?.for_process(pi)?;
    if ctx.owner_pid != target_pid || ctx.owner_generation != generation {
        return None;
    }
    let _reader = crate::hosted_loaded_images::HostedImageReadScope::capture(
        ctx.hosted_loaded_images,
        nt_exe_image::SpawnTarget::from_image(image),
    ).ok()?;
    let (pe, _) = (&*ctx.hosted_loaded_images).pe_and_pool_for_image(image)?;
    let image_size = pe.size_of_image();
    let file_size = u32::try_from(pe.bytes().len()).ok()?;
    let (subsystem_major, subsystem_minor) = pe.subsystem_version();
    let mut information = nt_dll_registry::image_info(
        ctx.img_base,
        pe.entry_point_rva(),
        image_size,
        false,
    );
    information[0x10..0x18].copy_from_slice(&pe.size_of_stack_reserve().to_le_bytes());
    information[0x18..0x20].copy_from_slice(&pe.size_of_stack_commit().to_le_bytes());
    information[0x20..0x24].copy_from_slice(&(pe.subsystem() as u32).to_le_bytes());
    information[0x24..0x26].copy_from_slice(&subsystem_minor.to_le_bytes());
    information[0x26..0x28].copy_from_slice(&subsystem_major.to_le_bytes());
    information[0x38..0x3c].copy_from_slice(&file_size.to_le_bytes());
    Some(ProcessImageEvidence {
        process_id: target_pid,
        image,
        image_information: information,
    })
}

/// The pump owns the reply cap and has already authenticated the physical badge. This service
/// binds it again to the exact native caller, selected attach owner, and pool allocation identity.
pub(crate) unsafe fn service_win32k_process_query_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    packet: u64,
    packet_length: u64,
    packet_generation: u64,
    reserved2: u64,
) -> i32 {
    let reject = |status: u32| status as i32;
    if packet_generation == 0
        || reserved2 != 0
        || packet_length < HEADER_SIZE as u64
        || packet_length > (HEADER_SIZE + MAX_OUTPUT_BYTES) as u64
    {
        return reject(INVALID_PARAMETER);
    }
    let (route, dispatch, caller) = match authenticate_win32k_service_request(
        channel, reply_cap, badge, mi,
        (win32k_subsystem::W32_PROCESS_QUERY_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => return reject(status),
    };
    if crate::provider_service_ingress::physical_win32k_provider(channel, route, dispatch).is_err() {
        return reject(INVALID_HANDLE);
    }
    let Some(logical) = channel.logical_caller else { return reject(INVALID_HANDLE); };
    if caller.effective_process() != logical.thread().process_id()
        || !validate_provider_logical_caller(logical)
    {
        return reject(INVALID_HANDLE);
    }
    let Some(effective) = crate::win32k_glue::current_query_process(logical, channel.pml4) else {
        return reject(INVALID_HANDLE);
    };
    let handler_ptr = SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) as *mut ExecNtHandler;
    if handler_ptr.is_null() {
        return reject(DEVICE_NOT_READY);
    }
    let handler = &*handler_ptr;
    if handler.hosted_process_generation(effective.pi) != Some(match effective.process.generation {
        nt_user_host::process_identity::ProcessGeneration::Hosted(generation) => generation,
        _ => return reject(INVALID_HANDLE),
    }) || handler.pm_pid_for_pi(effective.pi) != Some(effective.process.pid)
    {
        return reject(INVALID_HANDLE);
    }
    let packet_length = packet_length as usize;
    let (lease, mut bytes) = match win32k_subsystem::capture_provider_pool_packet(packet, packet_length) {
        Ok(captured) => captured,
        Err(status) => return reject(status),
    };
    if lease.native_identity().allocation_generation != packet_generation {
        return reject(INVALID_HANDLE);
    }
    let Some(pin) = win32k_subsystem::pin_root_provider_pool_packet(lease) else {
        return reject(INVALID_HANDLE);
    };
    let result = (|| {
        let request = decode_request(&bytes).map_err(|_| INVALID_PARAMETER)?;
        let dos_root = crate::installed_layout::DOS_ROOT_PREFIX
            .strip_suffix(b"\\")
            .ok_or(INVALID_PARAMETER)?;
        let captured = capture_process_information(
            &handler.pm,
            effective.process.pid,
            request.handle,
            request.class,
            request.output_address,
            request.output_length,
            dos_root,
            |target_pid| image_evidence_for_process(handler, target_pid),
        );
        encode_response(
            &mut bytes,
            request,
            captured.status,
            captured.return_length,
            &captured.bytes,
        ).map_err(|_| INVALID_PARAMETER)?;
        if !win32k_subsystem::publish_provider_pool_packet(lease, &bytes) {
            // Publication might have touched shared memory. Keep the pin and stop; never replay
            // this request or let its allocation be reused after an uncertain result.
            crate::provider_bugcheck::report(
                0xc4,
                [win32k_subsystem::W32_PROCESS_QUERY_LABEL, packet, packet_length as u64, 2],
            );
        }
        Ok::<(), u32>(())
    })();
    if !win32k_subsystem::release_component_provider_pool_packet_pin(lease, pin) {
        crate::provider_bugcheck::report(
            0xc4,
            [win32k_subsystem::W32_PROCESS_QUERY_LABEL, packet, packet_length as u64, 3],
        );
    }
    result.err().unwrap_or(0) as i32
}
