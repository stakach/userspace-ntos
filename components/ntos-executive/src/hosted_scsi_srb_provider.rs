//! Provider-local projection of a pointer-free SCSI SRB packet.
//!
//! The packet, SRB, and MDL are retained by the ordinary pending-IRP graph through terminal
//! completion and acknowledgement. The packet allocation also owns the data and sense slices.

use super::*;
use nt_io_manager::scsi_srb_transport::{ScsiDmaReceipt, ScsiSrbRoute,
    WDM_X64_LEGACY_SRB_SIZE};
use nt_io_manager::scsi_srb_wire::{
    capture_scsi_completion_in_place, decode_scsi_request,
};

#[derive(Clone, Copy)]
pub(super) struct ProviderScsiProjection {
    pub srb: u64,
    pub mdl: u64,
    pub route: ScsiSrbRoute,
    pub dma_receipt: Option<ScsiDmaReceipt>,
}

/// `packet` is one provider-local pool allocation already populated by the authenticated
/// transfer bank. All pointers written here refer to this provider address space.
pub(super) unsafe fn prepare(
    request: &IrpDispatchRequest, provider_pdo: u64, packet: u64, irp: u64,
) -> Result<ProviderScsiProjection, i32> {
    if request._reserved0 != nt_io_abi::IRP_DISPATCH_SCSI_SRB
        || request.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        || request.file_id != 0 || request.ioctl_code != 0
        || request.input_len != request.output_len
        || request.input_len != request.buffer_len
        || request.scsi_relation_generation == 0
        || request.target_domain_id == 0 || request.target_domain_cookie == 0
        || request.device_id == 0 || provider_pdo == 0 || packet == 0 || irp == 0
        || component_pool_allocation_capacity(packet)
            .is_none_or(|capacity| capacity < u64::from(request.input_len))
    { return Err(STATUS_INVALID_PARAMETER); }
    let route = ScsiSrbRoute {
        pdo: nt_io_manager::DeviceId(request.device_id),
        provider: HostedDomainIdentity {
            domain_id: nt_io_manager::HostedDomainId(request.target_domain_id),
            cookie: request.target_domain_cookie,
        },
        relation_generation: request.scsi_relation_generation,
        provider_pdo,
    };
    let packet_slice = core::slice::from_raw_parts(packet as *const u8, request.input_len as usize);
    let decoded = decode_scsi_request(packet_slice, route, IrpId(request.irp_id))
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let dma_receipt = if decoded.data.is_empty() { None } else {
        let (_label, status, grant_va, grant_len, reservation_id) = call_on5(
            (FSD_SERVICE_DMA_ADAPTER_LABEL << 12) | 5,
            request.irp_id,
            HOSTED_DMA_SERVICE_QUERY_SCSI_RESERVATION << HOSTED_DMA_SERVICE_OPERATION_SHIFT,
            provider_pdo, 0, 0,
        );
        if status as u32 as i32 != STATUS_SUCCESS {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        Some(ScsiDmaReceipt::from_authenticated_query(
            route, IrpId(request.irp_id), grant_va, grant_len, reservation_id,
            decoded.data.len() as u64,
        ).ok_or(STATUS_INVALID_DEVICE_REQUEST)?)
    };
    let data_pointer = dma_receipt.map_or(0, ScsiDmaReceipt::grant_va);
    if !decoded.data.is_empty() {
        core::ptr::copy_nonoverlapping(decoded.data.as_ptr(), data_pointer as *mut u8,
            decoded.data.len());
    }
    let sense_pointer = if decoded.sense.is_empty() { 0 } else { decoded.sense.as_ptr() as u64 };
    let srb = pool_alloc_zeroed(WDM_X64_LEGACY_SRB_SIZE as u64);
    if srb == 0 { return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw()); }
    core::ptr::copy_nonoverlapping(decoded.srb.as_ptr(), srb as *mut u8, WDM_X64_LEGACY_SRB_SIZE);
    write_unaligned((srb + 0x18) as *mut u64, data_pointer);
    write_unaligned((srb + 0x20) as *mut u64, sense_pointer);
    write_unaligned((srb + 0x30) as *mut u64, irp);
    let mdl = if decoded.data.is_empty() { 0 } else {
        allocate_nonpaged_mdl(data_pointer, decoded.data.len() as u64)
    };
    if !decoded.data.is_empty() && mdl == 0 {
        pool_free(srb);
        return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw());
    }
    Ok(ProviderScsiProjection { srb, mdl, route, dma_receipt })
}

/// Copy only provider scalar/CDB state into the retained packet. No provider-local pointer is
/// published in the completion buffer, including on a failing SCSI status with sense bytes.
pub(super) unsafe fn capture_completion(
    route: ScsiSrbRoute, irp_id: IrpId, packet: u64, packet_len: u64, srb: u64,
    dma_receipt: Option<ScsiDmaReceipt>,
) -> bool {
    if packet == 0 || srb == 0 || packet_len > usize::MAX as u64
        || component_pool_allocation_capacity(packet).is_none_or(|cap| cap < packet_len)
        || component_pool_allocation_capacity(srb)
            .is_none_or(|cap| cap < WDM_X64_LEGACY_SRB_SIZE as u64)
    { return false; }
    let packet_slice = core::slice::from_raw_parts_mut(packet as *mut u8, packet_len as usize);
    let srb_slice = core::slice::from_raw_parts(srb as *const u8, WDM_X64_LEGACY_SRB_SIZE);
    let (data_pointer, data_capacity) = match decode_scsi_request(packet_slice, route, irp_id) {
        Ok(decoded) => (decoded.data.as_ptr() as u64, decoded.data.len() as u64),
        Err(_) => return false,
    };
    if data_capacity != 0 {
        let transferred = read_unaligned((srb + 0x10) as *const u32) as u64;
        let Some(grant_va) = dma_receipt.and_then(|receipt| receipt.completion_source(
            route, irp_id, data_capacity,
            read_unaligned((srb + 0x18) as *const u64), transferred,
        )) else { return false; };
        core::ptr::copy_nonoverlapping(grant_va as *const u8,
            data_pointer as *mut u8, transferred as usize);
    } else if dma_receipt.is_some()
        || read_unaligned((srb + 0x18) as *const u64) != 0
    {
        return false;
    }
    let captured = capture_scsi_completion_in_place(packet_slice, route, irp_id, srb_slice).is_ok();
    static CAPACITY_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
    if captured && packet_slice.len() >= 64 + WDM_X64_LEGACY_SRB_SIZE + 12
        && srb_slice[0x48] == 0x9e && srb_slice[0x49] == 0x10
        && CAPACITY_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 4
    {
        let data = &packet_slice[64 + WDM_X64_LEGACY_SRB_SIZE..];
        print_str(b"[provider-scsi-capacity] data-pointer/expected/last-lba/sector-bytes=");
        print_u64(read_unaligned((srb + 0x18) as *const u64));
        print_str(b"/");
        print_u64(packet + (64 + WDM_X64_LEGACY_SRB_SIZE) as u64);
        print_str(b"/");
        print_u64(u64::from_be_bytes(data[0..8].try_into().unwrap()));
        print_str(b"/");
        print_u64(u32::from_be_bytes(data[8..12].try_into().unwrap()) as u64);
        print_str(b"\n");
    }
    captured
}
