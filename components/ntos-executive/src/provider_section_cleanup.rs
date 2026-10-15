//! Retirement of already-owned kernel Section objects and views on their physical provider lane.

use super::*;
use nt_io_manager::win32k_mm_section_wire as wire;
use provider_section_broker::SubmitResult;

pub(crate) unsafe fn service_win32k_section_cleanup_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    op: u64,
    address: u64,
    reserved0: u64,
    reserved1: u64,
) -> SubmitResult {
    let result = (|| {
        if !matches!(op, wire::OP_DEREFERENCE | wire::OP_UNMAP) || reserved0 != 0 || reserved1 != 0
        {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        let (route, dispatch) = provider_service_ingress::authenticate(
            channel,
            reply_cap,
            badge,
            mi,
            (win32k_subsystem::W32_SECTION_CREATE_LABEL << 12) | 4,
        )?;
        let physical =
            provider_service_ingress::physical_win32k_provider(channel, route, dispatch)?;
        let handler = service_sec_image::registry_live_handler_pointer()?;
        if (*handler).loop_ctx.is_none() {
            return Err(0xc000_00a3);
        }
        // The canonical object/view ledger verifies exact provider ownership and records
        // retirement before effects. No logical process handle authority is acquired here.
        let mut retired_view = None;
        let result = match op {
            wire::OP_DEREFERENCE => {
                provider_mm_section_objects::dereference(handler, address, physical)
            }
            wire::OP_UNMAP => {
                provider_mm_section_objects::unmap(handler, address, physical).map(|receipt| {
                    retired_view = receipt;
                    0
                })
            }
            _ => unreachable!(),
        };
        provider_section_receipts::observe_cleanup_result(
            handler, channel, physical, op, address, &result, retired_view,
        );
        result
    })();
    SubmitResult::Ready(match result {
        Ok(count) => (0, count, 0, 0),
        Err(status) => (status as i32, 0, 0, 0),
    })
}
