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
        if !matches!(op, wire::OP_DEREFERENCE | wire::OP_UNMAP | wire::OP_UNMAP_CLIENT)
            || reserved1 != 0
            || (op != wire::OP_UNMAP_CLIENT && reserved0 != 0)
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
        let handler = match service_sec_image::registry_live_handler_pointer() {
            Ok(handler) => {
                service_sec_image::registered_section_table_for_handler(handler)?;
                handler
            }
            Err(_) if op != wire::OP_UNMAP_CLIENT => {
                service_sec_image::bootstrap_section_table()?;
                let caller = provider_registry_caller::resolve(channel)?;
                if !provider_section_broker::bootstrap_caller_admitted(caller) {
                    return Err(nt_process::STATUS_INVALID_HANDLE);
                }
                core::ptr::null_mut()
            }
            Err(status) => return Err(status),
        };
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
            wire::OP_UNMAP_CLIENT => {
                provider_mm_section_objects::unmap_client(handler, physical, address, reserved0)
                    .map(|()| 0)
            }
            _ => unreachable!(),
        };
        if !handler.is_null() {
            provider_section_receipts::observe_cleanup_result(
                handler, channel, physical, op, address, &result, retired_view,
            );
        }
        result
    })();
    SubmitResult::Ready(match result {
        Ok(count) => (0, count, 0, 0),
        Err(status) => (status as i32, 0, 0, 0),
    })
}
