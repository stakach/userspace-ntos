//! How one hosted IRP dispatch (`run_irp_with_bank`) exchanges its canonical request with the
//! root: input and initial output in, the component packet's ledger binding, and the visible
//! output back out.
//!
//! The dispatch itself (FILE_OBJECT, buffers, MDLs, the driver call and its completion) does not
//! depend on how those exchanges travel. Today they travel over the component's primary pump
//! ([`PrimaryPumpIrpTransport`]), whose labels are each a wall for an IRQ lane.

use super::*;

/// The source-IRP ledger's binding of a component packet to its canonical dispatch.
#[derive(Clone, Copy)]
pub(super) struct PacketBinding {
    pub ticket: u64,
    pub generation: u64,
}

/// The exchanges a hosted IRP dispatch makes with the root for one canonical request.
pub(super) trait IrpTransport {
    /// Copies the request's `len` input bytes into `dst`. False means the input was not
    /// delivered, and the dispatch fails before driver entry.
    unsafe fn pull_input(&self, irp_id: u64, dst: u64, len: u64) -> bool;
    /// Copies the request's `len` initial output bytes into `dst`, with the same contract.
    unsafe fn pull_output(&self, irp_id: u64, dst: u64, len: u64) -> bool;
    /// Binds the component packet `irp` to the active canonical dispatch and the exact
    /// pending-node generation, before any driver code can forward it. A refusal returns the
    /// root's status. A malformed answer is a provider bugcheck, never a refusal.
    unsafe fn bind_packet(&self, owner_node: u64, irp_id: u64, irp: u64) -> Result<PacketBinding, i32>;
    /// A refused binding whose pre-entry state could not be unwound.
    unsafe fn packet_binding_violation(&self, irp: u64, detail: u64) -> !;
    /// Publishes `len` bytes of the request's visible output from `src`. False means the output
    /// was not published.
    unsafe fn push_output(&self, irp_id: u64, src: u64, len: u64) -> bool;
}

/// The component's primary pump: each exchange is a Call on the primary channel.
pub(super) struct PrimaryPumpIrpTransport;

impl IrpTransport for PrimaryPumpIrpTransport {
    unsafe fn pull_input(&self, irp_id: u64, dst: u64, len: u64) -> bool {
        pull_request_bytes(FSD_SERVICE_PULL_IRP_INPUT_LABEL, irp_id, dst, len)
    }

    unsafe fn pull_output(&self, irp_id: u64, dst: u64, len: u64) -> bool {
        pull_request_bytes(FSD_SERVICE_PULL_IRP_OUTPUT_LABEL, irp_id, dst, len)
    }

    unsafe fn bind_packet(&self, owner_node: u64, irp_id: u64, irp: u64) -> Result<PacketBinding, i32> {
        let (words, status, ticket, generation, _) = call_on4_raw(
            (FSD_SERVICE_SOURCE_IRP_LABEL << 12) | 4,
            6,
            owner_node,
            irp_id,
            irp,
        );
        if words != 3 {
            self.packet_binding_violation(irp, status);
        }
        if status as u32 as i32 != STATUS_SUCCESS {
            return Err(status as u32 as i32);
        }
        if ticket == 0 || generation == 0 {
            self.packet_binding_violation(irp, ticket);
        }
        Ok(PacketBinding { ticket, generation })
    }

    unsafe fn packet_binding_violation(&self, irp: u64, detail: u64) -> ! {
        crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_SOURCE_IRP_LABEL, 6, irp, detail])
    }

    unsafe fn push_output(&self, irp_id: u64, src: u64, len: u64) -> bool {
        pool_push_request_bytes(irp_id, src, 0, 0, len)
    }
}

/// Pulls `len` bytes in ARG-window chunks through `service_label` op 3.
unsafe fn pull_request_bytes(service_label: u64, transfer_id: u64, dst: u64, len: u64) -> bool {
    let arg = hosted_provider_export_lane::current_component_arg()
        .or_else(hosted_class_irp_lane::current_component_arg).unwrap_or(FSD_ARG_VADDR);
    let mut offset = 0u64;
    while offset < len {
        let chunk = (len - offset).min(FSD_ARG_BYTES);
        let (_, status, _, _, _) =
            call_on4((service_label << 12) | 3, transfer_id, offset, chunk, 0);
        if status as u32 as i32 != STATUS_SUCCESS {
            return false;
        }
        let mut index = 0u64;
        while index < chunk {
            let byte = read_volatile((arg + index) as *const u8);
            write_volatile((dst + offset + index) as *mut u8, byte);
            index += 1;
        }
        offset += chunk;
    }
    true
}
