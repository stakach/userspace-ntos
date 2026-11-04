//! Buffer shape admitted for a retained, kernel-built source IRP.
//!
//! The native adapter still resolves each address to an exact live allocation and
//! revalidates its identity at completion. This contract only classifies the
//! packet's major, lengths, flags, and pointer relationships.

use nt_io_abi::major;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceAuxiliaryBufferRequest {
    pub major: u8,
    pub minor: u8,
    /// READ/WRITE transfer length or WMI REGINFO buffer size.
    pub stack_length: u32,
    pub control_code: u32,
    pub control_input_length: u32,
    pub control_output_length: u32,
    pub control_type3_input_buffer: u64,
    pub irp_flags: u32,
    pub system_buffer: u64,
    pub mdl: u64,
    pub user_buffer: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceAuxiliaryBufferKind {
    Read,
    Write,
    WmiReginfo,
    NoTransfer,
    BufferedControlOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceAuxiliaryBufferContract {
    pub kind: SourceAuxiliaryBufferKind,
    /// Bytes whose source pool identity must be retained.
    pub system_length: u32,
    /// Bytes whose caller output identity must remain valid through completion.
    pub output_length: u32,
}

/// Immutable source-stack control fields retained before provider dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapturedBufferedControlOutput {
    pub code: u32,
    pub output_length: u32,
}

impl CapturedBufferedControlOutput {
    pub const fn valid(self) -> bool {
        self.code & 3 == 0 && self.output_length != 0
    }
}

/// Classify the source-IRP auxiliary's retained buffer shape. Only output-only
/// METHOD_BUFFERED controls are admitted here; other control transfer methods
/// need their own exact child and copyout contracts.
pub fn classify_source_auxiliary_buffer(
    request: SourceAuxiliaryBufferRequest,
) -> Option<SourceAuxiliaryBufferContract> {
    let kind = match (request.major, request.minor) {
        (major::IRP_MJ_READ, _) => SourceAuxiliaryBufferKind::Read,
        (major::IRP_MJ_WRITE, _) => SourceAuxiliaryBufferKind::Write,
        (major::IRP_MJ_SYSTEM_CONTROL, 8) => SourceAuxiliaryBufferKind::WmiReginfo,
        (major::IRP_MJ_DEVICE_CONTROL, 0)
            if request.control_code & 3 == 0
                && request.stack_length == 0
                && request.control_input_length == 0
                && request.control_output_length != 0
                && request.control_type3_input_buffer == 0
                && request.irp_flags == (crate::kernel_irp_builder::IRP_BUFFERED_IO
                    | crate::kernel_irp_builder::IRP_DEALLOCATE_BUFFER
                    | crate::kernel_irp_builder::IRP_INPUT_OPERATION)
                && request.system_buffer != 0
                && request.mdl == 0
                && request.user_buffer != 0 => SourceAuxiliaryBufferKind::BufferedControlOutput,
        (major::IRP_MJ_FLUSH_BUFFERS | major::IRP_MJ_SHUTDOWN | major::IRP_MJ_PNP | major::IRP_MJ_POWER, _) =>
            SourceAuxiliaryBufferKind::NoTransfer,
        _ => return None,
    };
    Some(SourceAuxiliaryBufferContract {
        kind,
        system_length: if kind == SourceAuxiliaryBufferKind::NoTransfer { 0 }
            else if kind == SourceAuxiliaryBufferKind::BufferedControlOutput { request.control_output_length }
            else { request.stack_length },
        output_length: if kind == SourceAuxiliaryBufferKind::Read { request.stack_length }
            else if kind == SourceAuxiliaryBufferKind::BufferedControlOutput { request.control_output_length }
            else { 0 },
    })
}

/// A provider may modify the source packet after dispatch. Before completion
/// begins, the root must still see the exact code and output extent captured
/// when it accepted the child allocations.
pub fn matches_captured_buffered_control(
    request: SourceAuxiliaryBufferRequest,
    captured: CapturedBufferedControlOutput,
) -> bool {
    captured.valid()
        && request.control_code == captured.code
        && request.control_output_length == captured.output_length
        && classify_source_auxiliary_buffer(request).is_some_and(|contract| {
            contract.kind == SourceAuxiliaryBufferKind::BufferedControlOutput
                && contract.system_length == captured.output_length
                && contract.output_length == captured.output_length
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_irp_builder::{plan_device_io_control_request, IRP_BUFFERED_IO, IRP_DEALLOCATE_BUFFER, IRP_INPUT_OPERATION};

    fn geometry_output() -> SourceAuxiliaryBufferRequest {
        let plan = plan_device_io_control_request(0x0007_00a0, false, 3,
            0x1000, 0, 0, 0x3000, 40).unwrap();
        SourceAuxiliaryBufferRequest {
            major: plan.stack.major,
            minor: 0,
            stack_length: 0,
            control_code: 0x0007_00a0,
            control_input_length: 0,
            control_output_length: 40,
            control_type3_input_buffer: 0,
            irp_flags: plan.irp_flags,
            system_buffer: 0x2000,
            mdl: 0,
            user_buffer: plan.user_buffer,
        }
    }

    #[test]
    fn buffered_geometry_output_has_exact_retained_children() {
        let request = geometry_output();
        assert_eq!(request.irp_flags,
            IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION);
        assert_eq!(classify_source_auxiliary_buffer(request), Some(SourceAuxiliaryBufferContract {
            kind: SourceAuxiliaryBufferKind::BufferedControlOutput,
            system_length: 40,
            output_length: 40,
        }));
    }

    #[test]
    fn buffered_control_refuses_malformed_flags_lengths_and_children() {
        let valid = geometry_output();
        for malformed in [
            SourceAuxiliaryBufferRequest { irp_flags: valid.irp_flags & !IRP_INPUT_OPERATION, ..valid },
            SourceAuxiliaryBufferRequest { irp_flags: valid.irp_flags | 0x8000, ..valid },
            SourceAuxiliaryBufferRequest { control_code: valid.control_code | 1, ..valid },
            SourceAuxiliaryBufferRequest { control_input_length: 1, ..valid },
            SourceAuxiliaryBufferRequest { control_output_length: 0, ..valid },
            SourceAuxiliaryBufferRequest { control_type3_input_buffer: 0x5000, ..valid },
            SourceAuxiliaryBufferRequest { system_buffer: 0, ..valid },
            SourceAuxiliaryBufferRequest { mdl: 0x4000, ..valid },
            SourceAuxiliaryBufferRequest { user_buffer: 0, ..valid },
        ] {
            assert_eq!(classify_source_auxiliary_buffer(malformed), None);
        }
    }

    #[test]
    fn buffered_control_revalidation_rejects_mutated_code_length_and_flags() {
        let valid = geometry_output();
        let captured = CapturedBufferedControlOutput {
            code: valid.control_code,
            output_length: valid.control_output_length,
        };
        assert!(matches_captured_buffered_control(valid, captured));
        for mutated in [
            SourceAuxiliaryBufferRequest { control_code: valid.control_code + 4, ..valid },
            SourceAuxiliaryBufferRequest { control_output_length: 32, ..valid },
            SourceAuxiliaryBufferRequest { irp_flags: valid.irp_flags & !IRP_INPUT_OPERATION, ..valid },
        ] {
            assert!(!matches_captured_buffered_control(mutated, captured));
        }
    }

    #[test]
    fn existing_read_write_wmi_and_no_transfer_kinds_remain_admitted() {
        let baseline = SourceAuxiliaryBufferRequest {
            major: major::IRP_MJ_READ, minor: 0, stack_length: 512,
            control_code: 0, control_input_length: 0, control_output_length: 0,
            control_type3_input_buffer: 0,
            irp_flags: 0, system_buffer: 0, mdl: 0x4000, user_buffer: 0,
        };
        assert_eq!(classify_source_auxiliary_buffer(baseline).unwrap().kind,
            SourceAuxiliaryBufferKind::Read);
        assert_eq!(classify_source_auxiliary_buffer(SourceAuxiliaryBufferRequest {
            major: major::IRP_MJ_WRITE, ..baseline
        }).unwrap().kind, SourceAuxiliaryBufferKind::Write);
        assert_eq!(classify_source_auxiliary_buffer(SourceAuxiliaryBufferRequest {
            major: major::IRP_MJ_SYSTEM_CONTROL, minor: 8, stack_length: 24,
            irp_flags: IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER,
            system_buffer: 0x2000, mdl: 0, user_buffer: 0, ..baseline
        }).unwrap().kind, SourceAuxiliaryBufferKind::WmiReginfo);
        assert_eq!(classify_source_auxiliary_buffer(SourceAuxiliaryBufferRequest {
            major: major::IRP_MJ_PNP, stack_length: 0, mdl: 0, ..baseline
        }).unwrap().kind, SourceAuxiliaryBufferKind::NoTransfer);
    }
}
