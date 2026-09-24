//! Scalar policy for the 14-argument kernel IoCreateFile entry point.

use alloc::vec::Vec;
use nt_types::AccessMode;

pub const IO_FORCE_ACCESS_CHECK: u32 = 0x1;
pub const IO_NO_PARAMETER_CHECKING: u32 = 0x100;
pub const IO_CHECK_CREATE_PARAMETERS: u32 = 0x200;
pub const IO_ATTACH_DEVICE: u32 = 0x400;
pub const IO_ATTACH_DEVICE_API: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoCreateFileType {
    Ordinary,
    NamedPipe,
    Mailslot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoCreateFileScalars {
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub create_options: u32,
    pub create_file_type: u32,
    pub extra_create_parameters_present: bool,
    pub io_options: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoCreateFilePolicy {
    pub file_type: IoCreateFileType,
    pub major: u8,
    pub access_mode: AccessMode,
    pub check_parameters: bool,
    pub force_access_check: bool,
    pub create_options: u32,
    pub io_options: u32,
    pub create_stack_flags: u8,
}

/// Input data copied out of a driver's address space before an IoCreateFile request is sent.
/// Output pointers and the reply capability remain owned by the caller-side transaction.
pub struct IoCreateFileInput<'a> {
    pub scalars: IoCreateFileScalars,
    pub previous_mode: AccessMode,
    pub object_attributes: u32,
    pub root_directory: u64,
    pub name: &'a [u16],
    pub allocation_size: Option<i64>,
    pub ea: &'a [u8],
    pub security_descriptor: Option<&'a [u8]>,
    pub security_qos: Option<&'a [u8]>,
    pub extra_create_parameters: Option<&'a [u8]>,
}

/// No field in this request is a pointer into the hosted driver's memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedIoCreateFileRequest {
    pub policy: IoCreateFilePolicy,
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub object_attributes: u32,
    pub root_directory: u64,
    pub name: Vec<u16>,
    pub allocation_size: Option<i64>,
    pub ea: Vec<u8>,
    pub security_descriptor: Option<Vec<u8>>,
    pub security_qos: Option<Vec<u8>>,
    pub extra_create_parameters: Option<Vec<u8>>,
}

fn copy_bytes(source: &[u8]) -> Result<Vec<u8>, u32> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(source.len())
        .map_err(|_| 0xc000_009au32)?; // STATUS_INSUFFICIENT_RESOURCES
    owned.extend_from_slice(source);
    Ok(owned)
}

fn copy_optional_bytes(source: Option<&[u8]>) -> Result<Option<Vec<u8>>, u32> {
    source.map(copy_bytes).transpose()
}

/// Build the transfer owner only after the driver adapter has probed and copied each pointed-to
/// structure. The adapter must not send raw OA, EA, or security pointers to the executive.
pub fn capture(input: IoCreateFileInput<'_>) -> Result<OwnedIoCreateFileRequest, u32> {
    const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
    const STATUS_EA_LIST_INCONSISTENT: u32 = 0x8000_0014;
    if input.name.len() > (u16::MAX as usize / 2)
        || input.allocation_size.is_some_and(|size| size < 0)
        || input.scalars.extra_create_parameters_present != input.extra_create_parameters.is_some()
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let policy = classify(input.scalars, input.previous_mode)?;
    if !input.ea.is_empty() && super::validate_ea_buffer(input.ea).is_err() {
        return Err(STATUS_EA_LIST_INCONSISTENT);
    }
    let mut name = Vec::new();
    name.try_reserve_exact(input.name.len())
        .map_err(|_| 0xc000_009au32)?;
    name.extend_from_slice(input.name);
    Ok(OwnedIoCreateFileRequest {
        policy,
        desired_access: input.scalars.desired_access,
        file_attributes: input.scalars.file_attributes,
        share_access: input.scalars.share_access,
        disposition: input.scalars.disposition,
        object_attributes: input.object_attributes,
        root_directory: input.root_directory,
        name,
        allocation_size: input.allocation_size,
        ea: copy_bytes(input.ea)?,
        security_descriptor: copy_optional_bytes(input.security_descriptor)?,
        security_qos: copy_optional_bytes(input.security_qos)?,
        extra_create_parameters: copy_optional_bytes(input.extra_create_parameters)?,
    })
}

/// Classify the scalar kernel entry contract. This does not capture pointers, authorize a name,
/// or validate the type-specific pipe/mailslot extra structure; the native adapter must do those
/// before dispatch. `Options` is deliberately separate from `CreateOptions`.
pub fn classify(
    args: IoCreateFileScalars,
    previous_mode: AccessMode,
) -> Result<IoCreateFilePolicy, u32> {
    const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

    let (file_type, major) = match args.create_file_type {
        0 => (IoCreateFileType::Ordinary, nt_io_abi::major::IRP_MJ_CREATE),
        1 => (
            IoCreateFileType::NamedPipe,
            nt_io_abi::major::IRP_MJ_CREATE_NAMED_PIPE,
        ),
        2 => (
            IoCreateFileType::Mailslot,
            nt_io_abi::major::IRP_MJ_CREATE_MAILSLOT,
        ),
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    if file_type != IoCreateFileType::Ordinary && !args.extra_create_parameters_present {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let access_mode = if args.io_options & IO_NO_PARAMETER_CHECKING != 0 {
        AccessMode::KernelMode
    } else {
        previous_mode
    };
    let check_parameters =
        access_mode != AccessMode::KernelMode || args.io_options & IO_CHECK_CREATE_PARAMETERS != 0;
    if check_parameters && file_type == IoCreateFileType::Ordinary {
        nt_fs::validate_file_create_parameters(
            args.desired_access,
            args.file_attributes,
            args.share_access,
            args.disposition,
            args.create_options,
        )?;
    }
    let mut create_options = args.create_options;
    let mut io_options = args.io_options;
    if access_mode == AccessMode::KernelMode && create_options & IO_ATTACH_DEVICE_API != 0 {
        create_options &= !IO_ATTACH_DEVICE_API;
        io_options |= IO_ATTACH_DEVICE;
    }
    Ok(IoCreateFilePolicy {
        file_type,
        major,
        access_mode,
        check_parameters,
        force_access_check: io_options & IO_FORCE_ACCESS_CHECK != 0,
        create_options,
        io_options,
        create_stack_flags: io_options as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_io_abi::major;

    fn mup() -> IoCreateFileScalars {
        IoCreateFileScalars {
            desired_access: 1,
            file_attributes: 0,
            share_access: 3,
            disposition: nt_fs::FILE_OPEN,
            create_options: 0,
            create_file_type: 0,
            extra_create_parameters_present: false,
            io_options: IO_NO_PARAMETER_CHECKING,
        }
    }

    fn mup_input<'a>(name: &'a [u16], ea: &'a [u8]) -> IoCreateFileInput<'a> {
        IoCreateFileInput {
            scalars: mup(),
            previous_mode: AccessMode::UserMode,
            object_attributes: 0x240,
            root_directory: 0,
            name,
            allocation_size: None,
            ea,
            security_descriptor: None,
            security_qos: None,
            extra_create_parameters: None,
        }
    }

    #[test]
    fn captured_mup_request_owns_name_and_optional_data() {
        let mut name = [b'\\' as u16, b'D' as u16, b'e' as u16, b'v' as u16];
        let mut security = [1u8, 2, 3, 4];
        let mut qos = [8u8, 9];
        let mut input = mup_input(&name, &[]);
        input.security_descriptor = Some(&security);
        input.security_qos = Some(&qos);
        let captured = capture(input).unwrap();
        name.fill(0);
        security.fill(0);
        qos.fill(0);
        assert_eq!(
            captured.name,
            [b'\\' as u16, b'D' as u16, b'e' as u16, b'v' as u16]
        );
        assert_eq!(
            captured.security_descriptor.as_deref(),
            Some(&[1, 2, 3, 4][..])
        );
        assert_eq!(captured.security_qos.as_deref(), Some(&[8, 9][..]));
        assert_eq!(captured.policy.access_mode, AccessMode::KernelMode);
        assert_eq!(captured.object_attributes, 0x240);
    }

    #[test]
    fn capture_rejects_invalid_optional_inputs_before_transfer() {
        let mut input = mup_input(&[b'X' as u16], &[]);
        input.allocation_size = Some(-1);
        assert!(matches!(capture(input), Err(0xc000_000d)));

        let mut input = mup_input(&[b'X' as u16], &[]);
        input.scalars.extra_create_parameters_present = true;
        assert!(matches!(capture(input), Err(0xc000_000d)));

        let input = mup_input(&[b'X' as u16], &[0; 7]);
        assert!(matches!(capture(input), Err(0x8000_0014)));
    }

    #[test]
    fn capture_keeps_io_options_distinct_from_create_options() {
        let input = mup_input(&[b'X' as u16], &[]);
        let captured = capture(input).unwrap();
        assert_eq!(captured.policy.io_options, IO_NO_PARAMETER_CHECKING);
        assert_eq!(captured.policy.create_options, 0);
    }

    #[test]
    fn mup_kernel_open_keeps_io_options_separate_from_create_options() {
        let policy = classify(mup(), AccessMode::UserMode).unwrap();
        assert_eq!(policy.file_type, IoCreateFileType::Ordinary);
        assert_eq!(policy.major, major::IRP_MJ_CREATE);
        assert_eq!(policy.access_mode, AccessMode::KernelMode);
        assert!(!policy.check_parameters);
        assert_eq!(policy.create_options, 0);
        assert_eq!(policy.io_options, IO_NO_PARAMETER_CHECKING);
        assert_eq!(policy.create_stack_flags, 0);
    }

    #[test]
    fn checked_user_or_explicit_kernel_call_validates_ordinary_create() {
        let mut args = mup();
        args.share_access = 8;
        assert!(
            !classify(args, AccessMode::UserMode)
                .unwrap()
                .check_parameters
        );
        args.io_options = 0;
        assert_eq!(classify(args, AccessMode::UserMode), Err(0xc000_000d));
        assert!(
            !classify(args, AccessMode::KernelMode)
                .unwrap()
                .check_parameters
        );
        args.io_options = IO_NO_PARAMETER_CHECKING | IO_CHECK_CREATE_PARAMETERS;
        assert_eq!(classify(args, AccessMode::UserMode), Err(0xc000_000d));
    }

    #[test]
    fn force_access_and_attach_flags_are_preserved_in_their_own_domains() {
        let mut args = mup();
        args.io_options |= IO_FORCE_ACCESS_CHECK;
        args.create_options = IO_ATTACH_DEVICE_API;
        let policy = classify(args, AccessMode::KernelMode).unwrap();
        assert!(policy.force_access_check);
        assert_eq!(policy.create_options, 0);
        assert_eq!(
            policy.io_options,
            IO_NO_PARAMETER_CHECKING | IO_FORCE_ACCESS_CHECK | IO_ATTACH_DEVICE
        );
        assert_eq!(policy.create_stack_flags, IO_FORCE_ACCESS_CHECK as u8);
    }

    #[test]
    fn pipe_and_mailslot_are_distinct_create_majors() {
        let mut args = mup();
        args.create_file_type = 1;
        assert_eq!(classify(args, AccessMode::KernelMode), Err(0xc000_000d));
        args.extra_create_parameters_present = true;
        assert_eq!(
            classify(args, AccessMode::KernelMode).unwrap().major,
            major::IRP_MJ_CREATE_NAMED_PIPE
        );
        args.create_file_type = 2;
        assert_eq!(
            classify(args, AccessMode::KernelMode).unwrap().major,
            major::IRP_MJ_CREATE_MAILSLOT
        );
        args.create_file_type = 3;
        assert_eq!(classify(args, AccessMode::KernelMode), Err(0xc000_000d));
    }
}
