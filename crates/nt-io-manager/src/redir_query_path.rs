//! Pointer-free capture policy for Mup's x64 `IOCTL_REDIR_QUERY_PATH` request.
//!
//! The caller must retain and validate the source security context separately. Its address in
//! `QUERY_PATH_REQUEST` is checked for presence but never becomes transport authority.

use alloc::vec::Vec;
use core::num::NonZeroU64;

pub const IOCTL_REDIR_QUERY_PATH: u32 = 0x0014_018f;
pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0e;
pub const QUERY_PATH_REQUEST_X64_SIZE: usize = 24;
pub const QUERY_PATH_RESPONSE_SIZE: usize = 4;

const PATH_LENGTH_OFFSET: usize = 0;
const SECURITY_CONTEXT_OFFSET: usize = 8;
const PATH_OFFSET: usize = 16;
const MAX_PATH_BYTES: usize = 65_532;
const STATUS_PENDING: u32 = 0x0000_0103;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPathError {
    WrongOperation,
    MissingSecurityContext,
    InvalidLength,
    InvalidPath,
    Pending,
    InsufficientResources,
}

/// Identity of an independently retained, generation-checked security context.
///
/// This is not a driver pointer. A transport must resolve this ticket to a valid local
/// `IO_SECURITY_CONTEXT`/access-state projection before dispatching to another driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedSecurityContextTicket {
    id: NonZeroU64,
    generation: NonZeroU64,
}

/// Source-local address checked against the security graph owned by the originating IRP.
/// The address is consumed during capture and is never stored in the forwarded request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSecurityContext {
    pub address: NonZeroU64,
    pub ticket: RetainedSecurityContextTicket,
}

impl RetainedSecurityContextTicket {
    pub fn new(id: u64, generation: u64) -> Option<Self> {
        Some(Self {
            id: NonZeroU64::new(id)?,
            generation: NonZeroU64::new(generation)?,
        })
    }

    pub fn id(self) -> u64 {
        self.id.get()
    }

    pub fn generation(self) -> u64 {
        self.generation.get()
    }
}

/// Scalar IO stack fields; no local pointers enter this descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryPathStack {
    pub major: u8,
    pub minor: u8,
    pub requestor_kernel_mode: bool,
    pub io_control_code: u32,
    pub input_buffer_length: u32,
    pub output_buffer_length: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedQueryPath {
    pub security: RetainedSecurityContextTicket,
    pub path: Vec<u16>,
    pub input_buffer_length: u32,
    pub output_buffer_length: u32,
}

impl CapturedQueryPath {
    pub fn path_length_bytes(&self) -> u32 {
        (self.path.len() * 2) as u32
    }
}

/// Capture the Mup request after the source domain has checked the exact backing allocation.
/// `source_buffer` must contain the declared input length. A nonzero pointer in the x64 request
/// must match the separately retained security graph for this source IRP.
pub fn capture_query_path(
    stack: QueryPathStack,
    source_buffer: &[u8],
    security: Option<SourceSecurityContext>,
) -> Result<CapturedQueryPath, QueryPathError> {
    if stack.major != IRP_MJ_DEVICE_CONTROL
        || stack.minor != 0
        || !stack.requestor_kernel_mode
        || stack.io_control_code != IOCTL_REDIR_QUERY_PATH
        || stack.io_control_code & 3 != 3
    {
        return Err(QueryPathError::WrongOperation);
    }
    let security = security.ok_or(QueryPathError::MissingSecurityContext)?;
    let input_len = stack.input_buffer_length as usize;
    if input_len < QUERY_PATH_REQUEST_X64_SIZE
        || input_len > source_buffer.len()
        || stack.output_buffer_length < QUERY_PATH_RESPONSE_SIZE as u32
    {
        return Err(QueryPathError::InvalidLength);
    }
    let input = &source_buffer[..input_len];
    let path_len = u32::from_le_bytes(
        input[PATH_LENGTH_OFFSET..PATH_LENGTH_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let security_pointer = u64::from_le_bytes(
        input[SECURITY_CONTEXT_OFFSET..SECURITY_CONTEXT_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    if security_pointer != security.address.get() {
        return Err(QueryPathError::MissingSecurityContext);
    }
    if path_len == 0 || path_len & 1 != 0 || path_len > MAX_PATH_BYTES {
        return Err(QueryPathError::InvalidPath);
    }
    if QUERY_PATH_REQUEST_X64_SIZE
        .checked_add(path_len)
        .is_none_or(|required| required > input_len)
    {
        return Err(QueryPathError::InvalidLength);
    }
    let mut path = Vec::new();
    path.try_reserve_exact(path_len / 2)
        .map_err(|_| QueryPathError::InsufficientResources)?;
    for unit in input[PATH_OFFSET..PATH_OFFSET + path_len].chunks_exact(2) {
        path.push(u16::from_le_bytes([unit[0], unit[1]]));
    }
    Ok(CapturedQueryPath {
        security: security.ticket,
        path,
        input_buffer_length: stack.input_buffer_length,
        output_buffer_length: stack.output_buffer_length,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryPathCompletion {
    pub status: u32,
    pub information: u64,
    pub length_accepted: u32,
}

/// Capture the provider's terminal result before the source-local Mup completion routine runs.
/// A failed IOCTL does not promise a response buffer. Successful acceptance must name a bounded
/// UTF-16 prefix of the captured path, even if the provider reports zero `Information`.
pub fn capture_completion(
    request: &CapturedQueryPath,
    status: u32,
    information: u64,
    response_buffer: &[u8],
) -> Result<QueryPathCompletion, QueryPathError> {
    if status == STATUS_PENDING {
        return Err(QueryPathError::Pending);
    }
    if information > request.output_buffer_length as u64 {
        return Err(QueryPathError::InvalidLength);
    }
    let length_accepted = if status as i32 >= 0 {
        if response_buffer.len() < QUERY_PATH_RESPONSE_SIZE {
            return Err(QueryPathError::InvalidLength);
        }
        let length = u32::from_le_bytes(response_buffer[..4].try_into().unwrap());
        if length & 1 != 0 || length > request.path_length_bytes() {
            return Err(QueryPathError::InvalidPath);
        }
        length
    } else {
        0
    };
    Ok(QueryPathCompletion {
        status,
        information,
        length_accepted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack() -> QueryPathStack {
        QueryPathStack {
            major: IRP_MJ_DEVICE_CONTROL,
            minor: 0,
            requestor_kernel_mode: true,
            io_control_code: IOCTL_REDIR_QUERY_PATH,
            input_buffer_length: 32,
            output_buffer_length: 4,
        }
    }

    fn request_bytes() -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&8u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0xfeed_cafe_dead_beefu64.to_le_bytes());
        for (index, unit) in [b'\\' as u16, b's' as u16, b'r' as u16, b'v' as u16]
            .into_iter()
            .enumerate()
        {
            bytes[16 + index * 2..18 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn security() -> SourceSecurityContext {
        SourceSecurityContext {
            address: NonZeroU64::new(0xfeed_cafe_dead_beef).unwrap(),
            ticket: RetainedSecurityContextTicket::new(7, 3).unwrap(),
        }
    }

    #[test]
    fn captured_request_owns_utf16_and_discards_source_pointer() {
        let bytes = request_bytes();
        let captured = capture_query_path(stack(), &bytes, Some(security())).unwrap();
        assert_eq!(
            captured.path,
            [b'\\' as u16, b's' as u16, b'r' as u16, b'v' as u16]
        );
        assert_eq!(captured.path_length_bytes(), 8);
        assert_eq!(captured.security.id(), 7);
        assert_eq!(captured.security.generation(), 3);
    }

    #[test]
    fn wrong_major_mode_minor_or_ioctl_is_rejected() {
        let bytes = request_bytes();
        let mut s = stack();
        s.major = 0;
        assert_eq!(
            capture_query_path(s, &bytes, Some(security())),
            Err(QueryPathError::WrongOperation)
        );
        s = stack();
        s.minor = 1;
        assert_eq!(
            capture_query_path(s, &bytes, Some(security())),
            Err(QueryPathError::WrongOperation)
        );
        s = stack();
        s.requestor_kernel_mode = false;
        assert_eq!(
            capture_query_path(s, &bytes, Some(security())),
            Err(QueryPathError::WrongOperation)
        );
        s = stack();
        s.io_control_code &= !3;
        assert_eq!(
            capture_query_path(s, &bytes, Some(security())),
            Err(QueryPathError::WrongOperation)
        );
    }

    #[test]
    fn security_requires_explicit_nonzero_retained_identity() {
        let bytes = request_bytes();
        assert!(RetainedSecurityContextTicket::new(0, 3).is_none());
        assert!(RetainedSecurityContextTicket::new(7, 0).is_none());
        assert_eq!(
            capture_query_path(stack(), &bytes, None),
            Err(QueryPathError::MissingSecurityContext)
        );
        let mut no_pointer = bytes;
        no_pointer[8..16].fill(0);
        assert_eq!(
            capture_query_path(stack(), &no_pointer, Some(security())),
            Err(QueryPathError::MissingSecurityContext)
        );
        let mut other = security();
        other.address = NonZeroU64::new(0x1000).unwrap();
        assert_eq!(
            capture_query_path(stack(), &bytes, Some(other)),
            Err(QueryPathError::MissingSecurityContext)
        );
    }

    #[test]
    fn truncated_odd_and_overlong_paths_are_rejected() {
        let bytes = request_bytes();
        let mut s = stack();
        s.input_buffer_length = 31;
        assert_eq!(
            capture_query_path(s, &bytes, Some(security())),
            Err(QueryPathError::InvalidLength)
        );
        s = stack();
        s.output_buffer_length = 3;
        assert_eq!(
            capture_query_path(s, &bytes, Some(security())),
            Err(QueryPathError::InvalidLength)
        );
        assert_eq!(
            capture_query_path(stack(), &bytes[..31], Some(security())),
            Err(QueryPathError::InvalidLength)
        );
        let mut odd = bytes;
        odd[..4].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            capture_query_path(stack(), &odd, Some(security())),
            Err(QueryPathError::InvalidPath)
        );
        let mut long = bytes;
        long[..4].copy_from_slice(&65_534u32.to_le_bytes());
        assert_eq!(
            capture_query_path(stack(), &long, Some(security())),
            Err(QueryPathError::InvalidPath)
        );
    }

    #[test]
    fn terminal_response_acceptance_is_bounded_to_path() {
        let request = capture_query_path(stack(), &request_bytes(), Some(security())).unwrap();
        assert_eq!(
            capture_completion(&request, 0, 0, &6u32.to_le_bytes()),
            Ok(QueryPathCompletion {
                status: 0,
                information: 0,
                length_accepted: 6
            })
        );
        assert_eq!(
            capture_completion(&request, STATUS_PENDING, 0, &0u32.to_le_bytes()),
            Err(QueryPathError::Pending)
        );
        assert_eq!(
            capture_completion(&request, 0, 0, &9u32.to_le_bytes()),
            Err(QueryPathError::InvalidPath)
        );
        assert_eq!(
            capture_completion(&request, 0, 0, &10u32.to_le_bytes()),
            Err(QueryPathError::InvalidPath)
        );
        assert_eq!(
            capture_completion(&request, 0, 5, &0u32.to_le_bytes()),
            Err(QueryPathError::InvalidLength)
        );
        assert_eq!(
            capture_completion(&request, 0, 0, &[]),
            Err(QueryPathError::InvalidLength)
        );
        assert_eq!(
            capture_completion(&request, 0xc000_000d, 0, &[]),
            Ok(QueryPathCompletion {
                status: 0xc000_000d,
                information: 0,
                length_accepted: 0
            })
        );
    }
}
