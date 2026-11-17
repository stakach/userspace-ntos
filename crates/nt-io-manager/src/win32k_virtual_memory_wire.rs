//! Four-word win32k Mm request for the attached client's address space.
//!
//! win32k's `ZwAllocateVirtualMemory`, `ZwFreeVirtualMemory`, `MmSecureVirtualMemory` and
//! `MmUnsecureVirtualMemory` all act on the process win32k is attached to. The executive owns
//! that process's VADs, commit charge and secure leases; win32k sends only these values.

/// Message registers carried by one request.
pub const WORDS: usize = 4;

const OP_SECURE: u64 = 1;
const OP_UNSECURE: u64 = 2;
const OP_ALLOCATE: u64 = 3;
const OP_FREE: u64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtualMemoryRequest {
    /// `MmSecureVirtualMemory(Address, Size, ProbeMode)`.
    Secure {
        address: u64,
        size: u64,
        protection: u32,
    },
    /// `MmUnsecureVirtualMemory(SecureHandle)`.
    Unsecure { handle: u64 },
    /// `ZwAllocateVirtualMemory(NtCurrentProcess(), ...)` with zero `ZeroBits`.
    Allocate {
        base: u64,
        size: u64,
        allocation_type: u32,
        protection: u32,
    },
    /// `ZwFreeVirtualMemory(NtCurrentProcess(), ...)`.
    Free { base: u64, size: u64, free_type: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtualMemoryWireError {
    UnknownOperation,
    Malformed,
}

impl VirtualMemoryRequest {
    pub const fn encode(self) -> [u64; WORDS] {
        match self {
            Self::Secure {
                address,
                size,
                protection,
            } => [OP_SECURE, address, size, protection as u64],
            Self::Unsecure { handle } => [OP_UNSECURE, handle, 0, 0],
            Self::Allocate {
                base,
                size,
                allocation_type,
                protection,
            } => [
                OP_ALLOCATE,
                base,
                size,
                allocation_type as u64 | (protection as u64) << 32,
            ],
            Self::Free {
                base,
                size,
                free_type,
            } => [OP_FREE, base, size, free_type as u64],
        }
    }

    pub fn decode(words: [u64; WORDS]) -> Result<Self, VirtualMemoryWireError> {
        let [op, first, second, third] = words;
        let ulong = |value: u64| u32::try_from(value).map_err(|_| VirtualMemoryWireError::Malformed);
        match op {
            OP_SECURE => Ok(Self::Secure {
                address: first,
                size: second,
                protection: ulong(third)?,
            }),
            OP_UNSECURE if second == 0 && third == 0 => Ok(Self::Unsecure { handle: first }),
            OP_ALLOCATE => Ok(Self::Allocate {
                base: first,
                size: second,
                allocation_type: third as u32,
                protection: (third >> 32) as u32,
            }),
            OP_FREE => Ok(Self::Free {
                base: first,
                size: second,
                free_type: ulong(third)?,
            }),
            OP_UNSECURE => Err(VirtualMemoryWireError::Malformed),
            _ => Err(VirtualMemoryWireError::UnknownOperation),
        }
    }
}
