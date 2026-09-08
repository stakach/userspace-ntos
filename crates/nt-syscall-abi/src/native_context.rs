//! Versioned native-call application continuation, captured before transport register clobbers.
//!
//! Requests use a distinct label, MR0 = SSN, MR1 = record pointer, MR2 onward = exact arguments.
//! The record is user-supplied execution data, not a capability, caller identity, or authority
//! token. Admission must separately establish the actual calling thread and its retained reply.
//! Capture returns owned immutable values: neither the user pointer nor a borrowed buffer survives.

pub const NT_NATIVE_CONTEXT_SYSCALL_LABEL: u64 = 0x4e55;
pub const NATIVE_CONTEXT_VERSION: u32 = 1;
pub const NATIVE_CONTEXT_BYTES: usize = 176;
pub const NATIVE_CONTEXT_ALIGNMENT: u64 = 16;
pub const NATIVE_CONTEXT_REGISTER_COUNT: usize = 18;
pub const NATIVE_CONTEXT_MAX_ARGS: u8 = 16;
pub const NATIVE_CONTEXT_PREFIX_WORDS: u64 = 2;

pub const VERSION_OFFSET: usize = 0;
pub const SIZE_OFFSET: usize = 4;
pub const SERVICE_OFFSET: usize = 8;
pub const RESERVED_HEADER_OFFSET: usize = 12;
pub const ENTRY_RSP_OFFSET: usize = 16;
pub const REGISTERS_OFFSET: usize = 24;
pub const RESERVED_TAIL_OFFSET: usize = 168;

const AMD64_USER_MAX: u64 = 0x0000_7fff_ffff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeContextError {
    InvalidEnvelope,
    UnknownService,
    InvalidArgumentCount,
    InvalidAddress,
    Misaligned,
    ReadFailed(u32),
    InvalidSize,
    UnsupportedVersion,
    ReservedBits,
    ServiceMismatch,
    InvalidInstructionPointer,
    InvalidStackPointer,
    InvalidStackRelation,
}

/// Resolve the exact service arity, never a conservative padding or unknown-service fallback.
pub fn exact_native_context_argc(ssn: u64) -> Result<u8, NativeContextError> {
    let service = u32::try_from(ssn).map_err(|_| NativeContextError::UnknownService)?;
    let argc = crate::name_of(service)
        .and_then(crate::exact_argc_of)
        .ok_or(NativeContextError::UnknownService)?;
    if argc > NATIVE_CONTEXT_MAX_ARGS {
        return Err(NativeContextError::InvalidArgumentCount);
    }
    Ok(argc)
}

/// Check the complete msginfo word, including label, exact arity, and absence of cap fields.
/// The returned arity bounds argument staging before any fallible user-memory access.
pub fn validate_native_context_request(
    message_info: u64,
    ssn: u64,
) -> Result<u8, NativeContextError> {
    let argc = exact_native_context_argc(ssn)?;
    let expected =
        (NT_NATIVE_CONTEXT_SYSCALL_LABEL << 12) | (NATIVE_CONTEXT_PREFIX_WORDS + u64::from(argc));
    if message_info != expected {
        return Err(NativeContextError::InvalidEnvelope);
    }
    Ok(argc)
}

/// Canonical UserContext order: RIP, post-RET RSP, RFLAGS, RAX, RBX, RCX, RDX, RSI, RDI,
/// RBP, R8, R9, R10, R11, R12, R13, R14, R15. No TLS bases or floating-point projections.
/// Raw flags and GPR bits are observations, not sanitized restore instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCallContinuation {
    service_number: u32,
    entry_rsp: u64,
    registers: [u64; NATIVE_CONTEXT_REGISTER_COUNT],
}

impl NativeCallContinuation {
    pub fn new(
        service_number: u32,
        entry_rsp: u64,
        registers: [u64; NATIVE_CONTEXT_REGISTER_COUNT],
        highest_user_address: u64,
    ) -> Result<Self, NativeContextError> {
        exact_native_context_argc(u64::from(service_number))?;
        let highest = highest_user_address.min(AMD64_USER_MAX);
        if registers[0] == 0 || registers[0] > highest {
            return Err(NativeContextError::InvalidInstructionPointer);
        }
        if entry_rsp == 0 || entry_rsp > highest || registers[1] == 0 || registers[1] > highest {
            return Err(NativeContextError::InvalidStackPointer);
        }
        if entry_rsp.checked_add(8) != Some(registers[1]) {
            return Err(NativeContextError::InvalidStackRelation);
        }
        Ok(Self {
            service_number,
            entry_rsp,
            registers,
        })
    }

    /// Decode exactly one complete record. Do not derive the return PC from executable bytes
    /// or assume a fixed distance between this record and its producer's caller frame.
    pub fn decode(
        bytes: &[u8],
        expected_ssn: u64,
        highest_user_address: u64,
    ) -> Result<Self, NativeContextError> {
        exact_native_context_argc(expected_ssn)?;
        if bytes.len() != NATIVE_CONTEXT_BYTES {
            return Err(NativeContextError::InvalidSize);
        }
        if u32_at(bytes, VERSION_OFFSET) != NATIVE_CONTEXT_VERSION {
            return Err(NativeContextError::UnsupportedVersion);
        }
        if u32_at(bytes, SIZE_OFFSET) != NATIVE_CONTEXT_BYTES as u32 {
            return Err(NativeContextError::InvalidSize);
        }
        if u32_at(bytes, RESERVED_HEADER_OFFSET) != 0 || u64_at(bytes, RESERVED_TAIL_OFFSET) != 0 {
            return Err(NativeContextError::ReservedBits);
        }
        let ssn = u32_at(bytes, SERVICE_OFFSET);
        if u64::from(ssn) != expected_ssn {
            return Err(NativeContextError::ServiceMismatch);
        }
        let mut registers = [0; NATIVE_CONTEXT_REGISTER_COUNT];
        for (index, value) in registers.iter_mut().enumerate() {
            *value = u64_at(bytes, REGISTERS_OFFSET + index * 8);
        }
        Self::new(
            ssn,
            u64_at(bytes, ENTRY_RSP_OFFSET),
            registers,
            highest_user_address,
        )
    }

    /// Validate framing and the entire lower-canonical user span before invoking the reader.
    /// Read exactly once, preserving its precise error even after a partial copy. The caller
    /// must stage request arguments before this call if the reader can perform nested IPC.
    pub fn capture(
        message_info: u64,
        ssn: u64,
        record_address: u64,
        highest_user_address: u64,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<(), u32>,
    ) -> Result<Self, NativeContextError> {
        validate_native_context_request(message_info, ssn)?;
        let highest = highest_user_address.min(AMD64_USER_MAX);
        if record_address == 0
            || record_address
                .checked_add(NATIVE_CONTEXT_BYTES as u64 - 1)
                .is_none_or(|last| last > highest)
        {
            return Err(NativeContextError::InvalidAddress);
        }
        if record_address % NATIVE_CONTEXT_ALIGNMENT != 0 {
            return Err(NativeContextError::Misaligned);
        }
        let mut bytes = [0; NATIVE_CONTEXT_BYTES];
        read(record_address, &mut bytes).map_err(NativeContextError::ReadFailed)?;
        Self::decode(&bytes, ssn, highest_user_address)
    }

    pub const fn service_number(&self) -> u32 {
        self.service_number
    }
    pub const fn entry_rsp(&self) -> u64 {
        self.entry_rsp
    }
    pub const fn registers(&self) -> &[u64; NATIVE_CONTEXT_REGISTER_COUNT] {
        &self.registers
    }

    /// Encode little-endian wire bytes without relying on Rust struct layout or padding.
    pub fn encode(&self) -> [u8; NATIVE_CONTEXT_BYTES] {
        let mut bytes = [0; NATIVE_CONTEXT_BYTES];
        bytes[VERSION_OFFSET..VERSION_OFFSET + 4]
            .copy_from_slice(&NATIVE_CONTEXT_VERSION.to_le_bytes());
        bytes[SIZE_OFFSET..SIZE_OFFSET + 4]
            .copy_from_slice(&(NATIVE_CONTEXT_BYTES as u32).to_le_bytes());
        bytes[SERVICE_OFFSET..SERVICE_OFFSET + 4]
            .copy_from_slice(&self.service_number.to_le_bytes());
        bytes[ENTRY_RSP_OFFSET..ENTRY_RSP_OFFSET + 8]
            .copy_from_slice(&self.entry_rsp.to_le_bytes());
        for (index, value) in self.registers.iter().enumerate() {
            let offset = REGISTERS_OFFSET + index * 8;
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests;
