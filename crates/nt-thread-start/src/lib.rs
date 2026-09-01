#![no_std]

pub const CONTEXT_RCX_OFFSET: u64 = 0x80;
pub const CONTEXT_RDX_OFFSET: u64 = 0x88;
pub const CONTEXT_RAX_OFFSET: u64 = 0x78;
pub const CONTEXT_RBX_OFFSET: u64 = 0x90;
pub const CONTEXT_RSP_OFFSET: u64 = 0x98;
pub const CONTEXT_RBP_OFFSET: u64 = 0xa0;
pub const CONTEXT_RSI_OFFSET: u64 = 0xa8;
pub const CONTEXT_RDI_OFFSET: u64 = 0xb0;
pub const CONTEXT_R8_OFFSET: u64 = 0xb8;
pub const CONTEXT_R9_OFFSET: u64 = 0xc0;
pub const CONTEXT_R10_OFFSET: u64 = 0xc8;
pub const CONTEXT_R11_OFFSET: u64 = 0xd0;
pub const CONTEXT_R12_OFFSET: u64 = 0xd8;
pub const CONTEXT_R13_OFFSET: u64 = 0xe0;
pub const CONTEXT_R14_OFFSET: u64 = 0xe8;
pub const CONTEXT_R15_OFFSET: u64 = 0xf0;
pub const CONTEXT_RIP_OFFSET: u64 = 0xf8;
pub const AMD64_CONTEXT_SIZE: usize = 0x4d0;
pub const USER_PAGE_SIZE: u64 = 0x1000;

pub const CONTEXT_P1_HOME_OFFSET: u64 = 0x00;
pub const CONTEXT_P2_HOME_OFFSET: u64 = 0x08;
pub const CONTEXT_P3_HOME_OFFSET: u64 = 0x10;
pub const CONTEXT_P4_HOME_OFFSET: u64 = 0x18;
pub const CONTEXT_DR0_OFFSET: u64 = 0x48;
pub const CONTEXT_DR1_OFFSET: u64 = 0x50;
pub const CONTEXT_DR2_OFFSET: u64 = 0x58;
pub const CONTEXT_DR3_OFFSET: u64 = 0x60;
pub const CONTEXT_DR6_OFFSET: u64 = 0x68;
pub const CONTEXT_DR7_OFFSET: u64 = 0x70;

const CONTEXT_FLAGS_OFFSET: usize = 0x30;
const CONTEXT_MXCSR_OFFSET: usize = 0x34;
const CONTEXT_SEG_CS_OFFSET: usize = 0x38;
const CONTEXT_SEG_DS_OFFSET: usize = 0x3a;
const CONTEXT_SEG_ES_OFFSET: usize = 0x3c;
const CONTEXT_SEG_FS_OFFSET: usize = 0x3e;
const CONTEXT_SEG_GS_OFFSET: usize = 0x40;
const CONTEXT_SEG_SS_OFFSET: usize = 0x42;
const CONTEXT_EFLAGS_OFFSET: usize = 0x44;

const CONTEXT_AMD64_FULL_WITH_SEGMENTS: u32 = 0x0010_000f;
const INITIAL_MXCSR: u32 = 0x1f80;
const EFLAGS_INTERRUPT_MASK: u32 = 0x200;
const USER_CODE_SELECTOR: u16 = 0x33;
const USER_DATA_SELECTOR: u16 = 0x2b;
const USER_CMTEB_SELECTOR: u16 = 0x53;

pub const INITIAL_TEB_STACK_BASE_OFFSET: u64 = 0x10;
pub const INITIAL_TEB_STACK_LIMIT_OFFSET: u64 = 0x18;
pub const INITIAL_TEB_ALLOCATED_STACK_BASE_OFFSET: u64 = 0x20;

pub const CALL_TRAMPOLINE_LEN: usize = 42;
pub const LOADER_TRAMPOLINE_LEN: usize = 93;
pub const AMD64_HW_BREAKPOINT_SLOTS: usize = 4;
pub const AMD64_DR6_INITIAL: u64 = 0xFFFF_0FF0;
pub const AMD64_DR7_RESERVED_ONE: u64 = 0x0000_0400;
pub const DEBUG_BREAKPOINT_DATA: u64 = 0;
pub const DEBUG_BREAKPOINT_INSTRUCTION: u64 = 1;
pub const DEBUG_ACCESS_READ: u64 = 0;
pub const DEBUG_ACCESS_WRITE: u64 = 1;
pub const DEBUG_ACCESS_READWRITE: u64 = 2;

const AMD64_DR7_ENABLE_MASK: u64 = 0x0000_00ff;
const AMD64_DR7_EXACT_MASK: u64 = 0x0000_0300;
const AMD64_DR7_SLOT_CONTROL_MASK: u64 = 0xffff_0000;
const AMD64_DR7_SUPPORTED_MASK: u64 = AMD64_DR7_ENABLE_MASK
    | AMD64_DR7_EXACT_MASK
    | AMD64_DR7_RESERVED_ONE
    | AMD64_DR7_SLOT_CONTROL_MASK;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Amd64ThreadContext {
    pub rip: u64,
    pub rsp: u64,
    pub rcx: u64,
    pub rdx: u64,
}

impl Amd64ThreadContext {
    pub fn read(mut read_u64: impl FnMut(u64) -> u64, context_va: u64) -> Self {
        Self {
            rip: read_u64(context_va + CONTEXT_RIP_OFFSET),
            rsp: read_u64(context_va + CONTEXT_RSP_OFFSET),
            rcx: read_u64(context_va + CONTEXT_RCX_OFFSET),
            rdx: read_u64(context_va + CONTEXT_RDX_OFFSET),
        }
    }

    pub fn call_trampoline(self) -> [u8; CALL_TRAMPOLINE_LEN] {
        let mut code = [0u8; CALL_TRAMPOLINE_LEN];
        code[0..4].copy_from_slice(&[0x48, 0x83, 0xec, 0x20]); // sub rsp, 32-byte home space
        code[4..6].copy_from_slice(&[0x48, 0xb9]);
        code[6..14].copy_from_slice(&self.rcx.to_le_bytes());
        code[14..16].copy_from_slice(&[0x48, 0xba]);
        code[16..24].copy_from_slice(&self.rdx.to_le_bytes());
        code[24..26].copy_from_slice(&[0x48, 0xb8]);
        code[26..34].copy_from_slice(&self.rip.to_le_bytes());
        code[34..36].copy_from_slice(&[0xff, 0xd0]);
        code[36..40].copy_from_slice(&[0x48, 0x83, 0xc4, 0x20]);
        code[40..42].copy_from_slice(&[0xeb, 0xfe]);
        code
    }

    /// Call `LdrInitializeThunk` with the native initial-APC register contract, then restore this
    /// context from durable target memory and jump to its original instruction pointer.
    pub fn loader_trampoline(
        loader_va: u64,
        ntdll_base: u64,
        context_va: u64,
    ) -> [u8; LOADER_TRAMPOLINE_LEN] {
        let mut code = [0u8; LOADER_TRAMPOLINE_LEN];
        let mut at = 0usize;
        let mut emit = |bytes: &[u8]| {
            code[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };

        emit(&[0x48, 0xb9]); // movabs rcx, 0
        emit(&0u64.to_le_bytes());
        emit(&[0x48, 0xba]); // movabs rdx, ntdll_base
        emit(&ntdll_base.to_le_bytes());
        emit(&[0x45, 0x31, 0xc0]); // xor r8d, r8d
        emit(&[0x49, 0xb9]); // movabs r9, context_va
        emit(&context_va.to_le_bytes());
        emit(&[0x48, 0xb8]); // movabs rax, loader_va
        emit(&loader_va.to_le_bytes());
        emit(&[0x48, 0x83, 0xec, 0x20]); // Win64 caller home space
        emit(&[0xff, 0xd0]); // call rax
        emit(&[0x48, 0x83, 0xc4, 0x20]);

        emit(&[0x48, 0xb8]); // movabs rax, context_va
        emit(&context_va.to_le_bytes());
        emit(&[0x48, 0x8b, 0x88]); // mov rcx, [rax+CONTEXT.Rcx]
        emit(&(CONTEXT_RCX_OFFSET as u32).to_le_bytes());
        emit(&[0x48, 0x8b, 0x90]); // mov rdx, [rax+CONTEXT.Rdx]
        emit(&(CONTEXT_RDX_OFFSET as u32).to_le_bytes());
        emit(&[0x48, 0x8b, 0xa0]); // mov rsp, [rax+CONTEXT.Rsp]
        emit(&(CONTEXT_RSP_OFFSET as u32).to_le_bytes());
        emit(&[0x48, 0x8b, 0x80]); // mov rax, [rax+CONTEXT.Rip]
        emit(&(CONTEXT_RIP_OFFSET as u32).to_le_bytes());
        emit(&[0xff, 0xe0]); // jmp rax
        debug_assert_eq!(at, LOADER_TRAMPOLINE_LEN);
        code
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Amd64DebugBreakpoint {
    pub address: u64,
    pub breakpoint_type: u64,
    pub size: u64,
    pub access: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Amd64DebugRegisterState {
    pub dr: [u64; AMD64_HW_BREAKPOINT_SLOTS],
    pub dr6: u64,
    pub dr7: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Amd64DebugRegisterError {
    UnsupportedControlBits,
    UnsupportedIoBreakpoint,
    InvalidBreakpointType,
    InvalidBreakpointAccess,
    InvalidDataBreakpointSize,
    UnalignedDataBreakpoint,
}

/// Convert an NT AMD64 DR0-DR3/DR7 tuple into seL4-style hardware-breakpoint slot operations.
///
/// NT exposes raw architectural DR7. The microkernel backend exposes four breakpoint slots. We
/// accept either local or global enable bits for each slot, ignore stale type/length fields on
/// disabled slots, reject control bits the slot API cannot represent, and clamp enabled breakpoint
/// addresses above the supplied user ceiling the same way ReactOS does before writing a trap frame.
pub fn plan_amd64_debug_registers(
    dr: [u64; AMD64_HW_BREAKPOINT_SLOTS],
    dr7: u64,
    highest_user_address: u64,
) -> Result<[Option<Amd64DebugBreakpoint>; AMD64_HW_BREAKPOINT_SLOTS], Amd64DebugRegisterError> {
    if dr7 & !AMD64_DR7_SUPPORTED_MASK != 0 {
        return Err(Amd64DebugRegisterError::UnsupportedControlBits);
    }

    let mut slots = [None; AMD64_HW_BREAKPOINT_SLOTS];
    for slot in 0..AMD64_HW_BREAKPOINT_SLOTS {
        if ((dr7 >> (slot * 2)) & 0x3) == 0 {
            continue;
        }
        let arch_type = (dr7 >> (16 + slot * 4)) & 0x3;
        let arch_len = (dr7 >> (18 + slot * 4)) & 0x3;
        let (breakpoint_type, access) = match arch_type {
            0 => (DEBUG_BREAKPOINT_INSTRUCTION, DEBUG_ACCESS_READ),
            1 => (DEBUG_BREAKPOINT_DATA, DEBUG_ACCESS_WRITE),
            3 => (DEBUG_BREAKPOINT_DATA, DEBUG_ACCESS_READWRITE),
            _ => return Err(Amd64DebugRegisterError::UnsupportedIoBreakpoint),
        };
        let size = if breakpoint_type == DEBUG_BREAKPOINT_INSTRUCTION {
            0
        } else {
            match arch_len {
                0 => 1,
                1 => 2,
                2 => 8,
                _ => 4,
            }
        };
        let address = if dr[slot] > highest_user_address {
            0
        } else {
            dr[slot]
        };
        let breakpoint = Amd64DebugBreakpoint {
            address,
            breakpoint_type,
            size,
            access,
        };
        validate_amd64_debug_breakpoint(breakpoint)?;
        slots[slot] = Some(breakpoint);
    }
    Ok(slots)
}

/// Synthesize the NT-visible debug-register image from seL4-style breakpoint slots.
pub fn synthesize_amd64_debug_registers(
    slots: &[Option<Amd64DebugBreakpoint>; AMD64_HW_BREAKPOINT_SLOTS],
) -> Result<Amd64DebugRegisterState, Amd64DebugRegisterError> {
    let mut state = Amd64DebugRegisterState {
        dr: [0; AMD64_HW_BREAKPOINT_SLOTS],
        dr6: AMD64_DR6_INITIAL,
        dr7: AMD64_DR7_RESERVED_ONE,
    };
    for (slot, maybe_breakpoint) in slots.iter().copied().enumerate() {
        let Some(breakpoint) = maybe_breakpoint else {
            continue;
        };
        validate_amd64_debug_breakpoint(breakpoint)?;
        state.dr[slot] = breakpoint.address;
        state.dr7 |= 1u64 << (slot * 2);
        state.dr7 |= amd64_dr7_type_bits(breakpoint)? << (16 + slot * 4);
        state.dr7 |= amd64_dr7_len_bits(breakpoint)? << (18 + slot * 4);
    }
    Ok(state)
}

fn validate_amd64_debug_breakpoint(
    breakpoint: Amd64DebugBreakpoint,
) -> Result<(), Amd64DebugRegisterError> {
    match breakpoint.breakpoint_type {
        DEBUG_BREAKPOINT_INSTRUCTION => {
            if breakpoint.access != DEBUG_ACCESS_READ {
                return Err(Amd64DebugRegisterError::InvalidBreakpointAccess);
            }
            if breakpoint.size != 0 {
                return Err(Amd64DebugRegisterError::InvalidDataBreakpointSize);
            }
        }
        DEBUG_BREAKPOINT_DATA => {
            if breakpoint.access != DEBUG_ACCESS_WRITE
                && breakpoint.access != DEBUG_ACCESS_READWRITE
                && breakpoint.access != DEBUG_ACCESS_READ
            {
                return Err(Amd64DebugRegisterError::InvalidBreakpointAccess);
            }
            if !matches!(breakpoint.size, 1 | 2 | 4 | 8) {
                return Err(Amd64DebugRegisterError::InvalidDataBreakpointSize);
            }
            if breakpoint.address & (breakpoint.size - 1) != 0 {
                return Err(Amd64DebugRegisterError::UnalignedDataBreakpoint);
            }
        }
        _ => return Err(Amd64DebugRegisterError::InvalidBreakpointType),
    }
    Ok(())
}

fn amd64_dr7_type_bits(breakpoint: Amd64DebugBreakpoint) -> Result<u64, Amd64DebugRegisterError> {
    match breakpoint.breakpoint_type {
        DEBUG_BREAKPOINT_INSTRUCTION => Ok(0),
        DEBUG_BREAKPOINT_DATA => match breakpoint.access {
            DEBUG_ACCESS_WRITE => Ok(1),
            DEBUG_ACCESS_READ | DEBUG_ACCESS_READWRITE => Ok(3),
            _ => Err(Amd64DebugRegisterError::InvalidBreakpointAccess),
        },
        _ => Err(Amd64DebugRegisterError::InvalidBreakpointType),
    }
}

fn amd64_dr7_len_bits(breakpoint: Amd64DebugBreakpoint) -> Result<u64, Amd64DebugRegisterError> {
    if breakpoint.breakpoint_type == DEBUG_BREAKPOINT_INSTRUCTION {
        return Ok(0);
    }
    match breakpoint.size {
        1 => Ok(0),
        2 => Ok(1),
        8 => Ok(2),
        4 => Ok(3),
        _ => Err(Amd64DebugRegisterError::InvalidDataBreakpointSize),
    }
}

/// Build the initialized portion of an AMD64 user thread `CONTEXT` using the same stack and
/// selector contract as ReactOS `RtlInitializeContext`.
pub fn initialize_amd64_user_context(
    context: &mut [u8],
    start_address: u64,
    parameter: u64,
    stack_base: u64,
) -> bool {
    if context.len() < AMD64_CONTEXT_SIZE {
        return false;
    }
    context[..AMD64_CONTEXT_SIZE].fill(0);
    let rsp = stack_base.wrapping_sub(6 * 8) & !15;
    let rsp = rsp.wrapping_sub(8);

    put_u32(
        context,
        CONTEXT_FLAGS_OFFSET,
        CONTEXT_AMD64_FULL_WITH_SEGMENTS,
    );
    put_u32(context, CONTEXT_MXCSR_OFFSET, INITIAL_MXCSR);
    put_u16(context, CONTEXT_SEG_CS_OFFSET, USER_CODE_SELECTOR);
    put_u16(context, CONTEXT_SEG_DS_OFFSET, USER_DATA_SELECTOR);
    put_u16(context, CONTEXT_SEG_ES_OFFSET, USER_DATA_SELECTOR);
    put_u16(context, CONTEXT_SEG_FS_OFFSET, USER_CMTEB_SELECTOR);
    put_u16(context, CONTEXT_SEG_GS_OFFSET, USER_DATA_SELECTOR);
    put_u16(context, CONTEXT_SEG_SS_OFFSET, USER_DATA_SELECTOR);
    put_u32(context, CONTEXT_EFLAGS_OFFSET, EFLAGS_INTERRUPT_MASK);
    put_u64(context, CONTEXT_RCX_OFFSET as usize, parameter);
    put_u64(context, CONTEXT_RSP_OFFSET as usize, rsp);
    put_u64(context, CONTEXT_RIP_OFFSET as usize, start_address);
    true
}

/// Build the AMD64 `CONTEXT` frame used by `KiUserApcDispatcher`.
///
/// `saved_registers` uses the seL4 x86-64 `UserContext` order used by the executive:
/// `[rip, rsp, rflags, rax, rbx, rcx, rdx, rsi, rdi, rbp, r8..r15, fs_base, gs_base]`.
/// The APC home slots are filled as ReactOS/Windows expect, while the resumable context is shaped
/// like a native syscall return: `Rip/Rsp` resume after the syscall, `Rax` carries the wait status,
/// and `Rcx/R11` hold the sysret aliases.
#[allow(clippy::too_many_arguments)]
pub fn initialize_amd64_user_apc_context(
    context: &mut [u8],
    saved_registers: &[u64; 20],
    resume_ip: u64,
    resume_sp: u64,
    resume_flags: u64,
    return_status: u64,
    normal_routine: u64,
    normal_context: u64,
    system_argument1: u64,
    system_argument2: u64,
) -> bool {
    if context.len() < AMD64_CONTEXT_SIZE {
        return false;
    }
    context[..AMD64_CONTEXT_SIZE].fill(0);

    put_u64(context, CONTEXT_P1_HOME_OFFSET as usize, normal_context);
    put_u64(context, CONTEXT_P2_HOME_OFFSET as usize, system_argument1);
    put_u64(context, CONTEXT_P3_HOME_OFFSET as usize, system_argument2);
    put_u64(context, CONTEXT_P4_HOME_OFFSET as usize, normal_routine);

    put_u32(
        context,
        CONTEXT_FLAGS_OFFSET,
        CONTEXT_AMD64_FULL_WITH_SEGMENTS,
    );
    put_u32(context, CONTEXT_MXCSR_OFFSET, INITIAL_MXCSR);
    put_u16(context, CONTEXT_SEG_CS_OFFSET, USER_CODE_SELECTOR);
    put_u16(context, CONTEXT_SEG_DS_OFFSET, USER_DATA_SELECTOR);
    put_u16(context, CONTEXT_SEG_ES_OFFSET, USER_DATA_SELECTOR);
    put_u16(context, CONTEXT_SEG_FS_OFFSET, USER_CMTEB_SELECTOR);
    put_u16(context, CONTEXT_SEG_GS_OFFSET, USER_DATA_SELECTOR);
    put_u16(context, CONTEXT_SEG_SS_OFFSET, USER_DATA_SELECTOR);
    put_u32(context, CONTEXT_EFLAGS_OFFSET, resume_flags as u32);

    put_u64(context, CONTEXT_RAX_OFFSET as usize, return_status);
    put_u64(context, CONTEXT_RCX_OFFSET as usize, resume_ip);
    put_u64(context, CONTEXT_RDX_OFFSET as usize, saved_registers[6]);
    put_u64(context, CONTEXT_RBX_OFFSET as usize, saved_registers[4]);
    put_u64(context, CONTEXT_RSP_OFFSET as usize, resume_sp);
    put_u64(context, CONTEXT_RBP_OFFSET as usize, saved_registers[9]);
    put_u64(context, CONTEXT_RSI_OFFSET as usize, saved_registers[7]);
    put_u64(context, CONTEXT_RDI_OFFSET as usize, saved_registers[8]);
    put_u64(context, CONTEXT_R8_OFFSET as usize, saved_registers[10]);
    put_u64(context, CONTEXT_R9_OFFSET as usize, saved_registers[11]);
    put_u64(context, CONTEXT_R10_OFFSET as usize, saved_registers[12]);
    put_u64(context, CONTEXT_R11_OFFSET as usize, resume_flags);
    put_u64(context, CONTEXT_R12_OFFSET as usize, saved_registers[14]);
    put_u64(context, CONTEXT_R13_OFFSET as usize, saved_registers[15]);
    put_u64(context, CONTEXT_R14_OFFSET as usize, saved_registers[16]);
    put_u64(context, CONTEXT_R15_OFFSET as usize, saved_registers[17]);
    put_u64(context, CONTEXT_RIP_OFFSET as usize, resume_ip);
    true
}

fn put_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialTeb64 {
    pub stack_base: u64,
    pub stack_limit: u64,
    pub allocated_stack_base: u64,
}

/// Return the page that may be committed for a guard-style downward stack-growth fault.
///
/// `mapped_low` is the lowest page already backed in the reservation. Growth is deliberately
/// contiguous: a skipped page or an address below the reservation is rejected.
pub fn next_stack_growth_page(
    allocation_base: u64,
    mapped_low: u64,
    fault_address: u64,
) -> Option<u64> {
    if allocation_base & (USER_PAGE_SIZE - 1) != 0
        || mapped_low & (USER_PAGE_SIZE - 1) != 0
        || mapped_low <= allocation_base
    {
        return None;
    }
    let page = fault_address & !(USER_PAGE_SIZE - 1);
    (page >= allocation_base && page.checked_add(USER_PAGE_SIZE) == Some(mapped_low))
        .then_some(page)
}

impl InitialTeb64 {
    pub fn read(mut read_u64: impl FnMut(u64) -> u64, initial_teb_va: u64) -> Self {
        Self {
            stack_base: read_u64(initial_teb_va + INITIAL_TEB_STACK_BASE_OFFSET),
            stack_limit: read_u64(initial_teb_va + INITIAL_TEB_STACK_LIMIT_OFFSET),
            allocated_stack_base: read_u64(
                initial_teb_va + INITIAL_TEB_ALLOCATED_STACK_BASE_OFFSET,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_reactos_amd64_context_layout() {
        let context = Amd64ThreadContext::read(
            |address| match address - 0x1000 {
                CONTEXT_RCX_OFFSET => 0x1111,
                CONTEXT_RDX_OFFSET => 0x2222,
                CONTEXT_RSP_OFFSET => 0x3333,
                CONTEXT_RIP_OFFSET => 0x4444,
                _ => 0,
            },
            0x1000,
        );
        assert_eq!(
            context,
            Amd64ThreadContext {
                rip: 0x4444,
                rsp: 0x3333,
                rcx: 0x1111,
                rdx: 0x2222,
            }
        );
    }

    #[test]
    fn initializes_reactos_amd64_user_context_contract() {
        let mut bytes = [0xa5; AMD64_CONTEXT_SIZE];
        assert!(initialize_amd64_user_context(
            &mut bytes,
            0x1234_5678,
            0xfeed_beef,
            0x7001_0000,
        ));
        assert_eq!(
            u32::from_le_bytes(bytes[0x30..0x34].try_into().unwrap()),
            0x0010_000f
        );
        assert_eq!(
            u32::from_le_bytes(bytes[0x34..0x38].try_into().unwrap()),
            0x1f80
        );
        assert_eq!(
            u16::from_le_bytes(bytes[0x38..0x3a].try_into().unwrap()),
            0x33
        );
        assert_eq!(
            u16::from_le_bytes(bytes[0x3a..0x3c].try_into().unwrap()),
            0x2b
        );
        assert_eq!(
            u16::from_le_bytes(bytes[0x3e..0x40].try_into().unwrap()),
            0x53
        );
        assert_eq!(
            u32::from_le_bytes(bytes[0x44..0x48].try_into().unwrap()),
            0x200
        );
        let decoded = Amd64ThreadContext::read(
            |address| {
                let at = address as usize;
                u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
            },
            0,
        );
        assert_eq!(decoded.rip, 0x1234_5678);
        assert_eq!(decoded.rcx, 0xfeed_beef);
        assert_eq!(decoded.rsp, 0x7000_ffc8);
        assert!(bytes[0x100..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn debug_register_plan_accepts_instruction_breakpoint() {
        let plan = plan_amd64_debug_registers([0x401000, 0, 0, 0], 1, 0x7fff_ffff)
            .expect("instruction breakpoint");
        assert_eq!(
            plan[0],
            Some(Amd64DebugBreakpoint {
                address: 0x401000,
                breakpoint_type: DEBUG_BREAKPOINT_INSTRUCTION,
                size: 0,
                access: DEBUG_ACCESS_READ,
            })
        );
        let state = synthesize_amd64_debug_registers(&plan).expect("synthesize");
        assert_eq!(state.dr[0], 0x401000);
        assert_eq!(state.dr6, AMD64_DR6_INITIAL);
        assert_eq!(state.dr7, AMD64_DR7_RESERVED_ONE | 1);
    }

    #[test]
    fn debug_register_plan_accepts_global_data_write_watchpoint() {
        let slot = 2usize;
        let dr7 = (1u64 << (slot * 2 + 1)) | (1u64 << (16 + slot * 4)) | (3u64 << (18 + slot * 4));
        let plan = plan_amd64_debug_registers([0, 0, 0x402000, 0], dr7, 0x7fff_ffff)
            .expect("data watchpoint");
        assert_eq!(
            plan[slot],
            Some(Amd64DebugBreakpoint {
                address: 0x402000,
                breakpoint_type: DEBUG_BREAKPOINT_DATA,
                size: 4,
                access: DEBUG_ACCESS_WRITE,
            })
        );
        let state = synthesize_amd64_debug_registers(&plan).expect("synthesize");
        assert_eq!(state.dr[slot], 0x402000);
        assert_eq!(
            state.dr7,
            AMD64_DR7_RESERVED_ONE
                | (1u64 << (slot * 2))
                | (1u64 << (16 + slot * 4))
                | (3u64 << (18 + slot * 4))
        );
    }

    #[test]
    fn debug_register_plan_ignores_disabled_stale_slot_fields() {
        let stale_io_slot = 2u64 << 16;
        let plan = plan_amd64_debug_registers([0x401000, 0, 0, 0], stale_io_slot, 0x7fff_ffff)
            .expect("disabled stale fields are inert");
        assert_eq!(plan, [None, None, None, None]);
    }

    #[test]
    fn debug_register_plan_clamps_kernel_addresses_like_reactos() {
        let plan = plan_amd64_debug_registers([0x8000_0000, 0, 0, 0], 1, 0x7fff_ffff)
            .expect("clamped instruction breakpoint");
        assert_eq!(plan[0].unwrap().address, 0);
    }

    #[test]
    fn debug_register_plan_rejects_unmodelled_or_invalid_slots() {
        assert_eq!(
            plan_amd64_debug_registers([0; 4], 1u64 << 13, 0x7fff_ffff),
            Err(Amd64DebugRegisterError::UnsupportedControlBits)
        );
        assert_eq!(
            plan_amd64_debug_registers([0x401000, 0, 0, 0], 1 | (2u64 << 16), 0x7fff_ffff),
            Err(Amd64DebugRegisterError::UnsupportedIoBreakpoint)
        );
        assert_eq!(
            plan_amd64_debug_registers(
                [0x401003, 0, 0, 0],
                1 | (1u64 << 16) | (3u64 << 18),
                0x7fff_ffff
            ),
            Err(Amd64DebugRegisterError::UnalignedDataBreakpoint)
        );
    }

    #[test]
    fn initializes_amd64_user_apc_dispatch_context_contract() {
        let mut saved = [0u64; 20];
        for (index, slot) in saved.iter_mut().enumerate() {
            *slot = 0x1000 + index as u64;
        }
        let mut bytes = [0xa5; AMD64_CONTEXT_SIZE];
        assert!(initialize_amd64_user_apc_context(
            &mut bytes,
            &saved,
            0x7fff_1234,
            0x7000_ff00,
            0x246,
            0xc0,
            0x1111_2222,
            0x3333_4444,
            0x5555_6666,
            0x7777_8888,
        ));
        let read_u64 = |offset: u64| {
            let offset = offset as usize;
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
        };
        assert_eq!(read_u64(CONTEXT_P1_HOME_OFFSET), 0x3333_4444);
        assert_eq!(read_u64(CONTEXT_P2_HOME_OFFSET), 0x5555_6666);
        assert_eq!(read_u64(CONTEXT_P3_HOME_OFFSET), 0x7777_8888);
        assert_eq!(read_u64(CONTEXT_P4_HOME_OFFSET), 0x1111_2222);
        assert_eq!(read_u64(CONTEXT_RAX_OFFSET), 0xc0);
        assert_eq!(read_u64(CONTEXT_RCX_OFFSET), 0x7fff_1234);
        assert_eq!(read_u64(CONTEXT_RDX_OFFSET), saved[6]);
        assert_eq!(read_u64(CONTEXT_RBX_OFFSET), saved[4]);
        assert_eq!(read_u64(CONTEXT_RSP_OFFSET), 0x7000_ff00);
        assert_eq!(read_u64(CONTEXT_RBP_OFFSET), saved[9]);
        assert_eq!(read_u64(CONTEXT_RSI_OFFSET), saved[7]);
        assert_eq!(read_u64(CONTEXT_RDI_OFFSET), saved[8]);
        assert_eq!(read_u64(CONTEXT_R8_OFFSET), saved[10]);
        assert_eq!(read_u64(CONTEXT_R9_OFFSET), saved[11]);
        assert_eq!(read_u64(CONTEXT_R10_OFFSET), saved[12]);
        assert_eq!(read_u64(CONTEXT_R11_OFFSET), 0x246);
        assert_eq!(read_u64(CONTEXT_R12_OFFSET), saved[14]);
        assert_eq!(read_u64(CONTEXT_R13_OFFSET), saved[15]);
        assert_eq!(read_u64(CONTEXT_R14_OFFSET), saved[16]);
        assert_eq!(read_u64(CONTEXT_R15_OFFSET), saved[17]);
        assert_eq!(read_u64(CONTEXT_RIP_OFFSET), 0x7fff_1234);
        assert_eq!(
            u32::from_le_bytes(bytes[0x44..0x48].try_into().unwrap()),
            0x246
        );
    }

    #[test]
    fn user_apc_context_preserves_an_io_terminal_status() {
        let mut bytes = [0u8; AMD64_CONTEXT_SIZE];
        assert!(initialize_amd64_user_apc_context(
            &mut bytes,
            &[0u64; 20],
            0x7fff_1234,
            0x7000_ff00,
            0x202,
            0xc000_0120,
            1,
            2,
            3,
            4,
        ));
        let offset = CONTEXT_RAX_OFFSET as usize;
        assert_eq!(
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
            0xc000_0120
        );
    }

    #[test]
    fn context_initializer_rejects_short_storage() {
        let mut bytes = [0u8; AMD64_CONTEXT_SIZE - 1];
        assert!(!initialize_amd64_user_context(&mut bytes, 1, 2, 3));
        assert!(!initialize_amd64_user_apc_context(
            &mut bytes,
            &[0u64; 20],
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
        ));
    }

    #[test]
    fn trampoline_restores_both_windows_argument_registers() {
        let code = Amd64ThreadContext {
            rip: 0x8877_6655_4433_2211,
            rsp: 0,
            rcx: 0x1020_3040_5060_7080,
            rdx: 0xfeed_face_cafe_beef,
        }
        .call_trampoline();
        assert_eq!(&code[0..4], &[0x48, 0x83, 0xec, 0x20]);
        assert_eq!(&code[4..6], &[0x48, 0xb9]);
        assert_eq!(
            u64::from_le_bytes(code[6..14].try_into().unwrap()),
            0x1020_3040_5060_7080
        );
        assert_eq!(&code[14..16], &[0x48, 0xba]);
        assert_eq!(
            u64::from_le_bytes(code[16..24].try_into().unwrap()),
            0xfeed_face_cafe_beef
        );
        assert_eq!(&code[24..26], &[0x48, 0xb8]);
        assert_eq!(
            u64::from_le_bytes(code[26..34].try_into().unwrap()),
            0x8877_6655_4433_2211
        );
        assert_eq!(
            &code[34..],
            &[0xff, 0xd0, 0x48, 0x83, 0xc4, 0x20, 0xeb, 0xfe]
        );
    }

    #[test]
    fn loader_trampoline_calls_thunk_then_restores_durable_context() {
        let loader = 0x1111_2222_3333_4444;
        let ntdll = 0x5555_6666_7777_8888;
        let context = 0x9999_aaaa_bbbb_cccc;
        let code = Amd64ThreadContext::loader_trampoline(loader, ntdll, context);

        assert_eq!(&code[0..2], &[0x48, 0xb9]);
        assert_eq!(u64::from_le_bytes(code[2..10].try_into().unwrap()), 0);
        assert_eq!(&code[10..12], &[0x48, 0xba]);
        assert_eq!(u64::from_le_bytes(code[12..20].try_into().unwrap()), ntdll);
        assert_eq!(&code[20..23], &[0x45, 0x31, 0xc0]);
        assert_eq!(&code[23..25], &[0x49, 0xb9]);
        assert_eq!(
            u64::from_le_bytes(code[25..33].try_into().unwrap()),
            context
        );
        assert_eq!(&code[33..35], &[0x48, 0xb8]);
        assert_eq!(u64::from_le_bytes(code[35..43].try_into().unwrap()), loader);
        assert_eq!(&code[43..47], &[0x48, 0x83, 0xec, 0x20]);
        assert_eq!(&code[47..49], &[0xff, 0xd0]);
        assert_eq!(&code[49..53], &[0x48, 0x83, 0xc4, 0x20]);
        assert_eq!(&code[53..55], &[0x48, 0xb8]);
        assert_eq!(
            u64::from_le_bytes(code[55..63].try_into().unwrap()),
            context
        );
        assert_eq!(&code[63..70], &[0x48, 0x8b, 0x88, 0x80, 0, 0, 0]);
        assert_eq!(&code[70..77], &[0x48, 0x8b, 0x90, 0x88, 0, 0, 0]);
        assert_eq!(&code[77..84], &[0x48, 0x8b, 0xa0, 0x98, 0, 0, 0]);
        assert_eq!(&code[84..91], &[0x48, 0x8b, 0x80, 0xf8, 0, 0, 0]);
        assert_eq!(&code[91..93], &[0xff, 0xe0]);
    }

    #[test]
    fn decodes_initial_teb_stack_bounds() {
        let teb = InitialTeb64::read(
            |address| match address - 0x2000 {
                INITIAL_TEB_STACK_BASE_OFFSET => 0x9000,
                INITIAL_TEB_STACK_LIMIT_OFFSET => 0x8000,
                INITIAL_TEB_ALLOCATED_STACK_BASE_OFFSET => 0x7000,
                _ => 0,
            },
            0x2000,
        );
        assert_eq!(teb.stack_base, 0x9000);
        assert_eq!(teb.stack_limit, 0x8000);
        assert_eq!(teb.allocated_stack_base, 0x7000);
    }

    #[test]
    fn stack_growth_accepts_only_the_next_reserved_page() {
        assert_eq!(
            next_stack_growth_page(0x7000_0000, 0x700f_e000, 0x700f_d123),
            Some(0x700f_d000)
        );
        assert_eq!(
            next_stack_growth_page(0x7000_0000, 0x700f_d000, 0x700f_cfff),
            Some(0x700f_c000)
        );
        assert_eq!(
            next_stack_growth_page(0x7000_0000, 0x700f_e000, 0x700f_cfff),
            None
        );
        assert_eq!(
            next_stack_growth_page(0x7000_0000, 0x7000_1000, 0x6fff_ffff),
            None
        );
        assert_eq!(next_stack_growth_page(1, 0x700f_e000, 0x700f_d123), None);
    }
}
