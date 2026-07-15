#![no_std]

pub const CONTEXT_RCX_OFFSET: u64 = 0x80;
pub const CONTEXT_RDX_OFFSET: u64 = 0x88;
pub const CONTEXT_RSP_OFFSET: u64 = 0x98;
pub const CONTEXT_RIP_OFFSET: u64 = 0xf8;

pub const INITIAL_TEB_STACK_BASE_OFFSET: u64 = 0x10;
pub const INITIAL_TEB_STACK_LIMIT_OFFSET: u64 = 0x18;
pub const INITIAL_TEB_ALLOCATED_STACK_BASE_OFFSET: u64 = 0x20;

pub const CALL_TRAMPOLINE_LEN: usize = 34;

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
        code[0..2].copy_from_slice(&[0x48, 0xb9]);
        code[2..10].copy_from_slice(&self.rcx.to_le_bytes());
        code[10..12].copy_from_slice(&[0x48, 0xba]);
        code[12..20].copy_from_slice(&self.rdx.to_le_bytes());
        code[20..22].copy_from_slice(&[0x48, 0xb8]);
        code[22..30].copy_from_slice(&self.rip.to_le_bytes());
        code[30..32].copy_from_slice(&[0xff, 0xd0]);
        code[32..34].copy_from_slice(&[0xeb, 0xfe]);
        code
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialTeb64 {
    pub stack_base: u64,
    pub stack_limit: u64,
    pub allocated_stack_base: u64,
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
    fn trampoline_restores_both_windows_argument_registers() {
        let code = Amd64ThreadContext {
            rip: 0x8877_6655_4433_2211,
            rsp: 0,
            rcx: 0x1020_3040_5060_7080,
            rdx: 0xfeed_face_cafe_beef,
        }
        .call_trampoline();
        assert_eq!(&code[0..2], &[0x48, 0xb9]);
        assert_eq!(
            u64::from_le_bytes(code[2..10].try_into().unwrap()),
            0x1020_3040_5060_7080
        );
        assert_eq!(&code[10..12], &[0x48, 0xba]);
        assert_eq!(
            u64::from_le_bytes(code[12..20].try_into().unwrap()),
            0xfeed_face_cafe_beef
        );
        assert_eq!(&code[20..22], &[0x48, 0xb8]);
        assert_eq!(
            u64::from_le_bytes(code[22..30].try_into().unwrap()),
            0x8877_6655_4433_2211
        );
        assert_eq!(&code[30..], &[0xff, 0xd0, 0xeb, 0xfe]);
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
}
