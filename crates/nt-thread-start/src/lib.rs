#![no_std]

pub const CONTEXT_RCX_OFFSET: u64 = 0x80;
pub const CONTEXT_RDX_OFFSET: u64 = 0x88;
pub const CONTEXT_RSP_OFFSET: u64 = 0x98;
pub const CONTEXT_RIP_OFFSET: u64 = 0xf8;

pub const INITIAL_TEB_STACK_BASE_OFFSET: u64 = 0x10;
pub const INITIAL_TEB_STACK_LIMIT_OFFSET: u64 = 0x18;
pub const INITIAL_TEB_ALLOCATED_STACK_BASE_OFFSET: u64 = 0x20;

pub const CALL_TRAMPOLINE_LEN: usize = 34;
pub const LOADER_TRAMPOLINE_LEN: usize = 85;

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
        emit(&[0xff, 0xd0]); // call rax

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
        assert_eq!(u64::from_le_bytes(code[25..33].try_into().unwrap()), context);
        assert_eq!(&code[33..35], &[0x48, 0xb8]);
        assert_eq!(u64::from_le_bytes(code[35..43].try_into().unwrap()), loader);
        assert_eq!(&code[43..45], &[0xff, 0xd0]);
        assert_eq!(&code[45..47], &[0x48, 0xb8]);
        assert_eq!(u64::from_le_bytes(code[47..55].try_into().unwrap()), context);
        assert_eq!(&code[55..62], &[0x48, 0x8b, 0x88, 0x80, 0, 0, 0]);
        assert_eq!(&code[62..69], &[0x48, 0x8b, 0x90, 0x88, 0, 0, 0]);
        assert_eq!(&code[69..76], &[0x48, 0x8b, 0xa0, 0x98, 0, 0, 0]);
        assert_eq!(&code[76..83], &[0x48, 0x8b, 0x80, 0xf8, 0, 0, 0]);
        assert_eq!(&code[83..85], &[0xff, 0xe0]);
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
