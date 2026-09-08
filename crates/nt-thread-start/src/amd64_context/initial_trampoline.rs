use super::CodecError;
use crate::{AMD64_CONTEXT_ALIGNMENT, AMD64_CONTEXT_SIZE};

pub const INITIAL_CONTEXT_TRAMPOLINE_CAPACITY: usize = 67;

/// Bounded code bytes, not an executable mapping or an authority to call the supplied exports.
pub struct InitialContextTrampoline {
    bytes: [u8; INITIAL_CONTEXT_TRAMPOLINE_CAPACITY],
    len: usize,
}

impl InitialContextTrampoline {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Enter optional `(LdrInitializeThunk, ntdll_base)`, then NtContinue(context, FALSE).
///
/// Entry RSP must be 16-byte aligned with room for the callee's 32-byte home area and return
/// address. The original requested RSP stays in the saved CONTEXT and is never adjusted here.
/// Returning from NtContinue is a genuine startup failure and executes UD2, not a synthetic
/// return or a spin. Export identity and executable mapping admission belong to the caller.
pub fn initial_context_trampoline(
    context_va: u64,
    nt_continue_va: u64,
    loader: Option<(u64, u64)>,
) -> Result<InitialContextTrampoline, CodecError> {
    if context_va == 0
        || context_va % AMD64_CONTEXT_ALIGNMENT != 0
        || context_va.checked_add(AMD64_CONTEXT_SIZE as u64).is_none()
    {
        return Err(CodecError::InvalidContextAddress);
    }
    if nt_continue_va == 0 || loader.is_some_and(|(entry, base)| entry == 0 || base == 0) {
        return Err(CodecError::InvalidInstructionPointer);
    }
    let mut output = InitialContextTrampoline {
        bytes: [0; INITIAL_CONTEXT_TRAMPOLINE_CAPACITY],
        len: 0,
    };
    let mut emit = |bytes: &[u8]| {
        let end = output.len + bytes.len();
        output.bytes[output.len..end].copy_from_slice(bytes);
        output.len = end;
    };
    emit(&[0x48, 0x83, 0xec, 0x20]); // sub rsp,32
    if let Some((entry, ntdll_base)) = loader {
        emit(&[0x31, 0xc9]); // xor ecx,ecx
        emit(&[0x48, 0xba]); // movabs rdx,ntdll
        emit(&ntdll_base.to_le_bytes());
        emit(&[0x45, 0x31, 0xc0]); // xor r8d,r8d
        emit(&[0x49, 0xb9]); // movabs r9,context
        emit(&context_va.to_le_bytes());
        emit(&[0x48, 0xb8]); // movabs rax,loader
        emit(&entry.to_le_bytes());
        emit(&[0xff, 0xd0]); // call rax
    }
    emit(&[0x48, 0xb9]); // movabs rcx,context
    emit(&context_va.to_le_bytes());
    emit(&[0x31, 0xd2]); // xor edx,edx: TestAlert FALSE
    emit(&[0x48, 0xb8]); // movabs rax,NtContinue
    emit(&nt_continue_va.to_le_bytes());
    emit(&[0xff, 0xd0]); // call rax
    emit(&[0x0f, 0x0b]); // ud2: NtContinue returned an error
    Ok(output)
}

#[cfg(test)]
mod tests;
