use super::{
    CapturedAmd64Context, CodecError, LegacyContextRestore, CONTEXT_AMD64,
    LEGACY_FLOATING_POINT_BYTES,
};
use crate::AMD64_CONTEXT_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserApcContinuation {
    NativeCall,
    Fault {
        resume_ip: u64,
        resume_sp: u64,
        resume_flags: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserApcPayload {
    pub routine: u64,
    pub normal_context: u64,
    pub system_argument1: u64,
    pub system_argument2: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PreparedUserApc {
    pub frame_va: u64,
    pub frame: [u8; AMD64_CONTEXT_SIZE],
    pub install: LegacyContextRestore,
}

/// Prepare an APC without writing memory, dequeuing its payload, or changing the target TCB.
/// Native Call resumes inside ntdll's saved-register prologue, not at the reported Windows RSP.
/// The adapter owns exact thread/APC admission and installs this plan without restarting it.
#[allow(clippy::too_many_arguments)]
pub fn prepare_user_apc(
    live: &[u64; 20],
    floating_point: &[u8; LEGACY_FLOATING_POINT_BYTES],
    continuation: UserApcContinuation,
    dispatcher: u64,
    payload: UserApcPayload,
    return_status: u32,
    highest_user_address: u64,
) -> Result<PreparedUserApc, CodecError> {
    if dispatcher == 0 || dispatcher > highest_user_address {
        return Err(CodecError::InvalidInstructionPointer);
    }
    let mut resume = *live;
    match continuation {
        UserApcContinuation::NativeCall => {
            // The stub checks the exact one-word reply envelope, then takes NTSTATUS from MR0.
            resume[7] = 1;
            resume[12] = u64::from(return_status);
        }
        UserApcContinuation::Fault { resume_ip, resume_sp, resume_flags } => {
            resume[0] = resume_ip;
            resume[1] = resume_sp;
            resume[2] = resume_flags;
            resume[5] = resume_ip;
            resume[13] = resume_flags;
        }
    }
    resume[3] = u64::from(return_status);
    let frame_va = resume[1]
        .checked_sub(AMD64_CONTEXT_SIZE as u64)
        .map(|address| address & !0xf)
        .filter(|address| *address != 0 && *address <= highest_user_address)
        .ok_or(CodecError::InvalidStackPointer)?;

    let mut frame = CapturedAmd64Context { bytes: [0; AMD64_CONTEXT_SIZE] };
    frame.bytes[0x30..0x34].copy_from_slice(&(CONTEXT_AMD64 | 0xf).to_le_bytes());
    frame.publish_legacy_registers(&resume)?;
    frame.publish_legacy_floating_point(floating_point)?;
    // Validate the entire saved continuation before publishing even one user byte.
    frame.prepare_continue(resume[0], resume[1], resume[2], highest_user_address, false)?;
    for (offset, value) in [
        (0, payload.normal_context),
        (8, payload.system_argument1),
        (16, payload.system_argument2),
        (24, payload.routine),
    ] {
        frame.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut registers = *live;
    registers[0] = dispatcher;
    registers[1] = frame_va;
    registers[3] = 0;
    registers[5] = dispatcher;
    registers[12] = 0;
    registers[13] = live[2];
    Ok(PreparedUserApc {
        frame_va,
        frame: frame.bytes,
        install: LegacyContextRestore {
            registers,
            register_mask: (1 << 0) | (1 << 1) | (1 << 3) | (1 << 5) | (1 << 12) | (1 << 13),
            floating_point: None,
            debug: None,
        },
    })
}

#[cfg(test)]
mod tests;
