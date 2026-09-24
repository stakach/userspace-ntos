//! NT5 x64 CREATE security graph layouts. Pointer values are supplied by the
//! caller, which owns the referenced tokens and the projected memory lifetime.

use crate::WdmLayoutError;

pub const WDM_X64_SECURITY_SUBJECT_CONTEXT_SIZE: usize = 0x20;
pub const WDM_X64_ACCESS_STATE_SIZE: usize = 0xa0;
pub const WDM_X64_IO_SECURITY_CONTEXT_SIZE: usize = 0x18;

const SUBJECT_CONTEXT_OFFSET: usize = 0x20;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmSecuritySubjectContext {
    pub client_token: u64,
    pub impersonation_level: u32,
    pub primary_token: u64,
    pub process_audit_id: u64,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmAccessStateInit {
    pub operation_id: u64,
    pub security_evaluated: bool,
    pub generate_audit: bool,
    pub generate_on_close: bool,
    pub privileges_allocated: bool,
    pub flags: u32,
    pub remaining_desired_access: u32,
    pub previously_granted_access: u32,
    pub original_desired_access: u32,
    pub subject: WdmSecuritySubjectContext,
    pub security_descriptor: u64,
    pub aux_data: u64,
    pub audit_privileges: bool,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmIoSecurityContextInit {
    pub security_qos: u64,
    pub access_state: u64,
    pub desired_access: u32,
    pub full_create_options: u32,
}

fn validate_subject(subject: WdmSecuritySubjectContext) -> Result<(), WdmLayoutError> {
    if subject.primary_token == 0
        || subject.impersonation_level > 3
        || (subject.client_token == 0 && subject.impersonation_level != 0)
    {
        return Err(WdmLayoutError::InvalidField);
    }
    Ok(())
}

fn validate_access(access: WdmAccessStateInit) -> Result<(), WdmLayoutError> {
    validate_subject(access.subject)?;
    if access.privileges_allocated {
        return Err(WdmLayoutError::InvalidField);
    }
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_subject_unchecked(bytes: &mut [u8], subject: WdmSecuritySubjectContext) {
    put_u64(bytes, 0x00, subject.client_token);
    put_u32(bytes, 0x08, subject.impersonation_level);
    put_u64(bytes, 0x10, subject.primary_token);
    put_u64(bytes, 0x18, subject.process_audit_id);
}

pub fn write_wdm_security_subject_context(
    bytes: &mut [u8],
    subject: WdmSecuritySubjectContext,
) -> Result<(), WdmLayoutError> {
    if bytes.len() < WDM_X64_SECURITY_SUBJECT_CONTEXT_SIZE {
        return Err(WdmLayoutError::BufferTooSmall);
    }
    validate_subject(subject)?;
    bytes[..WDM_X64_SECURITY_SUBJECT_CONTEXT_SIZE].fill(0);
    write_subject_unchecked(bytes, subject);
    Ok(())
}

pub fn write_wdm_access_state(
    bytes: &mut [u8],
    init: WdmAccessStateInit,
) -> Result<(), WdmLayoutError> {
    if bytes.len() < WDM_X64_ACCESS_STATE_SIZE {
        return Err(WdmLayoutError::BufferTooSmall);
    }
    validate_access(init)?;
    bytes[..WDM_X64_ACCESS_STATE_SIZE].fill(0);
    put_u64(bytes, 0x00, init.operation_id);
    bytes[0x08] = u8::from(init.security_evaluated);
    bytes[0x09] = u8::from(init.generate_audit);
    bytes[0x0a] = u8::from(init.generate_on_close);
    bytes[0x0b] = u8::from(init.privileges_allocated);
    put_u32(bytes, 0x0c, init.flags);
    put_u32(bytes, 0x10, init.remaining_desired_access);
    put_u32(bytes, 0x14, init.previously_granted_access);
    put_u32(bytes, 0x18, init.original_desired_access);
    write_subject_unchecked(
        &mut bytes[SUBJECT_CONTEXT_OFFSET..SUBJECT_CONTEXT_OFFSET + WDM_X64_SECURITY_SUBJECT_CONTEXT_SIZE],
        init.subject,
    );
    put_u64(bytes, 0x40, init.security_descriptor);
    put_u64(bytes, 0x48, init.aux_data);
    bytes[0x7c] = u8::from(init.audit_privileges);
    Ok(())
}

pub fn write_wdm_io_security_context(
    bytes: &mut [u8],
    init: WdmIoSecurityContextInit,
) -> Result<(), WdmLayoutError> {
    if bytes.len() < WDM_X64_IO_SECURITY_CONTEXT_SIZE {
        return Err(WdmLayoutError::BufferTooSmall);
    }
    if init.access_state == 0 || init.access_state & 7 != 0 {
        return Err(WdmLayoutError::InvalidField);
    }
    bytes[..WDM_X64_IO_SECURITY_CONTEXT_SIZE].fill(0);
    put_u64(bytes, 0x00, init.security_qos);
    put_u64(bytes, 0x08, init.access_state);
    put_u32(bytes, 0x10, init.desired_access);
    put_u32(bytes, 0x14, init.full_create_options);
    Ok(())
}

/// Validate both target buffers and pointer identities before mutating either.
pub fn write_wdm_create_security_graph(
    access_bytes: &mut [u8],
    io_bytes: &mut [u8],
    access: WdmAccessStateInit,
    io: WdmIoSecurityContextInit,
) -> Result<(), WdmLayoutError> {
    if access_bytes.len() < WDM_X64_ACCESS_STATE_SIZE
        || io_bytes.len() < WDM_X64_IO_SECURITY_CONTEXT_SIZE
    {
        return Err(WdmLayoutError::BufferTooSmall);
    }
    validate_access(access)?;
    if io.access_state == 0 || io.access_state & 7 != 0 {
        return Err(WdmLayoutError::InvalidField);
    }
    write_wdm_access_state(access_bytes, access)?;
    write_wdm_io_security_context(io_bytes, io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn create_graph_preserves_real_token_and_access_state_addresses() {
        let subject = WdmSecuritySubjectContext {
            client_token: 0x1000_1000,
            impersonation_level: 2,
            primary_token: 0x1000_2000,
            process_audit_id: 0x18,
        };
        let access = WdmAccessStateInit {
            operation_id: 0x1122_3344_5566_7788,
            remaining_desired_access: 0x120089,
            original_desired_access: 0x120089,
            subject,
            aux_data: 0x1000_4000,
            ..Default::default()
        };
        let io = WdmIoSecurityContextInit {
            access_state: 0x1000_3000,
            desired_access: 0x120089,
            full_create_options: 0x0300_0020,
            ..Default::default()
        };
        let mut access_bytes = [0xff; WDM_X64_ACCESS_STATE_SIZE];
        let mut io_bytes = [0xff; WDM_X64_IO_SECURITY_CONTEXT_SIZE];
        write_wdm_create_security_graph(&mut access_bytes, &mut io_bytes, access, io).unwrap();
        assert_eq!(u64_at(&access_bytes, 0x00), access.operation_id);
        assert_eq!(u32_at(&access_bytes, 0x10), io.desired_access);
        assert_eq!(u64_at(&access_bytes, 0x20), subject.client_token);
        assert_eq!(u32_at(&access_bytes, 0x28), subject.impersonation_level);
        assert_eq!(u64_at(&access_bytes, 0x30), subject.primary_token);
        assert_eq!(u64_at(&access_bytes, 0x38), subject.process_audit_id);
        assert_eq!(u64_at(&access_bytes, 0x48), access.aux_data);
        assert_eq!(u64_at(&io_bytes, 0x08), io.access_state);
        assert_eq!(u32_at(&io_bytes, 0x10), io.desired_access);
        assert_eq!(u32_at(&io_bytes, 0x14), io.full_create_options);
        assert!(access_bytes[0x50..0xa0].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rejects_missing_token_short_buffers_and_bad_access_pointer_without_mutation() {
        let mut access_bytes = [0xa5; WDM_X64_ACCESS_STATE_SIZE];
        let mut io_bytes = [0x5a; WDM_X64_IO_SECURITY_CONTEXT_SIZE];
        let mut access = WdmAccessStateInit::default();
        let mut io = WdmIoSecurityContextInit {
            access_state: 0x1000,
            ..Default::default()
        };
        assert_eq!(
            write_wdm_create_security_graph(&mut access_bytes, &mut io_bytes, access, io),
            Err(WdmLayoutError::InvalidField)
        );
        access.subject.primary_token = 0x2000;
        assert_eq!(
            write_wdm_create_security_graph(&mut access_bytes[..0x9f], &mut io_bytes, access, io),
            Err(WdmLayoutError::BufferTooSmall)
        );
        io.access_state = 0x1001;
        assert_eq!(
            write_wdm_create_security_graph(&mut access_bytes, &mut io_bytes, access, io),
            Err(WdmLayoutError::InvalidField)
        );
        io.access_state = 0x1000;
        access.privileges_allocated = true;
        assert_eq!(
            write_wdm_create_security_graph(&mut access_bytes, &mut io_bytes, access, io),
            Err(WdmLayoutError::InvalidField)
        );
        access.privileges_allocated = false;
        assert_eq!(
            write_wdm_create_security_graph(&mut access_bytes, &mut io_bytes[..0x17], access, io),
            Err(WdmLayoutError::BufferTooSmall)
        );
        assert!(access_bytes.iter().all(|byte| *byte == 0xa5));
        assert!(io_bytes.iter().all(|byte| *byte == 0x5a));
    }
}
