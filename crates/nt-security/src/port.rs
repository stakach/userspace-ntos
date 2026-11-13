//! Security capture and server-identity validation for secure LPC connections.

use crate::{
    AccessCheckResult, AccessToken, CapturedSubjectTokens, GenericMapping, ProcessorMode,
    SecurityQualityOfService, Sid, STATUS_ACCESS_DENIED,
};

/// Native Port object right and ReactOS `LpcpPortMapping` (`lpc/port.c`).
pub const PORT_CONNECT: u32 = 1;
pub const PORT_GENERIC_MAPPING: GenericMapping = GenericMapping {
    generic_read: 0x0002_0000 | PORT_CONNECT,
    generic_write: 0x0001_0000 | PORT_CONNECT,
    generic_execute: 0,
    generic_all: 0x001f_0000 | PORT_CONNECT,
};

/// Authorize a connect to the exact port object's owned descriptor. The caller
/// must bind this decision to the same object identity before enqueueing a
/// connection; a name alone cannot carry this grant across replacement.
pub fn authorize_port_connect(
    subject: &CapturedSubjectTokens<'_>,
    descriptor: &[u8],
    mode: ProcessorMode,
) -> Result<AccessCheckResult, u32> {
    if mode == ProcessorMode::KernelMode {
        return Ok(subject.check_access(None, PORT_CONNECT, &PORT_GENERIC_MAPPING, mode));
    }
    let (descriptor, label) = crate::native_sd::port_descriptor_for_access(descriptor)?;
    let mut result = subject.check_access(
        Some(&descriptor), PORT_CONNECT, &PORT_GENERIC_MAPPING, mode,
    );
    if !result.granted() {
        return Ok(result);
    }
    if let Some(label) = label {
        let (token, _) = subject.effective_token();
        let Some(level) = token.integrity_level else {
            result.status = STATUS_ACCESS_DENIED;
            result.granted_access = 0;
            return Ok(result);
        };
        // A Port connect grants the PORT_CONNECT bit under both GenericRead
        // and GenericWrite. Only those mandatory policies restrict this right.
        if level < label.level && label.policy & 0x3 != 0 {
            result.status = STATUS_ACCESS_DENIED;
            result.granted_access = 0;
        }
    }
    Ok(result)
}

/// The named port exists, but its creator has no matching primary-token user SID.
pub const STATUS_SERVER_SID_MISMATCH: u32 = 0xC000_02A0;

/// Security state captured before a secure port connection is queued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurePortConnectSecurity {
    pub qos: SecurityQualityOfService,
    pub required_server_sid: Option<Sid>,
}

/// Capture `SECURITY_QUALITY_OF_SERVICE` and an optional required server SID, then validate the
/// latter against the named port owner's primary token. A missing owner/token is a SID mismatch
/// when the caller supplied a required SID, matching `NtSecureConnectPort`.
pub fn validate_secure_port_connect(
    qos_bytes: &[u8],
    required_server_sid_bytes: Option<&[u8]>,
    server_token: Option<&AccessToken>,
) -> Result<SecurePortConnectSecurity, u32> {
    let qos = SecurityQualityOfService::from_native_bytes(qos_bytes)?;
    let required_server_sid = required_server_sid_bytes
        .map(Sid::from_native_bytes)
        .transpose()?;
    if required_server_sid
        .as_ref()
        .is_some_and(|required| server_token.is_none_or(|token| token.user != *required))
    {
        return Err(STATUS_SERVER_SID_MISMATCH);
    }
    Ok(SecurePortConnectSecurity {
        qos,
        required_server_sid,
    })
}
