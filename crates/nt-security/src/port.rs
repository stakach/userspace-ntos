//! Security capture and server-identity validation for secure LPC connections.

use crate::{AccessToken, SecurityQualityOfService, Sid};

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
