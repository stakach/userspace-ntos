//! The classic (pre-manifest) ETW API: trace providers (`RegisterTraceGuids`, `TraceEvent`),
//! trace sessions (`StartTrace`, `ControlTrace`, `QueryAllTraces`) and notifications.
//!
//! This personality has no ETW session service: no trace session exists and none can be
//! started. A provider can still register, as on Windows when no controller has enabled it;
//! its registration is real and its control callback is simply never called. Everything else
//! answers as Windows does when there is no session:
//! - a logger handle cannot be obtained, and nothing can be traced to one;
//! - controlling or querying a named session reports that it is not running;
//! - enumerating sessions finds none;
//! - starting a session, or the private session/notification plumbing, is not supported.

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_SUPPORTED: u32 = 50;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_WMI_INSTANCE_NOT_FOUND: u32 = 4201;
/// `(TRACEHANDLE)INVALID_HANDLE_VALUE`.
pub const INVALID_TRACE_HANDLE: u64 = u64::MAX;

/// `RegisterTraceGuids` argument checks (`RequestAddress`, `ControlGuid`, `RegistrationHandle`
/// required; `TraceGuidReg` required for a non-zero `GuidCount`).
pub fn register_trace_guids_arguments(
    request_address: bool,
    control_guid: bool,
    guid_count: u32,
    trace_guid_reg: bool,
    registration_handle: bool,
) -> u32 {
    if !request_address
        || !control_guid
        || !registration_handle
        || (guid_count != 0 && !trace_guid_reg)
    {
        ERROR_INVALID_PARAMETER
    } else {
        ERROR_SUCCESS
    }
}

/// `TraceEvent`, `TraceEventInstance`, `TraceMessage`(`Va`) and `LogTraceEvent` take a logger
/// (session) handle. No session exists, so no handle is one.
pub fn trace_to_session(event_present: bool) -> u32 {
    if event_present { ERROR_INVALID_HANDLE } else { ERROR_INVALID_PARAMETER }
}

/// `ControlTrace`, `StopTrace`, `FlushTrace`, `UpdateTrace` and `QueryTrace`: the session named
/// by handle or name is not running. Missing properties are an argument error.
pub fn control_session(properties_present: bool) -> u32 {
    if properties_present { ERROR_WMI_INSTANCE_NOT_FOUND } else { ERROR_INVALID_PARAMETER }
}

/// `QueryAllTraces`: `Ok(0)` sessions, or the argument error.
pub fn query_all_traces(array_present: bool, array_count: u32, logger_count_present: bool) -> Result<u32, u32> {
    if !logger_count_present || array_count == 0 || !array_present {
        Err(ERROR_INVALID_PARAMETER)
    } else {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_provider_can_register_without_a_session() {
        assert_eq!(register_trace_guids_arguments(true, true, 1, true, true), ERROR_SUCCESS);
        assert_eq!(register_trace_guids_arguments(true, true, 0, false, true), ERROR_SUCCESS);
        assert_eq!(register_trace_guids_arguments(false, true, 0, false, true), ERROR_INVALID_PARAMETER);
        assert_eq!(register_trace_guids_arguments(true, true, 2, false, true), ERROR_INVALID_PARAMETER);
        assert_eq!(register_trace_guids_arguments(true, true, 0, false, false), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn nothing_traces_to_or_controls_a_session_that_does_not_exist() {
        assert_eq!(trace_to_session(true), ERROR_INVALID_HANDLE);
        assert_eq!(trace_to_session(false), ERROR_INVALID_PARAMETER);
        assert_eq!(control_session(true), ERROR_WMI_INSTANCE_NOT_FOUND);
        assert_eq!(control_session(false), ERROR_INVALID_PARAMETER);
        assert_eq!(query_all_traces(true, 4, true), Ok(0));
        assert_eq!(query_all_traces(true, 0, true), Err(ERROR_INVALID_PARAMETER));
        assert_eq!(query_all_traces(true, 4, false), Err(ERROR_INVALID_PARAMETER));
    }
}
