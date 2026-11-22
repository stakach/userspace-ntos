//! The video-port START answer for a miniport's `HwFindAdapter` (#420).
//!
//! The port's IRP_MN_START_DEVICE runs HwFindAdapter in the hosted provider. Until that call
//! returns, the adapter's discovery is running and the START IRP is pending, exactly as for any
//! driver that has not returned from its dispatch yet. The IRP's terminal is FindAdapter's own
//! return, mapped once from its VP_STATUS. Only a return that cannot be trusted quarantines the
//! IRP.

const STATUS_SUCCESS: u32 = 0;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_DEVICE_NOT_CONNECTED: u32 = 0xC000_009D;

pub const VP_NO_ERROR: u32 = 0;
pub const VP_ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const VP_ERROR_DEV_NOT_EXIST: u32 = 55;
pub const VP_ERROR_INVALID_PARAMETER: u32 = 87;

/// How the provider's FindAdapter dispatch stood when its caller looked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindAdapterPump {
    /// It has not returned yet, and its pump is kept to be resumed.
    Unfinished,
    /// It stopped with no trustworthy return: a fault wall, or a fenced uncertain effect.
    Uncertain,
    /// It returned: the provider's own dispatch status, and FindAdapter's VP_STATUS.
    Returned { dispatch_status: u32, vp_status: u32 },
}

/// The START IRP's answer for a FindAdapter pump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindAdapterStart {
    /// FindAdapter is still running: the IRP is pending, the provider stays ready, and the
    /// pump's later return is the IRP's completion.
    Pending,
    /// No trustworthy return: the IRP's native storage is quarantined.
    Quarantined,
    /// The IRP's terminal NTSTATUS.
    Completed(u32),
}

pub const fn find_adapter_start(pump: FindAdapterPump) -> FindAdapterStart {
    match pump {
        FindAdapterPump::Unfinished => FindAdapterStart::Pending,
        FindAdapterPump::Uncertain => FindAdapterStart::Quarantined,
        // A failed dispatch is the terminal; otherwise FindAdapter's own VP_STATUS is.
        FindAdapterPump::Returned { dispatch_status, vp_status } =>
            FindAdapterStart::Completed(if (dispatch_status as i32) < 0 {
                dispatch_status
            } else {
                vp_status_to_nt(vp_status)
            }),
    }
}

/// videoprt's VP_STATUS to NTSTATUS mapping for FindAdapter.
pub const fn vp_status_to_nt(vp_status: u32) -> u32 {
    match vp_status {
        VP_NO_ERROR => STATUS_SUCCESS,
        VP_ERROR_NOT_ENOUGH_MEMORY => STATUS_INSUFFICIENT_RESOURCES,
        VP_ERROR_INVALID_PARAMETER => STATUS_INVALID_PARAMETER,
        VP_ERROR_DEV_NOT_EXIST => STATUS_DEVICE_NOT_CONNECTED,
        _ => STATUS_UNSUCCESSFUL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unfinished_find_adapter_leaves_the_start_irp_pending() {
        assert_eq!(find_adapter_start(FindAdapterPump::Unfinished), FindAdapterStart::Pending);
    }

    #[test]
    fn only_an_untrustworthy_return_quarantines_the_start_irp() {
        assert_eq!(find_adapter_start(FindAdapterPump::Uncertain), FindAdapterStart::Quarantined);
    }

    #[test]
    fn a_returned_find_adapter_completes_with_its_vp_status() {
        let returned = |vp_status| find_adapter_start(FindAdapterPump::Returned {
            dispatch_status: STATUS_SUCCESS, vp_status,
        });
        assert_eq!(returned(VP_NO_ERROR), FindAdapterStart::Completed(STATUS_SUCCESS));
        assert_eq!(returned(VP_ERROR_DEV_NOT_EXIST),
            FindAdapterStart::Completed(STATUS_DEVICE_NOT_CONNECTED));
        assert_eq!(returned(VP_ERROR_NOT_ENOUGH_MEMORY),
            FindAdapterStart::Completed(STATUS_INSUFFICIENT_RESOURCES));
        assert_eq!(returned(VP_ERROR_INVALID_PARAMETER),
            FindAdapterStart::Completed(STATUS_INVALID_PARAMETER));
        assert_eq!(returned(1), FindAdapterStart::Completed(STATUS_UNSUCCESSFUL));
    }

    #[test]
    fn a_failed_find_adapter_dispatch_is_the_start_terminal() {
        assert_eq!(find_adapter_start(FindAdapterPump::Returned {
            dispatch_status: STATUS_INSUFFICIENT_RESOURCES, vp_status: VP_NO_ERROR,
        }), FindAdapterStart::Completed(STATUS_INSUFFICIENT_RESOURCES));
    }
}
