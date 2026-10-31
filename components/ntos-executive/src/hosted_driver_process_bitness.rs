//! `IoIs32bitProcess` from the exact process architecture admitted by the process manager.

use super::*;

/// BOOLEAN IoIs32bitProcess(PIRP OPTIONAL).
/// LiberNT dxgkrnl calls the NULL form for its current D3DKMT caller. A non-NULL IRP requires
/// a separate retained requestor-thread identity and cannot borrow the current caller's proof.
pub(super) extern "win64" fn io_is_32bit_process(irp: u64) -> u8 {
    if irp != 0 {
        unsafe { crate::provider_bugcheck::report(
            0xc4, [FSD_SERVICE_PS_GET_CURRENT_THREAD_ID_LABEL, irp, 6, 0],
        ); }
    }
    let result = current_ps_value(6);
    if result > 1 {
        unsafe { crate::provider_bugcheck::report(
            0xc4, [FSD_SERVICE_PS_GET_CURRENT_THREAD_ID_LABEL, result, 6, 1],
        ); }
    }
    result as u8
}
