//! Executive ownership boundary for the default NT hard-error port.
//!
//! The isolated LPC broker owns the referenced connection-port endpoint. This module owns only the
//! one-shot Ex authority: its retained endpoint and the dynamic process identity that registered it.

static mut DEFAULT_PORT: nt_syscall::hard_error::DefaultHardErrorPort =
    nt_syscall::hard_error::DefaultHardErrorPort::new();

pub(crate) unsafe fn is_ready() -> bool {
    (*core::ptr::addr_of!(DEFAULT_PORT)).is_ready()
}

pub(crate) unsafe fn registration() -> Option<(u64, u64)> {
    (*core::ptr::addr_of!(DEFAULT_PORT)).registration()
}

pub(crate) unsafe fn register(
    user_port_handle: u64,
    owner_process: u64,
) -> Result<(), nt_status::NtStatus> {
    if is_ready() {
        return Err(nt_status::NtStatus::UNSUCCESSFUL);
    }
    let client = crate::lpc_client().ok_or(nt_status::NtStatus::UNSUCCESSFUL)?;
    let endpoint = client.retain_connection_port(user_port_handle)?;
    let authority = &mut *core::ptr::addr_of_mut!(DEFAULT_PORT);
    if authority.register(endpoint, owner_process).is_err() {
        let _ = client.release_connection_port(endpoint);
        return Err(nt_status::NtStatus::UNSUCCESSFUL);
    }
    Ok(())
}

pub(crate) unsafe fn disable() {
    (*core::ptr::addr_of_mut!(DEFAULT_PORT)).disable();
}
