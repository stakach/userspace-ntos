//! Canonical provider Timer operations shared by bootstrap and live dispatcher ownership.

use crate::win32k_subsystem;
use nt_provider_wait::{
    ProviderDomainIdentity, ProviderTimerId, ProviderTimerKind, ProviderTimerRetirement,
    ProviderTimerTable, ProviderWaitObject, ProviderWaitObjectType,
};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

pub(crate) fn dispatch(
    timers: &mut Option<ProviderTimerTable>,
    provider: ProviderDomainIdentity,
    op: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> Result<(i32, u64, u64, u64), u32> {
    if !crate::win32k_provider_domain_is_current(provider) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if op == win32k_subsystem::W32_TIMER_OP_PUBLISH_LOCAL {
        let kind = match arg2 {
            0 => ProviderTimerKind::Notification,
            1 => ProviderTimerKind::Synchronization,
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        if timers.is_none() {
            *timers =
                Some(ProviderTimerTable::new(provider).map_err(|_| STATUS_INVALID_PARAMETER)?);
        }
        let table = timers
            .as_mut()
            .filter(|table| table.provider() == provider)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let object = table
            .publish(arg1, kind)
            .map_err(|_| STATUS_INVALID_PARAMETER)?
            .wait_object();
        return Ok((0, object.object_id, object.object_generation, arg2));
    }
    let table = timers
        .as_mut()
        .filter(|table| table.provider() == provider)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    match op {
        win32k_subsystem::W32_TIMER_OP_RETIRE_LOCAL => {
            let retirement = table
                .request_retire_local(arg1)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            Ok(match retirement {
                Some(retirement) => {
                    let object = retirement.id.wait_object();
                    (0, object.object_id, object.object_generation, 0)
                }
                None => (0x103, 0, 0, 0),
            })
        }
        win32k_subsystem::W32_TIMER_OP_ACK_LOCAL_RETIREMENT => {
            let object = ProviderWaitObject::new(ProviderWaitObjectType::Timer, arg2, arg3);
            let id = ProviderTimerId::from_wait_object(object).ok_or(STATUS_INVALID_PARAMETER)?;
            table
                .ack_retirement(ProviderTimerRetirement {
                    id,
                    local_identity: arg1,
                })
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            Ok((0, 0, 0, 0))
        }
        win32k_subsystem::W32_TIMER_OP_SET_LOCAL => {
            let active = table
                .set_local(arg1, arg2 as i64, arg3 as u32, crate::nt_time_snapshot())
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            Ok((0, u64::from(active), 0, 0))
        }
        win32k_subsystem::W32_TIMER_OP_CANCEL_LOCAL => {
            let active = table
                .cancel_local(arg1)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            Ok((0, u64::from(active), 0, 0))
        }
        win32k_subsystem::W32_TIMER_OP_READ_LOCAL => {
            let id = table.id_for_local(arg1).ok_or(STATUS_INVALID_PARAMETER)?;
            let signaled = table.read_state(id).map_err(|_| STATUS_INVALID_PARAMETER)?;
            Ok((0, u64::from(signaled), 0, 0))
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}
