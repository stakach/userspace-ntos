//! Process-owned USER object handles for the win32k provider.
//!
//! The provider owns USER bodies and their counts; ProcessManager owns the handles. The provider
//! asks this broker to publish, look up, close and search handles for the caller of its current
//! dispatch. Handles the root copies or removes on its own (inheritance, duplication, `NtClose`,
//! teardown) are recorded in the ledger here and drained by the provider, which applies them to
//! its bodies and acknowledges them.

use super::*;
use nt_process::native_handle::{NativeCloseError, NativeHandleCaller, NativeHandleInformation};
use nt_process::user_object_handle::UserObjectTarget;
use nt_user_host::user_object_handle_wire as wire;
use nt_user_host::user_object_handles::UserObjectHandleLedger;

/// Root-only: the provider never reads this ledger; it drains it through this broker.
static mut LEDGER: UserObjectHandleLedger = UserObjectHandleLedger::new();

fn ledger() -> &'static mut UserObjectHandleLedger {
    unsafe { &mut *core::ptr::addr_of_mut!(LEDGER) }
}

/// ProcessManager is about to copy a handle to `target` (inheritance or duplication).
pub(crate) fn acquire(target: UserObjectTarget) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    ledger().acquire(target)
}

/// The copy prepared by [`acquire`] was not installed.
pub(crate) fn cancel_acquire(target: UserObjectTarget) {
    ledger()
        .cancel_acquire(target)
        .expect("a prepared USER handle copy retains its ledger row");
}

/// A ProcessManager handle to `target` has been removed.
pub(crate) fn release(target: UserObjectTarget) {
    ledger()
        .release(target)
        .expect("every USER handle removed from a table was recorded when it was published");
}

fn reply(result: Result<[u64; 3], u32>) -> (i32, u64, u64, u64) {
    match result {
        Ok([first, second, third]) => (0, first, second, third),
        Err(status) => (status as i32, 0, 0, 0),
    }
}

pub(crate) unsafe fn service(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    words: wire::Words,
) -> (i32, u64, u64, u64) {
    let expected = (crate::win32k_subsystem::W32_USER_OBJECT_LABEL << 12) | 4;
    if let Err(status) =
        crate::provider_service_ingress::authenticate(channel, reply_cap, badge, mi, expected)
    {
        return (status as i32, 0, 0, 0);
    }
    if let Err(status) = provider_ps_projection::authenticated_target(channel) {
        return (status as i32, 0, 0, 0);
    }
    let Some(provider) = current_win32k_provider_domain() else {
        return (nt_process::STATUS_INVALID_HANDLE as i32, 0, 0, 0);
    };
    let _durable = allocator::enter_durable();
    let op = wire::op(words);
    // The ledger belongs to the provider domain; handle operations act for the dispatch's caller.
    if op == wire::OP_DRAIN {
        return reply(if words == [wire::OP_DRAIN, 0, 0, 0] {
            Ok(ledger().next_delta(provider.domain).map_or([0; 3], wire::encode_delta))
        } else {
            Err(nt_process::STATUS_INVALID_PARAMETER)
        });
    }
    if op == wire::OP_ACKNOWLEDGE {
        return reply(if words[0] == wire::OP_ACKNOWLEDGE {
            wire::decode_delta(provider.domain, [words[1], words[2], words[3]])
                .and_then(|delta| ledger().acknowledge(provider.domain, delta))
                .map(|()| [0; 3])
        } else {
            Err(nt_process::STATUS_INVALID_PARAMETER)
        });
    }
    let caller = match crate::provider_registry_caller::resolve(channel) {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    reply(match op {
        wire::OP_PUBLISH => publish(caller, provider.domain, words),
        wire::OP_LOOKUP => lookup(caller, provider.domain, words),
        wire::OP_CLOSE => close(caller, provider.domain, words),
        wire::OP_FIND => find(caller, words),
        _ => Err(nt_process::STATUS_INVALID_PARAMETER),
    })
}

unsafe fn publish(caller: NativeHandleCaller, domain: u64, words: wire::Words) -> Result<[u64; 3], u32> {
    let request = wire::Publish::decode(words)?;
    let caller = caller.restricted_to(request.mode);
    let target = UserObjectTarget {
        domain,
        object_type: request.object_type,
        body: request.body,
        generation: request.generation,
    };
    ledger().prepare_publication(target)?;
    let result = service_sec_image::with_provider_process_manager(|pm| {
        let mut publication = pm.reserve_native_user_object_handle(caller, request.attributes)?;
        let published = publication
            .bind(pm, target, request.granted_access)
            .and_then(|()| publication.publish(pm));
        if published.is_err() {
            publication.abort(pm).expect("an unpublished USER handle reservation aborts");
        }
        published
    });
    match result {
        Ok(value) => {
            ledger()
                .record_published(target)
                .expect("a prepared USER handle publication retains its ledger row");
            Ok([value, 0, 0])
        }
        Err(status) => {
            ledger().discard_unpublished(target);
            Err(status)
        }
    }
}

unsafe fn lookup(caller: NativeHandleCaller, domain: u64, words: wire::Words) -> Result<[u64; 3], u32> {
    let request = wire::Lookup::decode(words)?;
    let caller = caller.restricted_to(request.mode);
    let expected = (request.expected_type != 0).then_some(request.expected_type);
    let (target, information) = service_sec_image::with_provider_process_manager(|pm| {
        pm.lookup_native_user_object_handle(caller, request.handle, request.desired_access, expected)
    })?;
    if target.domain != domain {
        return Err(nt_process::native_handle::STATUS_OBJECT_TYPE_MISMATCH);
    }
    Ok(wire::Resolved {
        body: target.body,
        object_type: target.object_type,
        generation: target.generation,
        granted_access: information.granted_access.ok_or(nt_process::STATUS_INVALID_HANDLE)?,
        attributes: information.attributes,
    }
    .encode())
}

unsafe fn close(caller: NativeHandleCaller, domain: u64, words: wire::Words) -> Result<[u64; 3], u32> {
    let request = wire::Close::decode(words)?;
    let caller = caller.restricted_to(request.mode);
    let result = service_sec_image::with_provider_process_manager(|pm| {
        let (target, _) = pm.lookup_native_user_object_handle(caller, request.handle, 0, None)?;
        if target.domain != domain {
            return Err(nt_process::native_handle::STATUS_OBJECT_TYPE_MISMATCH);
        }
        Ok(pm.close_native_user_object_handle(caller, request.handle))
    })?;
    match result {
        Ok(target) => {
            release(target);
            Ok([0; 3])
        }
        Err(NativeCloseError::Status(status)) => Err(status),
        // ObCloseHandle of a protected kernel handle: the provider raises this bugcheck.
        Err(NativeCloseError::BugCheck { code, parameters }) => {
            Ok([u64::from(code), parameters[0], parameters[1]])
        }
    }
}

unsafe fn find(caller: NativeHandleCaller, words: wire::Words) -> Result<[u64; 3], u32> {
    let request = wire::Find::decode(words)?;
    let found = service_sec_image::with_provider_process_manager(|pm| {
        let process = pm
            .pid_for_kernel_process_object(request.process)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        pm.find_native_user_object_handle(
            caller,
            process,
            (request.body != 0).then_some(request.body),
            (request.object_type != 0).then_some(request.object_type),
            request.information.map(|(attributes, granted)| NativeHandleInformation {
                attributes,
                granted_access: Some(granted),
            }),
        )
    })?;
    Ok(found.map_or([0; 3], |handle| [1, u64::from(handle), 0]))
}

/// NtQuery/SetSecurityObject on a USER handle in `pid`'s table: the exact target and grant.
pub(crate) fn handle_target(
    pm: &nt_process::ProcessManager,
    pid: nt_process::ProcessId,
    handle: u64,
) -> Option<(UserObjectTarget, u32)> {
    let handle = u32::try_from(handle).ok()? as nt_process::Handle;
    let nt_process::HandleObject::UserObject(target) = pm.lookup_handle(pid, handle)? else {
        return None;
    };
    Some((target, pm.handle_access(pid, handle)?))
}
