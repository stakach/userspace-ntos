//! Registry caller authority belongs to an exact executing provider job, never a provider badge.

use super::*;
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_process::native_handle::NativeHandleCaller;
use nt_process::STATUS_INVALID_HANDLE;
use nt_user_host::provider_registry_callers::RegistryCallerOwners;
use spawn_hosts::shared_ingress::owner::runtime;

static mut OWNERS: RegistryCallerOwners<PeerRoute, LaneDispatchIdentity> =
    RegistryCallerOwners::new();

/// Proof that the root has retained authority for one physical job. The canonical ingress
/// completion hook retires it, including after a pump parks or returns an uncertain wall.
pub(crate) struct Scope;

impl Scope {
    pub(crate) unsafe fn enter(
        channel: &spawn_hosts::PumpChannel,
        caller: NativeHandleCaller,
    ) -> Result<Self, u32> {
        let route = runtime::channel_route(channel)
            .map_err(|_| STATUS_INVALID_HANDLE)?
            .ok_or(STATUS_INVALID_HANDLE)?;
        let dispatch = match runtime::dispatch(route) {
            Ok(dispatch) => Some(dispatch),
            Err(_) if channel.initial == spawn_hosts::InitialAction::RecvFirst => None,
            Err(_) => return Err(STATUS_INVALID_HANDLE),
        };
        let _durable = allocator::enter_durable();
        let result = service_sec_image::with_provider_process_manager(|pm| {
            (&mut *core::ptr::addr_of_mut!(OWNERS)).capture(
                pm,
                route,
                dispatch,
                channel.pml4,
                caller,
            )
        });
        if let Err(status) = result {
            return Err(status);
        }
        Ok(Self)
    }
}

/// Called only after canonical shared ingress has authenticated this job's final completion.
pub(crate) unsafe fn retire_completed(route: PeerRoute, dispatch: LaneDispatchIdentity) {
    crate::driver_launch::driver_thread_projection::complete(route, dispatch)
        .expect("completed driver projection retains exact thread references");
    service_sec_image::with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(OWNERS)).retire(pm, route, dispatch)
    })
    .expect("terminal provider job owns exact registry requestor references");
}

fn reject(channel: &spawn_hosts::PumpChannel, stage: &[u8], status: u32) -> u32 {
    print_str(b"[provider-caller-rejected] stage=");
    print_str(stage);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" channel[tcb,pml4,reply,pi,generation]=");
    for value in [
        channel.tcb,
        channel.pml4,
        channel.reply_cap,
        channel.client_pi,
        channel.client_generation,
    ] {
        print_str(b" ");
        print_u64(value);
    }
    if let Some(caller) = channel.logical_caller {
        print_str(b" logical[pi,pid,tid,thread-generation,badge,tcb]=");
        for value in [
            caller.pi() as u64,
            u64::from(caller.process().pid),
            u64::from(caller.thread().thread_id()),
            caller.thread().generation(),
            caller.badge(),
            caller.tcb(),
        ] {
            print_str(b" ");
            print_u64(value);
        }
        if let nt_user_host::process_identity::ProcessGeneration::Hosted(generation) =
            caller.process().generation
        {
            print_str(b" logical-hosted-generation=");
            print_u64(generation);
        }
    }
    print_str(b"\n");
    status
}

pub(crate) unsafe fn resolve(
    channel: &spawn_hosts::PumpChannel,
) -> Result<NativeHandleCaller, u32> {
    let route = runtime::channel_route(channel)
        .map_err(|_| reject(channel, b"channel-route", STATUS_INVALID_HANDLE))?
        .ok_or_else(|| reject(channel, b"channel-route", STATUS_INVALID_HANDLE))?;
    let dispatch = runtime::dispatch(route)
        .map_err(|_| reject(channel, b"dispatch", STATUS_INVALID_HANDLE))?;
    if channel.logical_caller.is_some() && channel.kernel_caller.is_some() {
        return Err(reject(channel, b"mixed-caller", STATUS_INVALID_HANDLE));
    }
    if channel.kernel_caller.is_some() {
        return service_sec_image::kernel_provider_activation::registry_caller(channel)
            .map_err(|status| reject(channel, b"kernel-activation", status));
    }
    if let Some(caller) = channel.logical_caller {
        if !crate::win32k_glue::registry_logical_caller_is_current(channel) {
            return Err(reject(channel, b"registry-current", STATUS_INVALID_HANDLE));
        }
        if caller.pi() as u64 != channel.client_pi {
            return Err(reject(channel, b"client-pi", STATUS_INVALID_HANDLE));
        }
        if caller.process().generation
            != nt_user_host::process_identity::ProcessGeneration::Hosted(channel.client_generation)
        {
            return Err(reject(
                channel,
                b"process-generation",
                STATUS_INVALID_HANDLE,
            ));
        }
        if !service_sec_image::validate_provider_logical_caller(caller) {
            return Err(reject(
                channel,
                b"logical-caller-identity",
                STATUS_INVALID_HANDLE,
            ));
        }
        return service_sec_image::with_provider_process_manager(|pm| {
            pm.capture_native_handle_caller(caller.thread(), nt_types::AccessMode::KernelMode)
        })
        .map_err(|status| reject(channel, b"fresh-native-handle-caller", status));
    }
    if let Some(caller) = crate::driver_launch::autonomous_registry_caller(channel)
        .map_err(|status| reject(channel, b"autonomous-caller", status))?
    {
        return Ok(caller);
    }
    // RecvFirst has no admitted Call at root dispatch time. Bind once after shared ingress
    // authenticates its first real request; subsequent requests cannot change the dispatch epoch.
    service_sec_image::with_provider_process_manager(|pm| {
        (&mut *core::ptr::addr_of_mut!(OWNERS)).resolve(pm, route, dispatch, channel.pml4)
    })
    .map_err(|status| reject(channel, b"retained-owner", status))
}
