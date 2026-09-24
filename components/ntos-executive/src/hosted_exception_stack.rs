//! Physical stack access for a paused hosted-driver exception dispatch.
//!
//! A component virtual address is never sufficient to select a stack: every driver uses the same
//! main-stack address and worker slots are reused. Keep the reader scoped to the active physical
//! ingress dispatch, and revalidate that dispatch before touching its executive alias.

use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_io_manager::HostedDomainIdentity;
use nt_unwind::{
    raw_context::{RawContext, RawContextCaptureError},
    seh_linkage_image::{SehRaiseFirstPass, SehRaiseIngressError},
    StackReader,
};

use super::{
    hosted_driver_caller, hosted_thread_resources, hosted_worker_component_base_for_slot,
    hosted_worker_exec_base_for_alias, instance_domain_identity, instance_for_pump_channel,
    translate_component_range, DriverInstance, HostedDriverCaller, FSD_STACK_BYTES,
    FSD_STACK_VADDR, FSD_WORKER_STACK_FRAMES,
};

// Do not return this reader to a caller. Its executive alias is valid only while the authenticated
// physical dispatch is paused and retains the mapped stack frames.
struct HostedStackReader {
    channel: crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    instance: usize,
    domain: HostedDomainIdentity,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    tcb: u64,
    thread_handle: u64,
    worker: Option<WorkerIdentity>,
    component_base: u64,
    exec_base: u64,
    length: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct WorkerIdentity {
    component_slot: usize,
    exec_alias_slot: u64,
    construction: usize,
}

impl HostedStackReader {
    fn new(channel: &crate::spawn_hosts::PumpChannel, reply_cap: u64, badge: u64) -> Option<Self> {
        let (instance, inst) = instance_for_pump_channel(channel, reply_cap)?;
        let caller = hosted_driver_caller(instance, inst, badge)?;
        if channel.ingress_route != Some(caller.route)
            || channel.fault_ep != caller.route.endpoint()
            || caller.route.badge() != badge
        {
            return None;
        }
        let domain = instance_domain_identity(inst)?;
        let dispatch = unsafe {
            crate::spawn_hosts::shared_ingress::owner::runtime::dispatch(caller.route).ok()?
        };
        let (tcb, worker, component_base, exec_base, length) = Self::stack_window(inst, &caller)?;
        if channel.tcb != tcb || exec_base == 0 {
            return None;
        }
        Some(Self {
            channel: *channel,
            reply_cap,
            badge,
            instance,
            domain,
            route: caller.route,
            dispatch,
            tcb,
            thread_handle: caller.thread_handle,
            worker,
            component_base,
            exec_base,
            length,
        })
    }

    fn stack_window(
        inst: DriverInstance,
        caller: &HostedDriverCaller,
    ) -> Option<(u64, Option<WorkerIdentity>, u64, u64, u64)> {
        match caller.runtime {
            None => Some((
                inst.tcb,
                None,
                FSD_STACK_VADDR,
                inst.exec_stack_va,
                FSD_STACK_BYTES,
            )),
            Some(runtime) => {
                if unsafe { !hosted_thread_resources::matches(runtime.construction, runtime) } {
                    return None;
                }
                let component_base = hosted_worker_component_base_for_slot(runtime.component_slot)?;
                let exec_base = hosted_worker_exec_base_for_alias(runtime.exec_alias_slot)?;
                Some((
                    runtime.tcb,
                    Some(WorkerIdentity {
                        component_slot: runtime.component_slot,
                        exec_alias_slot: runtime.exec_alias_slot,
                        construction: runtime.construction,
                    }),
                    component_base,
                    exec_base,
                    FSD_WORKER_STACK_FRAMES.checked_mul(0x1000)?,
                ))
            }
        }
    }

    fn still_live(&self) -> bool {
        let Some((instance, inst)) = instance_for_pump_channel(&self.channel, self.reply_cap)
        else {
            return false;
        };
        if instance != self.instance || instance_domain_identity(inst) != Some(self.domain) {
            return false;
        }
        let Some(caller) = hosted_driver_caller(instance, inst, self.badge) else {
            return false;
        };
        if caller.route != self.route || caller.thread_handle != self.thread_handle {
            return false;
        }
        if unsafe { crate::spawn_hosts::shared_ingress::owner::runtime::dispatch(self.route).ok() }
            != Some(self.dispatch)
        {
            return false;
        }
        let Some((tcb, worker, component_base, exec_base, length)) =
            Self::stack_window(inst, &caller)
        else {
            return false;
        };
        tcb == self.tcb
            && worker == self.worker
            && component_base == self.component_base
            && exec_base == self.exec_base
            && length == self.length
    }

    fn bounds(&self) -> Option<(u64, u64)> {
        Some((
            self.component_base,
            self.component_base.checked_add(self.length)?,
        ))
    }
}

impl StackReader for HostedStackReader {
    fn read_u64(&self, addr: u64) -> Option<u64> {
        if addr & 7 != 0 || !self.still_live() {
            return None;
        }
        let exec =
            translate_component_range(addr, 8, self.component_base, self.length, self.exec_base)?;
        Some(unsafe { core::ptr::read_volatile(exec as *const u64) })
    }
}

/// Borrow a reader for exactly one paused physical ingress dispatch. No alias or reader escapes
/// the closure; the caller must not resume the component while it executes.
#[allow(dead_code)]
pub(super) fn with_reader<R>(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    use_reader: impl for<'a> FnOnce(&'a dyn StackReader, u64, u64) -> R,
) -> Option<R> {
    let reader = HostedStackReader::new(channel, reply_cap, badge)?;
    let (low, high) = reader.bounds()?;
    let result = use_reader(&reader, low, high);
    reader.still_live().then_some(result)
}

/// Return an owned native context only while every source word belongs to the same live dispatch.
#[allow(dead_code)]
pub(super) fn capture_raw_context(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    address: u64,
) -> Option<Result<RawContext, RawContextCaptureError>> {
    with_reader(channel, reply_cap, badge, |reader, low, high| {
        RawContext::capture_bounded(reader, address, low, high)
    })
}

pub(super) enum RaiseCaptureError {
    Context(RawContextCaptureError),
    Admission(SehRaiseIngressError),
}

/// Advance a software raise to the first owned handler invocation or terminal result while its
/// stack and sealed image catalog still belong to the same physically retained dispatch.
pub(super) fn capture_raise_first_step(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    context_address: u64,
    status_word: u64,
) -> Option<Result<SehRaiseFirstPass, RaiseCaptureError>> {
    let (instance, inst) = instance_for_pump_channel(channel, reply_cap)?;
    let domain = instance_domain_identity(inst)?;
    let linkage = inst.seh_linkage?;
    with_reader(channel, reply_cap, badge, |reader, low, high| {
        super::hosted_exception_images::with_catalog(instance, domain, |catalog| {
            let raw = RawContext::capture_bounded(reader, context_address, low, high)
                .map_err(RaiseCaptureError::Context)?;
            linkage
                .admit_first_pass(raw, status_word, low, high, catalog, reader, 64)
                .map_err(RaiseCaptureError::Admission)
        })
    })?
}
