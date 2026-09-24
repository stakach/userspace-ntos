//! Physical stack access for a paused hosted-driver exception dispatch.
//!
//! A component virtual address is never sufficient to select a stack: every driver uses the same
//! main-stack address and worker slots are reused. Keep the reader scoped to the active physical
//! ingress dispatch, and revalidate that dispatch before touching its executive alias.

use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_io_manager::HostedDomainIdentity;
use nt_unwind::{
    exception_walk::{
        ExceptionImageReader, ExceptionWalk, FirstRaiseStep, HandlerInvocation, WalkError,
        WalkMode, WalkStep,
    },
    raw_context::{RawContext, RawContextCaptureError, RawContextRestoreError},
    seh_handler_packet::{HandlerPacketError, SehHandlerPacket},
    seh_linkage_image::{SehRaiseFirstPass, SehRaiseIngressError},
    Context, ExceptionRecord, StackReader,
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

pub(crate) enum RaiseCaptureError {
    Context(RawContextCaptureError),
    Admission(SehRaiseIngressError),
}

/// Writes can have an uncertain effect after the first word. The caller must wall the physical
/// dispatch on `Uncertain`, never retry the packet on another stack or Reply.
pub(crate) enum PacketWriteError {
    Refused,
    Uncertain,
}

/// Publish one owned handler packet through the exact paused thread's executive stack alias.
pub(crate) fn write_handler_packet(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    address: u64,
    packet: &SehHandlerPacket,
) -> Result<(), PacketWriteError> {
    let reader = HostedStackReader::new(channel, reply_cap, badge)
        .ok_or(PacketWriteError::Refused)?;
    let length = core::mem::size_of::<SehHandlerPacket>() as u64;
    if address == 0 || address & 15 != 0 || !reader.still_live() {
        return Err(PacketWriteError::Refused);
    }
    let exec = translate_component_range(
        address,
        length,
        reader.component_base,
        reader.length,
        reader.exec_base,
    )
    .ok_or(PacketWriteError::Refused)?;
    // Ownership and bounds are established before the first write. Once a byte may have reached
    // the component's stack, failure is uncertain even if the final lease check rejects it.
    // `SehHandlerPacket` has ABI padding after RUNTIME_FUNCTION. Copy named fields into a
    // zeroed byte image so no uninitialized Rust padding is read or disclosed to the driver.
    let mut bytes = [0u8; core::mem::size_of::<SehHandlerPacket>()];
    macro_rules! field {
        ($name:ident) => {{
            let offset = core::mem::offset_of!(SehHandlerPacket, $name);
            let size = core::mem::size_of_val(&packet.$name);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::addr_of!(packet.$name).cast::<u8>(),
                    bytes.as_mut_ptr().add(offset),
                    size,
                );
            }
        }};
    }
    field!(exception);
    field!(exception_pointers);
    field!(original_context);
    field!(unwound_context);
    field!(dispatcher);
    field!(function);
    field!(filter_wrapper);
    field!(finally_wrapper);
    field!(search_wrapper);
    field!(unwind_wrapper);
    field!(token);
    field!(resume_va);
    for (index, word) in bytes.chunks_exact(8).enumerate() {
        if !reader.still_live() {
            return Err(if index == 0 {
                PacketWriteError::Refused
            } else {
                PacketWriteError::Uncertain
            });
        }
        let value = u64::from_le_bytes(word.try_into().expect("eight-byte packet word"));
        unsafe { core::ptr::write_volatile((exec + (index * 8) as u64) as *mut u64, value) };
    }
    if !reader.still_live() {
        return Err(PacketWriteError::Uncertain);
    }
    Ok(())
}

/// Capture the full packet after a handler Call, before consuming its one-shot continuation.
/// Each word is read under the same physical dispatch lease; no component reference escapes.
fn read_handler_packet(
    reader: &dyn StackReader,
    address: u64,
    low: u64,
    high: u64,
) -> Option<SehHandlerPacket> {
    let length = core::mem::size_of::<SehHandlerPacket>() as u64;
    if address == 0
        || address & 15 != 0
        || address < low
        || address.checked_add(length)? > high
    {
        return None;
    }
    let mut packet = core::mem::MaybeUninit::<SehHandlerPacket>::uninit();
    let output = packet.as_mut_ptr().cast::<u8>();
    for index in (0..length).step_by(8) {
        let word = reader.read_u64(address + index)?;
        unsafe { core::ptr::copy_nonoverlapping(word.to_le_bytes().as_ptr(), output.add(index as usize), 8) };
    }
    Some(unsafe { packet.assume_init() })
}

pub(crate) fn apply_handler_return(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    address: u64,
    expected: &SehHandlerPacket,
    invocation: &mut HandlerInvocation,
    disposition: i32,
) -> Option<Result<(), HandlerPacketError>> {
    with_reader(channel, reply_cap, badge, |reader, low, high| {
        let returned = read_handler_packet(reader, address, low, high)?;
        Some(expected.apply_return(
            &returned,
            invocation,
            disposition,
            reader,
            low,
            high,
        ))
    })?
}

/// Advance a software raise to the first owned handler invocation or terminal result while its
/// stack and sealed image catalog still belong to the same physically retained dispatch.
pub(crate) fn capture_raise_first_step(
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

/// Continue an owned walk only while its original component stack and exception-image catalog
/// are still physically retained. A handler result is applied before entering this helper.
pub(crate) fn advance_raise_walk(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mut walk: ExceptionWalk,
) -> Option<Result<FirstRaiseStep, WalkError>> {
    let (instance, inst) = instance_for_pump_channel(channel, reply_cap)?;
    let domain = instance_domain_identity(inst)?;
    with_reader(channel, reply_cap, badge, |reader, _, _| {
        super::hosted_exception_images::with_catalog(instance, domain, |catalog| loop {
            match walk.step(catalog, reader)? {
                WalkStep::Continue(next) => walk = next,
                WalkStep::Invoke(handler) => return Ok(FirstRaiseStep::Invoke(handler)),
                WalkStep::Complete(outcome) => return Ok(FirstRaiseStep::Complete(outcome)),
            }
        })
    })?
}

/// Start a target unwind from the authenticated search context. This transition occurs when a
/// real C filter selects a handler; the search handler does not return a disposition first.
pub(crate) fn start_target_unwind(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    exception: ExceptionRecord,
    context: Context,
    target_frame: u64,
    target_ip: u64,
) -> Option<Result<FirstRaiseStep, WalkError>> {
    let (instance, inst) = instance_for_pump_channel(channel, reply_cap)?;
    let domain = instance_domain_identity(inst)?;
    with_reader(channel, reply_cap, badge, |reader, low, high| {
        super::hosted_exception_images::with_catalog(instance, domain, |catalog| {
            catalog
                .lookup_exception_function(target_ip)
                .map_err(WalkError::ImageLookup)?;
            let mut walk = ExceptionWalk::new(
                WalkMode::Unwind {
                    target_frame: Some(target_frame),
                    target_ip,
                    return_value: u64::from(exception.code),
                },
                exception,
                context,
                low,
                high,
                64,
            )?;
            loop {
                match walk.step(catalog, reader)? {
                    WalkStep::Continue(next) => walk = next,
                    WalkStep::Invoke(handler) => return Ok(FirstRaiseStep::Invoke(handler)),
                    WalkStep::Complete(outcome) => return Ok(FirstRaiseStep::Complete(outcome)),
                }
            }
        })
    })?
}

/// Publish the checked final register state into this thread's current packet. A failed or
/// uncertain write is a wall; never reissue it against a new dispatch or stack lease.
pub(crate) fn publish_restore_context(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    packet_va: u64,
    captured: &RawContext,
    context: Context,
) -> Option<Result<u64, RawContextRestoreError>> {
    let (instance, inst) = instance_for_pump_channel(channel, reply_cap)?;
    let domain = instance_domain_identity(inst)?;
    let reader = HostedStackReader::new(channel, reply_cap, badge)?;
    let (low, high) = reader.bounds()?;
    let destination = packet_va.checked_add(
        core::mem::offset_of!(SehHandlerPacket, original_context) as u64,
    )?;
    let length = core::mem::size_of::<RawContext>() as u64;
    let exec = translate_component_range(
        destination,
        length,
        reader.component_base,
        reader.length,
        reader.exec_base,
    )?;
    let mut raw = captured.clone();
    raw.update_from_context(&context);
    let validation = super::hosted_exception_images::with_catalog(instance, domain, |catalog| {
        raw.validate_restore(captured, low, high, |pc| {
            catalog.lookup_exception_function(pc).is_ok()
        })
    })?;
    if let Err(error) = validation {
        return Some(Err(error));
    }
    let scratch = raw.rsp().checked_sub(32)?;
    if destination < raw.rsp() && destination.checked_add(length)? > scratch {
        return None;
    }
    for (index, bytes) in raw.as_bytes().chunks_exact(8).enumerate() {
        if !reader.still_live() {
            return None;
        }
        let word = u64::from_le_bytes(bytes.try_into().expect("eight-byte context word"));
        unsafe { core::ptr::write_volatile((exec + (index * 8) as u64) as *mut u64, word) };
    }
    reader.still_live().then_some(Ok(destination))
}
