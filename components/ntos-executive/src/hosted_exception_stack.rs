//! Physical stack access for a paused hosted-driver exception dispatch.
//!
//! A component virtual address is never sufficient to select a stack: every driver uses the same
//! main-stack address and worker slots are reused. Keep the reader scoped to the active physical
//! ingress dispatch, and revalidate that dispatch before touching its executive alias.

use alloc::vec::Vec;
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_io_manager::HostedDomainIdentity;
use nt_unwind::{
    exception_walk::{
        ExceptionImageReader, ExceptionWalk, FirstRaiseStep, HandlerInvocation, WalkError,
        WalkMode, WalkStep,
    },
    raw_context::{RawContext, RawContextCaptureError, RawContextRestoreError},
    hardware_fault,
    raw_exception::RawExceptionRecord,
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FaultSourceIdentity {
    instance: usize,
    domain: HostedDomainIdentity,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    tcb: u64,
    thread_handle: u64,
    worker: Option<WorkerIdentity>,
}

pub(crate) struct CapturedCpuFault {
    pub source: FaultSourceIdentity,
    pub first: SehRaiseFirstPass,
    pub entry_va: u64,
    pub entry_rsp: u64,
    pub registers: [u64; 20],
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

    fn fault_source(&self) -> FaultSourceIdentity {
        FaultSourceIdentity {
            instance: self.instance,
            domain: self.domain,
            route: self.route,
            dispatch: self.dispatch,
            tcb: self.tcb,
            thread_handle: self.thread_handle,
            worker: self.worker,
        }
    }
}

pub(crate) fn fault_source_identity(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
) -> Option<FaultSourceIdentity> {
    let reader = HostedStackReader::new(channel, reply_cap, badge)?;
    reader.still_live().then(|| reader.fault_source())
}

/// Read the actual fault-blocked TCB under the same physical dispatch lease used by the stack
/// walker. Every frame is classified before changing the target's registers or consuming Reply.
pub(crate) fn capture_cpu_fault(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    label: u64,
    words: [u64; 5],
) -> Option<CapturedCpuFault> {
    let (instance, inst) = instance_for_pump_channel(channel, reply_cap)?;
    let domain = instance_domain_identity(inst)?;
    let linkage = inst.seh_linkage?;
    with_reader(channel, reply_cap, badge, |stack, low, high| {
        let reader = HostedStackReader::new(channel, reply_cap, badge)?;
        let snapshot = unsafe { crate::thread_context::LegacyThreadContext::read(reader.tcb).ok()? };
        if !reader.still_live() || snapshot.registers[0] != words[0] {
            return None;
        }
        let raw = RawContext::from_legacy_snapshot(
            &snapshot.registers,
            &snapshot.floating_point,
            &snapshot.debug,
        ).ok()?;
        let exception = match label {
            6 if words[2] <= 1 => {
                hardware_fault::page_fault(words[0], words[1], words[3], words[2] != 0)?
            }
            3 if snapshot.registers[1] == words[1]
                && snapshot.registers[2] == words[2] => {
                hardware_fault::user_exception(words[0], words[3], words[4])?
            }
            _ => return None,
        };
        let original_rsp = raw.rsp();
        let entry_rsp = original_rsp.checked_sub(0x100)? & !15 | 8;
        if original_rsp > high || entry_rsp.checked_sub(0x4000)? < low {
            return None;
        }
        let step = super::hosted_exception_images::with_catalog(instance, domain, |catalog| {
            let mut walk = ExceptionWalk::new(
                WalkMode::Search,
                exception,
                raw.to_context(),
                low,
                high,
                64,
            ).ok()?
            .with_foreign_boundary(
                linkage.image_base,
                (linkage.foreign_call2_va - linkage.image_base) as u32,
            )
            .with_second_foreign_boundary(
                linkage.image_base,
                (linkage.foreign_call16_va - linkage.image_base) as u32,
            );
            loop {
                match walk.step(catalog, stack).ok()? {
                    WalkStep::Continue(next) => walk = next,
                    WalkStep::Invoke(handler) => break Some(FirstRaiseStep::Invoke(handler)),
                    WalkStep::Complete(outcome) => break Some(FirstRaiseStep::Complete(outcome)),
                }
            }
        })??;
        Some(CapturedCpuFault {
            source: reader.fault_source(),
            first: SehRaiseFirstPass { captured: raw, step },
            entry_va: linkage.fault_entry_va,
            entry_rsp,
            registers: snapshot.registers,
        })
    })?
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

pub(crate) enum UnwindCaptureError {
    Packet,
    Sidecar,
    Caller,
    Target,
    Record,
    Context(RawContextCaptureError),
    Walk(WalkError),
}

/// Writes can have an uncertain effect after the first word. The caller must wall the physical
/// dispatch on `Uncertain`, never retry the packet on another stack or Reply.
pub(crate) enum PacketWriteError {
    Refused,
    Uncertain,
}

/// Install the two control words needed when a target unwind reaches its landing point without
/// invoking a language handler. A later Prepare may replace the whole packet under this lease.
pub(crate) fn initialize_restore_packet(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    packet_va: u64,
    token: u64,
    resume_va: u64,
) -> Result<(), PacketWriteError> {
    let reader =
        HostedStackReader::new(channel, reply_cap, badge).ok_or(PacketWriteError::Refused)?;
    if packet_va == 0 || packet_va & 15 != 0 || token == 0 || resume_va == 0 {
        return Err(PacketWriteError::Refused);
    }
    let exec = translate_component_range(
        packet_va,
        core::mem::size_of::<SehHandlerPacket>() as u64,
        reader.component_base,
        reader.length,
        reader.exec_base,
    )
    .ok_or(PacketWriteError::Refused)?;
    if !reader.still_live() {
        return Err(PacketWriteError::Refused);
    }
    unsafe {
        core::ptr::write_volatile(
            (exec + core::mem::offset_of!(SehHandlerPacket, token) as u64) as *mut u64,
            token,
        );
    }
    if !reader.still_live() {
        return Err(PacketWriteError::Uncertain);
    }
    unsafe {
        core::ptr::write_volatile(
            (exec + core::mem::offset_of!(SehHandlerPacket, resume_va) as u64) as *mut u64,
            resume_va,
        );
    }
    if !reader.still_live() {
        return Err(PacketWriteError::Uncertain);
    }
    Ok(())
}

/// Publish one owned handler packet through the exact paused thread's executive stack alias.
pub(crate) fn write_handler_packet(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    address: u64,
    packet: &SehHandlerPacket,
) -> Result<(), PacketWriteError> {
    let reader =
        HostedStackReader::new(channel, reply_cap, badge).ok_or(PacketWriteError::Refused)?;
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
    if address == 0 || address & 15 != 0 || address < low || address.checked_add(length)? > high {
        return None;
    }
    let mut packet = core::mem::MaybeUninit::<SehHandlerPacket>::uninit();
    let output = packet.as_mut_ptr().cast::<u8>();
    for index in (0..length).step_by(8) {
        let word = reader.read_u64(address + index)?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                word.to_le_bytes().as_ptr(),
                output.add(index as usize),
                8,
            )
        };
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
        Some(expected.apply_return(&returned, invocation, disposition, reader, low, high))
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

/// Copy the shim's fixed request and register image under one physical stack lease, then run the
/// native unwind walker. The trusted component snapshots an optional caller exception record
/// into the retained packet before this Call, so its source may reside outside the stack.
pub(crate) fn capture_unwind_first_step(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    request_va: u64,
    packet_va: u64,
) -> Option<Result<SehRaiseFirstPass, UnwindCaptureError>> {
    let (instance, inst) = instance_for_pump_channel(channel, reply_cap)?;
    let domain = instance_domain_identity(inst)?;
    let linkage = inst.seh_linkage?;
    with_reader(channel, reply_cap, badge, |reader, low, high| {
        super::hosted_exception_images::with_catalog(instance, domain, |catalog| {
            let packet_end = packet_va
                .checked_add(core::mem::size_of::<SehHandlerPacket>() as u64)
                .ok_or(UnwindCaptureError::Packet)?;
            let request_end = request_va
                .checked_add(0x40)
                .ok_or(UnwindCaptureError::Sidecar)?;
            if packet_va & 15 != 0 || packet_va < low || packet_end > high {
                return Err(UnwindCaptureError::Packet);
            }
            if request_va & 15 != 0 || request_va < low || request_end > high {
                return Err(UnwindCaptureError::Sidecar);
            }
            let mut words = [0u64; 8];
            for (index, word) in words.iter_mut().enumerate() {
                *word = reader
                    .read_u64(request_va + (index as u64) * 8)
                    .ok_or(UnwindCaptureError::Sidecar)?;
            }
            let [target_frame, target_ip, record_va, return_value, context_record_va, _history, captured_va, original_rsp] =
                words;
            if captured_va != request_end
                || original_rsp
                    != request_va
                        .checked_add(0x518)
                        .ok_or(UnwindCaptureError::Sidecar)?
                || context_record_va == 0
                || context_record_va & 15 != 0
            {
                return Err(UnwindCaptureError::Sidecar);
            }
            let raw = RawContext::capture_bounded(reader, captured_va, low, high)
                .map_err(UnwindCaptureError::Context)?;
            if raw.rsp()
                != original_rsp
                    .checked_add(8)
                    .ok_or(UnwindCaptureError::Caller)?
                || reader.read_u64(original_rsp) != Some(raw.rip())
                || catalog.lookup_exception_function(raw.rip()).is_err()
            {
                return Err(UnwindCaptureError::Caller);
            }
            if target_frame != 0 && catalog.lookup_exception_function(target_ip).is_err() {
                return Err(UnwindCaptureError::Target);
            }
            let exception = if record_va == 0 {
                ExceptionRecord {
                    code: 0xc000_0027,
                    flags: 0,
                    address: raw.rip(),
                    information: Vec::new(),
                }
            } else {
                if record_va & 7 != 0 {
                    return Err(UnwindCaptureError::Record);
                }
                let copy_va = packet_va;
                let header = reader.read_u64(copy_va).ok_or(UnwindCaptureError::Record)?;
                let chained = reader
                    .read_u64(copy_va + 8)
                    .ok_or(UnwindCaptureError::Record)?;
                let address = reader
                    .read_u64(copy_va + 0x10)
                    .ok_or(UnwindCaptureError::Record)?;
                let count_word = reader
                    .read_u64(copy_va + 0x18)
                    .ok_or(UnwindCaptureError::Record)?;
                let count = count_word as u32;
                if chained != 0 || count_word >> 32 != 0 || count > 15 {
                    return Err(UnwindCaptureError::Record);
                }
                let mut information = Vec::new();
                information
                    .try_reserve(count as usize)
                    .map_err(|_| UnwindCaptureError::Record)?;
                for index in 0..count {
                    information.push(
                        reader
                            .read_u64(copy_va + 0x20 + u64::from(index) * 8)
                            .ok_or(UnwindCaptureError::Record)?,
                    );
                }
                ExceptionRecord {
                    code: header as u32,
                    flags: (header >> 32) as u32,
                    address,
                    information,
                }
            };
            let mut walk = ExceptionWalk::new(
                WalkMode::Unwind {
                    target_frame: (target_frame != 0).then_some(target_frame),
                    target_ip,
                    return_value,
                },
                exception,
                raw.to_context(),
                low,
                high,
                64,
            )
            .map_err(UnwindCaptureError::Walk)?
            .with_foreign_boundary(
                linkage.image_base,
                (linkage.foreign_call2_va - linkage.image_base) as u32,
            )
            .with_second_foreign_boundary(
                linkage.image_base,
                (linkage.foreign_call16_va - linkage.image_base) as u32,
            );
            let step = loop {
                match walk
                    .step(catalog, reader)
                    .map_err(UnwindCaptureError::Walk)?
                {
                    WalkStep::Continue(next) => walk = next,
                    WalkStep::Invoke(handler) => break FirstRaiseStep::Invoke(handler),
                    WalkStep::Complete(outcome) => break FirstRaiseStep::Complete(outcome),
                }
            };
            Ok(SehRaiseFirstPass {
                captured: raw,
                step,
            })
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
    let linkage = inst.seh_linkage?;
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
            )?
            .with_foreign_boundary(
                linkage.image_base,
                (linkage.foreign_call2_va - linkage.image_base) as u32,
            )
            .with_second_foreign_boundary(
                linkage.image_base,
                (linkage.foreign_call16_va - linkage.image_base) as u32,
            );
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
    let destination =
        packet_va.checked_add(core::mem::offset_of!(SehHandlerPacket, original_context) as u64)?;
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
