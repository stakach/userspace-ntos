//! File-less win32k TargetDeviceRelation dispatched to an exact canonical Device.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_target::HostedForwardTarget;
use nt_io_manager::win32k_source_pnp_wire as wire;
use nt_kernel_exec::{EventObjectId, EventSignalMode};
use nt_provider_wait::{ProviderAllocationCatalog, ProviderAllocationSnapshot, ProviderArenaIdentity};

use super::hosted_kernel_win32k_source_ioctl::{capture_event, release_event, CanonicalEvent, Target};

type Route = nt_component_suspension::peer_registry::PeerRoute;
type Identity = (Route, u64, u64);

struct Work {
    route: Route,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    source_address: u64,
    source_ticket: u64,
    source_generation: u64,
    source: crate::win32k_subsystem::SourcePnpDispatchLease,
    target: HostedForwardTarget,
    event: Option<CanonicalEvent>,
    iosb_target: Target,
    packet_lease: crate::win32k_subsystem::ProviderPoolPacketLease,
    packet: Vec<u8>,
    canonical_irp: Option<IrpId>,
    receipt: Option<nt_io_manager::ExternalPnpTerminalReceipt>,
    pending: bool,
    entered: bool,
    terminal: Option<(u32, u64)>,
    relation: Option<nt_pnp_manager::TargetRelationDelivery>,
    relation_allocation: Option<crate::win32k_subsystem::SourceRelationAllocationLease>,
    source_allocation: Option<hosted_driver_relation_source::DriverRelationSource>,
    source_pdo: Option<nt_io_manager::HostedDevicePointerReference>,
    allocations: ProviderAllocationCatalog,
    source_snapshot: Option<ProviderAllocationSnapshot>,
    destination_snapshot: Option<ProviderAllocationSnapshot>,
    relation_claimed: bool,
    terminal_claimed: bool,
    terminal_published: bool,
    event_claimed: bool,
    event_signaled: bool,
    packet_prepared: bool,
    reply_entered: bool,
    reply_acked: bool,
    ack_claimed: bool,
    cancel_requested: bool,
    indeterminate: bool,
}

struct CompletionWait {
    identity: Identity,
    route: Route,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    wait_token: u64,
    reply_entered: bool,
    cancelled: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static mut ACTIVE: Vec<Identity> = Vec::new();
static mut COMPLETED: Vec<Identity> = Vec::new();
static mut COMPLETION_WAITS: Vec<CompletionWait> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static NEXT_WAIT_TOKEN: AtomicU64 = AtomicU64::new(1);
static CURSOR: AtomicU64 = AtomicU64::new(0);

pub(crate) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    packet_address: u64,
    packet_length: u64,
    stack_pointer: u64,
    handler: *mut ExecNtHandler,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    let route = match runtime::channel_route(channel) {
        Ok(Some(route)) => route,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    if crate::win32k_glue::win32k_stack_alias_for_route(route, stack_pointer, 1).is_none() {
        return Some(STATUS_ACCESS_DENIED);
    }
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    if packet_length != wire::PACKET_BYTES as u64 {
        return Some(STATUS_INVALID_BUFFER_SIZE as i32);
    }
    let (packet_lease, packet) = match crate::win32k_subsystem::capture_provider_pool_packet(
        packet_address, wire::PACKET_BYTES,
    ) {
        Ok(captured) => captured,
        Err(status) => return Some(status as i32),
    };
    let request = match wire::decode_request(&packet) {
        Ok(request) => request,
        Err(_) => return Some(STATUS_INVALID_PARAMETER),
    };
    if super::hosted_kernel_win32k_source_admission::contains(request.source_irp_va) {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let access = match crate::win32k_device_consumer::authenticate(
        channel, reply_cap, request.device_object_va,
    ) {
        Ok(access) if access.dispatch() == dispatch => access,
        Ok(_) => return Some(STATUS_ACCESS_DENIED),
        Err(status) => return Some(status),
    };
    let mut target = match HostedForwardTarget::capture(
        io_manager_mut(), access.domain(), access.address(),
    ) {
        Ok(target) if target.device_id() == access.device() => target,
        Ok(mut target) => {
            target.release(io_manager_mut()).expect("mismatched PnP target");
            return Some(STATUS_INVALID_DEVICE_REQUEST as i32);
        }
        Err(status) => return Some(status.raw()),
    };
    let mut event = match capture_event(handler, request.event) {
        Ok(event) => event,
        Err(status) => {
            target.release(io_manager_mut()).expect("unentered PnP target");
            return Some(status);
        }
    };
    let mut source = match crate::win32k_subsystem::admit_source_target_relation_dispatch(
        request.source_irp_va, request.device_object_va, stack_pointer,
    ) {
        Ok(source) => source,
        Err(status) => {
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered PnP target");
            return Some(status);
        }
    };
    if !source.validate()
        || source.source_address() != request.source_irp_va
        || source.source_ticket_serial() != request.source_ticket_serial
        || source.source_native_generation() != request.native_allocation_generation
        || source.device != request.device_object_va
        || request.relation_type != nt_pnp_abi::TARGET_DEVICE_RELATION
        || source.event != request.event
        || source.event.is_some() != source.event_body().is_some()
    {
        if !crate::win32k_subsystem::abort_source_target_relation_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 40]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("mismatched PnP target");
        return Some(STATUS_INVALID_PARAMETER);
    }
    let Some(iosb_target) = Target::capture(route, source.iosb_va, 16) else {
        if !crate::win32k_subsystem::abort_source_target_relation_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 41]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered PnP target");
        return Some(STATUS_INVALID_PARAMETER);
    };
    let slot = (&*core::ptr::addr_of!(WORK)).iter().enumerate().find_map(|(index, row)| {
        (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
    });
    if (slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err())
        || (&mut *core::ptr::addr_of_mut!(ACTIVE)).try_reserve(1).is_err()
        || (&mut *core::ptr::addr_of_mut!(COMPLETED)).try_reserve(1).is_err()
    {
        if !crate::win32k_subsystem::abort_source_target_relation_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 42]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered PnP target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)) {
        Ok(token) if token != 0 => token,
        _ => {
            if !crate::win32k_subsystem::abort_source_target_relation_dispatch(&mut source) {
                crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 43]);
            }
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered PnP target");
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let source_address = source.source_address();
    let source_ticket = source.source_ticket_serial();
    let source_generation = source.source_native_generation();
    if !super::hosted_kernel_win32k_source_admission::register(
        route, source_address, source_ticket, source_generation,
    ) {
        if !crate::win32k_subsystem::abort_source_target_relation_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [source_address, token, 0, 58]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered PnP target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let work = Work {
        route, dispatch, reply, token, source_address, source_ticket, source_generation,
        source, target, event, iosb_target,
        packet_lease, packet, canonical_irp: None, receipt: None, pending: false, entered: false,
        terminal: None, relation: None, relation_allocation: None, source_allocation: None,
        source_pdo: None, allocations: ProviderAllocationCatalog::new(),
        source_snapshot: None, destination_snapshot: None,
        relation_claimed: false,
        terminal_claimed: false, terminal_published: false, event_claimed: false,
        event_signaled: false, packet_prepared: false, reply_entered: false,
        reply_acked: false, ack_claimed: false, cancel_requested: false,
        indeterminate: false,
    };
    let index = if let Some(index) = slot {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        index
    } else {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        super::hosted_kernel_win32k_source_admission::retire(
            route, source_address, source_ticket, source_generation,
        );
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index].take().unwrap();
        if !crate::win32k_subsystem::abort_source_target_relation_dispatch(&mut work.source) {
            crate::provider_bugcheck::report(0xc4, [source_address, token, 0, 44]);
        }
        if let Some(event) = work.event.take() { release_event(handler, event); }
        work.target.release(io_manager_mut()).expect("unparked PnP target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    (&mut *core::ptr::addr_of_mut!(ACTIVE)).push((route, source_address, token));
    None
}

pub(crate) unsafe fn completion_for_token(
    channel: &crate::spawn_hosts::PumpChannel,
    token: u64,
    source: u64,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    if token == 0 || source == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let Ok(Some(route)) = runtime::channel_route(channel) else {
        return Some(STATUS_INVALID_HANDLE);
    };
    let identity = (route, source, token);
    if (&*core::ptr::addr_of!(COMPLETED)).contains(&identity) {
        return Some(STATUS_SUCCESS);
    }
    if !(&*core::ptr::addr_of!(ACTIVE)).contains(&identity)
        || (&*core::ptr::addr_of!(COMPLETION_WAITS)).iter().any(|wait| wait.identity == identity)
    {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    if (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS)).try_reserve(1).is_err() {
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let wait_token = match NEXT_WAIT_TOKEN.fetch_update(
        Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1),
    ) {
        Ok(token) if token != 0 => token,
        _ => return Some(STATUS_INSUFFICIENT_RESOURCES),
    };
    if runtime::park_retained_service(route, wait_token).is_err() {
        return Some(STATUS_DEVICE_NOT_READY);
    }
    (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS)).push(CompletionWait {
        identity, route, dispatch, reply, wait_token, reply_entered: false, cancelled: false,
    });
    None
}

unsafe fn redrive_completion_waits() {
    let mut index = 0;
    while index < (&*core::ptr::addr_of!(COMPLETION_WAITS)).len() {
        let wait = &mut (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS))[index];
        if !wait.cancelled && runtime::retained_service_cancelled(
            wait.route, wait.dispatch, wait.reply, wait.wait_token,
        ) {
            runtime::acknowledge_retained_service_cancellation(
                wait.route, wait.dispatch, wait.reply, wait.wait_token,
            ).expect("PnP completion wait cancellation");
            wait.cancelled = true;
        }
        if wait.cancelled {
            if let Some(completed) = (&*core::ptr::addr_of!(COMPLETED))
                .iter().position(|identity| *identity == wait.identity)
            {
                (&mut *core::ptr::addr_of_mut!(COMPLETED)).swap_remove(completed);
                (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS)).swap_remove(index);
            } else { index += 1; }
            continue;
        }
        if !(&*core::ptr::addr_of!(COMPLETED)).contains(&wait.identity) {
            index += 1;
            continue;
        }
        if !wait.reply_entered {
            wait.reply_entered = true;
            let _ = runtime::wake_service(
                wait.route, wait.dispatch, wait.reply, wait.wait_token, STATUS_SUCCESS,
            );
        }
        let acknowledged = runtime::reconcile_retained_service_reply(
            wait.route, wait.dispatch, wait.reply, wait.wait_token,
        ).expect("PnP completion Reply identity");
        if !acknowledged { index += 1; continue; }
        runtime::retire_stopped_acknowledged_retained_service(
            wait.route, wait.dispatch, wait.reply, wait.wait_token,
        ).expect("PnP completion Reply retirement");
        (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS)).swap_remove(index);
    }
}

pub(crate) unsafe fn release_token(
    channel: &crate::spawn_hosts::PumpChannel,
    token: u64,
    source: u64,
) -> i32 {
    let _durable = crate::allocator::enter_durable();
    if token == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let Ok(Some(route)) = runtime::channel_route(channel) else { return STATUS_INVALID_HANDLE };
    let identity = (route, source, token);
    redrive_completion_waits();
    if (&*core::ptr::addr_of!(COMPLETION_WAITS)).iter().any(|wait| wait.identity == identity) {
        return STATUS_PENDING as i32;
    }
    let Some(index) = (&*core::ptr::addr_of!(COMPLETED)).iter().position(|row| *row == identity)
    else { return STATUS_INVALID_PARAMETER };
    (&mut *core::ptr::addr_of_mut!(COMPLETED)).swap_remove(index);
    STATUS_SUCCESS
}

impl Work {
    unsafe fn enter(&mut self) -> bool {
        if self.entered { return true; }
        if !self.source.validate() || self.target.validate(io_manager_mut()).is_err() {
            return false;
        }
        self.entered = true;
        let prepared = match io_manager_mut().prepare_external_pnp_to_exact_device(
            ClientId(IO_MANAGER_COMPONENT_ID),
            self.target.device_id(),
            0,
            nt_io_manager::PnpParameters::query_device_relations(nt_pnp_abi::TARGET_DEVICE_RELATION),
            &[],
        ) {
            Ok(prepared) => prepared,
            Err(status) => {
                self.terminal = Some((status.raw() as u32, 0));
                return true;
            }
        };
        match io_manager_mut().dispatch_prepared_external_pnp(prepared) {
            Ok(nt_io_manager::ExternalPnpDispatchResult::Returned {
                status, information, receipt,
            }) => {
                if receipt.status() != status || receipt.information() != information {
                    self.receipt = Some(receipt);
                    self.indeterminate = true;
                    return false;
                }
                self.receipt = Some(receipt);
            }
            Ok(nt_io_manager::ExternalPnpDispatchResult::Pending { irp_id }) => {
                self.canonical_irp = Some(irp_id);
                self.pending = true;
            }
            Ok(nt_io_manager::ExternalPnpDispatchResult::ReturnedPayload { receipt, .. }) => {
                self.receipt = Some(receipt);
                self.indeterminate = true;
                return false;
            }
            Ok(nt_io_manager::ExternalPnpDispatchResult::Indeterminate { irp_id, .. }) => {
                self.canonical_irp = Some(irp_id);
                self.indeterminate = true;
                return false;
            }
            Err(rejection) => {
                let (status, prepared) = rejection.into_parts();
                if io_manager_mut().discard_prepared_external_pnp(prepared).is_err() {
                    self.indeterminate = true;
                    return false;
                }
                self.terminal = Some((status.raw() as u32, 0));
            }
        }
        true
    }

    unsafe fn publish_reply(&mut self, status: u32) -> bool {
        if self.reply_entered { return true; }
        if !self.packet_prepared {
            let result = if status == STATUS_PENDING as u32 {
                wire::publish_pending(&mut self.packet, self.token)
            } else {
                let (_, information) = self.terminal.expect("inline PnP terminal");
                wire::publish_inline_terminal(&mut self.packet, self.token, status, information)
            };
            if result.is_err() { return false; }
            self.packet_prepared = true;
        }
        if !crate::win32k_subsystem::publish_provider_pool_packet(
            self.packet_lease, &self.packet,
        ) { return false; }
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route, self.dispatch, self.reply, self.token, status as i32,
        );
        false
    }

    unsafe fn finish_cancelled_before_entry(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.entered || self.reply_entered { return false; }
        if !crate::win32k_subsystem::abort_source_target_relation_dispatch(&mut self.source) {
            return false;
        }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("cancelled PnP target");
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("cancelled PnP Reply");
        let identity = (self.route, self.source_address, self.token);
        let index = (&*core::ptr::addr_of!(ACTIVE)).iter().position(|row| *row == identity)
            .expect("cancelled PnP identity");
        (&mut *core::ptr::addr_of_mut!(ACTIVE)).swap_remove(index);
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        true
    }

    unsafe fn finish_cancelled_after_entry(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.reply_entered || self.relation_claimed || self.terminal_claimed
            || self.event_claimed
        {
            return false;
        }
        if self.indeterminate && self.canonical_irp.is_none() && self.receipt.is_none() {
            return false;
        }
        if let Some(irp) = self.canonical_irp {
            if !self.cancel_requested {
                self.cancel_requested = true;
                let _ = cancel_irp_if_pending(irp.raw());
            }
            if self.receipt.is_none() {
                let Some(receipt) = io_manager_mut().take_completed_external_pnp_receipt(irp)
                else { return false };
                self.receipt = Some(receipt);
            }
        }
        if let Some(receipt) = self.receipt.as_ref() {
            if receipt.origin_device_id() != self.target.device_id()
                || receipt.minor() != nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS
                || receipt.relation_type() != Some(nt_pnp_abi::TARGET_DEVICE_RELATION)
                || receipt.driver_pending() != self.canonical_irp.is_some()
                || self.canonical_irp.is_some_and(|irp| receipt.irp_id() != irp)
            {
                crate::provider_bugcheck::report(0xc4, [self.source_address, receipt.irp_id().raw(), 0, 61]);
            }
            if receipt.status().is_success() {
                if receipt.information() == 0 { return false; }
                if self.source_allocation.is_none() {
                    let Some(source) = hosted_driver_relation_source::DriverRelationSource::capture(
                        receipt.completion_driver_id(), receipt.information(),
                    ) else { return false };
                    self.source_allocation = Some(source);
                }
                if self.source_pdo.is_none() {
                    let source = self.source_allocation.as_ref().expect("cancelled PnP source allocation");
                    if !source.validate() { return false; }
                    let Some(domain) = source.domain() else { return false };
                    let Ok(objects) = nt_pnp_manager::copy_device_relations_x64(source.bytes())
                    else { return false };
                    if objects.len() != 1 { return false; }
                    let Some(pdo) = io_manager_mut().hosted_device_by_identity(domain, objects[0])
                    else { return false };
                    let Some(registration) = io_manager_mut()
                        .hosted_device_pointer_registration(domain, objects[0])
                    else { return false };
                    if registration.device_id() != pdo { return false; }
                    let Ok(reference) = io_manager_mut()
                        .take_hosted_device_pointer_reference(registration)
                    else { return false };
                    self.source_pdo = Some(reference);
                }
            } else if receipt.information() != 0 {
                return false;
            }
        }
        if let Some(irp) = self.canonical_irp {
            if self.ack_claimed { return false; }
            self.ack_claimed = true;
            if acknowledge_completed_irp_strict(irp.raw()).is_err() { return false; }
            self.canonical_irp = None;
        }
        if let Some(mut reference) = self.source_pdo.take() {
            reference.release(io_manager_mut()).expect("cancelled PnP PDO reference");
        }
        if let Some(source) = self.source_allocation.take() {
            if !source.retire() {
                crate::provider_bugcheck::report(0xc4, [self.source_address, 0, 0, 62]);
            }
        }
        if !crate::win32k_subsystem::abort_source_target_relation_dispatch(&mut self.source) {
            return false;
        }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("cancelled entered PnP target");
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("cancelled entered PnP Reply");
        let identity = (self.route, self.source_address, self.token);
        let index = (&*core::ptr::addr_of!(ACTIVE)).iter().position(|row| *row == identity)
            .expect("cancelled entered PnP identity");
        (&mut *core::ptr::addr_of_mut!(ACTIVE)).swap_remove(index);
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        true
    }

    unsafe fn prepare_relation(&mut self) -> bool {
        if self.terminal.is_some() { return true; }
        let receipt = self.receipt.as_ref().expect("terminal PnP receipt");
        if !receipt.status().is_success() {
            if receipt.information() != 0 { return false; }
            self.terminal = Some((receipt.status().raw() as u32, 0));
            return true;
        }
        if !self.source.validate() || self.target.validate(io_manager_mut()).is_err() {
            return false;
        }
        self.relation_claimed = true;
        if self.source_allocation.is_none() {
            let Some(source_allocation) = hosted_driver_relation_source::DriverRelationSource::capture(
                receipt.completion_driver_id(), receipt.information(),
            ) else { return false };
            self.source_allocation = Some(source_allocation);
        }
        let source_allocation = self.source_allocation.as_ref()
            .expect("claimed PnP source allocation");
        if !source_allocation.validate() || source_allocation.address() != receipt.information() {
            return false;
        }
        let Some(source_domain) = source_allocation.domain() else { return false };
        let Ok(objects) = nt_pnp_manager::copy_device_relations_x64(source_allocation.bytes())
        else { return false };
        if objects.len() != 1 { return false; }
        let source_pdo_address = objects[0];
        let Some(canonical_pdo) = io_manager_mut().hosted_device_by_identity(
            source_domain, source_pdo_address,
        ) else { return false };
        let Some(source_registration) = io_manager_mut().hosted_device_pointer_registration(
            source_domain, source_pdo_address,
        ) else { return false };
        if source_registration.device_id() != canonical_pdo {
            return false;
        }
        if self.source_pdo.is_none() {
            let Ok(source_reference) = io_manager_mut()
                .take_hosted_device_pointer_reference(source_registration)
            else { return false };
            self.source_pdo = Some(source_reference);
        }
        if !self.source_pdo.as_ref().is_some_and(|reference| {
            reference.is_held() && reference.device_id() == canonical_pdo
        }) { return false; }
        let projected_pdo = match crate::win32k_device_consumer::ensure_projection(canonical_pdo) {
            Ok(address) => address,
            Err(_) => return false,
        };
        if self.relation_allocation.is_none() {
            let Some(relation_allocation) = crate::win32k_subsystem::allocate_source_target_relation()
            else { return false };
            self.relation_allocation = Some(relation_allocation);
        }
        let relation_allocation = self.relation_allocation.as_ref()
            .expect("claimed PnP destination allocation");
        if !source_allocation.validate() || !relation_allocation.validate() {
            return false;
        }
        let relation_bytes = nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES as u64;
        let source_arena = ProviderArenaIdentity {
            id: 1, generation: source_allocation.generation(),
        };
        let source_snapshot = if let Some(snapshot) = self.source_snapshot {
            if self.allocations.active_exact_capacity(
                source_arena, source_allocation.address(), relation_bytes,
            ) != Ok(snapshot) { return false; }
            snapshot
        } else {
            let Ok(snapshot) = self.allocations.register(
                source_arena, source_allocation.address(), relation_bytes,
            ) else { return false };
            self.source_snapshot = Some(snapshot);
            snapshot
        };
        let destination_native = relation_allocation.native_identity();
        let destination_arena = ProviderArenaIdentity {
            id: 2, generation: destination_native.allocation_generation,
        };
        if let Some(snapshot) = self.destination_snapshot {
            if self.allocations.active_exact_capacity(
                destination_arena, relation_allocation.address(), relation_bytes,
            ) != Ok(snapshot) { return false; }
        } else {
            let Ok(snapshot) = self.allocations.register(
                destination_arena, relation_allocation.address(), relation_bytes,
            ) else { return false };
            self.destination_snapshot = Some(snapshot);
        }
        if self.relation.is_none() {
            let source_bytes = *source_allocation.bytes();
            let relation_address = relation_allocation.address();
            let Ok(relation) = nt_pnp_manager::TargetRelationDelivery::capture(
                io_manager_mut(), &mut self.allocations, receipt, self.target.device_id(),
                source_allocation.address(), source_snapshot, &source_bytes,
                source_pdo_address, self.target.registration().domain(), projected_pdo,
                canonical_pdo, relation_address,
            ) else { return false };
            self.relation = Some(relation);
        }
        let relation = self.relation.as_mut().expect("claimed PnP relation delivery");
        match relation.phase() {
            nt_pnp_manager::TargetRelationPhase::Prepared => {
                let written = relation_allocation.with_bytes(|bytes| {
                    relation.write_relation(io_manager_mut(), &self.allocations, bytes)
                });
                if !matches!(written, Some(Ok(()))) { return false; }
            }
            nt_pnp_manager::TargetRelationPhase::RelationWritten => {}
            _ => return false,
        }
        self.terminal = Some((receipt.status().raw() as u32, relation_allocation.address()));
        true
    }

    unsafe fn publish_terminal(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.terminal_published {
            if self.terminal_claimed { return false; }
            let Some(iosb_address) = self.iosb_target.address_if_live(self.route) else { return false };
            if !self.source.validate()
                || self.source_allocation.as_ref().is_some_and(|source| !source.validate())
                || self.relation_allocation.as_ref().is_some_and(|relation| !relation.validate())
            {
                return false;
            }
            let (status, information) = self.terminal.expect("PnP terminal status");
            self.terminal_claimed = true;
            if !self.source.publish_terminal(status, information, iosb_address) {
                return false;
            }
            if let Some(relation) = &mut self.relation {
                if relation.iosb_published(nt_status::NtStatus(status as i32), information).is_err() {
                    crate::provider_bugcheck::report(0xc4, [self.source_address, information, 0, 45]);
                }
            }
            self.terminal_published = true;
        }
        if !self.event_signaled {
            if self.event_claimed { return false; }
            if let Some(event) = &self.event {
                let actual = crate::provider_local_event::LocalEventState::new(
                    &mut (*handler).obj_ns,
                    &mut (*handler).anon_event_seq,
                    &mut (*handler).events,
                    &mut (*handler).event_objects,
                ).identity(event.provider, event.local);
                if !matches!(actual, Ok((id, _, _, _)) if id == event.id) { return false; }
                self.event_claimed = true;
                if crate::provider_local_event::signal(
                    &mut *handler, event.provider, event.local, EventSignalMode::Set,
                ).is_err() || !self.source.mirror_event_signaled() {
                    return false;
                }
            } else {
                self.event_claimed = true;
            }
            self.event_signaled = true;
        }
        true
    }

    unsafe fn retire(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.source.validate() || self.target.validate(io_manager_mut()).is_err() {
            return false;
        }
        if let Some(irp) = self.canonical_irp {
            if self.ack_claimed { return false; }
            self.ack_claimed = true;
            if acknowledge_completed_irp_strict(irp.raw()).is_err() { return false; }
            self.canonical_irp = None;
        }
        if let Some(relation) = &mut self.relation {
            let receipt = self.receipt.as_ref().expect("successful PnP receipt");
            // Pending completion requires the strict ACK above. An inline return has already
            // freed its canonical IRP inside dispatch_prepared_external_pnp before minting this
            // receipt; there is no second ACK to issue for that path.
            if receipt.driver_pending() != self.ack_claimed {
                crate::provider_bugcheck::report(0xc4, [self.source_address, receipt.irp_id().raw(), 0, 50]);
            }
            if relation.canonical_acknowledged(receipt.irp_id()).is_err() {
                crate::provider_bugcheck::report(0xc4, [self.source_address, receipt.irp_id().raw(), 0, 46]);
            }
            let transferred = relation.transfer(io_manager_mut(), &mut self.allocations)
                .expect("acknowledged PnP relation transfer");
            let allocation = self.relation_allocation.as_mut()
                .expect("acknowledged win32k relation allocation");
            if transferred.relation.base != allocation.address()
                || transferred.pdo_reference.address() != transferred.projected_pdo
                || !allocation.transfer_to_caller()
            {
                crate::provider_bugcheck::report(0xc4, [self.source_address, transferred.relation.base, 0, 47]);
            }
        }
        if let Some(mut reference) = self.source_pdo.take() {
            reference.release(io_manager_mut())
                .expect("original PnP PDO reference release");
        }
        if let Some(source_allocation) = self.source_allocation.take() {
            if !source_allocation.retire() {
                crate::provider_bugcheck::report(0xc4, [self.source_address, 0, 0, 48]);
            }
        }
        if !crate::win32k_subsystem::release_source_target_relation_dispatch(&mut self.source) {
            return false;
        }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("terminal PnP target");
        runtime::retire_stopped_acknowledged_retained_service(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("PnP Reply retirement");
        let identity = (self.route, self.source_address, self.token);
        let index = (&*core::ptr::addr_of!(ACTIVE)).iter().position(|row| *row == identity)
            .expect("active PnP identity");
        (&mut *core::ptr::addr_of_mut!(ACTIVE)).swap_remove(index);
        (&mut *core::ptr::addr_of_mut!(COMPLETED)).push(identity);
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.entered && runtime::retained_service_cancelled(
            self.route, self.dispatch, self.reply, self.token,
        ) {
            return self.finish_cancelled_before_entry(handler);
        }
        if !self.enter() { return false; }
        if runtime::retained_service_cancelled(
            self.route, self.dispatch, self.reply, self.token,
        ) && !self.reply_entered {
            return self.finish_cancelled_after_entry(handler);
        }
        if self.indeterminate { return false; }
        if self.pending && !self.reply_entered {
            return self.publish_reply(STATUS_PENDING as u32);
        }
        if !self.pending && !self.reply_entered {
            if self.receipt.is_some() && !self.prepare_relation() { return false; }
            if !self.publish_terminal(handler) { return false; }
            let (status, _) = self.terminal.expect("inline PnP terminal");
            return self.publish_reply(status);
        }
        if !self.reply_acked {
            self.reply_acked = runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("PnP Reply identity");
            if !self.reply_acked { return false; }
        }
        if self.pending && self.receipt.is_none() {
            let Some(irp) = self.canonical_irp else { return false };
            let Some(receipt) = io_manager_mut().take_completed_external_pnp_receipt(irp)
            else { return false };
            if receipt.irp_id() != irp
                || receipt.origin_device_id() != self.target.device_id()
                || receipt.minor() != nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS
                || receipt.relation_type() != Some(nt_pnp_abi::TARGET_DEVICE_RELATION)
                || !receipt.driver_pending()
            {
                crate::provider_bugcheck::report(0xc4, [self.source_address, irp.raw(), 0, 49]);
            }
            self.receipt = Some(receipt);
        }
        if self.pending {
            if !self.prepare_relation() || !self.publish_terminal(handler) { return false; }
        }
        self.retire(handler)
    }
}

pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _durable = crate::allocator::enter_durable();
    redrive_completion_waits();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 { return; }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).contains(&index) { return None; }
        (&mut *core::ptr::addr_of_mut!(WORK))[index].take().map(|work| (index, work))
    }) else { return };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING)).try_reserve(1).is_err() {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push(index);
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance(handler);
    if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop(), Some(index));
    redrive_completion_waits();
}
