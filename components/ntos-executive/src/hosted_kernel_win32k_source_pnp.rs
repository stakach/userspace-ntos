//! File-less win32k TargetDeviceRelation dispatched to an exact canonical Device.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_target::HostedForwardTarget;
use nt_io_manager::win32k_source_pnp_wire as wire;
use nt_kernel_exec::{EventObjectId, EventSignalMode};
use nt_provider_wait::{ProviderAllocationCatalog, ProviderAllocationSnapshot, ProviderArenaIdentity};
use nt_io_manager::kernel_irp_builder::{
    validate_kernel_irp_dispatch_cursor, KernelIrpDispatchHeader,
};
use nt_io_manager::{WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE};

use super::hosted_kernel_win32k_source_ioctl::{
    capture_event, next_source_reply_token, release_event, CanonicalEvent,
};

type Route = nt_component_suspension::peer_registry::PeerRoute;
const STATUS_CANCELLED: u32 = 0xc000_0120;

struct Work {
    route: Route,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    source_address: u64,
    source_ticket: u64,
    source_generation: u64,
    nonce: u64,
    iosb_va: u64,
    source: crate::win32k_subsystem::ProviderPoolPacketLease,
    target: HostedForwardTarget,
    event: Option<CanonicalEvent>,
    packet_lease: Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
    packet: Vec<u8>,
    canonical_irp: Option<IrpId>,
    receipt: Option<nt_io_manager::ExternalPnpTerminalReceipt>,
    pending: bool,
    origin_armed: bool,
    entered: bool,
    terminal: Option<(u32, u64)>,
    relation: Option<nt_pnp_manager::TargetRelationDelivery>,
    projected_pdo: Option<u64>,
    relation_allocation: crate::win32k_subsystem::ProviderPoolPacketLease,
    relation_address: u64,
    relation_generation: u64,
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
    event_barrier: Option<crate::source_event_completion::Barrier>,
    terminal_handoff: Option<wire::SourcePnpTerminalHandoff>,
    terminal_packet: Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
    terminal_acknowledged: bool,
    origin_commit_requested: bool,
    origin_committed: bool,
    discarding: bool,
    packet_prepared: bool,
    reply_entered: bool,
    reply_acked: bool,
    ack_claimed: bool,
    resources_claimed: bool,
    resources_committed: bool,
    relation_transferred: bool,
    cancel_requested: bool,
    indeterminate: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);

unsafe fn capture_source(
    request: &wire::SourcePnpRequest,
) -> Result<crate::win32k_subsystem::ProviderPoolPacketLease, i32> {
    let (header_lease, header) = crate::win32k_subsystem::capture_provider_pool_packet(
        request.source_irp_va, WDM_X64_IRP_SIZE,
    ).map_err(|status| status as i32)?;
    let packet_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let stack_count = header[0x42];
    let expected_size = WDM_X64_IRP_SIZE
        .checked_add(stack_count as usize * WDM_X64_IO_STACK_LOCATION_SIZE)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if packet_size != expected_size
        || stack_count == 0
        || stack_count == u8::MAX
        || header_lease.native_identity().allocation_generation
            != request.native_allocation_generation
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (lease, packet) = crate::win32k_subsystem::capture_provider_pool_packet(
        request.source_irp_va, packet_size,
    ).map_err(|status| status as i32)?;
    if lease.native_identity() != header_lease.native_identity()
        || lease.capacity() < packet_size as u64
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let header = KernelIrpDispatchHeader {
        irp_type: u16::from_le_bytes([packet[0], packet[1]]),
        packet_size: packet_size as u16,
        stack_count,
        current_location: packet[0x43],
        current_stack_location: u64::from_le_bytes(packet[0xb8..0xc0].try_into().unwrap()),
    };
    let cursor = validate_kernel_irp_dispatch_cursor(
        request.source_irp_va, packet_size as u64, stack_count, header,
    ).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let stack = nt_io_manager::decode_wdm_kernel_built_io_stack(
        &packet[cursor.next_stack_offset
            ..cursor.next_stack_offset + WDM_X64_IO_STACK_LOCATION_SIZE],
    ).map_err(|_| STATUS_INVALID_PARAMETER)?;
    if stack.major != nt_io_abi::major::IRP_MJ_PNP
        || stack.minor != nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS
        || stack.device_object != request.device_object_va
        || stack.file_object != 0
        || !matches!(stack.parameters,
            nt_io_manager::WdmIoStackParameters::PnpQueryDeviceRelations {
                relation_type: nt_pnp_abi::TARGET_DEVICE_RELATION,
            })
        || u64::from_le_bytes(packet[0x08..0x10].try_into().unwrap()) != 0
        || u32::from_le_bytes(packet[0x10..0x14].try_into().unwrap()) != 0
        || u64::from_le_bytes(packet[0x18..0x20].try_into().unwrap()) != 0
        || u64::from_le_bytes(packet[0x70..0x78].try_into().unwrap()) != 0
        || u64::from_le_bytes(packet[0x48..0x50].try_into().unwrap()) != request.iosb_va
        || (u64::from_le_bytes(packet[0x50..0x58].try_into().unwrap()) == 0)
            != request.event.is_none()
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(lease)
}

pub(crate) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    packet_address: u64,
    packet_length: u64,
    stack_pointer: u64,
    handler: *mut ExecNtHandler,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    print_str(b"[source-pnp-root] submit packet=0x");
    print_hex_u64(packet_address);
    print_str(b" bytes=0x");
    print_hex_u64(packet_length);
    print_str(b" stack=0x");
    print_hex_u64(stack_pointer);
    print_str(b"\n");
    let route = match runtime::channel_route(channel) {
        Ok(Some(route)) => route,
        _ => { print_str(b"[source-pnp-root] no route\n"); return Some(STATUS_INVALID_HANDLE); },
    };
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        _ => { print_str(b"[source-pnp-root] no dispatch\n"); return Some(STATUS_INVALID_HANDLE); },
    };
    if crate::win32k_glue::win32k_stack_alias_for_route(route, stack_pointer, 1).is_none() {
        print_str(b"[source-pnp-root] stack alias denied\n");
        return Some(STATUS_ACCESS_DENIED);
    }
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        _ => { print_str(b"[source-pnp-root] no reply\n"); return Some(STATUS_INVALID_HANDLE); },
    };
    if packet_length != wire::PACKET_BYTES as u64 {
        return Some(STATUS_INVALID_BUFFER_SIZE as i32);
    }
    let (packet_lease, packet) = match crate::win32k_subsystem::capture_provider_pool_packet(
        packet_address, wire::PACKET_BYTES,
    ) {
        Ok(captured) => captured,
        Err(status) => {
            print_str(b"[source-pnp-root] packet capture status=0x");
            print_hex(status as u32);
            print_str(b"\n");
            return Some(status as i32);
        },
    };
    let request = match wire::decode_request(&packet) {
        Ok(request) => request,
        Err(_) => {
            print_str(b"[source-pnp-root] invalid request packet\n");
            return Some(STATUS_INVALID_PARAMETER);
        }
    };
    if super::hosted_kernel_win32k_source_admission::contains(request.source_irp_va) {
        print_str(b"[source-pnp-root] source already admitted\n");
        return Some(STATUS_INVALID_PARAMETER);
    }
    if (&*core::ptr::addr_of!(WORK)).iter().any(|row| {
        row.as_ref().is_some_and(|work| work.route == route && work.nonce == request.nonce)
    }) {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let access = match crate::win32k_device_consumer::authenticate(
        channel, reply_cap, request.device_object_va,
    ) {
        Ok(access) if access.dispatch() == dispatch => access,
        Ok(_) => return Some(STATUS_ACCESS_DENIED),
        Err(status) => {
            print_str(b"[source-pnp-root] device authentication status=0x");
            print_hex(status as u32);
            print_str(b"\n");
            return Some(status);
        }
    };
    let mut target = match HostedForwardTarget::capture(
        io_manager_mut(), access.domain(), access.address(),
    ) {
        Ok(target) if target.device_id() == access.device() => target,
        Ok(mut target) => {
            target.release(io_manager_mut()).expect("mismatched PnP target");
            return Some(STATUS_INVALID_DEVICE_REQUEST as i32);
        }
        Err(status) => {
            print_str(b"[source-pnp-root] canonical target status=0x");
            print_hex(status.raw() as u32);
            print_str(b"\n");
            return Some(status.raw());
        }
    };
    let mut event = match capture_event(handler, request.event) {
        Ok(event) => event,
        Err(status) => {
            print_str(b"[source-pnp-root] Event capture status=0x");
            print_hex(status as u32);
            print_str(b"\n");
            target.release(io_manager_mut()).expect("unentered PnP target");
            return Some(status);
        }
    };
    let source = match capture_source(&request) {
        Ok(source) => source,
        Err(status) => {
            print_str(b"[source-pnp-root] native source admission status=0x");
            print_hex(status as u32);
            print_str(b"\n");
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered PnP target");
            return Some(status);
        }
    };
    let relation_allocation = match crate::win32k_subsystem::capture_provider_pool_packet(
        request.relation_allocation_va, nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES,
    ) {
        Ok((lease, _)) if lease.native_identity().allocation_generation
            == request.relation_allocation_generation
            && request.relation_allocation_va != request.source_irp_va
            && request.relation_allocation_va != packet_address => lease,
        _ => {
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered PnP target");
            return Some(STATUS_INVALID_PARAMETER);
        }
    };
    if request.iosb_va == 0
        || super::hosted_kernel_win32k_source_ioctl::Target::capture(route, request.iosb_va, 16).is_none()
    {
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered PnP target");
        return Some(STATUS_INVALID_PARAMETER);
    };
    let slot = (&*core::ptr::addr_of!(WORK)).iter().enumerate().find_map(|(index, row)| {
        (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
    });
    if slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err()
    {
        print_str(b"[source-pnp-root] work reserve failed\n");
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered PnP target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let token = match next_source_reply_token() {
        Some(token) => token,
        _ => {
            print_str(b"[source-pnp-root] reply token exhausted\n");
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered PnP target");
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let source_address = request.source_irp_va;
    let source_ticket = request.source_ticket_serial;
    let source_generation = request.native_allocation_generation;
    if !super::hosted_kernel_win32k_source_admission::register(
        route, source_address, source_ticket, source_generation,
    ) {
        print_str(b"[source-pnp-root] source registration failed\n");
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered PnP target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let work = Work {
        route, dispatch, reply, token, source_address, source_ticket, source_generation,
        nonce: request.nonce, iosb_va: request.iosb_va, source, target, event,
        packet_lease: Some(packet_lease), packet, canonical_irp: None, receipt: None, pending: false, origin_armed: false, entered: false,
        terminal: None, relation: None, projected_pdo: None, relation_allocation,
        relation_address: request.relation_allocation_va,
        relation_generation: request.relation_allocation_generation,
        source_allocation: None,
        source_pdo: None, allocations: ProviderAllocationCatalog::new(),
        source_snapshot: None, destination_snapshot: None,
        relation_claimed: false,
        terminal_claimed: false, terminal_published: false, event_claimed: false,
        event_signaled: false, event_barrier: None, terminal_handoff: None, terminal_packet: None,
        terminal_acknowledged: false, origin_commit_requested: false, origin_committed: false, discarding: false,
        packet_prepared: false, reply_entered: false,
        reply_acked: false, ack_claimed: false, resources_claimed: false,
        resources_committed: false, relation_transferred: false, cancel_requested: false,
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
        print_str(b"[source-pnp-root] retained service park failed\n");
        super::hosted_kernel_win32k_source_admission::retire(
            route, source_address, source_ticket, source_generation,
        );
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index].take().unwrap();
        if let Some(event) = work.event.take() { release_event(handler, event); }
        work.target.release(io_manager_mut()).expect("unparked PnP target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    print_str(b"[source-pnp-root] admitted and parked\n");
    None
}

/// Authenticated broker receipt, not inference from native Reply acknowledgement.
pub(super) unsafe fn arm_pending(
    route: Route,
    identity: nt_io_manager::source_pending_armed::PendingArmedIdentity,
) -> Result<(), i32> {
    use nt_io_manager::source_pending_armed::{PendingArmedIdentity, PendingSourceKind};
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(work) = rows.iter_mut().filter_map(Option::as_mut).find(|work| {
        work.route == route && work.nonce == identity.nonce
    }) else { return Err(STATUS_INVALID_PARAMETER); };
    let expected = PendingArmedIdentity {
        kind: PendingSourceKind::Pnp, nonce: work.nonce, token: work.token,
        source_irp_va: work.source_address, source_ticket_serial: work.source_ticket,
        native_allocation_generation: work.source_generation,
    };
    if identity != expected || !work.pending || !work.reply_entered || work.indeterminate
        || !runtime::retained_service_reply_acknowledged(
            work.route, work.dispatch, work.reply, work.token,
        ).unwrap_or(false)
    { return Err(STATUS_INVALID_PARAMETER); }
    work.origin_armed = true;
    Ok(())
}

impl Work {
    unsafe fn ready_for_nested_step(&self) -> bool {
        use nt_io_manager::retained_source_progress::RetainedSourceProgress as Progress;
        let progress = if self.indeterminate {
            Progress::Indeterminate
        } else if runtime::retained_service_owner_stopped(self.route, self.dispatch, self.reply, self.token) {
            Progress::Stopped {
                cancellation_pending: self.canonical_irp.is_some() && !self.cancel_requested,
                completion_ready: self.canonical_irp.is_none_or(|irp| nested_irp_completion_ready_exact(irp.raw())),
                broker_stopped: runtime::retained_service_owner_stopped_at_broker(
                    self.route, self.dispatch, self.reply, self.token,
                ) && self.event_barrier.is_none(),
                source_lane_ready: crate::win32k_glue::source_terminal_dispatch_ready(),
            }
        } else if !self.entered {
            Progress::AwaitingDispatch { provider_ready:
                super::hosted_kernel_win32k_source_ioctl::target_dispatch_ready(self.target.device_id()) }
        } else if self.pending && !self.reply_entered {
            Progress::PublishReply
        } else if self.reply_entered && !self.reply_acked {
            Progress::AwaitingReply { acknowledged: runtime::retained_service_reply_acknowledged(
                self.route, self.dispatch, self.reply, self.token,
            ).unwrap_or(false) }
        } else if self.pending && !self.origin_armed {
            Progress::AwaitingOriginArmed
        } else if self.pending && self.receipt.is_none() {
            Progress::AwaitingCompletion {
                completion_ready: self.canonical_irp.is_some_and(|irp| nested_irp_completion_ready_exact(irp.raw())),
                cancellation_pending: false,
            }
        } else if !self.origin_committed {
            Progress::Terminal { source_lane_ready: crate::win32k_glue::source_terminal_dispatch_ready() }
        } else {
            Progress::Retirement
        };
        progress.ready_for_nested_step()
    }

    fn progress_state(&self) -> [u64; 18] {
        [self.entered as u64, self.pending as u64, self.reply_entered as u64,
            self.reply_acked as u64, self.receipt.is_some() as u64, self.terminal.is_some() as u64,
            self.terminal_acknowledged as u64, self.origin_commit_requested as u64,
            self.origin_committed as u64, self.event_claimed as u64, self.event_signaled as u64,
            self.ack_claimed as u64, self.cancel_requested as u64, self.resources_committed as u64,
            self.indeterminate as u64, self.terminal_packet.is_some() as u64,
            self.relation.is_some() as u64, self.relation_transferred as u64]
    }

    unsafe fn source_live(&self) -> bool {
        crate::win32k_subsystem::provider_pool_packet_lease_live(self.source)
            && self.source.native_identity().allocation_generation == self.source_generation
    }

    unsafe fn relation_live(&self) -> bool {
        crate::win32k_subsystem::provider_pool_packet_lease_live(self.relation_allocation)
            && self.relation_allocation.native_identity().allocation_generation
                == self.relation_generation
    }

    unsafe fn enter(&mut self) -> bool {
        if self.entered { return true; }
        if !self.source_live() || !self.relation_live()
            || self.target.validate(io_manager_mut()).is_err() {
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
        let Some(packet_lease) = self.packet_lease else { return false };
        if !crate::win32k_subsystem::publish_provider_pool_packet(
            packet_lease, &self.packet,
        ) { return false; }
        self.reply_entered = true;
        self.packet_lease = None;
        drop(core::mem::take(&mut self.packet));
        let _ = runtime::wake_service(
            self.route, self.dispatch, self.reply, self.token, status as i32,
        );
        false
    }

    unsafe fn prepare_relation(&mut self) -> bool {
        if self.terminal.is_some() { return true; }
        let receipt = self.receipt.as_ref().expect("terminal PnP receipt");
        if !receipt.status().is_success() {
            if receipt.information() != 0 { return false; }
            self.terminal = Some((receipt.status().raw() as u32, 0));
            return true;
        }
        if !self.source_live() || !self.relation_live()
            || self.target.validate(io_manager_mut()).is_err() {
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
        self.projected_pdo = Some(projected_pdo);
        if !source_allocation.validate() || !self.relation_live() {
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
        let destination_native = self.relation_allocation.native_identity();
        let destination_arena = ProviderArenaIdentity {
            id: 2, generation: destination_native.allocation_generation,
        };
        if let Some(snapshot) = self.destination_snapshot {
            if self.allocations.active_exact_capacity(
                destination_arena, self.relation_address, relation_bytes,
            ) != Ok(snapshot) { return false; }
        } else {
            let Ok(snapshot) = self.allocations.register(
                destination_arena, self.relation_address, relation_bytes,
            ) else { return false };
            self.destination_snapshot = Some(snapshot);
        }
        if self.relation.is_none() {
            let source_bytes = *source_allocation.bytes();
            let relation_address = self.relation_address;
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
                let mut bytes = [0u8; nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES];
                if relation.write_relation(io_manager_mut(), &self.allocations, &mut bytes).is_err() {
                    return false;
                }
                if !crate::win32k_subsystem::publish_provider_pool_packet(
                    self.relation_allocation, &bytes,
                ) {
                    self.indeterminate = true;
                    return false;
                }
            }
            nt_pnp_manager::TargetRelationPhase::RelationWritten => {}
            _ => return false,
        }
        self.terminal = Some((receipt.status().raw() as u32, self.relation_address));
        true
    }

    unsafe fn deliver_terminal(&mut self) -> bool {
        if self.terminal_acknowledged { return true; }
        let (status, information) = self.terminal.expect("PnP terminal result");
        if self.terminal_handoff.is_none() {
            if !self.source_live() || !self.relation_live() { return false; }
            let handoff = wire::SourcePnpTerminalHandoff {
            delivery: if self.pending { wire::TerminalDelivery::Pending } else { wire::TerminalDelivery::Inline },
                nonce: self.nonce,
                token: self.token,
                source_irp_va: self.source_address,
                source_ticket_serial: self.source_ticket,
                native_allocation_generation: self.source_generation,
                iosb_va: self.iosb_va,
                relation_allocation_va: self.relation_address,
                relation_allocation_generation: self.relation_generation,
                status,
                information,
                pdo_va: if status & 0x8000_0000 == 0 { self.projected_pdo.unwrap_or(0) } else { 0 },
            };
            let Some((lease, mut packet)) =
                crate::win32k_subsystem::allocate_root_provider_pool_packet(
                    wire::TERMINAL_PACKET_BYTES,
                )
            else { return false };
            if wire::encode_terminal_handoff(handoff, &mut packet).is_err()
                || !crate::win32k_subsystem::publish_provider_pool_packet(lease, &packet)
            {
                if !crate::win32k_subsystem::retire_root_provider_pool_packet(lease) {
                    crate::provider_bugcheck::report(0xc4, [self.source_address, self.token, 0, 63]);
                }
                return false;
            }
            self.terminal_handoff = Some(handoff);
            self.terminal_packet = Some(lease);
        }
        if self.discarding { return true; }
        let lease = self.terminal_packet.expect("retained terminal packet");
        let dispatch = crate::win32k_glue::dispatch_source_pnp_terminal(
            lease.address(), wire::TERMINAL_PACKET_BYTES as u64,
        );
        match dispatch {
            crate::win32k_glue::SourcePnpTerminalDispatch::NotEntered(_) => return false,
            crate::win32k_glue::SourcePnpTerminalDispatch::Returned(status)
                if status == nt_io_manager::source_terminal::TERMINAL_NOT_READY => return false,
            crate::win32k_glue::SourcePnpTerminalDispatch::Returned(0) => {}
            _ => { self.indeterminate = true; return false; }
        }
        let (actual, packet) = match crate::win32k_subsystem::capture_provider_pool_packet(
            lease.address(), wire::TERMINAL_PACKET_BYTES,
        ) {
            Ok(captured) => captured,
            Err(_) => {
                self.indeterminate = true;
                return false;
            }
        };
        let ack = wire::decode_terminal_ack(&packet);
        if actual.native_identity() != lease.native_identity()
            || !matches!(ack, Ok(ack) if
                ack.handoff == self.terminal_handoff.expect("retained terminal handoff")
                    && ack.publication == wire::TerminalPublication::Published)
        {
            self.indeterminate = true;
            return false;
        }
        self.terminal_acknowledged = true;
        true
    }

    unsafe fn accept_terminal_ack(&mut self) -> bool {
        if !self.terminal_acknowledged {
            return false;
        }
        if !self.terminal_published {
            if self.terminal_claimed { return false; }
            if self.source_allocation.as_ref().is_some_and(|source| !source.validate()) {
                return false;
            }
            let (status, information) = self.terminal.expect("PnP terminal status");
            self.terminal_claimed = true;
            if let Some(relation) = &mut self.relation {
                if relation.iosb_published(nt_status::NtStatus(status as i32), information).is_err() {
                    crate::provider_bugcheck::report(0xc4, [self.source_address, information, 0, 45]);
                }
            }
            self.terminal_published = true;
        }
        true
    }

    unsafe fn signal_event(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.terminal_published || !self.terminal_acknowledged { return false; }
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
                let barrier = match crate::source_event_completion::capture(handler, event.id) {
                    Ok(barrier) => barrier,
                    Err(_) => return false,
                };
                self.event_barrier = Some(barrier);
                self.event_claimed = true;
            } else {
                self.event_claimed = true;
            }
            self.event_signaled = true;
        }
        true
    }

    unsafe fn commit_origin(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.indeterminate { return false; }
        if self.origin_committed { return self.event_barrier.is_none(); }
        if !self.terminal_acknowledged || !self.event_signaled { return false; }
        let length = wire::TERMINAL_PACKET_BYTES;
        if !super::hosted_kernel_win32k_source_ioctl::commit_origin_packet(
            &mut self.terminal_packet, length, 96,
            &mut self.origin_commit_requested, &mut self.indeterminate, false,
            self.event_barrier.map_or(0, |barrier| barrier.sequence()),
            crate::win32k_glue::dispatch_source_pnp_terminal,
        ) { return false; }
        self.origin_committed = true;
        if let Some(barrier) = self.event_barrier {
            if crate::source_event_completion::release(handler, barrier).is_err() {
                self.indeterminate = true;
                return false;
            }
            self.event_barrier = None;
        }
        true
    }

    unsafe fn commit_terminal(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.resources_committed { return true; }
        if !self.terminal_acknowledged || !self.terminal_published
            || self.target.validate(io_manager_mut()).is_err() {
            return false;
        }
        if let Some(irp) = self.canonical_irp {
            if self.ack_claimed { return false; }
            self.ack_claimed = true;
            if acknowledge_completed_irp_strict(irp.raw()).is_err() { return false; }
            self.canonical_irp = None;
        }
        if !self.relation_transferred {
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
            if transferred.relation.base != self.relation_address
                || transferred.pdo_reference.address() != transferred.projected_pdo
                || Some(transferred.projected_pdo) != self.projected_pdo
            {
                crate::provider_bugcheck::report(0xc4, [self.source_address, transferred.relation.base, 0, 47]);
            }
        }
        self.relation_transferred = true;
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
        if !self.signal_event(handler) || !self.commit_origin(handler) { return false; }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("terminal PnP target");
        self.resources_committed = true;
        true
    }

    unsafe fn retire(&mut self) -> bool {
        if !self.resources_committed || !self.reply_acked { return false; }
        runtime::retire_stopped_acknowledged_retained_service(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("PnP Reply retirement");
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        true
    }

    unsafe fn finish_stopped(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.indeterminate { return false; }
        if let Some(irp) = self.canonical_irp {
            if !self.cancel_requested {
                self.cancel_requested = true;
                let _ = cancel_irp_if_pending(irp.raw());
            }
            if self.receipt.is_none() {
                let Some(receipt) = io_manager_mut().take_completed_external_pnp_receipt(irp) else { return false };
                self.receipt = Some(receipt);
            }
        }
        // Only a sealed stop while physically parked in this broker Call proves local guards
        // cannot be held. A stopped-running or whole-domain owner remains quarantined.
        if !runtime::retained_service_owner_stopped_at_broker(
            self.route, self.dispatch, self.reply, self.token,
        ) { return false; }
        if self.event_barrier.is_some() || self.resources_committed {
            // Canonical transfer/signal preparation already began; do not turn an uncertain
            // committed terminal into a new cancellation transaction.
            return false;
        }
        {
        if let Some(receipt) = self.receipt.as_ref() {
            if receipt.origin_device_id() != self.target.device_id()
                || receipt.minor() != nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS
                || receipt.relation_type() != Some(nt_pnp_abi::TARGET_DEVICE_RELATION)
                || receipt.driver_pending() != self.pending
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
                if acknowledge_completed_irp_strict(irp.raw()).is_err() {
                    self.indeterminate = true;
                    return false;
                }
                self.canonical_irp = None;
            }
            if let Some(relation) = &mut self.relation {
                let receipt = self.receipt.as_ref().expect("stopped PnP exact receipt");
                if relation.discard_after_canonical_retirement(io_manager_mut(), &mut self.allocations, receipt).is_err() {
                    self.indeterminate = true;
                    return false;
                }
            }
            self.relation = None;
            if self.terminal_packet.is_none() { self.terminal = Some((0xc000_0120, 0)); }
            self.discarding = true;
            if !self.deliver_terminal() { return false; }
            let length = wire::TERMINAL_PACKET_BYTES;
            if !super::hosted_kernel_win32k_source_ioctl::commit_origin_packet(
                &mut self.terminal_packet, length, 96,
                &mut self.origin_commit_requested, &mut self.indeterminate, true, 0,
                crate::win32k_glue::dispatch_source_pnp_terminal,
            ) { return false; }
            self.origin_committed = true;
            if let Some(mut reference) = self.source_pdo.take() {
                reference.release(io_manager_mut()).expect("stopped PnP source PDO");
            }
            if let Some(source) = self.source_allocation.take() {
                if !source.retire() { self.indeterminate = true; return false; }
            }
        }
        if !self.resources_committed {
            if let Some(event) = self.event.take() { release_event(handler, event); }
            self.target.release(io_manager_mut()).expect("stopped source target");
            self.resources_committed = true;
        }
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("sealed broker-stopped source Reply");
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if runtime::retained_service_owner_stopped(self.route, self.dispatch, self.reply, self.token) {
            return self.finish_stopped(handler);
        }
        if !self.entered && !super::hosted_kernel_win32k_source_ioctl::target_dispatch_ready(self.target.device_id()) {
            return false;
        }
        if !self.enter() { return false; }
        if self.indeterminate { return false; }
        if self.pending && !self.reply_entered {
            return self.publish_reply(STATUS_PENDING as u32);
        }
        if !self.pending && !self.reply_entered {
            if self.receipt.is_some() && !self.prepare_relation() { return false; }
            if !self.deliver_terminal()
                || !self.accept_terminal_ack()
                || !self.commit_terminal(handler) { return false; }
            let (status, _) = self.terminal.expect("inline PnP terminal");
            return self.publish_reply(status);
        }
        if !self.reply_acked {
            self.reply_acked = runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("PnP Reply identity");
            if !self.reply_acked { return false; }
        }
        if self.pending && !self.origin_armed { return false; }
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
            if !self.prepare_relation()
                || !self.deliver_terminal()
                || !self.accept_terminal_ack()
                || !self.commit_terminal(handler) { return false; }
        }
        self.retire()
    }
}

unsafe fn redrive_one(handler: *mut ExecNtHandler, nested_ready_only: bool) -> bool {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 { return false; }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).contains(&index) { return None; }
        if nested_ready_only && !(&*core::ptr::addr_of!(WORK))[index]
            .as_ref().is_some_and(|work| work.ready_for_nested_step()) { return None; }
        (&mut *core::ptr::addr_of_mut!(WORK))[index].take().map(|work| (index, work))
    }) else { return false };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING)).try_reserve(1).is_err() {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return false;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push(index);
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let before = work.progress_state();
    let done = work.advance(handler);
    let progressed = done || before != work.progress_state();
    if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop(), Some(index));
    progressed
}

pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _ = redrive_one(handler, false);
}

pub(super) unsafe fn nested_work_ready() -> bool {
    (&*core::ptr::addr_of!(WORK)).iter().enumerate().any(|(index, row)| {
        !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)
            && row.as_ref().is_some_and(|work| work.ready_for_nested_step())
    })
}

pub(super) unsafe fn redrive_nested_ready(handler: *mut ExecNtHandler) -> bool {
    redrive_one(handler, true)
}
