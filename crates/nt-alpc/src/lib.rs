//! # `nt-alpc` — the ALPC adapter over the unified port core
//!
//! The Vista+/Win7 `NtAlpc*` API surface, translated onto the shared
//! [`nt_port_core::PortCore`] — the SAME core the classic-LPC adapter
//! (`nt-lpc-server`) drives. Because both adapters mutate one core, an LPC client
//! and an ALPC host that name the same port share a single core connection, so a
//! message from one reaches the other with no relaying: **the LPC↔ALPC bridge is
//! automatic.** This crate adds the ALPC-only model on top of the core:
//!
//! * **ALPC message attributes** (`ALPC_MESSAGE_ATTRIBUTES` + the per-attribute
//!   structs) — parsed into the core's API-neutral [`MessageAttrs`] on send,
//!   projected back on receive.
//! * **Port sections + section views** (`NtAlpcCreatePortSection` /
//!   `NtAlpcCreateSectionView`) — the large-data shared-memory model. Tracked
//!   here (server-modeled in this increment).
//! * **Accept folds complete** — unlike LPC (separate `NtCompleteConnectPort`),
//!   ALPC's `NtAlpcAcceptConnectPort` accepts AND completes in one call.
//!
//! ## The LPC↔ALPC bridge degradation policy (documented, enforced here)
//!
//! A message crossing between API surfaces carries only what the destination API
//! can express:
//!
//! | attribute | ALPC → LPC | LPC → ALPC |
//! |---|---|---|
//! | (PORT_MESSAGE body) | delivered | delivered |
//! | CONTEXT (`PortContext`) | **bridges** (rides the PORT_MESSAGE header / connection port-context) | absent → default |
//! | VIEW (shared section) | **dropped** — the LPC peer sees only the inline body; degradation recorded | absent |
//! | HANDLE | **dropped** | absent |
//! | SECURITY / TOKEN | **dropped** — the LPC peer uses the connection's client identity | absent |
//!
//! * ALPC → LPC: the LPC receiver reads only the `PORT_MESSAGE`; non-bridging
//!   attributes are dropped (the core still carries them, but the LPC data plane
//!   has no field to surface them). A dropped view/handle sets the degradation
//!   flag so the loss is observable.
//! * LPC → ALPC: the ALPC receiver's `ALPC_MESSAGE_ATTRIBUTES.ValidAttributes`
//!   comes back **0** (empty/default) — an LPC-originated message has no
//!   attributes.
//! * Connection-info: the connect blob is passed through the core byte-for-byte.
//!   An ALPC host receiving an LPC connect sees the `SB_CONNECTION_INFO` bytes as
//!   its ConnectionInformation (plus `subsystem_type`); an LPC host receiving an
//!   ALPC connect sees the ALPC connect `PORT_MESSAGE` payload as its
//!   connection-info blob (`subsystem_type` defaults to 0 if unset).

#![no_std]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::mem::size_of;

use bytemuck::Pod;
use nt_alpc_abi::{
    connect_flag, msg_attr_flag, opcode, port_flag, send_flag, AlpcAcceptConnectCheckedRequest,
    AlpcAcceptConnectRequest, AlpcAcknowledgeSendReceiveRequest,
    AlpcCheckedInvocation, AlpcConnectPortAuthorizedRequest,
    AlpcConnectPortCheckedRequest, AlpcConnectPortRequest,
    AlpcContextAttr, AlpcCreatePortCheckedRequest, AlpcCreatePortOwnedRequest,
    AlpcCreatePortSecuredRequest,
    AlpcCloseCreatedPortRequest, AlpcCreatePortRequest, AlpcCreatePortSectionRequest,
    AlpcCreateSectionViewRequest,
    AlpcDataViewAttr, AlpcHandleAttr, AlpcHandleRequest, AlpcLookupCreatePortRequest,
    AlpcMessageAttributes, AlpcPortAttributes, AlpcReply, AlpcSecurityAttr, AlpcSendReceiveRequest,
    AlpcSendReceiveCheckedRequest, AlpcTokenAttr, AlpcViewIoRequest, PortMessage,
};
use nt_port_core::{
    ClientId, ConnectOutcome, ConnectionSecurity, DataView, MessageAttrs, PortApi, PortCore, PortHandleEndpoint,
    MessageIdentity, PortAdmission, PortLimits, QueuedMessage, ReceiveOutcome, MAX_CONNINFO,
};
use nt_status::NtStatus;

/// Base for allocated ALPC section handles (ASCII `"AS"` — distinct from the
/// core's `"LP"` port-handle range).
const ALPC_SECTION_BASE: u64 = 0x0000_4153_0000_0001;

fn port_admission(flags: u32) -> Result<PortAdmission, NtStatus> {
    const SUPPORTED: u32 = port_flag::LPC_MODE | port_flag::ALLOW_LPC_REQUESTS
        | port_flag::ALLOW_IMPERSONATION;
    if flags & !SUPPORTED != 0 { return Err(NtStatus::INVALID_PARAMETER); }
    Ok(PortAdmission {
        allow_lpc_requests: flags & (port_flag::LPC_MODE | port_flag::ALLOW_LPC_REQUESTS) != 0,
        allow_impersonation: flags & port_flag::ALLOW_IMPERSONATION != 0,
    })
}

fn connect_port_options(attributes: AlpcPortAttributes, has_attributes: u32)
    -> Result<(ConnectionSecurity, Option<u32>), NtStatus>
{
    if has_attributes > 1 || (has_attributes == 0 && attributes != AlpcPortAttributes::default()) {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    if has_attributes == 0 { return Ok((ConnectionSecurity::default(), None)); }
    if attributes.flags != 0 || attributes.max_message_length > u16::MAX as u64
        || attributes.memory_bandwidth != 0 || attributes.max_pool_usage != 0
        || attributes.max_section_size != 0 || attributes.max_view_size != 0
        || attributes.max_total_section_size != 0 || attributes.dup_object_types != 0
        || attributes.reserved != 0
    { return Err(NtStatus::INVALID_PARAMETER); }
    let qos = attributes.security_qos;
    if (qos.length != 0 && qos.length != size_of::<nt_alpc_abi::SecurityQualityOfService>() as u32)
        || (qos.length == 0 && (qos.impersonation_level != 0
            || qos.context_tracking_mode != 0 || qos.effective_only != 0))
        || qos.impersonation_level > 3 || qos.context_tracking_mode > 1
        || qos.effective_only > 1 || qos._pad != 0
    { return Err(NtStatus::INVALID_PARAMETER); }
    Ok((ConnectionSecurity {
        impersonation_level: qos.impersonation_level,
        dynamic_tracking: qos.context_tracking_mode != 0,
        effective_only: qos.effective_only != 0,
    }, (attributes.max_message_length != 0)
        .then_some(attributes.max_message_length as u32)))
}

/// Upper bound on a port section's backing store, so a malformed/hostile
/// `SectionSize` can't grow the broker's memory without bound. 8 MiB comfortably
/// covers the WOW64 large-transfer path (real ALPC caps a section at
/// `MaximumViewSize`, typically well under this).
const MAX_SECTION_SIZE: u64 = 8 * 1024 * 1024;
const SECTION_PAGE_SIZE: usize = 4096;
const MAX_CHECKED_SEND_RECEIVE: usize = 256;
const MAX_CHECKED_CREATE_RESULTS: usize = 128;
const RECENT_SETTLED_CREATE_RESULTS: usize = 32;

struct SparseSectionBacking {
    len: usize,
    pages: Vec<Option<Box<[u8; SECTION_PAGE_SIZE]>>>,
}

impl SparseSectionBacking {
    fn new(len: u64) -> Result<Self, NtStatus> {
        if len > usize::MAX as u64 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let len = len as usize;
        let page_count = len
            .checked_add(SECTION_PAGE_SIZE - 1)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            / SECTION_PAGE_SIZE;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(page_count)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        for _ in 0..page_count {
            pages.push(None);
        }
        Ok(Self { len, pages })
    }

    fn check_range(&self, offset: usize, len: usize) -> Result<(), NtStatus> {
        let end = offset.checked_add(len).ok_or(NtStatus::INVALID_PARAMETER)?;
        if end > self.len {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(())
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), NtStatus> {
        self.check_range(offset, data.len())?;
        let mut done = 0usize;
        while done < data.len() {
            let absolute = offset + done;
            let page_index = absolute / SECTION_PAGE_SIZE;
            let page_offset = absolute % SECTION_PAGE_SIZE;
            let count = (SECTION_PAGE_SIZE - page_offset).min(data.len() - done);
            if self.pages[page_index].is_none() {
                self.pages[page_index] = Some(Box::new([0u8; SECTION_PAGE_SIZE]));
            }
            let page = self.pages[page_index]
                .as_mut()
                .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
            page[page_offset..page_offset + count].copy_from_slice(&data[done..done + count]);
            done += count;
        }
        Ok(())
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), NtStatus> {
        self.check_range(offset, out.len())?;
        let mut done = 0usize;
        while done < out.len() {
            let absolute = offset + done;
            let page_index = absolute / SECTION_PAGE_SIZE;
            let page_offset = absolute % SECTION_PAGE_SIZE;
            let count = (SECTION_PAGE_SIZE - page_offset).min(out.len() - done);
            match self.pages[page_index].as_ref() {
                Some(page) => {
                    out[done..done + count].copy_from_slice(&page[page_offset..page_offset + count])
                }
                None => out[done..done + count].fill(0),
            }
            done += count;
        }
        Ok(())
    }

    #[cfg(test)]
    fn allocated_pages(&self) -> usize {
        self.pages.iter().filter(|page| page.is_some()).count()
    }
}

/// A port section: the REAL shared-memory region both endpoints map. `backing` is
/// the actual bytes — every view of this section aliases it, so a write through
/// one endpoint's view is visible through the other's (the "not a copy" proof).
/// In a live two-VSpace deployment the broker additionally `copy_cap`+`page_map`s
/// these frames into each endpoint's address space (the CSR-anonymous-section
/// machinery); with the synthetic single-address-space endpoints exercised here
/// the shared `backing` IS that region. The section is sparse: creating a large
/// ALPC transfer window reserves the object extent, but pages materialize only
/// when a caller writes them, matching NT's demand-committed section semantics.
struct PortSection {
    handle: u64,
    port_handle: u64,
    size: u64,
    backing: SparseSectionBacking,
}

/// A mapped view of a section: a `view_base` handle plus the section it aliases
/// and the byte offset within that section where the view starts.
struct SectionView {
    view_base: u64,
    section_handle: u64,
    /// Byte offset into the section's backing store where this view begins.
    section_offset: u64,
    size: u64,
}

/// A completed checked invocation stays recorded after handle close. In particular,
/// closing a result must not turn a delayed duplicate SQE into a second create.
struct CreatePortResult {
    owner: ClientId,
    owner_generation: u64,
    token: (u64, u64),
    request: AlpcCreatePortRequest,
    attributes: Option<AlpcPortAttributes>,
    security_descriptor: Option<Vec<u8>>,
    name: Vec<u16>,
    result: AlpcReply,
    closed: bool,
}

/// A native invocation's receive continuation. A pending receive may be polled
/// again, but its send half must never be repeated after the first attempt.
struct CheckedSendReceive {
    owner: ClientId,
    owner_generation: u64,
    token: (u64, u64),
    op: u16,
    request: Vec<u8>,
    output: Vec<u8>,
    terminal: Option<AlpcReply>,
}

struct CheckedConnect {
    owner: ClientId,
    owner_generation: u64,
    token: (u64, u64),
    request: Vec<u8>,
    result: AlpcReply,
    response: Vec<u8>,
    closed: bool,
    acknowledged: bool,
}

struct CheckedAccept {
    owner: ClientId,
    owner_generation: u64,
    token: (u64, u64),
    request: Vec<u8>,
    result: AlpcReply,
    closed: bool,
    acknowledged: bool,
}

/// Compact authority retained after a checked receive's large output is ACKed.
struct ConnectionReceipt {
    owner: ClientId,
    owner_generation: u64,
    listen_port: u64,
    connection_id: u64,
}

fn checked_identity(invocation: AlpcCheckedInvocation)
    -> Result<(ClientId, u64, (u64, u64)), NtStatus>
{
    let owner = ClientId { process: invocation.owner_process,
        thread: invocation.owner_thread };
    let token = (invocation.invocation_hi, invocation.invocation_lo);
    if owner.process == 0 || owner.thread == 0 || invocation.owner_generation == 0
        || token == (0, 0)
    { return Err(NtStatus::INVALID_PARAMETER); }
    Ok((owner, invocation.owner_generation, token))
}

/// The ALPC service: the `NtAlpc*` ABI adapter. It borrows a shared
/// [`PortCore`]; it owns only ALPC-specific state (port sections + views).
#[derive(Default)]
pub struct AlpcServer {
    create_results: Vec<CreatePortResult>,
    retired_create_sequence: u64,
    send_receive_results: Vec<CheckedSendReceive>,
    retired_send_receive_sequence: u64,
    connect_results: Vec<CheckedConnect>,
    retired_connect_sequence: u64,
    accept_results: Vec<CheckedAccept>,
    retired_accept_sequence: u64,
    connection_receipts: Vec<ConnectionReceipt>,
    sections: Vec<PortSection>,
    views: Vec<SectionView>,
    next_section: u64,
    next_view_base: u64,
}

impl AlpcServer {
    /// Keep only a small recent reconciliation window. The retired sequence
    /// rejects any pruned invocation before another core create effect.
    fn retire_settled_create_results(&mut self) {
        loop {
            let settled = self.create_results.iter().filter(|saved|
                saved.closed || saved.result.status != NtStatus::SUCCESS.0).count();
            if settled < RECENT_SETTLED_CREATE_RESULTS
                && self.create_results.len() < MAX_CHECKED_CREATE_RESULTS { break; }
            let Some((index, _)) = self.create_results.iter().enumerate()
                .filter(|(_, saved)| saved.closed
                    || saved.result.status != NtStatus::SUCCESS.0)
                .min_by_key(|(_, saved)| saved.token.1)
            else { break };
            let removed = self.create_results.swap_remove(index);
            self.retired_create_sequence = self.retired_create_sequence.max(removed.token.1);
        }
    }

    /// A new ALPC adapter with no sections/views.
    pub fn new() -> Self {
        Self {
            create_results: Vec::new(),
            retired_create_sequence: 0,
            send_receive_results: Vec::new(),
            retired_send_receive_sequence: 0,
            connect_results: Vec::new(),
            retired_connect_sequence: 0,
            accept_results: Vec::new(),
            retired_accept_sequence: 0,
            connection_receipts: Vec::new(),
            sections: Vec::new(),
            views: Vec::new(),
            next_section: ALPC_SECTION_BASE,
            next_view_base: 0x0000_5000_0000_0000,
        }
    }

    /// Dispatch one ALPC request against the shared `core`. Always returns a
    /// reply — a malformed request yields an error status, never a panic.
    pub fn dispatch(
        &mut self,
        core: &mut PortCore,
        op: u16,
        in_buf: &[u8],
        out_buf: &mut [u8],
    ) -> AlpcReply {
        match self.try_dispatch(core, op, in_buf, out_buf) {
            Ok(r) => r,
            Err(status) => reply(status, 0, 0, 0),
        }
    }

    fn try_dispatch(
        &mut self,
        core: &mut PortCore,
        op: u16,
        in_buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<AlpcReply, NtStatus> {
        match op {
            opcode::ALPC_OP_PING => Ok(ok()),
            opcode::ALPC_OP_CREATE_PORT => self.op_create_port(core, in_buf),
            opcode::ALPC_OP_LOOKUP_CREATE_PORT => self.op_lookup_create_port(core, in_buf),
            opcode::ALPC_OP_CLOSE_CREATED_PORT => self.op_close_created_port(core, in_buf),
            opcode::ALPC_OP_ACK_SEND_RECEIVE => self.op_ack_send_receive(in_buf),
            opcode::ALPC_OP_CLOSE_LATER_PORT => self.op_close_later_port(core, in_buf),
            opcode::ALPC_OP_ACK_CONNECT_PORT => self.op_ack_later(in_buf, false),
            opcode::ALPC_OP_ACK_ACCEPT_CONNECT => self.op_ack_later(in_buf, true),
            opcode::ALPC_OP_CONNECT_PORT => self.op_connect_port(core, in_buf, out_buf),
            opcode::ALPC_OP_ACCEPT_CONNECT => self.op_accept_connect(core, in_buf),
            opcode::ALPC_OP_SEND_RECEIVE | opcode::ALPC_OP_RECEIVE => {
                self.op_send_receive(core, op, in_buf, out_buf)
            }
            opcode::ALPC_OP_DISCONNECT_PORT => self.op_disconnect(core, in_buf),
            opcode::ALPC_OP_CLOSE_PORT => self.op_close_port(core, in_buf),
            opcode::ALPC_OP_CREATE_PORT_SECTION => self.op_create_port_section(in_buf),
            opcode::ALPC_OP_CREATE_SECTION_VIEW => self.op_create_section_view(in_buf),
            opcode::ALPC_OP_DELETE_PORT_SECTION => self.op_delete_port_section(in_buf),
            opcode::ALPC_OP_DELETE_SECTION_VIEW => self.op_delete_section_view(in_buf),
            opcode::ALPC_OP_WRITE_SECTION_VIEW => self.op_write_section_view(in_buf),
            opcode::ALPC_OP_READ_SECTION_VIEW => self.op_read_section_view(in_buf, out_buf),
            _ => Err(NtStatus::NOT_IMPLEMENTED),
        }
    }

    // --- connection rendezvous --------------------------------------------

    fn op_create_port(&mut self, core: &mut PortCore, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcCreatePortRequest = read_req(buf)?;
        if req.abi_size as usize == size_of::<AlpcCreatePortCheckedRequest>()
            || req.abi_size as usize == size_of::<AlpcCreatePortOwnedRequest>()
            || req.abi_size as usize == size_of::<AlpcCreatePortSecuredRequest>()
        {
            return self.op_create_port_checked(core, buf);
        }
        if req.abi_size as usize != size_of::<AlpcCreatePortRequest>() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        let admission = port_admission(req.port_flags)?;
        let handle = core.create_port_with_limits_admission(
            &name,
            PortApi::Alpc,
            PortLimits {
                max_connection_info: MAX_CONNINFO as u32,
                max_message: req.max_message_length,
                max_pool_usage: 0,
            },
            admission,
        )?;
        Ok(reply(NtStatus::SUCCESS, 0, handle, 0))
    }

    fn op_create_port_checked(
        &mut self,
        core: &mut PortCore,
        buf: &[u8],
    ) -> Result<AlpcReply, NtStatus> {
        let req: AlpcCreatePortCheckedRequest = read_req(buf)?;
        let attributes = if req.create.abi_size as usize == size_of::<AlpcCreatePortOwnedRequest>()
            || req.create.abi_size as usize == size_of::<AlpcCreatePortSecuredRequest>()
        {
            let owned: AlpcCreatePortOwnedRequest = read_req(buf)?;
            let attrs = owned.attributes;
            if owned.checked != req
                || attrs.flags != req.create.port_flags
                || attrs.max_message_length != u64::from(req.create.max_message_length)
                || attrs.max_pool_usage > u32::MAX as u64
                || port_admission(attrs.flags).is_err()
                || attrs.memory_bandwidth != 0
                || attrs.max_section_size != 0
                || attrs.max_view_size != 0
                || attrs.max_total_section_size != 0
                || attrs.dup_object_types != 0
                || attrs.reserved != 0
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let qos = attrs.security_qos;
            if (qos.length != 0
                && qos.length != size_of::<nt_alpc_abi::SecurityQualityOfService>() as u32)
                || (qos.length == 0
                    && (qos.impersonation_level != 0
                        || qos.context_tracking_mode != 0
                        || qos.effective_only != 0))
                || qos.impersonation_level > 3
                || qos.context_tracking_mode > 1
                || qos.effective_only > 1
                || qos._pad != 0
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Some(attrs)
        } else if req.create.abi_size as usize == size_of::<AlpcCreatePortCheckedRequest>() {
            None
        } else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        let security_descriptor = if req.create.abi_size as usize
            == size_of::<AlpcCreatePortSecuredRequest>()
        {
            let secured: AlpcCreatePortSecuredRequest = read_req(buf)?;
            if secured.owned.checked != req
                || secured.security_len_bytes == 0
                || secured.security_offset as usize
                    != size_of::<AlpcCreatePortSecuredRequest>()
                        + req.create.name_len_bytes as usize
            { return Err(NtStatus::INVALID_PARAMETER); }
            let bytes = read_blob(buf, secured.security_offset, secured.security_len_bytes)?;
            if secured.security_offset as usize + bytes.len() != buf.len() {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            nt_security::validate_security_descriptor_bytes(bytes)
                .map_err(|status| NtStatus(status as i32))?;
            let mut owned = Vec::new();
            owned.try_reserve_exact(bytes.len())
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            owned.extend_from_slice(bytes);
            Some(owned)
        } else { None };
        let owner = ClientId {
            process: req.owner_process,
            thread: req.owner_thread,
        };
        let token = (req.invocation_hi, req.invocation_lo);
        if owner.process == 0
            || owner.thread == 0
            || req.owner_generation == 0
            || token == (0, 0)
            || req.create.name_offset < req.create.abi_size as u32
            || req.create._reserved != 0
            || req.create._reserved2 != 0
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let name = read_name(buf, req.create.name_offset, req.create.name_len_bytes)?;
        if let Some(saved) = self
            .create_results
            .iter()
            .find(|saved| saved.token == token)
        {
            if saved.owner != owner || saved.owner_generation != req.owner_generation {
                return Err(NtStatus::OBJECT_NAME_COLLISION);
            }
            if saved.closed { return Err(NtStatus::INVALID_PORT_HANDLE); }
            if saved.request != req.create || saved.attributes != attributes
                || saved.security_descriptor != security_descriptor || saved.name != name {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            return Ok(self.live_create_result(core, saved));
        }
        self.retire_settled_create_results();
        if token.1 <= self.retired_create_sequence {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        if self.create_results.len() >= MAX_CHECKED_CREATE_RESULTS {
            return Err(NtStatus::INSUFFICIENT_RESOURCES);
        }
        // Reserve the replay record before the core may publish a port. An allocation
        // failure must leave the operation at known zero effect.
        self.create_results
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let admission = port_admission(req.create.port_flags)?;
        let result = match core.create_port_with_owner_and_limits_checked_admission(
            &name,
            PortApi::Alpc,
            owner,
            PortLimits {
                max_connection_info: MAX_CONNINFO as u32,
                max_message: req.create.max_message_length,
                max_pool_usage: attributes.map_or(0, |attrs| attrs.max_pool_usage as u32),
            },
            admission,
        ) {
            Ok(handle) => reply(NtStatus::SUCCESS, 0, handle, 0),
            Err(status) => reply(status, 0, 0, 0),
        };
        self.create_results.push(CreatePortResult {
            owner,
            owner_generation: req.owner_generation,
            token,
            request: req.create,
            attributes,
            security_descriptor,
            name,
            result,
            closed: false,
        });
        Ok(result)
    }

    fn op_close_created_port(
        &mut self,
        core: &mut PortCore,
        buf: &[u8],
    ) -> Result<AlpcReply, NtStatus> {
        let req: AlpcCloseCreatedPortRequest = read_req(buf)?;
        if req.abi_size as usize != size_of::<AlpcCloseCreatedPortRequest>()
            || req._reserved != 0 || req._reserved2 != 0 || req.handle == 0
            || req.owner_process == 0 || req.owner_thread == 0 || req.owner_generation == 0
            || (req.invocation_hi, req.invocation_lo) == (0, 0)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let saved = self.create_results.iter_mut().find(|saved| {
            saved.token == (req.invocation_hi, req.invocation_lo)
        }).ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
        if saved.owner.process != req.owner_process
            || saved.owner_generation != req.owner_generation
            || saved.result.status != NtStatus::SUCCESS.0
            || saved.result.detail0 != req.handle
        {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        if saved.closed {
            return Ok(ok());
        }
        let info = core.handle_info(req.handle).ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        if info.endpoint != PortHandleEndpoint::ListenPort
            || info.api != PortApi::Alpc || info.server_id != saved.owner
        {
            return Err(NtStatus::INVALID_PORT_HANDLE);
        }
        core.close_port_checked(req.handle)?;
        saved.closed = true;
        saved.request = AlpcCreatePortRequest::default();
        saved.attributes = None;
        saved.security_descriptor = None;
        saved.name = Vec::new();
        Ok(ok())
    }

    fn op_close_later_port(&mut self, core: &mut PortCore,
        buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcCloseCreatedPortRequest = read_req(buf)?;
        if req.abi_size as usize != size_of::<AlpcCloseCreatedPortRequest>()
            || req._reserved != 0 || req._reserved2 != 0 || req.handle == 0
            || req.owner_process == 0 || req.owner_thread == 0 || req.owner_generation == 0
            || (req.invocation_hi, req.invocation_lo) == (0, 0)
        { return Err(NtStatus::INVALID_PARAMETER); }
        let token = (req.invocation_hi, req.invocation_lo);
        let owner = ClientId { process: req.owner_process, thread: req.owner_thread };
        let (endpoint, saved_owner, saved_generation, saved_handle, closed) =
            if let Some(saved) = self.connect_results.iter().find(|saved| saved.token == token) {
                (PortHandleEndpoint::ClientCommPort, saved.owner, saved.owner_generation,
                    saved.result.detail0, saved.closed)
            } else if let Some(saved) = self.accept_results.iter().find(|saved| saved.token == token) {
                (PortHandleEndpoint::ServerCommPort, saved.owner, saved.owner_generation,
                    saved.result.detail0, saved.closed)
            } else { return Err(NtStatus::OBJECT_NAME_NOT_FOUND); };
        if saved_owner.process != owner.process || saved_generation != req.owner_generation
            || saved_handle != req.handle
        { return Err(NtStatus::OBJECT_NAME_COLLISION); }
        if closed { return Ok(ok()); }
        let info = core.handle_info(req.handle).ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        if info.endpoint != endpoint || info.api != PortApi::Alpc
            || match endpoint {
                PortHandleEndpoint::ClientCommPort => info.client_id
                    .is_none_or(|client| client.process != owner.process),
                PortHandleEndpoint::ServerCommPort => info.server_id.process != owner.process,
                PortHandleEndpoint::ListenPort => true,
            }
        { return Err(NtStatus::INVALID_PORT_HANDLE); }
        core.close_port_checked(req.handle)?;
        if endpoint == PortHandleEndpoint::ClientCommPort {
            self.connect_results.iter_mut().find(|saved| saved.token == token).unwrap().closed = true;
        } else {
            self.accept_results.iter_mut().find(|saved| saved.token == token).unwrap().closed = true;
        }
        Ok(ok())
    }

    fn op_ack_later(&mut self, buf: &[u8], accept: bool) -> Result<AlpcReply, NtStatus> {
        let ack: AlpcAcknowledgeSendReceiveRequest = read_req(buf)?;
        let (owner, generation, token) = checked_identity(ack.invocation)?;
        if ack.abi_size as usize != size_of::<AlpcAcknowledgeSendReceiveRequest>()
            || ack._reserved != 0 || ack._reserved2 != 0
        { return Err(NtStatus::INVALID_PARAMETER); }
        if accept {
            let index = self.accept_results.iter().position(|saved| saved.token == token)
                .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
            let saved = &self.accept_results[index];
            if saved.owner != owner || saved.owner_generation != generation {
                return Err(NtStatus::OBJECT_NAME_COLLISION);
            }
            let saved = &mut self.accept_results[index];
            if saved.result.status == NtStatus::SUCCESS.0 && saved.result.detail0 != 0
                && !saved.closed {
                saved.acknowledged = true;
                saved.request = Vec::new();
            } else { self.accept_results.swap_remove(index); }
            self.retired_accept_sequence = self.retired_accept_sequence.max(token.1);
        } else {
            let index = self.connect_results.iter().position(|saved| saved.token == token)
                .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
            let saved = &self.connect_results[index];
            if saved.owner != owner || saved.owner_generation != generation {
                return Err(NtStatus::OBJECT_NAME_COLLISION);
            }
            if saved.result.status == NtStatus::PENDING.0 {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let saved = &mut self.connect_results[index];
            if saved.result.status == NtStatus::SUCCESS.0 && saved.result.detail0 != 0
                && !saved.closed {
                saved.acknowledged = true;
                saved.request = Vec::new();
                saved.response = Vec::new();
            } else { self.connect_results.swap_remove(index); }
            self.retired_connect_sequence = self.retired_connect_sequence.max(token.1);
        }
        Ok(ok())
    }

    fn op_lookup_create_port(&self, core: &PortCore, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcLookupCreatePortRequest = read_req(buf)?;
        if req.abi_size as usize != size_of::<AlpcLookupCreatePortRequest>()
            || req._reserved != 0
            || req._reserved2 != 0
            || req.owner_process == 0
            || req.owner_thread == 0
            || req.owner_generation == 0
            || (req.invocation_hi, req.invocation_lo) == (0, 0)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let Some(saved) = self
            .create_results
            .iter()
            .find(|saved| saved.token == (req.invocation_hi, req.invocation_lo))
        else {
            return Err(if (req.invocation_hi, req.invocation_lo) != (0, 0)
                && req.invocation_lo <= self.retired_create_sequence {
                NtStatus::INVALID_PORT_HANDLE
            } else { NtStatus::OBJECT_NAME_NOT_FOUND });
        };
        if saved.owner
            != (ClientId {
                process: req.owner_process,
                thread: req.owner_thread,
            })
            || saved.owner_generation != req.owner_generation
        {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        Ok(self.live_create_result(core, saved))
    }

    fn live_create_result(&self, core: &PortCore, saved: &CreatePortResult) -> AlpcReply {
        if saved.closed {
            return reply(NtStatus::INVALID_PORT_HANDLE, 0, 0, 0);
        }
        if saved.result.status == NtStatus::SUCCESS.0
            && core.handle_info(saved.result.detail0).is_none()
        {
            return reply(NtStatus::INVALID_HANDLE, 0, 0, 0);
        }
        saved.result
    }

    fn op_connect_port(&mut self, core: &mut PortCore, buf: &[u8],
        out_buf: &mut [u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcConnectPortRequest = read_req(buf)?;
        if req.abi_size as usize == size_of::<AlpcConnectPortCheckedRequest>()
            || req.abi_size as usize == size_of::<AlpcConnectPortAuthorizedRequest>() {
            return self.op_connect_port_checked(core, buf, out_buf);
        }
        if req.abi_size as usize != size_of::<AlpcConnectPortRequest>() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        // The ALPC connect PORT_MESSAGE payload IS the connection-info blob (the
        // bridge passthrough); an LPC host will read these bytes as its blob.
        let conn_info = read_blob(buf, req.message_offset, req.message_len_bytes)?;
        match core.connect(&name, PortApi::Alpc, req.subsystem_type, conn_info)? {
            ConnectOutcome::Completed {
                client_handle,
                connection_id,
            } => Ok(reply(NtStatus::SUCCESS, 0, client_handle, connection_id)),
            ConnectOutcome::Pending { connection_id } => {
                Ok(reply(NtStatus::PENDING, 0, 0, connection_id))
            }
        }
    }

    fn op_connect_port_checked(&mut self, core: &mut PortCore,
        buf: &[u8], out_buf: &mut [u8]) -> Result<AlpcReply, NtStatus> {
        let checked: AlpcConnectPortCheckedRequest = read_req(buf)?;
        let req = checked.connect;
        let authorized = if req.abi_size as usize
            == size_of::<AlpcConnectPortAuthorizedRequest>() {
            let authorization: AlpcConnectPortAuthorizedRequest = read_req(buf)?;
            if authorization.checked != checked || authorization._reserved != 0
                || authorization.access_granted != 1
                || authorization.target_listen_handle == 0
            { return Err(NtStatus::INVALID_PARAMETER); }
            Some(authorization.target_listen_handle)
        } else { None };
        let (owner, generation, token) = checked_identity(checked.invocation)?;
        if req._reserved != 0 || checked._reserved != 0
            || req.valid_attributes != 0 || req.attr_len_bytes != 0
            || req.connect_flags & !connect_flag::SYNC_CONNECTION != 0
        { return Err(NtStatus::INVALID_PARAMETER); }
        let (connection_security, client_max_message) =
            connect_port_options(checked.port_attributes, checked.has_port_attributes)?;
        if let Some(saved) = self.connect_results.iter().find(|saved| saved.token == token) {
            if saved.owner != owner || saved.owner_generation != generation {
                return Err(NtStatus::OBJECT_NAME_COLLISION);
            }
            if saved.acknowledged { return Err(NtStatus::OBJECT_NAME_COLLISION); }
            if saved.request != buf { return Err(NtStatus::INVALID_PARAMETER); }
            if saved.closed { return Err(NtStatus::INVALID_PORT_HANDLE); }
            if saved.response.len() > out_buf.len() { return Err(NtStatus::BUFFER_TOO_SMALL); }
            out_buf[..saved.response.len()].copy_from_slice(&saved.response);
            return Ok(saved.result);
        }
        if token.1 <= self.retired_connect_sequence {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        let framed = read_blob(buf, req.message_offset, req.message_len_bytes)?;
        let payload = if framed.is_empty() { &[][..] } else {
            if framed.len() < size_of::<PortMessage>() { return Err(NtStatus::INVALID_PARAMETER); }
            let header: PortMessage = bytemuck::pod_read_unaligned(&framed[..size_of::<PortMessage>()]);
            if header.total_length as usize != framed.len()
                || header.data_length as usize != framed.len() - size_of::<PortMessage>()
            { return Err(NtStatus::INVALID_PARAMETER); }
            &framed[size_of::<PortMessage>()..]
        };
        // A checked caller identity alone is not an access decision. Keep a
        // protected port closed to this route until the executive submits a
        // token-derived grant bound to the exact current listen object.
        let live_handle = core.named_listen_port_handle(&name);
        if let Some(target) = authorized {
            if live_handle != Some(target) { return Err(NtStatus::INVALID_PORT_HANDLE); }
        }
        if let Some(live_handle) = live_handle {
            if authorized.is_none() && self.create_results.iter().any(|created| {
                !created.closed && created.result.status == NtStatus::SUCCESS.0
                    && created.result.detail0 == live_handle
                    && created.security_descriptor.is_some()
            }) {
                return Err(NtStatus::ACCESS_DENIED);
            }
        }
        self.connect_results.retain(|saved| !saved.acknowledged || !saved.closed);
        if self.connect_results.len() >= MAX_CHECKED_SEND_RECEIVE {
            return Err(NtStatus::INSUFFICIENT_RESOURCES);
        }
        self.connect_results.try_reserve(1).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let mut request = Vec::new();
        request.try_reserve_exact(buf.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(buf);
        let result = match core.connect_with_client_id_and_security_limit(&name, PortApi::Alpc,
            req.subsystem_type, payload, owner, connection_security, client_max_message)? {
            ConnectOutcome::Completed { client_handle, connection_id } =>
                reply(NtStatus::SUCCESS, 0, client_handle, connection_id),
            ConnectOutcome::Pending { connection_id } =>
                reply(NtStatus::PENDING, 0, 0, connection_id),
        };
        self.connect_results.push(CheckedConnect { owner, owner_generation: generation,
            token, request, result, response: Vec::new(), closed: false,
            acknowledged: false });
        Ok(result)
    }

    /// ALPC accept folds complete: on accept the connection is driven all the way
    /// to Connected in one call. `detail0` = server comm-port handle, `detail1` =
    /// client comm-port handle (to unblock the connector).
    fn op_accept_connect(
        &mut self,
        core: &mut PortCore,
        buf: &[u8],
    ) -> Result<AlpcReply, NtStatus> {
        let req: AlpcAcceptConnectRequest = read_req(buf)?;
        if req.abi_size as usize == size_of::<AlpcAcceptConnectCheckedRequest>() {
            return self.op_accept_connect_checked(core, buf);
        }
        if req.abi_size as usize != size_of::<AlpcAcceptConnectRequest>() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let accept = req.accept != 0;
        let sh = core.accept(req.connection_id, accept, req.port_context)?;
        if !accept {
            return Ok(reply(NtStatus::SUCCESS, 0, 0, req.connection_id));
        }
        let (client_handle, _) = core.complete(req.connection_id)?;
        Ok(reply(NtStatus::SUCCESS, 0, sh, client_handle))
    }

    fn op_accept_connect_checked(&mut self, core: &mut PortCore,
        buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let checked: AlpcAcceptConnectCheckedRequest = read_req(buf)?;
        let req = checked.accept;
        let (owner, generation, token) = checked_identity(checked.invocation)?;
        if req._reserved != 0 || req.accept > 1 || req.connection_id == 0
            || checked.listen_port == 0
        { return Err(NtStatus::INVALID_PARAMETER); }
        if let Some(saved) = self.accept_results.iter().find(|saved| saved.token == token) {
            if saved.owner != owner || saved.owner_generation != generation {
                return Err(NtStatus::OBJECT_NAME_COLLISION);
            }
            if saved.acknowledged { return Err(NtStatus::OBJECT_NAME_COLLISION); }
            if saved.request != buf { return Err(NtStatus::INVALID_PARAMETER); }
            if saved.closed { return Err(NtStatus::INVALID_PORT_HANDLE); }
            return Ok(saved.result);
        }
        if token.1 <= self.retired_accept_sequence {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        let info = core.handle_info(checked.listen_port).ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        if info.endpoint != PortHandleEndpoint::ListenPort || info.api != PortApi::Alpc {
            return Err(NtStatus::INVALID_PORT_HANDLE);
        }
        if info.server_id.process != owner.process { return Err(NtStatus::ACCESS_DENIED); }
        let receipt = self.connection_receipts.iter().position(|receipt|
            receipt.listen_port == checked.listen_port
                && receipt.connection_id == req.connection_id
                && receipt.owner.process == owner.process
                && receipt.owner_generation == generation)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let message = read_blob(buf, checked.message_offset, checked.message_len_bytes)?;
        let response = if message.is_empty() { &[][..] } else {
            if checked.message_offset as usize != size_of::<AlpcAcceptConnectCheckedRequest>()
                || message.len() < size_of::<PortMessage>()
            { return Err(NtStatus::INVALID_PARAMETER); }
            let header: PortMessage = bytemuck::pod_read_unaligned(&message[..size_of::<PortMessage>()]);
            if header.total_length as usize != message.len()
                || header.data_length as usize != message.len() - size_of::<PortMessage>()
                || header.msg_type != nt_alpc_abi::msg_type::CONNECTION_REQUEST
                || u64::from(header.message_id) != req.connection_id
                || core.connection_client_id(req.connection_id)
                    != Some(ClientId { process: header.client_process, thread: header.client_thread })
            { return Err(NtStatus::INVALID_PARAMETER); }
            &message[size_of::<PortMessage>()..]
        };
        self.accept_results.retain(|saved| !saved.acknowledged || !saved.closed);
        if self.accept_results.len() >= MAX_CHECKED_SEND_RECEIVE {
            return Err(NtStatus::INSUFFICIENT_RESOURCES);
        }
        self.accept_results.try_reserve(1).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let mut request = Vec::new();
        request.try_reserve_exact(buf.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(buf);
        let mut copied_response = Vec::new();
        copied_response.try_reserve_exact(response.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        copied_response.extend_from_slice(response);
        let accepted = req.accept != 0;
        let server_handle = if message.is_empty() {
            core.accept(req.connection_id, accepted, req.port_context)?
        } else {
            core.accept_with_connection_info(req.connection_id, accepted,
                req.port_context, response)?
        };
        let result = if accepted {
            let (client_handle, _) = core.complete(req.connection_id)?;
            reply(NtStatus::SUCCESS, 0, server_handle, client_handle)
        } else {
            reply(NtStatus::SUCCESS, 0, 0, req.connection_id)
        };
        self.connection_receipts.swap_remove(receipt);
        if let Some(connect) = self.connect_results.iter_mut().find(|saved|
            saved.result.detail1 == req.connection_id
                && saved.result.status == NtStatus::PENDING.0)
        {
            connect.result = if accepted {
                reply(NtStatus::SUCCESS, copied_response.len() as u32,
                    result.detail1, req.connection_id)
            } else { reply(NtStatus::PORT_CONNECTION_REFUSED, 0, 0, req.connection_id) };
            if accepted { connect.response = copied_response; }
        }
        self.accept_results.push(CheckedAccept { owner, owner_generation: generation,
            token, request, result, closed: false, acknowledged: false });
        Ok(result)
    }

    /// Send an outgoing `PORT_MESSAGE` (if present) with its ALPC attributes, then
    /// receive the next inbound one. Receiving projects the stored core
    /// attributes back into an `ALPC_MESSAGE_ATTRIBUTES` view: `detail0` =
    /// `ValidAttributes` (0 = degraded/empty from an LPC peer), `detail1` =
    /// received `PORT_MESSAGE.Type` (0 = data). `information` = received message
    /// byte length in `out_buf`.
    fn op_send_receive(
        &mut self,
        core: &mut PortCore,
        op: u16,
        buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<AlpcReply, NtStatus> {
        let req: AlpcSendReceiveRequest = read_req(buf)?;
        if req.abi_size as usize == size_of::<AlpcSendReceiveCheckedRequest>() {
            return self.op_send_receive_checked(core, op, buf, out_buf);
        }
        if req.abi_size as usize != size_of::<AlpcSendReceiveRequest>() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if req.flags & send_flag::SYNC_REQUEST != 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }

        Self::perform_send_receive(core, op, req, buf, out_buf, true, false, None)
    }

    fn op_send_receive_checked(
        &mut self,
        core: &mut PortCore,
        op: u16,
        buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<AlpcReply, NtStatus> {
        let checked: AlpcSendReceiveCheckedRequest = read_req(buf)?;
        let invocation = checked.invocation;
        let owner = ClientId {
            process: invocation.owner_process,
            thread: invocation.owner_thread,
        };
        let token = (invocation.invocation_hi, invocation.invocation_lo);
        if owner.process == 0 || owner.thread == 0 || invocation.owner_generation == 0
            || token == (0, 0) || checked.send_receive._reserved != 0
            || checked.send_receive._reserved2 != 0
            || checked.send_receive.flags
                & !(send_flag::RECV_ATTRIBUTES | send_flag::REPLY_MESSAGE
                    | send_flag::SYNC_REQUEST) != 0
            || (checked.send_receive.flags & send_flag::REPLY_MESSAGE != 0
                && checked.send_receive.message_len_bytes == 0)
            || (checked.send_receive.flags & send_flag::SYNC_REQUEST != 0
                && (checked.send_receive.flags & send_flag::REPLY_MESSAGE != 0
                    || checked.send_receive.message_len_bytes == 0
                    || op != opcode::ALPC_OP_SEND_RECEIVE))
            || (checked.send_receive.flags & send_flag::RECV_ATTRIBUTES != 0
                && (checked.send_receive.valid_attributes != msg_attr_flag::CONTEXT
                    || checked.send_receive.attr_len_bytes != 0))
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let sync_identity = if checked.send_receive.flags & send_flag::SYNC_REQUEST != 0 {
            Some(MessageIdentity { client: owner,
                message_id: u32::try_from(token.1).ok().filter(|id| *id != 0)
                    .ok_or(NtStatus::INVALID_PARAMETER)? })
        } else { None };
        if let Some(saved) = self.send_receive_results.iter_mut().find(|saved| saved.token == token) {
            if saved.owner != owner || saved.owner_generation != invocation.owner_generation {
                return Err(NtStatus::OBJECT_NAME_COLLISION);
            }
            if saved.op != op || saved.request != buf || saved.output.len() != out_buf.len() {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if let Some(result) = saved.terminal {
                out_buf.copy_from_slice(&saved.output);
                return Ok(result);
            }
            if core.handle_info(checked.send_receive.port_handle)
                .is_some_and(|info| info.endpoint == PortHandleEndpoint::ListenPort)
            {
                if self.connection_receipts.len() >= MAX_CHECKED_SEND_RECEIVE {
                    return Err(NtStatus::INSUFFICIENT_RESOURCES);
                }
                self.connection_receipts.try_reserve(1)
                    .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            }
            // The request was reserved before its first effect. Redrive only
            // the receive half, including when the first send is uncertain.
            let result = Self::perform_send_receive(
                core, op, checked.send_receive, buf, &mut saved.output, false, true,
                sync_identity,
            );
            let result = match result {
                Ok(reply) => reply,
                Err(status) => reply(status, 0, 0, 0),
            };
            if result.status != NtStatus::PENDING.0 {
                saved.terminal = Some(result);
            }
            if result.status == NtStatus::SUCCESS.0
                && result.detail1 == u64::from(nt_alpc_abi::msg_type::CONNECTION_REQUEST)
            {
                self.connection_receipts.push(ConnectionReceipt { owner,
                    owner_generation: invocation.owner_generation,
                    listen_port: checked.send_receive.port_handle,
                    connection_id: result.detail0 });
            }
            out_buf.copy_from_slice(&saved.output);
            return Ok(result);
        }
        if token.1 <= self.retired_send_receive_sequence {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        let info = core.handle_info(checked.send_receive.port_handle)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let port_owner = match info.endpoint {
            PortHandleEndpoint::ListenPort | PortHandleEndpoint::ServerCommPort => info.server_id.process,
            PortHandleEndpoint::ClientCommPort => info.client_id.ok_or(NtStatus::INVALID_PORT_HANDLE)?.process,
        };
        if info.api != PortApi::Alpc || owner.process != port_owner {
            return Err(NtStatus::ACCESS_DENIED);
        }
        if info.endpoint == PortHandleEndpoint::ListenPort {
            if self.connection_receipts.len() >= MAX_CHECKED_SEND_RECEIVE {
                return Err(NtStatus::INSUFFICIENT_RESOURCES);
            }
            self.connection_receipts.try_reserve(1)
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        }
        // Reserve the exact request and output capacity before sending or
        // consuming a queued message. A failed allocation has zero effect.
        if self.send_receive_results.len() >= MAX_CHECKED_SEND_RECEIVE {
            return Err(NtStatus::INSUFFICIENT_RESOURCES);
        }
        self.send_receive_results.try_reserve(1).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let mut request = Vec::new();
        request.try_reserve_exact(buf.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        request.extend_from_slice(buf);
        let mut output = Vec::new();
        output.try_reserve_exact(out_buf.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        output.resize(out_buf.len(), 0);
        self.send_receive_results.push(CheckedSendReceive {
            owner,
            owner_generation: invocation.owner_generation,
            token,
            op,
            request,
            output,
            terminal: None,
        });
        let saved = self.send_receive_results.last_mut().ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        let result = Self::perform_send_receive(
            core, op, checked.send_receive, buf, &mut saved.output, true, true,
            sync_identity,
        );
        let result = match result {
            Ok(reply) => reply,
            Err(status) => reply(status, 0, 0, 0),
        };
        if result.status != NtStatus::PENDING.0 {
            saved.terminal = Some(result);
        }
        if result.status == NtStatus::SUCCESS.0
            && result.detail1 == u64::from(nt_alpc_abi::msg_type::CONNECTION_REQUEST)
        {
            self.connection_receipts.push(ConnectionReceipt { owner,
                owner_generation: invocation.owner_generation,
                listen_port: checked.send_receive.port_handle,
                connection_id: result.detail0 });
        }
        out_buf.copy_from_slice(&saved.output);
        Ok(result)
    }

    fn op_ack_send_receive(&mut self, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let ack: AlpcAcknowledgeSendReceiveRequest = read_req(buf)?;
        let invocation = ack.invocation;
        let token = (invocation.invocation_hi, invocation.invocation_lo);
        if ack.abi_size as usize != size_of::<AlpcAcknowledgeSendReceiveRequest>()
            || ack._reserved != 0 || ack._reserved2 != 0
            || invocation.owner_process == 0 || invocation.owner_thread == 0
            || invocation.owner_generation == 0 || token == (0, 0)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let index = self.send_receive_results.iter().position(|saved| saved.token == token)
            .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
        let saved = &self.send_receive_results[index];
        if saved.owner != (ClientId { process: invocation.owner_process,
            thread: invocation.owner_thread })
            || saved.owner_generation != invocation.owner_generation
        {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        if saved.terminal.is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.send_receive_results.swap_remove(index);
        self.retired_send_receive_sequence = self.retired_send_receive_sequence.max(token.1);
        Ok(ok())
    }

    fn perform_send_receive(
        core: &mut PortCore,
        op: u16,
        req: AlpcSendReceiveRequest,
        buf: &[u8],
        out_buf: &mut [u8],
        send_allowed: bool,
        native_checked: bool,
        sync_identity: Option<MessageIdentity>,
    ) -> Result<AlpcReply, NtStatus> {

        // Send half (skipped for a pure receive op or a zero-length send).
        if send_allowed && op == opcode::ALPC_OP_SEND_RECEIVE && req.message_len_bytes != 0 {
            let msg = read_blob(buf, req.message_offset, req.message_len_bytes)?;
            let attr_blob = read_blob(buf, req.attr_offset, req.attr_len_bytes)?;
            let attrs = parse_attrs(req.valid_attributes, attr_blob);
            if req.flags & send_flag::REPLY_MESSAGE != 0 {
                let header: PortMessage = read_at(msg, 0).ok_or(NtStatus::INVALID_PARAMETER)?;
                if usize::from(header.total_length) != msg.len()
                    || usize::from(header.data_length) + size_of::<PortMessage>() != msg.len()
                { return Err(NtStatus::INVALID_PARAMETER); }
                let mut reply = Vec::new();
                reply.try_reserve_exact(msg.len())
                    .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
                reply.extend_from_slice(msg);
                reply[4..6].copy_from_slice(&nt_alpc_abi::msg_type::REPLY.to_le_bytes());
                core.send_reply_message(req.port_handle, &reply, attrs,
                    nt_port_core::MessageIdentity {
                        client: ClientId {
                            process: header.client_process,
                            thread: header.client_thread,
                        },
                        message_id: header.message_id,
                    })?;
            } else if let Some(identity) = sync_identity {
                let header: PortMessage = read_at(msg, 0).ok_or(NtStatus::INVALID_PARAMETER)?;
                if usize::from(header.total_length) != msg.len()
                    || usize::from(header.data_length) + size_of::<PortMessage>() != msg.len()
                { return Err(NtStatus::INVALID_PARAMETER); }
                let mut request = Vec::new();
                request.try_reserve_exact(msg.len())
                    .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
                request.extend_from_slice(msg);
                // ALPC supplies the request type to the server. User-mode CSR
                // initializes this header field to zero before the syscall.
                request[4..6].copy_from_slice(&nt_alpc_abi::msg_type::REQUEST.to_le_bytes());
                request[8..16].copy_from_slice(&identity.client.process.to_le_bytes());
                request[16..24].copy_from_slice(&identity.client.thread.to_le_bytes());
                request[24..28].copy_from_slice(&identity.message_id.to_le_bytes());
                core.send_request_message(req.port_handle, &request, attrs, identity)?;
            } else {
                core.send_message(req.port_handle, msg, attrs)?;
            }
        }

        if let Some(identity) = sync_identity {
            let Some(QueuedMessage { bytes, attrs, .. }) =
                core.receive_reply_message(req.port_handle, identity)?
            else { return Ok(reply(NtStatus::PENDING, 0, 0, 0)); };
            let present = project_valid_attributes(&attrs);
            let prefix = if req.flags & send_flag::RECV_ATTRIBUTES != 0 {
                let (valid, blob) = serialize_attrs(req.valid_attributes, &attrs);
                if blob.len().checked_add(bytes.len()).is_none_or(|len| len > out_buf.len()) {
                    return Err(NtStatus::BUFFER_TOO_SMALL);
                }
                out_buf[..blob.len()].copy_from_slice(&blob);
                (blob.len(), valid)
            } else { (0, present) };
            let total = prefix.0.checked_add(bytes.len()).ok_or(NtStatus::BUFFER_TOO_SMALL)?;
            if total > out_buf.len() { return Err(NtStatus::BUFFER_TOO_SMALL); }
            out_buf[prefix.0..total].copy_from_slice(&bytes);
            return Ok(reply(NtStatus::SUCCESS, total as u32,
                u64::from(prefix.1), u64::from(read_msg_type(&bytes))));
        }

        if native_checked {
            if let Some((connection_id, payload_len)) =
                core.peek_pending_connection(req.port_handle)
            {
                let total = size_of::<PortMessage>().checked_add(payload_len)
                    .ok_or(NtStatus::INVALID_PARAMETER)?;
                if u32::try_from(connection_id).is_err() {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
                let attribute_reserve = if req.flags & send_flag::RECV_ATTRIBUTES != 0 {
                    8 + size_of::<AlpcContextAttr>()
                } else { 0 };
                if total > out_buf.len().saturating_sub(attribute_reserve)
                    || total > u16::MAX as usize {
                    return Err(NtStatus::BUFFER_TOO_SMALL);
                }
            }
        }

        // Receive half. NtAlpcSendWaitReceivePort receives BOTH a pending
        // connection request (on a listen port) AND a data message (on a comm
        // port); try the connection request first, then the data queue.
        let conn_try = core.receive(req.port_handle);
        if let Ok(ReceiveOutcome::ConnectionRequest {
            connection_id,
            msg_type,
        }) = conn_try
        {
            if native_checked {
                let payload = core.connection_info(connection_id)
                    .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
                let client = core.connection_client_id(connection_id)
                    .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
                let total = size_of::<PortMessage>() + payload.len();
                let header = PortMessage {
                    data_length: payload.len() as u16,
                    total_length: total as u16,
                    msg_type,
                    client_process: client.process,
                    client_thread: client.thread,
                    message_id: connection_id as u32,
                    ..Default::default()
                };
                let prefix = if req.flags & send_flag::RECV_ATTRIBUTES != 0 {
                    out_buf[..8].copy_from_slice(bytemuck::bytes_of(&AlpcMessageAttributes {
                        allocated_attributes: req.valid_attributes,
                        valid_attributes: 0,
                    }));
                    8
                } else { 0 };
                out_buf[prefix..prefix + size_of::<PortMessage>()]
                    .copy_from_slice(bytemuck::bytes_of(&header));
                out_buf[prefix + size_of::<PortMessage>()..prefix + total].copy_from_slice(payload);
                return Ok(reply(NtStatus::SUCCESS, (prefix + total) as u32,
                    connection_id, msg_type as u64));
            }
            // detail0 = connection id (feed to accept), detail1 = CONNECTION_REQUEST.
            return Ok(reply(NtStatus::SUCCESS, 0, connection_id, msg_type as u64));
        }
        // A valid listen port with nothing pending must park, not error.
        let is_listen_port = conn_try.is_ok();
        let checked_message_capacity = if req.flags & send_flag::RECV_ATTRIBUTES != 0 {
            out_buf.len().saturating_sub(8 + size_of::<AlpcContextAttr>())
        } else { out_buf.len() };
        if native_checked && core.peek_receive_message_len(req.port_handle)
            .is_some_and(|len| len > checked_message_capacity)
        {
            return Err(NtStatus::BUFFER_TOO_SMALL);
        }
        let server_receive = core.handle_info(req.port_handle).is_some_and(|info|
            matches!(info.endpoint,
                PortHandleEndpoint::ListenPort | PortHandleEndpoint::ServerCommPort));
        match core.receive_message(req.port_handle) {
            Ok(Some(QueuedMessage { bytes, mut attrs, provenance, port_context,
                request_identity })) => {
                let msg_type = read_msg_type(&bytes);
                // A checked ALPC request carries the accepted connection's
                // PortContext. Ordinary messages retain their sender attributes,
                // including LPC bridge degradation and ALPC message context.
                if native_checked && server_receive && provenance.connection_id != 0
                    && request_identity.is_some()
                    && core.connection_apis(provenance.connection_id)
                        .is_some_and(|(client, _)| client == PortApi::Alpc)
                {
                    attrs.context = Some(port_context);
                }
                // Project the neutral attrs into the ALPC valid-attributes view.
                // Non-bridging attrs from an ALPC peer are surfaced; an LPC peer
                // carried none, so valid == 0 (the LPC → ALPC degradation).
                let present = project_valid_attributes(&attrs);
                if req.flags & send_flag::RECV_ATTRIBUTES != 0 {
                    // Full ALPC_MESSAGE_ATTRIBUTES out-param: the 8-byte header +
                    // the per-attr structs (fixed order) at the FRONT of the reply,
                    // the message body after. ValidAttributes = allocated & present.
                    let (valid, blob) = serialize_attrs(req.valid_attributes, &attrs);
                    let a = blob.len().min(out_buf.len());
                    out_buf[..a].copy_from_slice(&blob[..a]);
                    let rest = out_buf.len().saturating_sub(a);
                    let n = bytes.len().min(rest);
                    out_buf[a..a + n].copy_from_slice(&bytes[..n]);
                    Ok(reply(
                        NtStatus::SUCCESS,
                        (a + n) as u32,
                        valid as u64,
                        msg_type as u64,
                    ))
                } else {
                    let n = bytes.len().min(out_buf.len());
                    out_buf[..n].copy_from_slice(&bytes[..n]);
                    Ok(reply(
                        NtStatus::SUCCESS,
                        n as u32,
                        present as u64,
                        msg_type as u64,
                    ))
                }
            }
            Ok(None) => Ok(reply(NtStatus::PENDING, 0, 0, 0)),
            Err(e) => {
                if is_listen_port {
                    Ok(reply(NtStatus::PENDING, 0, 0, 0))
                } else {
                    Err(e)
                }
            }
        }
    }

    fn op_disconnect(&mut self, core: &mut PortCore, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcHandleRequest = read_req(buf)?;
        let info = core
            .handle_info(req.handle)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        if info.endpoint == PortHandleEndpoint::ListenPort || info.api != PortApi::Alpc {
            return Err(NtStatus::INVALID_PORT_HANDLE);
        }
        let connection_id = info.connection_id;
        core.disconnect(connection_id);
        Ok(ok())
    }

    fn op_close_port(&mut self, core: &mut PortCore, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcHandleRequest = read_req(buf)?;
        core.close_port(req.handle);
        Ok(ok())
    }

    // --- port sections / views (REAL shared backing store) ----------------

    fn op_create_port_section(&mut self, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcCreatePortSectionRequest = read_req(buf)?;
        if req.section_size == 0 || req.section_size > MAX_SECTION_SIZE {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let handle = self.next_section;
        self.next_section += 1;
        // Reserve the REAL shared backing object without eagerly committing every byte.
        let backing = SparseSectionBacking::new(req.section_size)?;
        self.sections.push(PortSection {
            handle,
            port_handle: req.port_handle,
            size: req.section_size,
            backing,
        });
        // detail0 = AlpcSectionHandle, information = ActualSectionSize (low 32).
        Ok(reply(NtStatus::SUCCESS, req.section_size as u32, handle, 0))
    }

    fn op_create_section_view(&mut self, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcCreateSectionViewRequest = read_req(buf)?;
        // The view must reference a known section and fit within it.
        let section = self
            .sections
            .iter()
            .find(|s| s.handle == req.alpc_section_handle)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let size = if req.view_size == 0 {
            section.size
        } else {
            req.view_size
        };
        if size > section.size {
            return Err(NtStatus::INVALID_VIEW_SIZE);
        }
        let view_base = self.next_view_base;
        self.next_view_base += size.max(0x1000);
        self.views.push(SectionView {
            view_base,
            section_handle: req.alpc_section_handle,
            // Views map the section from its start; every view of a section thus
            // aliases the same backing bytes (the cross-endpoint sharing).
            section_offset: 0,
            size,
        });
        // detail0 = ViewBase (written back into ALPC_DATA_VIEW_ATTR.ViewBase).
        Ok(reply(NtStatus::SUCCESS, 0, view_base, 0))
    }

    fn op_delete_port_section(&mut self, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcHandleRequest = read_req(buf)?;
        self.sections.retain(|s| s.handle != req.handle);
        Ok(ok())
    }

    fn op_delete_section_view(&mut self, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcHandleRequest = read_req(buf)?;
        self.views.retain(|v| v.view_base != req.handle);
        Ok(ok())
    }

    /// Write bytes THROUGH a mapped view into the section's shared backing store.
    /// Because every view of a section aliases the same `backing`, a subsequent
    /// read through ANOTHER endpoint's view of the same section observes these
    /// bytes — real cross-endpoint shared memory, no message copy.
    fn op_write_section_view(&mut self, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcViewIoRequest = read_req(buf)?;
        let data = read_blob(buf, req.data_offset, req.data_len_bytes)?;
        let (section_handle, section_offset) =
            self.resolve_view(req.view_base, req.view_offset, data.len() as u64)?;
        let section = self
            .sections
            .iter_mut()
            .find(|s| s.handle == section_handle)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let start = section_offset as usize;
        section.backing.write(start, data)?;
        Ok(reply(NtStatus::SUCCESS, data.len() as u32, 0, 0))
    }

    /// Read bytes THROUGH a mapped view out of the section's shared backing store
    /// into the reply frame.
    fn op_read_section_view(
        &mut self,
        buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<AlpcReply, NtStatus> {
        let req: AlpcViewIoRequest = read_req(buf)?;
        let len = req.data_len_bytes as u64;
        let (section_handle, section_offset) =
            self.resolve_view(req.view_base, req.view_offset, len)?;
        let section = self
            .sections
            .iter()
            .find(|s| s.handle == section_handle)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let start = section_offset as usize;
        let n = (len as usize).min(out_buf.len());
        section.backing.read(start, &mut out_buf[..n])?;
        Ok(reply(NtStatus::SUCCESS, n as u32, 0, 0))
    }

    /// Resolve a `(view_base, view_offset, len)` to the aliased section handle and
    /// the absolute byte offset into its backing store, bounds-checking that
    /// `[view_offset, view_offset+len)` stays within the view AND the section.
    fn resolve_view(
        &self,
        view_base: u64,
        view_offset: u64,
        len: u64,
    ) -> Result<(u64, u64), NtStatus> {
        let view = self
            .views
            .iter()
            .find(|v| v.view_base == view_base)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let end = view_offset
            .checked_add(len)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if end > view.size {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let section_offset = view
            .section_offset
            .checked_add(view_offset)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        Ok((view.section_handle, section_offset))
    }

    /// Number of tracked port sections (diagnostics/tests).
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Number of tracked section views (diagnostics/tests).
    pub fn view_count(&self) -> usize {
        self.views.len()
    }

    /// True if a port section is registered for `port_handle` (diagnostics).
    pub fn has_section_for(&self, port_handle: u64) -> bool {
        self.sections.iter().any(|s| s.port_handle == port_handle)
    }
}

// ---------------------------------------------------------------------------
// ALPC message-attribute (de)serialization — the bridge boundary.
// Fixed order in the serialized blob: SECURITY, VIEW, CONTEXT, HANDLE, TOKEN.
// ---------------------------------------------------------------------------

/// Parse a serialized `ALPC_MESSAGE_ATTRIBUTES` payload into the core-neutral
/// [`MessageAttrs`]. Unknown/absent attributes are simply not set. Bounds-checked
/// — a truncated blob yields whatever parsed cleanly (never panics).
pub fn parse_attrs(valid: u32, blob: &[u8]) -> MessageAttrs {
    let mut out = MessageAttrs::default();
    let mut off = 0usize;
    if valid & msg_attr_flag::SECURITY != 0 {
        if let Some(a) = read_at::<AlpcSecurityAttr>(blob, off) {
            out.security = Some(a.context_handle);
        }
        off += size_of::<AlpcSecurityAttr>();
    }
    if valid & msg_attr_flag::VIEW != 0 {
        if let Some(a) = read_at::<AlpcDataViewAttr>(blob, off) {
            out.view = Some(DataView {
                section_handle: a.section_handle,
                view_base: a.view_base,
                view_size: a.view_size,
            });
        }
        off += size_of::<AlpcDataViewAttr>();
    }
    if valid & msg_attr_flag::CONTEXT != 0 {
        if let Some(a) = read_at::<AlpcContextAttr>(blob, off) {
            out.context = Some(a.port_context);
        }
        off += size_of::<AlpcContextAttr>();
    }
    if valid & msg_attr_flag::HANDLE != 0 {
        if let Some(a) = read_at::<AlpcHandleAttr>(blob, off) {
            out.handles.push(a.handle);
        }
        off += size_of::<AlpcHandleAttr>();
    }
    if valid & msg_attr_flag::TOKEN != 0 {
        if let Some(a) = read_at::<AlpcTokenAttr>(blob, off) {
            out.token = Some(a.token_id);
        }
    }
    out
}

/// Serialize a core-neutral [`MessageAttrs`] into a full `ALPC_MESSAGE_ATTRIBUTES`
/// out-buffer: the 8-byte [`AlpcMessageAttributes`] header followed by the
/// per-attribute structs in the fixed order SECURITY, VIEW, CONTEXT, HANDLE,
/// TOKEN. `allocated` is the receiver's `AllocatedAttributes` mask (which
/// attributes it has buffer space for); the emitted `ValidAttributes` (and the
/// structs written) = `allocated & present`. Returns `(valid, blob)`.
pub fn serialize_attrs(allocated: u32, attrs: &MessageAttrs) -> (u32, Vec<u8>) {
    let valid = allocated & project_valid_attributes(attrs);
    let mut blob = Vec::new();
    blob.extend_from_slice(bytemuck::bytes_of(&AlpcMessageAttributes {
        allocated_attributes: allocated,
        valid_attributes: valid,
    }));
    if valid & msg_attr_flag::SECURITY != 0 {
        blob.extend_from_slice(bytemuck::bytes_of(&AlpcSecurityAttr {
            context_handle: attrs.security.unwrap_or(0),
            ..Default::default()
        }));
    }
    if valid & msg_attr_flag::VIEW != 0 {
        let v = attrs.view.unwrap_or_default();
        blob.extend_from_slice(bytemuck::bytes_of(&AlpcDataViewAttr {
            section_handle: v.section_handle,
            view_base: v.view_base,
            view_size: v.view_size,
            ..Default::default()
        }));
    }
    if valid & msg_attr_flag::CONTEXT != 0 {
        blob.extend_from_slice(bytemuck::bytes_of(&AlpcContextAttr {
            port_context: attrs.context.unwrap_or(0),
            ..Default::default()
        }));
    }
    if valid & msg_attr_flag::HANDLE != 0 {
        blob.extend_from_slice(bytemuck::bytes_of(&AlpcHandleAttr {
            handle: attrs.handles.first().copied().unwrap_or(0),
            ..Default::default()
        }));
    }
    if valid & msg_attr_flag::TOKEN != 0 {
        blob.extend_from_slice(bytemuck::bytes_of(&AlpcTokenAttr {
            token_id: attrs.token.unwrap_or(0),
            ..Default::default()
        }));
    }
    (valid, blob)
}

/// Parse a full `ALPC_MESSAGE_ATTRIBUTES` buffer (header + structs) — the inverse
/// of [`serialize_attrs`]. Reads the 8-byte header for `ValidAttributes`, then the
/// per-attribute structs in the fixed order. Returns `(valid, attrs, header_plus_
/// structs_len)` so the caller can locate any trailing message body. Bounds-checked;
/// a truncated buffer yields whatever parsed cleanly.
pub fn parse_message_attributes(blob: &[u8]) -> (u32, MessageAttrs, usize) {
    let header: AlpcMessageAttributes = match read_at(blob, 0) {
        Some(h) => h,
        None => return (0, MessageAttrs::default(), 0),
    };
    let valid = header.valid_attributes;
    let body = blob
        .get(size_of::<AlpcMessageAttributes>()..)
        .unwrap_or(&[]);
    let attrs = parse_attrs(valid, body);
    // Compute the consumed length (header + only the present structs).
    let mut structs = 0usize;
    if valid & msg_attr_flag::SECURITY != 0 {
        structs += size_of::<AlpcSecurityAttr>();
    }
    if valid & msg_attr_flag::VIEW != 0 {
        structs += size_of::<AlpcDataViewAttr>();
    }
    if valid & msg_attr_flag::CONTEXT != 0 {
        structs += size_of::<AlpcContextAttr>();
    }
    if valid & msg_attr_flag::HANDLE != 0 {
        structs += size_of::<AlpcHandleAttr>();
    }
    if valid & msg_attr_flag::TOKEN != 0 {
        structs += size_of::<AlpcTokenAttr>();
    }
    (valid, attrs, size_of::<AlpcMessageAttributes>() + structs)
}

/// The `ValidAttributes` bitmask a set of core-neutral [`MessageAttrs`] projects
/// to for an ALPC receiver. An empty set (an LPC-originated message) → 0.
pub fn project_valid_attributes(attrs: &MessageAttrs) -> u32 {
    let mut v = 0u32;
    if attrs.security.is_some() {
        v |= msg_attr_flag::SECURITY;
    }
    if attrs.view.is_some() {
        v |= msg_attr_flag::VIEW;
    }
    if attrs.context.is_some() {
        v |= msg_attr_flag::CONTEXT;
    }
    if !attrs.handles.is_empty() {
        v |= msg_attr_flag::HANDLE;
    }
    if attrs.token.is_some() {
        v |= msg_attr_flag::TOKEN;
    }
    v
}

/// True if these attributes would be **degraded** (silently dropped) crossing to
/// an LPC peer — i.e. any non-bridging attribute is present.
pub fn degrades_to_lpc(attrs: &MessageAttrs) -> bool {
    attrs.has_non_bridging()
}

// --- decode helpers (all bounds-checked; never panic) ----------------------

fn read_req<T: Pod>(buf: &[u8]) -> Result<T, NtStatus> {
    let slice = buf
        .get(0..size_of::<T>())
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    bytemuck::try_pod_read_unaligned(slice).map_err(|_| NtStatus::INVALID_PARAMETER)
}

fn read_at<T: Pod>(buf: &[u8], off: usize) -> Option<T> {
    let slice = buf.get(off..off.checked_add(size_of::<T>())?)?;
    bytemuck::try_pod_read_unaligned(slice).ok()
}

fn read_name(buf: &[u8], offset: u32, len_bytes: u32) -> Result<Vec<u16>, NtStatus> {
    let bytes = read_blob(buf, offset, len_bytes)?;
    if bytes.len() % 2 != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect())
}

fn read_blob(buf: &[u8], offset: u32, len_bytes: u32) -> Result<&[u8], NtStatus> {
    if len_bytes == 0 {
        return Ok(&[]);
    }
    let start = offset as usize;
    let end = start
        .checked_add(len_bytes as usize)
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    buf.get(start..end).ok_or(NtStatus::INVALID_PARAMETER)
}

/// The `PORT_MESSAGE.Type` at offset 4 of a framed message (0 if too short).
fn read_msg_type(bytes: &[u8]) -> u16 {
    match bytes.get(4..6) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}

fn reply(status: NtStatus, information: u32, detail0: u64, detail1: u64) -> AlpcReply {
    AlpcReply {
        status: status.raw(),
        information,
        detail0,
        detail1,
    }
}

fn ok() -> AlpcReply {
    reply(NtStatus::SUCCESS, 0, 0, 0)
}

#[cfg(test)]
mod tests;
