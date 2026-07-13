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

use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::Pod;
use nt_alpc_abi::{
    msg_attr_flag, opcode, AlpcAcceptConnectRequest, AlpcConnectPortRequest,
    AlpcContextAttr, AlpcCreatePortRequest, AlpcCreatePortSectionRequest,
    AlpcCreateSectionViewRequest, AlpcDataViewAttr, AlpcHandleAttr, AlpcHandleRequest, AlpcReply,
    AlpcSecurityAttr, AlpcSendReceiveRequest, AlpcTokenAttr, AlpcViewIoRequest,
};
use nt_port_core::{
    ConnectOutcome, DataView, MessageAttrs, PortApi, PortCore, QueuedMessage, ReceiveOutcome,
};
use nt_status::NtStatus;

/// Base for allocated ALPC section handles (ASCII `"AS"` — distinct from the
/// core's `"LP"` port-handle range).
const ALPC_SECTION_BASE: u64 = 0x0000_4153_0000_0001;

/// Upper bound on a port section's backing store, so a malformed/hostile
/// `SectionSize` can't grow the broker's memory without bound. 8 MiB comfortably
/// covers the WOW64 large-transfer path (real ALPC caps a section at
/// `MaximumViewSize`, typically well under this).
const MAX_SECTION_SIZE: u64 = 8 * 1024 * 1024;

/// A port section: the REAL shared-memory region both endpoints map. `backing` is
/// the actual bytes — every view of this section aliases it, so a write through
/// one endpoint's view is visible through the other's (the "not a copy" proof).
/// In a live two-VSpace deployment the broker additionally `copy_cap`+`page_map`s
/// these frames into each endpoint's address space (the CSR-anonymous-section
/// machinery); with the synthetic single-address-space endpoints exercised here
/// the shared `backing` IS that region.
struct PortSection {
    handle: u64,
    port_handle: u64,
    size: u64,
    backing: Vec<u8>,
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

/// The ALPC service: the `NtAlpc*` ABI adapter. It borrows a shared
/// [`PortCore`]; it owns only ALPC-specific state (port sections + views).
#[derive(Default)]
pub struct AlpcServer {
    sections: Vec<PortSection>,
    views: Vec<SectionView>,
    next_section: u64,
    next_view_base: u64,
}

impl AlpcServer {
    /// A new ALPC adapter with no sections/views.
    pub fn new() -> Self {
        Self {
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
            opcode::ALPC_OP_CONNECT_PORT => self.op_connect_port(core, in_buf),
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
        let name = read_name(buf, req.name_offset, req.name_len_bytes)?;
        let handle = core.create_port(&name, PortApi::Alpc);
        Ok(reply(NtStatus::SUCCESS, 0, handle, 0))
    }

    fn op_connect_port(&mut self, core: &mut PortCore, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcConnectPortRequest = read_req(buf)?;
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

    /// ALPC accept folds complete: on accept the connection is driven all the way
    /// to Connected in one call. `detail0` = server comm-port handle, `detail1` =
    /// client comm-port handle (to unblock the connector).
    fn op_accept_connect(&mut self, core: &mut PortCore, buf: &[u8]) -> Result<AlpcReply, NtStatus> {
        let req: AlpcAcceptConnectRequest = read_req(buf)?;
        let accept = req.accept != 0;
        let sh = core.accept(req.connection_id, accept, req.port_context)?;
        if !accept {
            return Ok(reply(NtStatus::SUCCESS, 0, 0, req.connection_id));
        }
        let (client_handle, _) = core.complete(req.connection_id)?;
        Ok(reply(NtStatus::SUCCESS, 0, sh, client_handle))
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

        // Send half (skipped for a pure receive op or a zero-length send).
        if op == opcode::ALPC_OP_SEND_RECEIVE && req.message_len_bytes != 0 {
            let msg = read_blob(buf, req.message_offset, req.message_len_bytes)?;
            let attr_blob = read_blob(buf, req.attr_offset, req.attr_len_bytes)?;
            let attrs = parse_attrs(req.valid_attributes, attr_blob);
            core.send_message(req.port_handle, msg, attrs)?;
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
            // detail0 = connection id (feed to accept), detail1 = CONNECTION_REQUEST.
            return Ok(reply(NtStatus::SUCCESS, 0, connection_id, msg_type as u64));
        }
        // A valid listen port with nothing pending must park, not error.
        let is_listen_port = conn_try.is_ok();
        match core.receive_message(req.port_handle) {
            Ok(Some(QueuedMessage { bytes, attrs })) => {
                let n = bytes.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&bytes[..n]);
                // Project the neutral attrs into the ALPC valid-attributes view.
                // Non-bridging attrs from an ALPC peer are surfaced; an LPC peer
                // carried none, so valid == 0 (the LPC → ALPC degradation).
                let valid = project_valid_attributes(&attrs);
                let msg_type = read_msg_type(&bytes);
                Ok(reply(NtStatus::SUCCESS, n as u32, valid as u64, msg_type as u64))
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
        core.disconnect(req.handle);
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
        // Allocate the REAL backing store — the shared region views will alias.
        self.sections.push(PortSection {
            handle,
            port_handle: req.port_handle,
            size: req.section_size,
            backing: alloc::vec![0u8; req.section_size as usize],
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
        let end = start + data.len();
        section
            .backing
            .get_mut(start..end)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .copy_from_slice(data);
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
        let (section_handle, section_offset) = self.resolve_view(req.view_base, req.view_offset, len)?;
        let section = self
            .sections
            .iter()
            .find(|s| s.handle == section_handle)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let start = section_offset as usize;
        let end = start + len as usize;
        let src = section
            .backing
            .get(start..end)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let n = src.len().min(out_buf.len());
        out_buf[..n].copy_from_slice(&src[..n]);
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
