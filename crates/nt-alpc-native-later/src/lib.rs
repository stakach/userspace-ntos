//! Owned native ALPC ingress for calls that may block after a port-service effect.
//!
//! This module copies caller memory and models request/Reply ownership. It does not
//! submit to the port service; the native executive must authenticate the physical
//! caller, park the Reply, and bind a checked completion before using these values.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;
use nt_alpc_abi::{
    AlpcAcceptConnectCheckedRequest, AlpcAcceptConnectRequest, AlpcCheckedInvocation,
    AlpcConnectPortAuthorizedRequest, AlpcConnectPortCheckedRequest,
    AlpcConnectPortRequest, AlpcPortAttributes,
    AlpcSendReceiveCheckedRequest, AlpcSendReceiveRequest,
};

pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const MAX_MESSAGE: usize = 65_536;
const HEADER_SIZE: usize = 40;
const MAX_NAME_BYTES: usize = 2048;
const CONTEXT_ATTR: u32 = 0x2000_0000;

#[derive(Debug, PartialEq, Eq)]
pub struct CapturedAttributes {
    pub allocated: u32,
    pub valid: u32,
    /// Attribute structures in native fixed order, without the eight-byte header.
    pub bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReceiveTarget {
    pub message: u64,
    pub capacity: usize,
    pub size_pointer: u64,
    /// Destination and allocation mask captured before the service effect.
    pub attributes: Option<(u64, u32)>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CapturedSendWaitReceive {
    pub port: u64,
    pub flags: u32,
    pub send_message: Option<Vec<u8>>,
    pub send_attributes: Option<CapturedAttributes>,
    pub receive: Option<ReceiveTarget>,
    pub timeout: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CapturedConnectPort {
    pub output: u64,
    pub name: Vec<u16>,
    pub connect_flags: u32,
    pub port_attributes: Option<[u8; 72]>,
    pub message: Option<Vec<u8>>,
    /// Original writable message, its capacity, and the size field. The
    /// message bytes above are copied input and never reread after submission.
    pub message_target: Option<(u64, usize, u64)>,
    pub send_attributes: Option<CapturedAttributes>,
    pub timeout: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CapturedAcceptConnect {
    pub output: u64,
    pub listen_port: u64,
    pub connection_id: u32,
    pub port_context: u64,
    pub accept: bool,
    /// Complete copied connection-request message, retained across acceptance.
    pub message: Vec<u8>,
}

fn invocation(caller: NativeCaller, token: (u64, u64)) -> Result<AlpcCheckedInvocation, u32> {
    if caller.process == 0 || caller.thread == 0 || caller.generation == 0
        || caller.badge == 0 || caller.tcb == 0 || token == (0, 0)
    { return Err(STATUS_INVALID_PARAMETER); }
    Ok(AlpcCheckedInvocation {
        owner_process: caller.process,
        owner_thread: caller.thread,
        owner_generation: caller.generation,
        invocation_hi: token.0,
        invocation_lo: token.1,
    })
}

fn checked_bytes<T: bytemuck::Pod>(header: &T, blobs: &[&[u8]]) -> Result<Vec<u8>, u32> {
    let total = blobs.iter().try_fold(size_of::<T>(), |sum, blob| sum.checked_add(blob.len()))
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let mut wire = Vec::new();
    wire.try_reserve_exact(total).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    wire.extend_from_slice(bytemuck::bytes_of(header));
    for blob in blobs { wire.extend_from_slice(blob); }
    Ok(wire)
}

fn u32_len(len: usize) -> Result<u32, u32> { u32::try_from(len).map_err(|_| STATUS_INVALID_PARAMETER) }

impl CapturedSendWaitReceive {
    /// Copy-ready service request. Submission still requires retained Reply and
    /// service-side token reservation before its first possible effect.
    pub fn checked_wire(&self, caller: NativeCaller, token: (u64, u64)) -> Result<Vec<u8>, u32> {
        let invocation = invocation(caller, token)?;
        let send = self.send_message.as_deref().unwrap_or(&[]);
        let attrs = self.send_attributes.as_ref().map_or(&[][..], |a| a.bytes.as_slice());
        let base = size_of::<AlpcSendReceiveCheckedRequest>();
        let attr_offset = base.checked_add(send.len()).ok_or(STATUS_INVALID_PARAMETER)?;
        let header = AlpcSendReceiveCheckedRequest {
            send_receive: AlpcSendReceiveRequest {
                abi_size: u16::try_from(base).map_err(|_| STATUS_INVALID_PARAMETER)?,
                flags: self.flags | if self.receive.as_ref().is_some_and(|target| target.attributes.is_some()) {
                    nt_alpc_abi::send_flag::RECV_ATTRIBUTES
                } else { 0 },
                port_handle: self.port,
                message_offset: if send.is_empty() { 0 } else { u32_len(base)? },
                message_len_bytes: u32_len(send.len())?,
                valid_attributes: self.receive.as_ref()
                    .and_then(|target| target.attributes.map(|(_, allocated)| allocated))
                    .unwrap_or_else(|| self.send_attributes.as_ref().map_or(0, |a| a.valid)),
                attr_offset: if attrs.is_empty() { 0 } else { u32_len(attr_offset)? },
                attr_len_bytes: u32_len(attrs.len())?,
                ..Default::default()
            },
            invocation,
        };
        checked_bytes(&header, &[send, attrs])
    }
}

impl CapturedConnectPort {
    pub fn checked_wire(&self, caller: NativeCaller, token: (u64, u64)) -> Result<Vec<u8>, u32> {
        self.checked_wire_for(caller, token, None)
    }

    pub fn checked_wire_authorized(&self, caller: NativeCaller, token: (u64, u64),
        target_listen_handle: u64) -> Result<Vec<u8>, u32> {
        if target_listen_handle == 0 { return Err(STATUS_INVALID_PARAMETER); }
        self.checked_wire_for(caller, token, Some(target_listen_handle))
    }

    fn checked_wire_for(&self, caller: NativeCaller, token: (u64, u64),
        target_listen_handle: Option<u64>) -> Result<Vec<u8>, u32> {
        let invocation = invocation(caller, token)?;
        let base = if target_listen_handle.is_some() {
            size_of::<AlpcConnectPortAuthorizedRequest>()
        } else {
            size_of::<AlpcConnectPortCheckedRequest>()
        };
        let mut name = Vec::new();
        name.try_reserve_exact(self.name.len().checked_mul(2).ok_or(STATUS_INVALID_PARAMETER)?)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for unit in &self.name { name.extend_from_slice(&unit.to_le_bytes()); }
        let message = self.message.as_deref().unwrap_or(&[]);
        let attrs = self.send_attributes.as_ref().map_or(&[][..], |a| a.bytes.as_slice());
        let message_offset = base.checked_add(name.len()).ok_or(STATUS_INVALID_PARAMETER)?;
        let attr_offset = message_offset.checked_add(message.len()).ok_or(STATUS_INVALID_PARAMETER)?;
        let port_attributes = self.port_attributes.map(|bytes| bytemuck::pod_read_unaligned::<AlpcPortAttributes>(&bytes));
        let header = AlpcConnectPortCheckedRequest {
            connect: AlpcConnectPortRequest {
                abi_size: u16::try_from(base).map_err(|_| STATUS_INVALID_PARAMETER)?,
                connect_flags: self.connect_flags,
                name_offset: u32_len(base)?,
                name_len_bytes: u32_len(name.len())?,
                message_offset: if message.is_empty() { 0 } else { u32_len(message_offset)? },
                message_len_bytes: u32_len(message.len())?,
                valid_attributes: self.send_attributes.as_ref().map_or(0, |a| a.valid),
                attr_offset: if attrs.is_empty() { 0 } else { u32_len(attr_offset)? },
                attr_len_bytes: u32_len(attrs.len())?,
                ..Default::default()
            },
            invocation,
            port_attributes: port_attributes.unwrap_or_default(),
            has_port_attributes: u32::from(port_attributes.is_some()),
            _reserved: 0,
        };
        match target_listen_handle {
            Some(target_listen_handle) => checked_bytes(&AlpcConnectPortAuthorizedRequest {
                checked: header, target_listen_handle, access_granted: 1, _reserved: 0,
            }, &[&name, message, attrs]),
            None => checked_bytes(&header, &[&name, message, attrs]),
        }
    }
}

impl CapturedAcceptConnect {
    pub fn checked_wire(&self, caller: NativeCaller, token: (u64, u64)) -> Result<Vec<u8>, u32> {
        let base = size_of::<AlpcAcceptConnectCheckedRequest>();
        let header = AlpcAcceptConnectCheckedRequest {
            accept: AlpcAcceptConnectRequest {
                abi_size: base as u16,
                accept: u16::from(self.accept),
                connection_id: self.connection_id as u64,
                port_context: self.port_context,
                ..Default::default()
            },
            invocation: invocation(caller, token)?,
            listen_port: self.listen_port,
            message_offset: if self.message.is_empty() { 0 } else { u32_len(base)? },
            message_len_bytes: u32_len(self.message.len())?,
        };
        checked_bytes(&header, &[&self.message])
    }
}

fn copy_bounded(
    pointer: u64, len: usize, max: usize, read: &mut impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<Vec<u8>, u32> {
    if pointer == 0 || len > max { return Err(STATUS_INVALID_PARAMETER); }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    bytes.resize(len, 0);
    if !read(pointer, &mut bytes) { return Err(STATUS_ACCESS_VIOLATION); }
    Ok(bytes)
}

fn copy_message(pointer: u64, read: &mut impl FnMut(u64, &mut [u8]) -> bool) -> Result<Vec<u8>, u32> {
    let mut header = [0u8; HEADER_SIZE];
    if !read(pointer, &mut header) { return Err(STATUS_ACCESS_VIOLATION); }
    let data = u16::from_le_bytes(header[..2].try_into().unwrap()) as usize;
    let total = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
    if total < HEADER_SIZE || total > MAX_MESSAGE || data != total - HEADER_SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    copy_bounded(pointer, total, MAX_MESSAGE, read)
}

fn copy_attributes(pointer: u64, read: &mut impl FnMut(u64, &mut [u8]) -> bool)
    -> Result<CapturedAttributes, u32>
{
    let mut header = [0u8; 8];
    if !read(pointer, &mut header) { return Err(STATUS_ACCESS_VIOLATION); }
    let allocated = u32::from_le_bytes(header[..4].try_into().unwrap());
    let valid = u32::from_le_bytes(header[4..8].try_into().unwrap());
    if valid & !allocated != 0 { return Err(STATUS_INVALID_PARAMETER); }
    // The later adapter has only a context transfer contract. Security, handle,
    // view, and token attributes need their own object/capability policy.
    if allocated & !CONTEXT_ATTR != 0 { return Err(STATUS_NOT_SUPPORTED); }
    let len = if allocated == CONTEXT_ATTR { 32 } else { 0 };
    let bytes = if len == 0 { Vec::new() } else {
        copy_bounded(pointer.checked_add(8).ok_or(STATUS_INVALID_PARAMETER)?, len, 32, read)?
    };
    Ok(CapturedAttributes { allocated, valid, bytes })
}

fn copy_timeout(pointer: u64, read: &mut impl FnMut(u64, &mut [u8]) -> bool) -> Result<Option<i64>, u32> {
    if pointer == 0 { return Ok(None); }
    let mut bytes = [0u8; 8];
    if !read(pointer, &mut bytes) { return Err(STATUS_ACCESS_VIOLATION); }
    Ok(Some(i64::from_le_bytes(bytes)))
}

/// Capture all native input before an ALPC send/wait/receive effect. Output
/// addresses are only probed here and must be probed again at copyout.
pub fn capture_send_wait_receive(
    args: [u64; 8],
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
    mut probe_output: impl FnMut(u64, usize) -> bool,
) -> Result<CapturedSendWaitReceive, u32> {
    let [port, flags, send, send_attrs, receive, receive_size, receive_attrs, timeout] = args;
    if port == 0 || flags & !u64::from(nt_alpc_abi::send_flag::REPLY_MESSAGE) != 0
        || (flags != 0 && send == 0) || (send == 0 && send_attrs != 0)
        || (receive == 0) != (receive_size == 0)
        || (receive == 0 && receive_attrs != 0)
    { return Err(STATUS_INVALID_PARAMETER); }
    let send_message = if send == 0 { None } else { Some(copy_message(send, &mut read)?) };
    let send_attributes = if send_attrs == 0 { None } else { Some(copy_attributes(send_attrs, &mut read)?) };
    let receive = if receive == 0 { None } else {
        let mut size = [0u8; 8];
        if !read(receive_size, &mut size) { return Err(STATUS_ACCESS_VIOLATION); }
        let capacity = usize::try_from(u64::from_le_bytes(size)).map_err(|_| STATUS_INVALID_PARAMETER)?;
        if !(HEADER_SIZE..=MAX_MESSAGE).contains(&capacity) { return Err(STATUS_INVALID_PARAMETER); }
        if !probe_output(receive, capacity) || !probe_output(receive_size, 8) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let attributes = if receive_attrs == 0 { None } else {
            let mut header = [0u8; 8];
            if !read(receive_attrs, &mut header) { return Err(STATUS_ACCESS_VIOLATION); }
            let allocated = u32::from_le_bytes(header[..4].try_into().unwrap());
            let valid = u32::from_le_bytes(header[4..8].try_into().unwrap());
            if valid & !allocated != 0 { return Err(STATUS_INVALID_PARAMETER); }
            if allocated != CONTEXT_ATTR { return Err(STATUS_NOT_SUPPORTED); }
            if !probe_output(receive_attrs, 8 + 32) { return Err(STATUS_ACCESS_VIOLATION); }
            Some((receive_attrs, allocated))
        };
        Some(ReceiveTarget { message: receive, capacity, size_pointer: receive_size, attributes })
    };
    Ok(CapturedSendWaitReceive { port, flags: flags as u32, send_message, send_attributes,
        receive, timeout: copy_timeout(timeout, &mut read)? })
}

/// Native `NtAlpcConnectPort` input capture. Unsupported security and receive
/// attributes fail before any service submission.
pub fn capture_connect_port(
    args: [u64; 11],
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
    mut probe_output: impl FnMut(u64, usize) -> bool,
) -> Result<CapturedConnectPort, u32> {
    let [output, name_pointer, object_attributes, attributes, flags, server_sid,
        message_pointer, message_size, send_attrs, receive_attrs, timeout] = args;
    if output == 0 || !probe_output(output, 8) { return Err(STATUS_ACCESS_VIOLATION); }
    if object_attributes != 0 || server_sid != 0 || receive_attrs != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    if flags & !u64::from(nt_alpc_abi::connect_flag::SYNC_CONNECTION) != 0
        || name_pointer == 0 || (message_pointer == 0) != (message_size == 0)
        || (message_pointer == 0 && send_attrs != 0)
    { return Err(STATUS_INVALID_PARAMETER); }
    let mut unicode = [0u8; 16];
    if !read(name_pointer, &mut unicode) { return Err(STATUS_ACCESS_VIOLATION); }
    let len = u16::from_le_bytes(unicode[..2].try_into().unwrap()) as usize;
    let maximum = u16::from_le_bytes(unicode[2..4].try_into().unwrap()) as usize;
    let pointer = u64::from_le_bytes(unicode[8..16].try_into().unwrap());
    if len == 0 || len & 1 != 0 || len > maximum || len > MAX_NAME_BYTES {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let name_bytes = copy_bounded(pointer, len, MAX_NAME_BYTES, &mut read)?;
    let name = name_bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    let port_attributes = if attributes == 0 { None } else {
        let mut copied = [0u8; 72];
        if !read(attributes, &mut copied) { return Err(STATUS_ACCESS_VIOLATION); }
        Some(copied)
    };
    let (message, message_target) = if message_pointer == 0 { (None, None) } else {
        let mut size = [0u8; 8];
        if !read(message_size, &mut size) { return Err(STATUS_ACCESS_VIOLATION); }
        let capacity = usize::try_from(u64::from_le_bytes(size)).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let copied = copy_message(message_pointer, &mut read)?;
        if capacity < copied.len() { return Err(STATUS_INVALID_PARAMETER); }
        if !probe_output(message_pointer, capacity) || !probe_output(message_size, 8) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        (Some(copied), Some((message_pointer, capacity, message_size)))
    };
    let send_attributes = if send_attrs == 0 { None } else { Some(copy_attributes(send_attrs, &mut read)?) };
    Ok(CapturedConnectPort { output, name, connect_flags: flags as u32,
        port_attributes, message, message_target, send_attributes,
        timeout: copy_timeout(timeout, &mut read)? })
}

/// Native `NtAlpcAcceptConnectPort` capture. `MessageId` is the service's
/// connection ID only after a checked receive binds that native message to it.
pub fn capture_accept_connect(
    args: [u64; 9],
    // Connection ID from a checked receive on this authenticated listen port.
    expected_connection_id: u32,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
    mut probe_output: impl FnMut(u64, usize) -> bool,
) -> Result<CapturedAcceptConnect, u32> {
    let [output, listen_port, flags, object_attrs, port_attrs, context, message, message_attrs, accept] = args;
    if output == 0 || !probe_output(output, 8) { return Err(STATUS_ACCESS_VIOLATION); }
    if listen_port == 0 || message == 0 || accept > 1 || flags != 0 { return Err(STATUS_INVALID_PARAMETER); }
    if object_attrs != 0 || port_attrs != 0 || message_attrs != 0 { return Err(STATUS_NOT_SUPPORTED); }
    let copied = copy_message(message, &mut read)?;
    if u16::from_le_bytes(copied[4..6].try_into().unwrap()) != 10 { return Err(STATUS_INVALID_PARAMETER); }
    let connection_id = u32::from_le_bytes(copied[24..28].try_into().unwrap());
    if connection_id == 0 || connection_id != expected_connection_id {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(CapturedAcceptConnect { output, listen_port, connection_id, port_context: context,
        accept: accept != 0, message: copied })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaller {
    pub process: u64,
    pub thread: u64,
    pub generation: u64,
    pub badge: u64,
    pub tcb: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedError { InvalidIdentity, WrongCaller, WrongRequest, WrongPhase }

#[derive(Debug, Eq, PartialEq)]
pub struct TerminalLater {
    pub status: i32,
    pub information: u32,
    pub detail0: u64,
    pub detail1: u64,
    /// Copied CQE data, kept until native copyout and Reply acknowledgement.
    pub output: Vec<u8>,
    pub service_effect_possible: bool,
}

impl TerminalLater {
    pub fn service(status: i32, information: u32, detail0: u64, detail1: u64, output: Vec<u8>) -> Self {
        Self { status, information, detail0, detail1, output, service_effect_possible: true }
    }
    fn no_effect(status: i32) -> Self {
        Self { status, information: 0, detail0: 0, detail1: 0,
            output: Vec::new(), service_effect_possible: false }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Phase { Prepared, Submitted(u64), Terminal { request_id: u64, result: TerminalLater } }

/// Owns the original physical caller, Reply capability and full wire bytes
/// across blocked receives, timeouts, uncertain effects, and failed Reply sends.
#[must_use = "retain the Reply and wire request until exact completion and reply acknowledgement"]
pub struct RetainedLater {
    caller: NativeCaller,
    token: (u64, u64),
    reply_cap: u64,
    request: Vec<u8>,
    phase: Phase,
    reply_attempted: bool,
}

impl RetainedLater {
    pub fn new(caller: NativeCaller, token: (u64, u64), reply_cap: u64, request: Vec<u8>)
        -> Result<Self, RetainedError>
    {
        if caller.process == 0 || caller.thread == 0 || caller.generation == 0
            || caller.badge == 0 || caller.tcb == 0 || token == (0, 0)
            || reply_cap == 0 || request.is_empty()
        { return Err(RetainedError::InvalidIdentity); }
        Ok(Self { caller, token, reply_cap, request, phase: Phase::Prepared,
            reply_attempted: false })
    }
    pub fn caller(&self) -> NativeCaller { self.caller }
    pub fn token(&self) -> (u64, u64) { self.token }
    pub fn reply_cap(&self) -> u64 { self.reply_cap }
    pub fn request(&self) -> &[u8] { &self.request }
    pub fn terminal(&self) -> Option<&TerminalLater> {
        if let Phase::Terminal { result, .. } = &self.phase { Some(result) } else { None }
    }
    pub fn begin(&mut self, request_id: u64) -> Result<(), RetainedError> {
        if request_id == 0 { return Err(RetainedError::InvalidIdentity); }
        if !matches!(&self.phase, Phase::Prepared) { return Err(RetainedError::WrongPhase); }
        self.phase = Phase::Submitted(request_id);
        Ok(())
    }
    pub fn observe(&self, request_id: u64, caller: NativeCaller) -> Result<Option<&TerminalLater>, RetainedError> {
        if caller != self.caller { return Err(RetainedError::WrongCaller); }
        match &self.phase {
            Phase::Submitted(id) if *id == request_id => Ok(None),
            Phase::Submitted(_) => Err(RetainedError::WrongRequest),
            Phase::Terminal { request_id: id, result } if *id == request_id => Ok(Some(result)),
            Phase::Terminal { .. } => Err(RetainedError::WrongRequest),
            Phase::Prepared => Err(RetainedError::WrongPhase),
        }
    }
    pub fn complete(&mut self, request_id: u64, caller: NativeCaller, result: TerminalLater)
        -> Result<(), RetainedError>
    {
        if self.observe(request_id, caller)?.is_some() { return Err(RetainedError::WrongPhase); }
        self.phase = Phase::Terminal { request_id, result };
        Ok(())
    }
    /// An exact STATUS_PENDING CQE consumed this SQE but did not complete the
    /// syscall. The checked service token keeps its send half reserved; the
    /// executive may submit a fresh SQE solely to poll the same receive.
    pub fn continue_pending(&mut self, request_id: u64, caller: NativeCaller)
        -> Result<(), RetainedError>
    {
        if caller != self.caller { return Err(RetainedError::WrongCaller); }
        match self.phase {
            Phase::Submitted(id) if id == request_id => {
                self.phase = Phase::Prepared;
                Ok(())
            }
            Phase::Submitted(_) | Phase::Terminal { .. } => Err(RetainedError::WrongRequest),
            Phase::Prepared => Err(RetainedError::WrongPhase),
        }
    }
    pub fn no_effect(&mut self, request_id: u64, caller: NativeCaller, status: i32)
        -> Result<(), RetainedError>
    {
        if status >= 0 { return Err(RetainedError::WrongPhase); }
        self.complete(request_id, caller, TerminalLater::no_effect(status))
    }
    /// Mark the only permitted physical Reply attempt before entering IPC.
    /// A false transport return does not establish that no delivery occurred.
    pub fn begin_reply(&mut self) -> Result<(), RetainedError> {
        if self.reply_attempted || self.terminal().is_none() {
            return Err(RetainedError::WrongPhase);
        }
        self.reply_attempted = true;
        Ok(())
    }
    pub fn finish_after_reply(self, acknowledged: bool) -> Result<(), Self> {
        if acknowledged && self.terminal().is_some() { Ok(()) } else { Err(self) }
    }
}

#[cfg(test)] mod tests;
