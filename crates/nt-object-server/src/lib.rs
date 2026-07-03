//! # `nt-object-server` — the Object Manager service dispatcher
//!
//! The transport-agnostic half of service mode: it owns an [`ObjectManager`] and
//! turns decoded wire requests into object-model calls. A SURT binding (the
//! `object-manager` component) feeds it opcodes + request/response buffers; this
//! crate does **no** transport itself, so it is fully host-testable.
//!
//! Every request is decoded and bounds-checked from raw bytes with
//! `bytemuck::try_pod_read_unaligned` and explicit slice checks — a malformed or
//! truncated request can never panic the server; it returns an error reply.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::Pod;
use nt_object_abi::{
    opcode, ObCloseHandleRequest, ObCreateDirectoryRequest, ObCreateSymbolicLinkRequest,
    ObLookupPathRequest, ObOpenObjectRequest, ObReply,
};
use nt_object_manager::{ClientKind, ObjectManager, ObjectRef};
use nt_status::NtStatus;
use nt_types::{
    AccessMask, AccessMode, CaseSensitivity, ClientId, HandleValue, NtPath, ObjAttrFlags,
    ObjectTypeId, UnicodeString,
};

/// The Object Manager service: an object model plus a wire-request dispatcher.
pub struct Server {
    om: ObjectManager,
}

impl Server {
    /// Create a server with a bootstrapped namespace.
    pub fn new() -> Result<Self, NtStatus> {
        let mut om = ObjectManager::new();
        om.bootstrap_namespace()?;
        Ok(Self { om })
    }

    /// Borrow the underlying object manager (for the hosting component / tests).
    pub fn object_manager(&self) -> &ObjectManager {
        &self.om
    }

    /// A new client connection (the transport calls this when a component
    /// attaches); returns the assigned id.
    pub fn connect(&mut self, kind: ClientKind, mode: AccessMode) -> ClientId {
        self.om.register_client(kind, mode)
    }

    /// A client disconnected or faulted: close all its handles and retire its id.
    pub fn disconnect(&mut self, client: ClientId) -> Result<(), NtStatus> {
        self.om.close_client(client)
    }

    /// Dispatch one request from `client`. `in_buf` holds the typed request
    /// struct (at offset 0) followed by any inline UTF-16 path/name payloads;
    /// `out_buf` receives variable-length results. Always returns a reply — a
    /// bad request yields an error status, never a panic.
    pub fn dispatch(
        &mut self,
        client: ClientId,
        op: u16,
        in_buf: &[u8],
        out_buf: &mut [u8],
    ) -> ObReply {
        match self.try_dispatch(client, op, in_buf, out_buf) {
            Ok(r) => r,
            Err(status) => reply(status, 0, 0, 0),
        }
    }

    fn try_dispatch(
        &mut self,
        client: ClientId,
        op: u16,
        in_buf: &[u8],
        out_buf: &mut [u8],
    ) -> Result<ObReply, NtStatus> {
        match op {
            opcode::OB_OP_PING => Ok(ok()),
            opcode::OB_OP_OPEN_OBJECT => self.op_open(client, in_buf),
            opcode::OB_OP_CLOSE_HANDLE => self.op_close_handle(client, in_buf),
            opcode::OB_OP_LOOKUP_PATH => self.op_lookup(in_buf),
            opcode::OB_OP_CREATE_DIRECTORY => self.op_create_directory(in_buf),
            opcode::OB_OP_CREATE_SYMBOLIC_LINK => self.op_create_symlink(in_buf),
            opcode::OB_OP_QUERY_SYMBOLIC_LINK => self.op_query_symlink(in_buf, out_buf),
            _ => Err(NtStatus::NOT_IMPLEMENTED),
        }
    }

    fn op_open(&mut self, client: ClientId, buf: &[u8]) -> Result<ObReply, NtStatus> {
        let req: ObOpenObjectRequest = read_req(buf)?;
        check_size::<ObOpenObjectRequest>(req.abi_size)?;
        let path = read_path(buf, req.path_offset, req.path_len_bytes)?;
        let obj = self.om.lookup_path(&path, case_of(req.flags))?;
        if let Some(t) = type_of(req.expected_type) {
            if obj.type_id() != t {
                return Err(NtStatus::OBJECT_TYPE_MISMATCH);
            }
        }
        let handle = self.om.open(
            client,
            &obj,
            AccessMask::from_bits_retain(req.desired_access),
            ObjAttrFlags::from_bits_retain(req.flags as u32),
        )?;
        Ok(reply(NtStatus::SUCCESS, 0, handle.0, 0))
    }

    fn op_close_handle(&mut self, client: ClientId, buf: &[u8]) -> Result<ObReply, NtStatus> {
        let req: ObCloseHandleRequest = read_req(buf)?;
        self.om.close_handle(client, HandleValue(req.handle))?;
        Ok(ok())
    }

    fn op_lookup(&mut self, buf: &[u8]) -> Result<ObReply, NtStatus> {
        let req: ObLookupPathRequest = read_req(buf)?;
        let path = read_path(buf, req.path_offset, req.path_len_bytes)?;
        let obj = self.om.lookup_path(&path, case_of(req.flags))?;
        Ok(reply(NtStatus::SUCCESS, 0, obj.id().0, 0))
    }

    fn op_create_directory(&mut self, buf: &[u8]) -> Result<ObReply, NtStatus> {
        let req: ObCreateDirectoryRequest = read_req(buf)?;
        let path = read_path(buf, req.path_offset, req.path_len_bytes)?;
        let (parent, leaf) = self.split_parent(&path)?;
        let permanent = permanent_of(req.obj_attributes);
        let dir = self.om.create_directory(&parent, &leaf, permanent)?;
        Ok(reply(NtStatus::SUCCESS, 0, dir.id().0, 0))
    }

    fn op_create_symlink(&mut self, buf: &[u8]) -> Result<ObReply, NtStatus> {
        let req: ObCreateSymbolicLinkRequest = read_req(buf)?;
        let link_path = read_path(buf, req.link_offset, req.link_len_bytes)?;
        let target = read_path(buf, req.target_offset, req.target_len_bytes)?;
        let (parent, leaf) = self.split_parent(&link_path)?;
        let permanent = permanent_of(req.obj_attributes);
        let link = self
            .om
            .create_symbolic_link(&parent, &leaf, target, permanent)?;
        Ok(reply(NtStatus::SUCCESS, 0, link.id().0, 0))
    }

    fn op_query_symlink(&mut self, buf: &[u8], out_buf: &mut [u8]) -> Result<ObReply, NtStatus> {
        let req: ObLookupPathRequest = read_req(buf)?;
        let path = read_path(buf, req.path_offset, req.path_len_bytes)?;
        let link = self.om.lookup_link(&path, case_of(req.flags))?;
        let target = self.om.query_symbolic_link(&link)?;
        let units = target.to_units();
        let nbytes = units.len() * 2;
        let dst = out_buf
            .get_mut(..nbytes)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        for (i, u) in units.iter().enumerate() {
            dst[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        Ok(reply(NtStatus::SUCCESS, nbytes as u32, 0, 0))
    }

    /// Resolve the parent directory of `path` + return `(parent_ref, leaf_name)`.
    fn split_parent(&self, path: &NtPath) -> Result<(ObjectRef, UnicodeString), NtStatus> {
        let leaf = path.leaf().ok_or(NtStatus::INVALID_PARAMETER)?.clone();
        let parent_path = path.parent().ok_or(NtStatus::INVALID_PARAMETER)?;
        let parent = self
            .om
            .lookup_path(&parent_path, CaseSensitivity::CaseInsensitive)?;
        Ok((parent, leaf))
    }
}

// --- decode helpers (all bounds-checked; never panic) ----------------------

fn read_req<T: Pod>(buf: &[u8]) -> Result<T, NtStatus> {
    let slice = buf
        .get(0..size_of::<T>())
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    bytemuck::try_pod_read_unaligned(slice).map_err(|_| NtStatus::INVALID_PARAMETER)
}

fn read_path(buf: &[u8], offset: u32, len_bytes: u32) -> Result<NtPath, NtStatus> {
    let start = offset as usize;
    let end = start
        .checked_add(len_bytes as usize)
        .ok_or(NtStatus::INVALID_PARAMETER)?;
    let bytes = buf.get(start..end).ok_or(NtStatus::INVALID_PARAMETER)?;
    if bytes.len() % 2 != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    NtPath::parse(&units)
}

fn check_size<T>(abi_size: u16) -> Result<(), NtStatus> {
    if abi_size as usize == size_of::<T>() {
        Ok(())
    } else {
        Err(NtStatus::INVALID_PARAMETER)
    }
}

fn case_of(flags: u16) -> CaseSensitivity {
    if ObjAttrFlags::from_bits_retain(flags as u32).contains(ObjAttrFlags::CASE_INSENSITIVE) {
        CaseSensitivity::CaseInsensitive
    } else {
        CaseSensitivity::CaseSensitive
    }
}

fn permanent_of(obj_attributes: u16) -> bool {
    ObjAttrFlags::from_bits_retain(obj_attributes as u32).contains(ObjAttrFlags::PERMANENT)
}

fn type_of(id: u64) -> Option<ObjectTypeId> {
    if id == 0 {
        None
    } else {
        Some(ObjectTypeId(id as u32))
    }
}

fn reply(status: NtStatus, information: u32, detail0: u64, detail1: u64) -> ObReply {
    ObReply {
        status: status.raw(),
        information,
        detail0,
        detail1,
    }
}

fn ok() -> ObReply {
    reply(NtStatus::SUCCESS, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_ok() {
        let mut s = Server::new().unwrap();
        let c = s.connect(ClientKind::Test, AccessMode::UserMode);
        let r = s.dispatch(c, opcode::OB_OP_PING, &[], &mut []);
        assert_eq!(r.status, NtStatus::SUCCESS.raw());
    }

    #[test]
    fn unknown_opcode_not_implemented() {
        let mut s = Server::new().unwrap();
        let c = s.connect(ClientKind::Test, AccessMode::UserMode);
        let r = s.dispatch(c, 0x2099, &[], &mut []);
        assert_eq!(r.status, NtStatus::NOT_IMPLEMENTED.raw());
    }

    #[test]
    fn malformed_requests_do_not_panic() {
        let mut s = Server::new().unwrap();
        let c = s.connect(ClientKind::Test, AccessMode::UserMode);
        // Truncated open request (too few bytes for the struct).
        let r = s.dispatch(c, opcode::OB_OP_OPEN_OBJECT, &[0u8; 3], &mut []);
        assert_eq!(r.status, NtStatus::INVALID_PARAMETER.raw());
        // Open request whose path offset/len run past the buffer.
        let mut buf = [0u8; size_of::<ObOpenObjectRequest>()];
        let bad = ObOpenObjectRequest {
            abi_size: size_of::<ObOpenObjectRequest>() as u16,
            flags: ObjAttrFlags::CASE_INSENSITIVE.bits() as u16,
            desired_access: 0,
            expected_type: 0,
            path_offset: 1000,
            path_len_bytes: 8,
        };
        buf.copy_from_slice(bytemuck::bytes_of(&bad));
        let r = s.dispatch(c, opcode::OB_OP_OPEN_OBJECT, &buf, &mut []);
        assert_eq!(r.status, NtStatus::INVALID_PARAMETER.raw());
    }
}
