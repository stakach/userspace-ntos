//! # `nt-object-client` — the Object Manager client stub
//!
//! An ergonomic Rust API over the Object Manager service ABI. It encodes each
//! call into an `nt-object-abi` request buffer, sends it through a [`Backend`],
//! and decodes the [`ObReply`]. The backend is pluggable: an in-process
//! `DirectBackend` (calling the server directly, for tests / library mode) or a
//! SURT backend (for a real isolated component). This crate itself depends on
//! neither the server nor SURT.

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::Pod;
use nt_object_abi::{
    opcode, ObCloseHandleRequest, ObCreateDirectoryRequest, ObCreateSymbolicLinkRequest,
    ObLookupPathRequest, ObOpenObjectRequest, ObReply,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, HandleValue, ObjAttrFlags, ObjectId, ObjectTypeId};

/// A transport that carries one request to the Object Manager and returns the
/// reply. `out_buf` receives any variable-length result payload.
pub trait Backend {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> ObReply;
}

/// The Object Manager client.
pub struct ObjectClient<B> {
    backend: B,
}

impl<B: Backend> ObjectClient<B> {
    /// Wrap a transport backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Access the backend (e.g. to reach the server in `DirectBackend`).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Liveness check.
    pub fn ping(&mut self) -> NtStatus {
        NtStatus(self.backend.call(opcode::OB_OP_PING, &[], &mut []).status)
    }

    /// Open an object by path, returning a handle.
    pub fn open(
        &mut self,
        path: &str,
        desired_access: AccessMask,
        expected_type: Option<ObjectTypeId>,
        case_insensitive: bool,
    ) -> Result<HandleValue, NtStatus> {
        let units = utf16(path);
        let req = ObOpenObjectRequest {
            abi_size: size_of::<ObOpenObjectRequest>() as u16,
            flags: case_flag(case_insensitive),
            desired_access: desired_access.bits(),
            expected_type: expected_type.map_or(0, |t| t.0 as u64),
            path_offset: size_of::<ObOpenObjectRequest>() as u32,
            path_len_bytes: byte_len(&units),
        };
        let buf = pack(&req, &units);
        let r = self.backend.call(opcode::OB_OP_OPEN_OBJECT, &buf, &mut []);
        NtStatus(r.status).to_result()?;
        Ok(HandleValue(r.detail0))
    }

    /// Close a handle.
    pub fn close_handle(&mut self, handle: HandleValue) -> Result<(), NtStatus> {
        let req = ObCloseHandleRequest {
            abi_size: size_of::<ObCloseHandleRequest>() as u16,
            _reserved: 0,
            _reserved2: 0,
            handle: handle.0,
        };
        let buf = bytemuck::bytes_of(&req).to_vec();
        let r = self.backend.call(opcode::OB_OP_CLOSE_HANDLE, &buf, &mut []);
        NtStatus(r.status).to_result()
    }

    /// Resolve a path to an object id (no handle opened).
    pub fn lookup(&mut self, path: &str, case_insensitive: bool) -> Result<ObjectId, NtStatus> {
        let units = utf16(path);
        let req = ObLookupPathRequest {
            abi_size: size_of::<ObLookupPathRequest>() as u16,
            flags: case_flag(case_insensitive),
            path_offset: size_of::<ObLookupPathRequest>() as u32,
            path_len_bytes: byte_len(&units),
        };
        let buf = pack(&req, &units);
        let r = self.backend.call(opcode::OB_OP_LOOKUP_PATH, &buf, &mut []);
        NtStatus(r.status).to_result()?;
        Ok(ObjectId(r.detail0))
    }

    /// Create a directory at `path`, returning its object id.
    pub fn create_directory(&mut self, path: &str, permanent: bool) -> Result<ObjectId, NtStatus> {
        let units = utf16(path);
        let req = ObCreateDirectoryRequest {
            abi_size: size_of::<ObCreateDirectoryRequest>() as u16,
            obj_attributes: perm_flag(permanent),
            desired_access: 0,
            path_offset: size_of::<ObCreateDirectoryRequest>() as u32,
            path_len_bytes: byte_len(&units),
        };
        let buf = pack(&req, &units);
        let r = self
            .backend
            .call(opcode::OB_OP_CREATE_DIRECTORY, &buf, &mut []);
        NtStatus(r.status).to_result()?;
        Ok(ObjectId(r.detail0))
    }

    /// Create a symbolic link `link` → `target`.
    pub fn create_symbolic_link(
        &mut self,
        link: &str,
        target: &str,
        permanent: bool,
    ) -> Result<ObjectId, NtStatus> {
        let l = utf16(link);
        let t = utf16(target);
        let hdr = size_of::<ObCreateSymbolicLinkRequest>();
        let req = ObCreateSymbolicLinkRequest {
            abi_size: hdr as u16,
            obj_attributes: perm_flag(permanent),
            desired_access: 0,
            link_offset: hdr as u32,
            link_len_bytes: byte_len(&l),
            target_offset: (hdr + l.len() * 2) as u32,
            target_len_bytes: byte_len(&t),
        };
        let mut buf = bytemuck::bytes_of(&req).to_vec();
        push_units(&mut buf, &l);
        push_units(&mut buf, &t);
        let r = self
            .backend
            .call(opcode::OB_OP_CREATE_SYMBOLIC_LINK, &buf, &mut []);
        NtStatus(r.status).to_result()?;
        Ok(ObjectId(r.detail0))
    }

    /// Query a symbolic link's target (as UTF-16 code units).
    pub fn query_symbolic_link(
        &mut self,
        path: &str,
        case_insensitive: bool,
    ) -> Result<Vec<u16>, NtStatus> {
        let units = utf16(path);
        let req = ObLookupPathRequest {
            abi_size: size_of::<ObLookupPathRequest>() as u16,
            flags: case_flag(case_insensitive),
            path_offset: size_of::<ObLookupPathRequest>() as u32,
            path_len_bytes: byte_len(&units),
        };
        let buf = pack(&req, &units);
        let mut out = vec![0u8; 2048];
        let r = self
            .backend
            .call(opcode::OB_OP_QUERY_SYMBOLIC_LINK, &buf, &mut out);
        NtStatus(r.status).to_result()?;
        let n = r.information as usize;
        let bytes = out.get(..n).ok_or(NtStatus::INVALID_PARAMETER)?;
        Ok(bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect())
    }
}

// --- encode helpers --------------------------------------------------------

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn byte_len(units: &[u16]) -> u32 {
    (units.len() * 2) as u32
}

fn case_flag(case_insensitive: bool) -> u16 {
    if case_insensitive {
        ObjAttrFlags::CASE_INSENSITIVE.bits() as u16
    } else {
        0
    }
}

fn perm_flag(permanent: bool) -> u16 {
    if permanent {
        ObjAttrFlags::PERMANENT.bits() as u16
    } else {
        0
    }
}

fn pack<T: Pod>(req: &T, units: &[u16]) -> Vec<u8> {
    let mut buf = bytemuck::bytes_of(req).to_vec();
    push_units(&mut buf, units);
    buf
}

fn push_units(buf: &mut Vec<u8>, units: &[u16]) {
    for &u in units {
        buf.extend_from_slice(&u.to_le_bytes());
    }
}
