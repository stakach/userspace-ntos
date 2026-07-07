//! Ergonomic client for the NT Configuration Manager (registry) service ABI.
//!
//! Encodes each call into the [`nt_config_abi`] wire form, hands it to a pluggable
//! [`Backend`] (SURT rings on the kernel; in-process in tests), and decodes the
//! [`CmReply`]. Mirrors `nt-object-client`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use nt_config_abi::{opcode, CmKeyRequest, CmReply, CmValueRequest};

/// A pluggable transport: send `opcode` + `in_buf`, receive a `CmReply` (+ optional
/// `out_buf` for future variable-length replies).
pub trait Backend {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply;
}

const STATUS_SUCCESS: i32 = 0;

fn utf16_bytes(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

/// The ergonomic Configuration Manager client.
pub struct ConfigClient<B> {
    backend: B,
}

impl<B: Backend> ConfigClient<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn ping(&mut self) -> bool {
        self.backend.call(opcode::CM_OP_PING, &[], &mut []).status == STATUS_SUCCESS
    }

    /// Create (or get) a key by full path. `Ok(key_id)`.
    pub fn create_key(&mut self, path: &str) -> Result<u64, i32> {
        let r = self.key_op(opcode::CM_OP_CREATE_KEY, path);
        if r.status == STATUS_SUCCESS {
            Ok(r.detail0)
        } else {
            Err(r.status)
        }
    }

    /// Whether a key exists at `path`.
    pub fn open_key(&mut self, path: &str) -> bool {
        self.key_op(opcode::CM_OP_OPEN_KEY, path).status == STATUS_SUCCESS
    }

    /// Set a DWORD value on a key (created if absent).
    pub fn set_dword(&mut self, key_path: &str, name: &str, value: u32) -> Result<(), i32> {
        let r = self.value_op(opcode::CM_OP_SET_DWORD, key_path, name, value);
        if r.status == STATUS_SUCCESS {
            Ok(())
        } else {
            Err(r.status)
        }
    }

    /// Query a DWORD value.
    pub fn query_dword(&mut self, key_path: &str, name: &str) -> Result<u32, i32> {
        let r = self.value_op(opcode::CM_OP_QUERY_DWORD, key_path, name, 0);
        if r.status == STATUS_SUCCESS {
            Ok(r.detail0 as u32)
        } else {
            Err(r.status)
        }
    }

    fn key_op(&mut self, op: u16, path: &str) -> CmReply {
        let path_bytes = utf16_bytes(path);
        let hdr = CmKeyRequest {
            abi_size: core::mem::size_of::<CmKeyRequest>() as u16,
            _pad: 0,
            path_offset: core::mem::size_of::<CmKeyRequest>() as u32,
            path_len_bytes: path_bytes.len() as u32,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(hdr.as_bytes());
        buf.extend_from_slice(&path_bytes);
        self.backend.call(op, &buf, &mut [])
    }

    fn value_op(&mut self, op: u16, key_path: &str, name: &str, dword: u32) -> CmReply {
        let key_bytes = utf16_bytes(key_path);
        let name_bytes = utf16_bytes(name);
        let base = core::mem::size_of::<CmValueRequest>() as u32;
        let hdr = CmValueRequest {
            abi_size: base as u16,
            _pad: 0,
            dword,
            key_offset: base,
            key_len_bytes: key_bytes.len() as u32,
            name_offset: base + key_bytes.len() as u32,
            name_len_bytes: name_bytes.len() as u32,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(hdr.as_bytes());
        buf.extend_from_slice(&key_bytes);
        buf.extend_from_slice(&name_bytes);
        self.backend.call(op, &buf, &mut [])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_config_server::CmServer;

    /// In-process backend: dispatch straight into the server (no ring).
    struct Direct {
        server: CmServer,
    }
    impl Backend for Direct {
        fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
            self.server.dispatch(opcode, in_buf, out_buf)
        }
    }

    fn client() -> ConfigClient<Direct> {
        ConfigClient::new(Direct {
            server: CmServer::new(),
        })
    }

    #[test]
    fn ping() {
        assert!(client().ping());
    }

    #[test]
    fn create_set_query_dword_roundtrip() {
        let mut c = client();
        let k = r"\Registry\Machine\System\CurrentControlSet\Services\Demo";
        assert!(c.create_key(k).is_ok());
        assert!(c.open_key(k));
        assert!(c.set_dword(k, "Start", 3).is_ok());
        assert_eq!(c.query_dword(k, "Start"), Ok(3));
        // set_dword auto-creates the key.
        let k2 = r"\Registry\Machine\Software\Demo2";
        assert!(c.set_dword(k2, "Answer", 42).is_ok());
        assert_eq!(c.query_dword(k2, "Answer"), Ok(42));
    }

    #[test]
    fn missing_key_and_value() {
        let mut c = client();
        assert!(!c.open_key(r"\Registry\Machine\Nope"));
        assert!(c.query_dword(r"\Registry\Machine\Nope", "X").is_err());
        c.create_key(r"\Registry\Machine\Empty").unwrap();
        assert!(c.query_dword(r"\Registry\Machine\Empty", "Missing").is_err());
    }
}
