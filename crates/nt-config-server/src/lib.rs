//! Transport-agnostic NT Configuration Manager (registry) service dispatcher.
//!
//! Decodes a wire request ([`nt_config_abi`]) and drives the `nt-config-manager`
//! core, returning a [`CmReply`]. Wrapping the registry authority behind SURT lets
//! it run as an isolated service the executive/PnP/SCM reach over rings. First cut:
//! path-addressed keys + DWORD values (the calls the boot chain needs earliest).

#![no_std]

extern crate alloc;

use alloc::string::String;

use nt_config_abi::{opcode, read_utf16, CmKeyRequest, CmReply, CmValueRequest};
use nt_config_manager::ConfigManager;

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_INVALID_SYSTEM_SERVICE: i32 = 0xC000_001Cu32 as i32;

/// Max UTF-16 units in a decoded key path / value name.
const MAX_NAME_UNITS: usize = 512;

fn reply(status: i32, detail0: u64) -> CmReply {
    CmReply {
        status,
        information: 0,
        detail0,
        detail1: 0,
    }
}

fn decode(buf: &[u8], offset: u32, len_bytes: u32) -> Option<String> {
    let mut units = [0u16; MAX_NAME_UNITS];
    let n = read_utf16(buf, offset, len_bytes, &mut units)?;
    Some(String::from_utf16_lossy(&units[..n]))
}

/// The Configuration Manager service: the registry authority + the wire dispatcher.
pub struct CmServer {
    cm: ConfigManager,
}

impl Default for CmServer {
    fn default() -> Self {
        Self::new()
    }
}

impl CmServer {
    pub fn new() -> Self {
        Self {
            cm: ConfigManager::new(),
        }
    }

    /// Direct access to the registry authority (for seeding hives at boot).
    pub fn config_mut(&mut self) -> &mut ConfigManager {
        &mut self.cm
    }

    /// Decode + dispatch one wire request. `out_buf` is reserved for variable-length
    /// replies (none yet — DWORD results ride in `detail0`).
    pub fn dispatch(&mut self, opcode: u16, in_buf: &[u8], _out_buf: &mut [u8]) -> CmReply {
        match opcode {
            opcode::CM_OP_PING => reply(STATUS_SUCCESS, 0),
            opcode::CM_OP_CREATE_KEY => self.op_create_key(in_buf),
            opcode::CM_OP_OPEN_KEY => self.op_open_key(in_buf),
            opcode::CM_OP_SET_DWORD => self.op_set_dword(in_buf),
            opcode::CM_OP_QUERY_DWORD => self.op_query_dword(in_buf),
            _ => reply(STATUS_INVALID_SYSTEM_SERVICE, 0),
        }
    }

    fn op_create_key(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(path) = decode(buf, req.path_offset, req.path_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let key = self.cm.registry_mut().create_key(&path);
        reply(STATUS_SUCCESS, key)
    }

    fn op_open_key(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(path) = decode(buf, req.path_offset, req.path_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        match self.cm.registry().open_key(&path) {
            Some(key) => reply(STATUS_SUCCESS, key),
            None => reply(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        }
    }

    fn op_set_dword(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmValueRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let (Some(key_path), Some(name)) = (
            decode(buf, req.key_offset, req.key_len_bytes),
            decode(buf, req.name_offset, req.name_len_bytes),
        ) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let key = self.cm.registry_mut().create_key(&key_path);
        if self.cm.registry_mut().set_dword(key, &name, req.dword) {
            reply(STATUS_SUCCESS, 0)
        } else {
            reply(STATUS_INVALID_PARAMETER, 0)
        }
    }

    fn op_query_dword(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmValueRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let (Some(key_path), Some(name)) = (
            decode(buf, req.key_offset, req.key_len_bytes),
            decode(buf, req.name_offset, req.name_len_bytes),
        ) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(key) = self.cm.registry().open_key(&key_path) else {
            return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
        };
        match self.cm.registry().query_dword(key, &name) {
            Some(v) => reply(STATUS_SUCCESS, v as u64),
            None => reply(STATUS_OBJECT_NAME_NOT_FOUND, 0),
        }
    }
}
