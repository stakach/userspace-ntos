//! Transport-agnostic NT Configuration Manager (registry) service dispatcher.
//!
//! Decodes a wire request ([`nt_config_abi`]) and drives the `nt-config-manager`
//! core, returning a [`CmReply`]. Wrapping the registry authority behind SURT lets
//! it run as an isolated service the executive/PnP/SCM reach over rings. The current
//! ABI exposes path-addressed keys plus DWORD and raw typed values.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use nt_config_abi::{opcode, read_utf16, CmKeyRequest, CmRawValueRequest, CmReply, CmValueRequest};
use nt_config_manager::{ConfigManager, RegistryValueType};

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_INVALID_SYSTEM_SERVICE: i32 = 0xC000_001Cu32 as i32;

/// Max UTF-16 units in a decoded key path / value name.
const MAX_NAME_UNITS: usize = 512;

fn reply(status: i32, detail0: u64) -> CmReply {
    reply_with_info(status, 0, detail0, 0)
}

fn reply_with_info(status: i32, information: u32, detail0: u64, detail1: u64) -> CmReply {
    CmReply {
        status,
        information,
        detail0,
        detail1,
    }
}

fn decode(buf: &[u8], offset: u32, len_bytes: u32) -> Option<String> {
    let mut units = [0u16; MAX_NAME_UNITS];
    let n = read_utf16(buf, offset, len_bytes, &mut units)?;
    Some(String::from_utf16_lossy(&units[..n]))
}

fn request_slice(buf: &[u8], offset: u32, len_bytes: u32) -> Option<&[u8]> {
    let start = offset as usize;
    let len = len_bytes as usize;
    let end = start.checked_add(len)?;
    if end <= buf.len() {
        Some(&buf[start..end])
    } else {
        None
    }
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

    /// Build a server around an already-seeded Configuration Manager.
    pub fn with_config(cm: ConfigManager) -> Self {
        Self { cm }
    }

    /// Direct read access to the registry authority.
    pub fn config(&self) -> &ConfigManager {
        &self.cm
    }

    /// Direct access to the registry authority (for seeding hives at boot).
    pub fn config_mut(&mut self) -> &mut ConfigManager {
        &mut self.cm
    }

    /// Decode + dispatch one wire request. `out_buf` carries variable-length value data for raw
    /// queries; scalar results ride in `detail0`.
    pub fn dispatch(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        match opcode {
            opcode::CM_OP_PING => reply(STATUS_SUCCESS, 0),
            opcode::CM_OP_CREATE_KEY => self.op_create_key(in_buf),
            opcode::CM_OP_OPEN_KEY => self.op_open_key(in_buf),
            opcode::CM_OP_SET_DWORD => self.op_set_dword(in_buf),
            opcode::CM_OP_QUERY_DWORD => self.op_query_dword(in_buf),
            opcode::CM_OP_SET_VALUE => self.op_set_value(in_buf),
            opcode::CM_OP_QUERY_VALUE => self.op_query_value(in_buf, out_buf),
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

    fn op_set_value(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmRawValueRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let (Some(key_path), Some(name), Some(data)) = (
            decode(buf, req.key_offset, req.key_len_bytes),
            decode(buf, req.name_offset, req.name_len_bytes),
            request_slice(buf, req.data_offset, req.data_len_bytes),
        ) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(value_type) = RegistryValueType::from_u32(req.value_type) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let key = self.cm.registry_mut().create_key(&key_path);
        if self
            .cm
            .registry_mut()
            .set_value(key, &name, value_type, Vec::from(data))
        {
            reply(STATUS_SUCCESS, 0)
        } else {
            reply(STATUS_INVALID_PARAMETER, 0)
        }
    }

    fn op_query_value(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmRawValueRequest::from_bytes(buf) else {
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
        let Some(value) = self.cm.registry().query_value(key, &name) else {
            return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
        };
        let needed = value.data.len();
        let value_type = value.value_type as u32 as u64;
        if out_buf.len() < needed {
            return reply_with_info(STATUS_BUFFER_OVERFLOW, needed as u32, value_type, 0);
        }
        out_buf[..needed].copy_from_slice(&value.data);
        reply_with_info(STATUS_SUCCESS, needed as u32, value_type, 0)
    }
}
