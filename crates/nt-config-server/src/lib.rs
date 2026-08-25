//! Transport-agnostic NT Configuration Manager (registry) service dispatcher.
//!
//! Decodes a wire request ([`nt_config_abi`]) and drives the `nt-config-manager`
//! core, returning a [`CmReply`]. Wrapping the registry authority behind SURT lets
//! it run as an isolated service the executive/PnP/SCM reach over rings. The current
//! ABI exposes path-addressed keys, DWORD and raw typed values, and semantic devnode
//! property queries.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use nt_config_abi::{
    device_property_transfer, opcode, read_utf16, CmDevicePropertyRequest, CmEnumerateKeyRequest,
    CmKeyRequest, CmRawValueRequest, CmReply, CmValueRequest, CM_ABI_VERSION,
    CM_DEVICE_PROPERTY_CHUNK_BYTES, CM_MAX_INSTANCE_UNITS,
};
use nt_config_manager::{device_property, ConfigManager, DevicePropertySource, RegistryValueType};

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;
const STATUS_INVALID_SYSTEM_SERVICE: i32 = 0xC000_001Cu32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BBu32 as i32;

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

struct DevicePropertySnapshot {
    token: u64,
    instance: String,
    property: u32,
    output_capacity: u32,
    value: Vec<u8>,
    offset: usize,
}

/// The Configuration Manager service: the registry authority + the wire dispatcher.
pub struct CmServer {
    cm: ConfigManager,
    device_property_snapshot: Option<DevicePropertySnapshot>,
    next_device_property_token: u64,
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
            device_property_snapshot: None,
            next_device_property_token: 1,
        }
    }

    /// Build a server around an already-seeded Configuration Manager.
    pub fn with_config(cm: ConfigManager) -> Self {
        Self {
            cm,
            device_property_snapshot: None,
            next_device_property_token: 1,
        }
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
            opcode::CM_OP_ENUMERATE_KEY => self.op_enumerate_key(in_buf, out_buf),
            opcode::CM_OP_QUERY_DEVICE_PROPERTY => self.op_query_device_property(in_buf, out_buf),
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

    fn op_enumerate_key(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmEnumerateKeyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(path) = decode(buf, req.path_offset, req.path_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Some(key) = self.cm.registry().open_key(&path) else {
            return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
        };
        let subkeys = self.cm.registry().enum_subkeys(key);
        let Some(name) = subkeys.get(req.index as usize) else {
            return reply(STATUS_NO_MORE_ENTRIES, 0);
        };
        let mut name_bytes = Vec::with_capacity(name.len() * 2);
        for unit in name.encode_utf16() {
            name_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let needed = name_bytes.len();
        if out_buf.len() < needed {
            return reply_with_info(STATUS_BUFFER_TOO_SMALL, needed as u32, 0, 0);
        }
        out_buf[..needed].copy_from_slice(&name_bytes);
        reply_with_info(STATUS_SUCCESS, needed as u32, 0, 0)
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

    fn op_query_device_property(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmDevicePropertyRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmDevicePropertyRequest>();
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req._reserved != 0
            || req.instance_offset as usize != header_size
            || req.instance_len_bytes == 0
            || req.instance_len_bytes % 2 != 0
            || req.instance_len_bytes as usize > CM_MAX_INSTANCE_UNITS * 2
            || (req.instance_offset as usize).checked_add(req.instance_len_bytes as usize)
                != Some(buf.len())
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }

        let mut units = [0u16; CM_MAX_INSTANCE_UNITS];
        let Some(unit_count) =
            read_utf16(buf, req.instance_offset, req.instance_len_bytes, &mut units)
        else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let units = &units[..unit_count];
        if units.contains(&0) {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Ok(instance) = String::from_utf16(units) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };

        match device_property::source(req.property) {
            DevicePropertySource::Invalid => return reply(STATUS_INVALID_PARAMETER, 0),
            DevicePropertySource::External => return reply(STATUS_NOT_SUPPORTED, 0),
            DevicePropertySource::Configuration => {}
        }
        let chunk_capacity = req.chunk_capacity as usize;
        if chunk_capacity > CM_DEVICE_PROPERTY_CHUNK_BYTES
            || chunk_capacity > out_buf.len()
            || req.chunk_capacity > req.output_capacity
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        match req.operation {
            device_property_transfer::BEGIN => {
                if req.transfer_token != 0
                    || req.value_offset != 0
                    || (req.chunk_capacity == 0 && req.output_capacity != 0)
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(value) = self.cm.device_property_bytes(&instance, req.property) else {
                    return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0);
                };
                let needed = value.len();
                let Ok(needed_u32) = u32::try_from(needed) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                self.device_property_snapshot = None;
                if req.output_capacity < needed_u32 {
                    return reply_with_info(STATUS_BUFFER_TOO_SMALL, 0, needed as u64, 0);
                }
                let written = core::cmp::min(needed, chunk_capacity);
                out_buf[..written].copy_from_slice(&value[..written]);
                if written == needed {
                    return reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, 0);
                }
                let token = self.next_device_property_token;
                if token == 0 {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                self.next_device_property_token = token.checked_add(1).unwrap_or(0);
                self.device_property_snapshot = Some(DevicePropertySnapshot {
                    token,
                    instance,
                    property: req.property,
                    output_capacity: req.output_capacity,
                    value,
                    offset: written,
                });
                reply_with_info(STATUS_SUCCESS, written as u32, needed as u64, token)
            }
            device_property_transfer::PULL => {
                if req.transfer_token == 0 || req.chunk_capacity == 0 {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(snapshot) = self.device_property_snapshot.as_mut() else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                if snapshot.token != req.transfer_token
                    || snapshot.instance != instance
                    || snapshot.property != req.property
                    || snapshot.output_capacity != req.output_capacity
                    || snapshot.offset != req.value_offset as usize
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let needed = snapshot.value.len();
                let written = core::cmp::min(needed - snapshot.offset, chunk_capacity);
                let end = snapshot.offset + written;
                out_buf[..written].copy_from_slice(&snapshot.value[snapshot.offset..end]);
                snapshot.offset = end;
                if end == needed {
                    self.device_property_snapshot = None;
                }
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    needed as u64,
                    req.transfer_token,
                )
            }
            device_property_transfer::ABORT => {
                if req.transfer_token == 0
                    || req.value_offset != 0
                    || req.chunk_capacity != 0
                    || self
                        .device_property_snapshot
                        .as_ref()
                        .is_none_or(|snapshot| {
                            snapshot.token != req.transfer_token
                                || snapshot.instance != instance
                                || snapshot.property != req.property
                                || snapshot.output_capacity != req.output_capacity
                        })
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                self.device_property_snapshot = None;
                reply(STATUS_SUCCESS, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use nt_config_abi::{device_property_transfer, CmDevicePropertyRequest, CM_ABI_VERSION};
    use nt_config_manager::{encode_sz, ENUM_PATH};

    const INSTANCE: &str = r"PCI\VEN_8086&DEV_100E\0001";

    fn request(instance: &str, property: u32, output_capacity: u32) -> Vec<u8> {
        let instance_bytes = utf16(instance);
        request_with_bytes(&instance_bytes, property, output_capacity)
    }

    fn utf16(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn request_with_bytes(instance_bytes: &[u8], property: u32, output_capacity: u32) -> Vec<u8> {
        request_bank(
            instance_bytes,
            property,
            output_capacity,
            device_property_transfer::BEGIN,
            0,
            0,
            core::cmp::min(output_capacity, CM_DEVICE_PROPERTY_CHUNK_BYTES as u32),
        )
    }

    fn request_bank(
        instance_bytes: &[u8],
        property: u32,
        output_capacity: u32,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
    ) -> Vec<u8> {
        let header_size = core::mem::size_of::<CmDevicePropertyRequest>();
        let header = CmDevicePropertyRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            operation,
            _reserved: 0,
            property,
            output_capacity,
            value_offset,
            chunk_capacity,
            instance_offset: header_size as u32,
            instance_len_bytes: instance_bytes.len() as u32,
            transfer_token,
        };
        let mut bytes = Vec::from(header.as_bytes());
        bytes.extend_from_slice(instance_bytes);
        bytes
    }

    fn server() -> CmServer {
        let mut cm = ConfigManager::new();
        let key = cm
            .registry_mut()
            .create_key(&alloc::format!(r"{}\{}", ENUM_PATH, INSTANCE));
        cm.registry_mut()
            .set_string(key, "PdoName", r"\Device\NTPNP_PCI0001");
        cm.registry_mut()
            .set_string(key, "FriendlyName", "Intel Test Adapter");
        CmServer::with_config(cm)
    }

    #[test]
    fn device_property_query_is_semantic_and_capacity_bounded() {
        let expected = encode_sz("Intel Test Adapter");
        let success_request = request(
            &INSTANCE.to_ascii_lowercase(),
            device_property::FRIENDLY_NAME,
            expected.len() as u32,
        );
        let mut out = vec![0xa5; 4096];
        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &success_request,
            &mut out,
        );
        assert_eq!(response.status, STATUS_SUCCESS);
        assert_eq!(response.information as usize, expected.len());
        assert_eq!(response.detail0 as usize, expected.len());
        assert_eq!(response.detail1, 0);
        assert_eq!(&out[..expected.len()], expected.as_slice());

        let small_request = request(INSTANCE, device_property::FRIENDLY_NAME, 2);
        let mut out = vec![0xa5; 4096];
        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &small_request,
            &mut out,
        );
        assert_eq!(response.status, STATUS_BUFFER_TOO_SMALL);
        assert_eq!(response.information, 0);
        assert_eq!(response.detail0 as usize, expected.len());
        assert!(out.iter().all(|byte| *byte == 0xa5));

        let framed_request = request(INSTANCE, device_property::FRIENDLY_NAME, 4096);
        let mut out = [0xa5; 2];
        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &framed_request,
            &mut out,
        );
        assert_eq!(response.status, STATUS_INVALID_PARAMETER);
        assert_eq!(response.information, 0);
        assert_eq!(out, [0xa5; 2]);
    }

    #[test]
    fn device_property_query_distinguishes_policy_and_absence() {
        let mut out = [0u8; 128];
        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request(INSTANCE, device_property::BUS_NUMBER, out.len() as u32),
            &mut out,
        );
        assert_eq!(response.status, STATUS_NOT_SUPPORTED);

        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request(INSTANCE, 23, out.len() as u32),
            &mut out,
        );
        assert_eq!(response.status, STATUS_INVALID_PARAMETER);

        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request(
                r"PCI\VEN_1234&DEV_5678\MISSING",
                device_property::FRIENDLY_NAME,
                out.len() as u32,
            ),
            &mut out,
        );
        assert_eq!(response.status, STATUS_OBJECT_NAME_NOT_FOUND);

        let response = server().dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request(INSTANCE, device_property::CLASS_NAME, out.len() as u32),
            &mut out,
        );
        assert_eq!(response.status, STATUS_OBJECT_NAME_NOT_FOUND);
    }

    #[test]
    fn device_property_query_rejects_malformed_envelopes() {
        let mut out = [0u8; 128];
        assert_eq!(
            server()
                .dispatch(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &[0; 19], &mut out)
                .status,
            STATUS_INVALID_PARAMETER
        );

        let valid = request(INSTANCE, device_property::FRIENDLY_NAME, out.len() as u32);
        for mutate in [
            |header: &mut CmDevicePropertyRequest| header.abi_size -= 1,
            |header: &mut CmDevicePropertyRequest| header.abi_version += 1,
            |header: &mut CmDevicePropertyRequest| header.instance_offset += 2,
            |header: &mut CmDevicePropertyRequest| header.instance_len_bytes -= 1,
        ] {
            let mut malformed = valid.clone();
            let mut header = CmDevicePropertyRequest::from_bytes(&malformed).unwrap();
            mutate(&mut header);
            malformed[..core::mem::size_of::<CmDevicePropertyRequest>()]
                .copy_from_slice(header.as_bytes());
            assert_eq!(
                server()
                    .dispatch(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &malformed, &mut out)
                    .status,
                STATUS_INVALID_PARAMETER
            );
        }

        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            server()
                .dispatch(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &trailing, &mut out)
                .status,
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            server()
                .dispatch(
                    opcode::CM_OP_QUERY_DEVICE_PROPERTY,
                    &request_with_bytes(&[0, 0], device_property::FRIENDLY_NAME, 128),
                    &mut out,
                )
                .status,
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            server()
                .dispatch(
                    opcode::CM_OP_QUERY_DEVICE_PROPERTY,
                    &request_with_bytes(&[0, 0xd8], device_property::FRIENDLY_NAME, 128),
                    &mut out,
                )
                .status,
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            server()
                .dispatch(
                    opcode::CM_OP_QUERY_DEVICE_PROPERTY,
                    &request_with_bytes(
                        &vec![b'A'; CM_MAX_INSTANCE_UNITS * 2 + 2],
                        device_property::FRIENDLY_NAME,
                        128,
                    ),
                    &mut out,
                )
                .status,
            STATUS_INVALID_PARAMETER
        );

        for mutate in [
            |header: &mut CmDevicePropertyRequest| header._reserved = 1,
            |header: &mut CmDevicePropertyRequest| header.operation = 0,
            |header: &mut CmDevicePropertyRequest| header.transfer_token = 1,
            |header: &mut CmDevicePropertyRequest| header.value_offset = 1,
            |header: &mut CmDevicePropertyRequest| {
                header.chunk_capacity = CM_DEVICE_PROPERTY_CHUNK_BYTES as u32 + 1
            },
        ] {
            let mut malformed = valid.clone();
            let mut header = CmDevicePropertyRequest::from_bytes(&malformed).unwrap();
            mutate(&mut header);
            malformed[..core::mem::size_of::<CmDevicePropertyRequest>()]
                .copy_from_slice(header.as_bytes());
            assert_eq!(
                server()
                    .dispatch(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &malformed, &mut out)
                    .status,
                STATUS_INVALID_PARAMETER
            );
        }
    }

    #[test]
    fn device_property_banks_are_one_immutable_snapshot() {
        let mut server = server();
        let original = "A".repeat(3000);
        let replacement = "B".repeat(3000);
        let key = server
            .config_mut()
            .registry_mut()
            .create_key(&alloc::format!(r"{}\{}", ENUM_PATH, INSTANCE));
        server
            .config_mut()
            .registry_mut()
            .set_string(key, "FriendlyName", &original);
        let expected = encode_sz(&original);
        let instance_bytes = utf16(INSTANCE);
        let mut first = [0xa5; CM_DEVICE_PROPERTY_CHUNK_BYTES];
        let begin = server.dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request_bank(
                &instance_bytes,
                device_property::FRIENDLY_NAME,
                expected.len() as u32,
                device_property_transfer::BEGIN,
                0,
                0,
                CM_DEVICE_PROPERTY_CHUNK_BYTES as u32,
            ),
            &mut first,
        );
        assert_eq!(begin.status, STATUS_SUCCESS);
        assert_ne!(begin.detail1, 0);
        assert_eq!(begin.information as usize, first.len());

        server
            .config_mut()
            .registry_mut()
            .set_string(key, "FriendlyName", &replacement);
        let tail_len = expected.len() - first.len();
        let mut tail = vec![0xa5; tail_len];
        let pull = server.dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request_bank(
                &instance_bytes,
                device_property::FRIENDLY_NAME,
                expected.len() as u32,
                device_property_transfer::PULL,
                begin.detail1,
                first.len() as u32,
                tail_len as u32,
            ),
            &mut tail,
        );
        assert_eq!(pull.status, STATUS_SUCCESS);
        assert_eq!(pull.detail1, begin.detail1);
        let mut assembled = Vec::from(first);
        assembled.extend_from_slice(&tail);
        assert_eq!(assembled, expected);

        let stale = server.dispatch(
            opcode::CM_OP_QUERY_DEVICE_PROPERTY,
            &request_bank(
                &instance_bytes,
                device_property::FRIENDLY_NAME,
                expected.len() as u32,
                device_property_transfer::PULL,
                begin.detail1,
                expected.len() as u32,
                1,
            ),
            &mut [0u8; 1],
        );
        assert_eq!(stale.status, STATUS_INVALID_PARAMETER);
    }
}
