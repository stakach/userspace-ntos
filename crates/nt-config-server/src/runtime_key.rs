//! Runtime handles name a non-reused key ID, never a path to resolve again.
use super::*;
use nt_config_abi::{
    runtime_key_op as op, CmRuntimeKeyInfo, CmRuntimeKeyRequest, CM_RUNTIME_FRAME_BYTES,
};

impl CmServer {
    pub(super) fn op_runtime_key_snapshot(&mut self, input: &[u8], output: &mut [u8]) -> CmReply {
        let Some(req) = CmRuntimeKeyRequest::from_bytes(input) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if !matches!(
            req.operation,
            op::SECURITY | op::VALUE | op::ENUM_VALUE | op::ENUM_KEY | op::CLASS | op::INFO
        ) {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        // Both sizing and capture run in this single CM dispatch, before any IPC can mutate it.
        let first = self.op_runtime_key(input, &mut []);
        if first.status != STATUS_SUCCESS && first.status != STATUS_BUFFER_TOO_SMALL {
            return first;
        }
        let size = first.information as usize;
        let mut payload = Vec::new();
        if payload.try_reserve_exact(size.saturating_add(16)).is_err() {
            return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        payload.resize(size + 16, 0);
        let result = self.op_runtime_key(input, &mut payload[16..]);
        if result.status != STATUS_SUCCESS {
            return result;
        }
        payload[..8].copy_from_slice(&result.detail0.to_le_bytes());
        payload[8..16].copy_from_slice(&result.detail1.to_le_bytes());
        let needed = payload.len();
        let Some(chunk) = self.raw_value_snapshots.begin(
            0,
            payload,
            CM_RAW_VALUE_CHUNK_BYTES.min(output.len()),
            output,
        ) else {
            return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
        };
        reply_with_info(
            STATUS_SUCCESS,
            chunk.written as u32,
            needed as u64,
            chunk.token,
        )
    }

    pub(super) fn op_runtime_key(&mut self, input: &[u8], output: &mut [u8]) -> CmReply {
        let Some(req) = CmRuntimeKeyRequest::from_bytes(input) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header = core::mem::size_of::<CmRuntimeKeyRequest>();
        let name_end = header.checked_add(req.name_len as usize);
        if req.abi_size as usize != header
            || req.reserved != 0
            || input.len() > CM_RUNTIME_FRAME_BYTES
            || name_end.and_then(|end| end.checked_add(req.data_len as usize)) != Some(input.len())
            || req.key == 0
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Some(name_bytes) = input.get(header..name_end.unwrap()) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if name_bytes.len() % 2 != 0 {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Ok(name) = String::from_utf16(
            &name_bytes
                .chunks_exact(2)
                .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                .collect::<Vec<_>>(),
        ) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let data = &input[name_end.unwrap()..];
        let valid = match req.operation {
            op::SECURITY | op::INFO | op::CLASS => {
                req.name_len == 0 && data.is_empty() && req.index == 0 && req.value_type == 0
            }
            op::ENUM_KEY | op::ENUM_VALUE => {
                req.name_len == 0 && data.is_empty() && req.value_type == 0
            }
            op::SET_SECURITY => {
                req.name_len == 0 && req.index == 0 && req.value_type == 0 && !data.is_empty()
            }
            op::VALUE | op::DELETE_VALUE => {
                data.is_empty() && req.index == 0 && req.value_type == 0
            }
            op::OPEN_RELATIVE => {
                data.is_empty()
                    && req.index == 0
                    && req.value_type == 0
                    && !name.starts_with('\\')
                    && !name.contains('\0')
            }
            op::SET_VALUE => req.index == 0,
            _ => false,
        };
        if !valid {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        if self.cm.registry().generation(req.key).is_none() {
            return reply(0xC000_017Cu32 as i32, 0);
        }
        match req.operation {
            op::OPEN_RELATIVE => {
                let mut key = req.key;
                let mut names = name.split('\\').filter(|part| !part.is_empty()).peekable();
                while let Some(part) = names.next() {
                    let Some(child) = self.cm.registry().open_subkey(key, part) else {
                        return reply(
                            if names.peek().is_some() {
                                0xC000_003Au32 as i32
                            } else {
                                STATUS_OBJECT_NAME_NOT_FOUND
                            },
                            0,
                        );
                    };
                    key = child;
                }
                reply(STATUS_SUCCESS, key)
            }
            op::CLASS => {
                let mut bytes = Vec::new();
                for unit in self
                    .cm
                    .registry()
                    .key_class(req.key)
                    .unwrap_or("")
                    .encode_utf16()
                {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                runtime_payload(output, &bytes, 0, 0)
            }
            op::SET_SECURITY => match self
                .cm
                .registry_mut()
                .set_key_security_descriptor(req.key, data)
            {
                Ok(()) => reply(STATUS_SUCCESS, 0),
                Err(status) => reply(status as i32, 0),
            },
            op::SET_VALUE => {
                let Some(ty) = RegistryValueType::from_u32(req.value_type) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                self.cm
                    .registry_mut()
                    .set_value(req.key, &name, ty, data.to_vec());
                reply(STATUS_SUCCESS, 0)
            }
            op::DELETE_VALUE => reply(
                if self.cm.registry_mut().delete_value(req.key, &name) {
                    STATUS_SUCCESS
                } else {
                    STATUS_OBJECT_NAME_NOT_FOUND
                },
                0,
            ),
            op::SECURITY => {
                let Some(descriptor) = self.cm.registry().key_security_descriptor(req.key) else {
                    return reply(0xC000_0079u32 as i32, 0);
                };
                runtime_payload(
                    output,
                    descriptor,
                    req.key,
                    self.cm.registry().generation(req.key).unwrap() as u64,
                )
            }
            op::VALUE | op::ENUM_VALUE => {
                let value = if req.operation == op::VALUE {
                    self.cm.registry().query_value(req.key, &name)
                } else {
                    self.cm.registry().values(req.key).get(req.index as usize)
                };
                let Some(value) = value else {
                    return reply(
                        if req.operation == op::VALUE {
                            STATUS_OBJECT_NAME_NOT_FOUND
                        } else {
                            STATUS_NO_MORE_ENTRIES
                        },
                        0,
                    );
                };
                if req.operation == op::VALUE {
                    return runtime_payload(output, &value.data, value.value_type as u64, 0);
                }
                let mut payload = Vec::new();
                for unit in value.name.encode_utf16() {
                    payload.extend_from_slice(&unit.to_le_bytes());
                }
                let name_len = payload.len();
                payload.extend_from_slice(&value.data);
                runtime_payload(output, &payload, value.value_type as u64, name_len as u64)
            }
            op::ENUM_KEY => {
                let names = self.cm.registry().enum_subkeys(req.key);
                let Some(name) = names.get(req.index as usize) else {
                    return reply(STATUS_NO_MORE_ENTRIES, 0);
                };
                let child = self.cm.registry().open_subkey(req.key, name).unwrap();
                let mut payload = Vec::new();
                for unit in name.encode_utf16() {
                    payload.extend_from_slice(&unit.to_le_bytes());
                }
                runtime_payload(output, &payload, child, 0)
            }
            op::INFO => {
                let names = self.cm.registry().enum_subkeys(req.key);
                let values = self.cm.registry().values(req.key);
                let info = CmRuntimeKeyInfo {
                    subkeys: names.len() as u32,
                    max_subkey_name: names
                        .iter()
                        .map(|n| n.encode_utf16().count() as u32 * 2)
                        .max()
                        .unwrap_or(0),
                    values: values.len() as u32,
                    max_value_name: values
                        .iter()
                        .map(|v| v.name.encode_utf16().count() as u32 * 2)
                        .max()
                        .unwrap_or(0),
                    max_value_data: values
                        .iter()
                        .map(|v| v.data.len() as u32)
                        .max()
                        .unwrap_or(0),
                    generation: self.cm.registry().generation(req.key).unwrap(),
                    max_subkey_class: names
                        .iter()
                        .filter_map(|name| self.cm.registry().open_subkey(req.key, name))
                        .filter_map(|key| self.cm.registry().key_class(key))
                        .map(|class| class.encode_utf16().count() as u32 * 2)
                        .max()
                        .unwrap_or(0),
                };
                runtime_payload(output, info.as_bytes(), 0, 0)
            }
            _ => reply(STATUS_INVALID_PARAMETER, 0),
        }
    }
}

fn runtime_payload(output: &mut [u8], bytes: &[u8], detail0: u64, detail1: u64) -> CmReply {
    if output.len() < bytes.len() {
        return reply_with_info(STATUS_BUFFER_TOO_SMALL, bytes.len() as u32, 0, 0);
    }
    output[..bytes.len()].copy_from_slice(bytes);
    reply_with_info(STATUS_SUCCESS, bytes.len() as u32, detail0, detail1)
}
