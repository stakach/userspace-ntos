use super::*;
use nt_config_abi::{
    runtime_key_op as op, CmRuntimeKeyInfo, CmRuntimeKeyRequest, CM_RUNTIME_FRAME_BYTES,
};

impl<B: Backend> ConfigClient<B> {
    pub fn runtime_key_class(&mut self, key: u64) -> Result<Option<String>, i32> {
        let (_, bytes) = self.runtime_key_operation(key, op::CLASS, 0, "", 0, &[])?;
        if bytes.is_empty() {
            return Ok(None);
        }
        String::from_utf16(
            &bytes
                .chunks_exact(2)
                .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                .collect::<Vec<_>>(),
        )
        .map(Some)
        .map_err(|_| STATUS_INVALID_PARAMETER)
    }
    /// The runtime key at `path`. A path through a symbolic link fails with
    /// `CM_STATUS_REPARSE`; NT opens use [`Self::open_key_id_following`].
    pub fn open_key_id(&mut self, path: &str) -> Result<u64, i32> {
        match self.open_key_id_following(path, false)? {
            RuntimeKeyOpen::Key(key) => Ok(key),
            RuntimeKeyOpen::Reparse(_) => Err(nt_config_abi::CM_STATUS_REPARSE),
        }
    }

    /// Open `path`, reporting a symbolic link crossed on the way instead of following it.
    /// `open_link` opens a final link key itself (OBJ_OPENLINK).
    pub fn open_key_id_following(&mut self, path: &str, open_link: bool) -> Result<RuntimeKeyOpen, i32> {
        let path_bytes = utf16_bytes(path);
        let header = nt_config_abi::CmKeyRequest {
            abi_size: core::mem::size_of::<nt_config_abi::CmKeyRequest>() as u16,
            flags: if open_link { nt_config_abi::key_flags::OPEN_LINK } else { 0 },
            path_offset: core::mem::size_of::<nt_config_abi::CmKeyRequest>() as u32,
            path_len_bytes: path_bytes.len() as u32,
        };
        let mut input = Vec::new();
        input.extend_from_slice(header.as_bytes());
        input.extend_from_slice(&path_bytes);
        let mut output = alloc::vec![0u8; CM_RUNTIME_FRAME_BYTES];
        let response = self.backend.call(opcode::CM_OP_OPEN_KEY, &input, &mut output);
        runtime_open_reply(response, &output)
    }

    /// Open `name` beneath runtime key `key`, as [`Self::open_key_id_following`] does.
    pub fn open_runtime_relative(&mut self, key: u64, name: &str, open_link: bool)
        -> Result<RuntimeKeyOpen, i32>
    {
        let name = utf16_bytes(name);
        let header = core::mem::size_of::<CmRuntimeKeyRequest>();
        let request = CmRuntimeKeyRequest {
            abi_size: header as u16,
            operation: op::OPEN_RELATIVE,
            index: if open_link { nt_config_abi::runtime_open_flags::OPEN_LINK } else { 0 },
            key,
            name_len: name.len() as u32,
            data_len: 0,
            value_type: 0,
            reserved: 0,
        };
        if header + name.len() > CM_RUNTIME_FRAME_BYTES {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut input = Vec::with_capacity(header + name.len());
        input.extend_from_slice(request.as_bytes());
        input.extend_from_slice(&name);
        let mut output = alloc::vec![0u8; CM_RUNTIME_FRAME_BYTES];
        let response = self.backend.call(opcode::CM_OP_RUNTIME_KEY, &input, &mut output);
        runtime_open_reply(response, &output)
    }

    /// Exact runtime key operation. Missing IDs are deleted keys, never names to reopen.
    pub fn runtime_key_operation(
        &mut self,
        key: u64,
        operation: u16,
        index: u32,
        name: &str,
        value_type: u32,
        data: &[u8],
    ) -> Result<(CmReply, Vec<u8>), i32> {
        if operation == op::SET_VALUE
            && core::mem::size_of::<CmRuntimeKeyRequest>()
                .saturating_add(name.encode_utf16().count() * 2)
                .saturating_add(data.len())
                > CM_RUNTIME_FRAME_BYTES
        {
            let token = self.begin_set_value_id_transfer(key, name, value_type, data.len())?;
            for (index, chunk) in data.chunks(CM_RAW_VALUE_CHUNK_BYTES).enumerate() {
                if let Err(status) = self.append_set_value_transfer(
                    token,
                    index * CM_RAW_VALUE_CHUNK_BYTES,
                    data.len(),
                    chunk,
                ) {
                    let _ = self.abort_set_value_transfer(token, data.len());
                    return Err(status);
                }
            }
            if let Err(status) = self.commit_set_value_transfer(token, data.len()) {
                let _ = self.abort_set_value_transfer(token, data.len());
                return Err(status);
            }
            return Ok((
                CmReply {
                    status: STATUS_SUCCESS,
                    information: 0,
                    detail0: 0,
                    detail1: 0,
                },
                Vec::new(),
            ));
        }
        let name = utf16_bytes(name);
        let header = core::mem::size_of::<CmRuntimeKeyRequest>();
        let total = header
            .checked_add(name.len())
            .and_then(|n| n.checked_add(data.len()))
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if total > CM_RUNTIME_FRAME_BYTES {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let req = CmRuntimeKeyRequest {
            abi_size: header as u16,
            operation,
            index,
            key,
            name_len: name.len() as u32,
            data_len: data.len() as u32,
            value_type,
            reserved: 0,
        };
        let mut input = Vec::with_capacity(total);
        input.extend_from_slice(req.as_bytes());
        input.extend_from_slice(&name);
        input.extend_from_slice(data);
        if matches!(
            operation,
            op::SECURITY | op::VALUE | op::ENUM_VALUE | op::ENUM_KEY | op::CLASS | op::INFO
        ) {
            let mut chunk = [0; CM_RAW_VALUE_CHUNK_BYTES];
            let first = self
                .backend
                .call(opcode::CM_OP_RUNTIME_KEY_SNAPSHOT, &input, &mut chunk);
            let (kind, mut bytes) = self
                .collect_raw_value_snapshot(first, &mut chunk)
                .map_err(|error| error.status)?;
            if kind != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if bytes.len() < 16 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let detail0 = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let detail1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
            bytes.drain(..16);
            let reply = CmReply {
                status: STATUS_SUCCESS,
                information: bytes.len() as u32,
                detail0,
                detail1,
            };
            validate_runtime_reply(key, operation, &reply, &bytes)?;
            return Ok((reply, bytes));
        }
        let mut output = alloc::vec![0; CM_RUNTIME_FRAME_BYTES];
        let response = self
            .backend
            .call(opcode::CM_OP_RUNTIME_KEY, &input, &mut output);
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        if response.information as usize > output.len() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        output.truncate(response.information as usize);
        validate_runtime_reply(key, operation, &response, &output)?;
        Ok((response, output))
    }

    pub fn begin_set_value_id_transfer(
        &mut self,
        key: u64,
        name: &str,
        value_type: u32,
        total_len: usize,
    ) -> Result<u64, i32> {
        let name = utf16_bytes(name);
        let header = core::mem::size_of::<CmRawValueTransferRequest>();
        if header + 8 + name.len() > CM_RUNTIME_FRAME_BYTES || key == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let request = CmRawValueTransferRequest {
            abi_size: header as u16,
            abi_version: CM_ABI_VERSION,
            operation: raw_value_transfer::BEGIN_ID,
            value_type,
            total_len_bytes: u32::try_from(total_len).map_err(|_| STATUS_INVALID_PARAMETER)?,
            key_offset: header as u32,
            key_len_bytes: 8,
            name_offset: header as u32 + 8,
            name_len_bytes: name.len() as u32,
            ..Default::default()
        };
        let mut bytes = request.as_bytes().to_vec();
        bytes.extend_from_slice(&key.to_le_bytes());
        bytes.extend_from_slice(&name);
        let reply = self
            .backend
            .call(opcode::CM_OP_SET_VALUE_TRANSFER, &bytes, &mut []);
        if reply.status != STATUS_SUCCESS {
            return Err(reply.status);
        }
        if reply.information != 0 || reply.detail0 != 0 || reply.detail1 == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(reply.detail1)
    }
}

fn valid_utf16(bytes: &[u8]) -> bool {
    bytes.len() % 2 == 0
        && core::char::decode_utf16(
            bytes
                .chunks_exact(2)
                .map(|unit| u16::from_le_bytes([unit[0], unit[1]])),
        )
        .all(|unit| unit.is_ok())
}

fn validate_runtime_reply(
    key: u64,
    operation: u16,
    reply: &CmReply,
    bytes: &[u8],
) -> Result<(), i32> {
    let valid = match operation {
        op::SECURITY => {
            reply.detail0 == key
                && reply.detail1 != 0
                && reply.detail1 <= u32::MAX as u64
                && nt_security::security_descriptor_bytes_for_access(bytes).is_ok()
        }
        op::INFO => {
            bytes.len() == core::mem::size_of::<CmRuntimeKeyInfo>()
                && reply.detail0 == 0
                && reply.detail1 == 0
                && CmRuntimeKeyInfo::from_bytes(bytes).is_some_and(|info| info.generation != 0)
        }
        op::CLASS => reply.detail0 == 0 && reply.detail1 == 0 && valid_utf16(bytes),
        op::VALUE => reply.detail0 <= u32::MAX as u64 && reply.detail1 == 0,
        op::ENUM_VALUE => {
            reply.detail0 <= u32::MAX as u64
                && usize::try_from(reply.detail1)
                    .ok()
                    .and_then(|len| bytes.get(..len))
                    .is_some_and(valid_utf16)
        }
        op::ENUM_KEY => {
            reply.detail0 != 0 && reply.detail1 == 0 && !bytes.is_empty() && valid_utf16(bytes)
        }
        op::OPEN_RELATIVE => reply.detail0 != 0 && reply.detail1 == 0 && bytes.is_empty(),
        op::SET_SECURITY | op::SET_VALUE | op::DELETE_VALUE => {
            bytes.is_empty() && reply.detail0 == 0 && reply.detail1 == 0
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(STATUS_INVALID_PARAMETER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_runtime_reply_schemas_are_rejected() {
        let base = CmReply {
            status: STATUS_SUCCESS,
            information: 0,
            detail0: 0,
            detail1: 0,
        };
        assert!(validate_runtime_reply(7, op::SET_VALUE, &base, &[]).is_ok());
        assert!(
            validate_runtime_reply(7, op::SET_VALUE, &CmReply { detail0: 1, ..base }, &[]).is_err()
        );
        assert!(validate_runtime_reply(7, op::INFO, &base, &[0; 4]).is_err());
        assert!(validate_runtime_reply(
            7,
            op::SECURITY,
            &CmReply {
                detail0: 8,
                detail1: 1,
                ..base
            },
            &[1]
        )
        .is_err());
        assert!(validate_runtime_reply(
            7,
            op::SECURITY,
            &CmReply {
                detail0: 7,
                detail1: u64::MAX,
                ..base
            },
            &[1]
        )
        .is_err());
        assert!(validate_runtime_reply(
            7,
            op::ENUM_VALUE,
            &CmReply { detail1: 3, ..base },
            &[0; 4]
        )
        .is_err());
        assert!(validate_runtime_reply(
            7,
            op::ENUM_VALUE,
            &CmReply { detail1: 8, ..base },
            &[0; 4]
        )
        .is_err());
        assert!(validate_runtime_reply(
            7,
            op::ENUM_VALUE,
            &CmReply { detail1: 2, ..base },
            &[0, 0xd8]
        )
        .is_err());
        assert!(validate_runtime_reply(7, op::ENUM_KEY, &base, &[b'A', 0]).is_err());
        assert!(validate_runtime_reply(7, op::CLASS, &base, &[0, 0xd8]).is_err());
        assert!(validate_runtime_reply(7, op::OPEN_RELATIVE, &base, &[]).is_err());
    }
}

/// A runtime key OPEN step: the key id, or the absolute name a symbolic link redirects to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeKeyOpen {
    Key(u64),
    Reparse(String),
}

fn runtime_open_reply(response: CmReply, output: &[u8]) -> Result<RuntimeKeyOpen, i32> {
    match response.status {
        STATUS_SUCCESS => {
            if response.detail0 == 0 || response.information != 0 || response.detail1 != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            Ok(RuntimeKeyOpen::Key(response.detail0))
        }
        nt_config_abi::CM_STATUS_REPARSE => {
            let length = response.information as usize;
            if length == 0 || length % 2 != 0 || length > output.len()
                || response.detail0 != 0 || response.detail1 != 0
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let target = String::from_utf16(
                &output[..length].chunks_exact(2)
                    .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                    .collect::<Vec<_>>(),
            ).map_err(|_| STATUS_INVALID_PARAMETER)?;
            if !target.starts_with('\\') || target.contains('\0') {
                return Err(STATUS_INVALID_PARAMETER);
            }
            Ok(RuntimeKeyOpen::Reparse(target))
        }
        status => Err(status),
    }
}
