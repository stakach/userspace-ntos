//! Ergonomic client for the NT Configuration Manager (registry) service ABI.
//!
//! Encodes each call into the [`nt_config_abi`] wire form, hands it to a pluggable
//! [`Backend`] (SURT rings on the kernel; in-process in tests), and decodes the
//! [`CmReply`]. Supports path-addressed keys plus DWORD and raw typed values. Mirrors
//! `nt-object-client`, with semantic devnode property queries that preserve required
//! output length across the shared-frame transport.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use nt_config_abi::{
    device_property_transfer, opcode, CmDevicePropertyRequest, CmEnumerateKeyRequest, CmKeyRequest,
    CmRawValueRequest, CmReply, CmValueRequest, CM_ABI_VERSION, CM_DEVICE_PROPERTY_CHUNK_BYTES,
    CM_MAX_INSTANCE_UNITS,
};

/// A pluggable transport: send `opcode` + `in_buf`, receive a `CmReply` (+ optional
/// `out_buf` for future variable-length replies).
pub trait Backend {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply;
}

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueryError {
    pub status: i32,
    pub required_len: usize,
}

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

    /// Enumerate an immediate subkey name by index into `out` as UTF-16LE bytes without a NUL.
    pub fn enumerate_key(&mut self, path: &str, index: u32, out: &mut [u8]) -> Result<usize, i32> {
        let r = self.enumerate_key_op(path, index, out);
        if r.status == STATUS_SUCCESS {
            Ok(r.information as usize)
        } else {
            Err(r.status)
        }
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

    /// Set a raw typed registry value. The key is created if absent, matching `set_dword`.
    pub fn set_value(
        &mut self,
        key_path: &str,
        name: &str,
        value_type: u32,
        data: &[u8],
    ) -> Result<(), i32> {
        let r = self.raw_value_op(
            opcode::CM_OP_SET_VALUE,
            key_path,
            name,
            value_type,
            data,
            &mut [],
        );
        if r.status == STATUS_SUCCESS {
            Ok(())
        } else {
            Err(r.status)
        }
    }

    /// Query a raw typed registry value into `out`. Returns `(REG_* type, bytes_written)`.
    pub fn query_value(
        &mut self,
        key_path: &str,
        name: &str,
        out: &mut [u8],
    ) -> Result<(u32, usize), i32> {
        let r = self.raw_value_op(opcode::CM_OP_QUERY_VALUE, key_path, name, 0, &[], out);
        if r.status == STATUS_SUCCESS {
            Ok((r.detail0 as u32, r.information as usize))
        } else {
            Err(r.status)
        }
    }

    /// Query a legacy device property by stable devnode instance path. Errors retain the exact
    /// required length so native `IoGetDeviceProperty` callers can report and retry correctly.
    pub fn query_device_property(
        &mut self,
        instance: &str,
        property: u32,
        out: &mut [u8],
    ) -> Result<usize, QueryError> {
        let instance_bytes = utf16_bytes(instance);
        if instance_bytes.is_empty()
            || instance_bytes.len() > CM_MAX_INSTANCE_UNITS * 2
            || instance.chars().any(|ch| ch == '\0')
        {
            return Err(QueryError {
                status: STATUS_INVALID_PARAMETER,
                required_len: 0,
            });
        }
        let Ok(output_capacity) = u32::try_from(out.len()) else {
            return Err(QueryError {
                status: STATUS_INVALID_PARAMETER,
                required_len: 0,
            });
        };
        let mut offset = 0usize;
        let mut total = None;
        let mut token = 0u64;
        let mut staged = Vec::new();
        let mut reply_bytes = [0u8; CM_DEVICE_PROPERTY_CHUNK_BYTES];
        loop {
            let chunk_capacity = core::cmp::min(
                out.len().saturating_sub(offset),
                CM_DEVICE_PROPERTY_CHUNK_BYTES,
            );
            let operation = if token == 0 {
                device_property_transfer::BEGIN
            } else {
                device_property_transfer::PULL
            };
            let response = match self.device_property_call(
                &instance_bytes,
                property,
                output_capacity,
                operation,
                token,
                offset as u32,
                chunk_capacity as u32,
                &mut reply_bytes[..chunk_capacity],
            ) {
                Ok(response) => response,
                Err(error) => {
                    self.abort_device_property(&instance_bytes, property, output_capacity, token);
                    return Err(error);
                }
            };
            let required_len = match usize::try_from(response.detail0) {
                Ok(required_len) => required_len,
                Err(_) => {
                    self.abort_device_property(&instance_bytes, property, output_capacity, token);
                    return Err(QueryError {
                        status: STATUS_INVALID_PARAMETER,
                        required_len: 0,
                    });
                }
            };
            if response.status != STATUS_SUCCESS {
                self.abort_device_property(&instance_bytes, property, output_capacity, token);
                return Err(QueryError {
                    status: response.status,
                    required_len,
                });
            }
            let written = response.information as usize;
            let reply_token_valid = if token == 0 {
                (written == required_len && response.detail1 == 0)
                    || (written < required_len && response.detail1 != 0)
            } else {
                response.detail1 == token
            };
            if !reply_token_valid
                || total.is_some_and(|expected| expected != required_len)
                || required_len > out.len()
                || written > chunk_capacity
                || offset
                    .checked_add(written)
                    .is_none_or(|end| end > required_len)
                || (offset < required_len && written == 0)
            {
                self.abort_device_property(
                    &instance_bytes,
                    property,
                    output_capacity,
                    if token == 0 { response.detail1 } else { token },
                );
                return Err(QueryError {
                    status: STATUS_INVALID_PARAMETER,
                    required_len,
                });
            }
            if total.is_none() {
                if staged.try_reserve_exact(required_len).is_err() {
                    self.abort_device_property(
                        &instance_bytes,
                        property,
                        output_capacity,
                        response.detail1,
                    );
                    return Err(QueryError {
                        status: STATUS_INSUFFICIENT_RESOURCES,
                        required_len,
                    });
                }
                staged.resize(required_len, 0);
            }
            total = Some(required_len);
            staged[offset..offset + written].copy_from_slice(&reply_bytes[..written]);
            offset += written;
            if offset == required_len {
                out[..required_len].copy_from_slice(&staged[..required_len]);
                return Ok(required_len);
            }
            if token == 0 {
                token = response.detail1;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn device_property_call(
        &mut self,
        instance_bytes: &[u8],
        property: u32,
        output_capacity: u32,
        operation: u16,
        transfer_token: u64,
        value_offset: u32,
        chunk_capacity: u32,
        reply_bytes: &mut [u8],
    ) -> Result<CmReply, QueryError> {
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
        let mut request = Vec::new();
        request
            .try_reserve_exact(header_size.saturating_add(instance_bytes.len()))
            .map_err(|_| QueryError {
                status: STATUS_INSUFFICIENT_RESOURCES,
                required_len: 0,
            })?;
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(instance_bytes);
        Ok(self
            .backend
            .call(opcode::CM_OP_QUERY_DEVICE_PROPERTY, &request, reply_bytes))
    }

    fn abort_device_property(
        &mut self,
        instance_bytes: &[u8],
        property: u32,
        output_capacity: u32,
        transfer_token: u64,
    ) {
        if transfer_token == 0 {
            return;
        }
        let _ = self.device_property_call(
            instance_bytes,
            property,
            output_capacity,
            device_property_transfer::ABORT,
            transfer_token,
            0,
            0,
            &mut [],
        );
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

    fn enumerate_key_op(&mut self, path: &str, index: u32, out: &mut [u8]) -> CmReply {
        let path_bytes = utf16_bytes(path);
        let hdr = CmEnumerateKeyRequest {
            abi_size: core::mem::size_of::<CmEnumerateKeyRequest>() as u16,
            _pad: 0,
            index,
            path_offset: core::mem::size_of::<CmEnumerateKeyRequest>() as u32,
            path_len_bytes: path_bytes.len() as u32,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(hdr.as_bytes());
        buf.extend_from_slice(&path_bytes);
        self.backend.call(opcode::CM_OP_ENUMERATE_KEY, &buf, out)
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

    fn raw_value_op(
        &mut self,
        op: u16,
        key_path: &str,
        name: &str,
        value_type: u32,
        data: &[u8],
        out: &mut [u8],
    ) -> CmReply {
        let key_bytes = utf16_bytes(key_path);
        let name_bytes = utf16_bytes(name);
        let base = core::mem::size_of::<CmRawValueRequest>() as u32;
        let data_offset = base + key_bytes.len() as u32 + name_bytes.len() as u32;
        let hdr = CmRawValueRequest {
            abi_size: base as u16,
            _pad: 0,
            value_type,
            key_offset: base,
            key_len_bytes: key_bytes.len() as u32,
            name_offset: base + key_bytes.len() as u32,
            name_len_bytes: name_bytes.len() as u32,
            data_offset,
            data_len_bytes: data.len() as u32,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(hdr.as_bytes());
        buf.extend_from_slice(&key_bytes);
        buf.extend_from_slice(&name_bytes);
        buf.extend_from_slice(data);
        self.backend.call(op, &buf, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use nt_config_manager::{
        device_property, encode_sz, ConfigManager, RegistryValueType, ENUM_PATH,
        SERVICE_AUTO_START, SERVICE_WIN32_SHARE_PROCESS,
    };
    use nt_config_server::CmServer;

    /// In-process backend: dispatch straight into the server (no ring).
    struct Direct {
        server: CmServer,
    }

    /// Model the integrated service: dispatch into a whole page even when the final caller's slice
    /// is smaller, then copy completion bytes exactly as `RingChannel` does.
    struct Framed {
        server: CmServer,
    }
    impl Backend for Framed {
        fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
            let mut frame = [0u8; 4096];
            let reply = self.server.dispatch(opcode, in_buf, &mut frame);
            let copy_len = core::cmp::min(reply.information as usize, out_buf.len());
            out_buf[..copy_len].copy_from_slice(&frame[..copy_len]);
            reply
        }
    }
    impl Backend for Direct {
        fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
            self.server.dispatch(opcode, in_buf, out_buf)
        }
    }

    fn client() -> ConfigClient<Direct> {
        client_with_server(CmServer::new())
    }

    fn client_with_server(server: CmServer) -> ConfigClient<Direct> {
        ConfigClient::new(Direct { server })
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
    fn set_query_raw_value_roundtrip() {
        let mut c = client();
        let k = r"\Registry\Machine\Hardware\DeviceMap\Video";
        let data = b"v\0i\0d\0e\0o\0\0\0";
        assert!(c.set_value(k, r"\Device\Video0", 1, data).is_ok());
        let mut out = [0u8; 32];
        assert_eq!(
            c.query_value(k, r"\Device\Video0", &mut out),
            Ok((1, data.len()))
        );
        assert_eq!(&out[..data.len()], data);
    }

    #[test]
    fn seeded_config_manager_services_are_visible() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "RpcSs",
            r"%SystemRoot%\system32\svchost.exe -k rpcss",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        let mut c = client_with_server(CmServer::with_config(cm));
        let key = r"\Registry\Machine\System\CurrentControlSet\Services\RpcSs";
        assert!(c.open_key(key));
        assert_eq!(c.query_dword(key, "Type"), Ok(SERVICE_WIN32_SHARE_PROCESS));
        assert_eq!(c.query_dword(key, "Start"), Ok(SERVICE_AUTO_START));

        let expected = encode_sz(r"%SystemRoot%\system32\svchost.exe -k rpcss");
        let mut out = [0u8; 128];
        assert_eq!(
            c.query_value(key, "ImagePath", &mut out),
            Ok((1, expected.len()))
        );
        assert_eq!(&out[..expected.len()], expected.as_slice());
    }

    #[test]
    fn enumerate_key_returns_case_preserved_subkey_names() {
        let mut c = client();
        let parent = r"\Registry\Machine\System\CurrentControlSet\Services";
        assert!(c.create_key(&format!(r"{}\Tcpip", parent)).is_ok());
        assert!(c.create_key(&format!(r"{}\Ndis", parent)).is_ok());
        let mut out = [0u8; 32];
        let n0 = c.enumerate_key(parent, 0, &mut out).unwrap();
        let first = String::from_utf16_lossy(
            &out[..n0]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        );
        let n1 = c.enumerate_key(parent, 1, &mut out).unwrap();
        let second = String::from_utf16_lossy(
            &out[..n1]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        );
        assert_eq!(first, "Tcpip");
        assert_eq!(second, "Ndis");
        assert!(c.enumerate_key(parent, 2, &mut out).is_err());
    }

    #[test]
    fn missing_key_and_value() {
        let mut c = client();
        assert!(!c.open_key(r"\Registry\Machine\Nope"));
        assert!(c.query_dword(r"\Registry\Machine\Nope", "X").is_err());
        c.create_key(r"\Registry\Machine\Empty").unwrap();
        assert!(c
            .query_dword(r"\Registry\Machine\Empty", "Missing")
            .is_err());
    }

    fn device_property_server() -> CmServer {
        let mut cm = ConfigManager::new();
        let instance = r"PCI\VEN_8086&DEV_100E\0001";
        let key = cm
            .registry_mut()
            .create_key(&format!(r"{}\{}", ENUM_PATH, instance));
        cm.registry_mut()
            .set_string(key, "PdoName", r"\Device\NTPNP_PCI0001");
        cm.registry_mut()
            .set_string(key, "FriendlyName", "Intel Test Adapter");
        CmServer::with_config(cm)
    }

    #[test]
    fn device_property_query_roundtrip_preserves_semantics() {
        let mut client = client_with_server(device_property_server());
        let mut out = [0u8; 128];
        let written = client
            .query_device_property(
                r"pci\ven_8086&dev_100e\0001",
                device_property::FRIENDLY_NAME,
                &mut out,
            )
            .unwrap();
        let expected = encode_sz("Intel Test Adapter");
        assert_eq!(written, expected.len());
        assert_eq!(&out[..written], expected.as_slice());

        let external = client
            .query_device_property(
                r"PCI\VEN_8086&DEV_100E\0001",
                device_property::BUS_NUMBER,
                &mut out,
            )
            .unwrap_err();
        assert_eq!(external.status, 0xC000_00BBu32 as i32);
        assert_eq!(external.required_len, 0);

        let invalid = client
            .query_device_property(r"PCI\VEN_8086&DEV_100E\0001", 23, &mut out)
            .unwrap_err();
        assert_eq!(invalid.status, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn device_property_query_honors_final_slice_capacity() {
        let mut client = ConfigClient::new(Framed {
            server: device_property_server(),
        });
        let mut out = [0xa5; 2];
        let error = client
            .query_device_property(
                r"PCI\VEN_8086&DEV_100E\0001",
                device_property::FRIENDLY_NAME,
                &mut out,
            )
            .unwrap_err();
        assert_eq!(error.status, 0xC000_0023u32 as i32);
        assert_eq!(error.required_len, encode_sz("Intel Test Adapter").len());
        assert_eq!(out, [0xa5; 2]);
    }

    #[test]
    fn device_property_query_reassembles_multiple_reply_frames() {
        let mut cm = ConfigManager::new();
        let key = cm
            .registry_mut()
            .create_key(&format!(r"{}\{}", ENUM_PATH, r"PCI\VEN_8086&DEV_100E\0001"));
        let mut expected = vec![0u8; CM_DEVICE_PROPERTY_CHUNK_BYTES * 2 + 132];
        let content_len = expected.len() - 4;
        for pair in expected[..content_len].chunks_exact_mut(2) {
            pair.copy_from_slice(&u16::from(b'A').to_le_bytes());
        }
        assert!(cm.registry_mut().set_value(
            key,
            "HardwareID",
            RegistryValueType::MultiSz,
            expected.clone(),
        ));
        let mut client = ConfigClient::new(Framed {
            server: CmServer::with_config(cm),
        });
        let mut out = vec![0xa5; expected.len()];
        assert_eq!(
            client.query_device_property(
                r"PCI\VEN_8086&DEV_100E\0001",
                device_property::HARDWARE_ID,
                &mut out,
            ),
            Ok(expected.len())
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn device_property_query_rejects_invalid_client_paths() {
        let mut client = client_with_server(device_property_server());
        let mut out = [0u8; 8];
        assert_eq!(
            client
                .query_device_property("", device_property::FRIENDLY_NAME, &mut out)
                .unwrap_err()
                .status,
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            client
                .query_device_property("PCI\0DEVICE", device_property::FRIENDLY_NAME, &mut out)
                .unwrap_err()
                .status,
            STATUS_INVALID_PARAMETER
        );
        let oversized = "A".repeat(CM_MAX_INSTANCE_UNITS + 1);
        assert_eq!(
            client
                .query_device_property(&oversized, device_property::FRIENDLY_NAME, &mut out)
                .unwrap_err()
                .status,
            STATUS_INVALID_PARAMETER
        );
    }
}
