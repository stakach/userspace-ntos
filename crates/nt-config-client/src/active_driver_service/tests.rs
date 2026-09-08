use super::*;
use alloc::{format, vec};

const PATH: &str = r"\Registry\Machine\System\ControlSet002\Services\Stable";

fn string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn snapshot(path: &str, count: u32) -> Vec<u8> {
    let mut binding = Vec::new();
    binding.extend_from_slice(&CM_DRIVER_SERVICE_SNAPSHOT_MAGIC.to_le_bytes());
    binding.extend_from_slice(&CM_DRIVER_SERVICE_SNAPSHOT_VERSION.to_le_bytes());
    binding.extend_from_slice(&driver_service_class::DEVICE.to_le_bytes());
    binding.extend_from_slice(&3u32.to_le_bytes());
    binding.extend_from_slice(&count.to_le_bytes());
    for value in ["Stable", r"system32\drivers\stable.sys", r"\Driver\Stable"] { string(&mut binding, value); }
    for _ in 0..4 { binding.extend_from_slice(&u32::MAX.to_le_bytes()); }
    for index in 0..count {
        string(&mut binding, &format!(r"ROOT\STABLE_DEVICE_WITH_A_LONG_INSTANCE_ID_FOR_BANKING\{index:04}"));
        for _ in 0..3 { binding.extend_from_slice(&u32::MAX.to_le_bytes()); }
        binding.extend_from_slice(&0u32.to_le_bytes());
        binding.extend_from_slice(&0u32.to_le_bytes());
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES as u16).to_le_bytes());
    bytes.extend_from_slice(&7u64.to_le_bytes());
    bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(binding.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(&binding);
    bytes
}

struct Bank {
    bytes: Vec<u8>,
    mode: u8,
    offsets: Vec<u32>,
    aborts: Vec<u64>,
    operations: Vec<u16>,
}

impl Bank {
    fn new(bytes: Vec<u8>, mode: u8) -> Self { Self { bytes, mode, offsets: Vec::new(), aborts: Vec::new(), operations: Vec::new() } }
}

impl Backend for Bank {
    fn call(&mut self, op: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        assert_eq!(op, opcode::CM_OP_QUERY_ACTIVE_DRIVER_SERVICE, "query must never open or close a key lease");
        let request = CmActiveDriverServiceRequest::from_bytes(input).unwrap();
        assert_eq!(request._reserved, 0);
        assert_eq!(request.abi_version, CM_ABI_VERSION);
        assert_eq!(request.path_offset as usize, core::mem::size_of::<CmActiveDriverServiceRequest>());
        self.operations.push(request.operation);
        if request.operation == driver_service_transfer::ABORT {
            self.aborts.push(request.transfer_token);
            return CmReply { status: STATUS_SUCCESS, information: 0, detail0: 0, detail1: 0 };
        }
        self.offsets.push(request.value_offset);
        let offset = request.value_offset as usize;
        let written = core::cmp::min(97, self.bytes.len() - offset);
        output[..written].copy_from_slice(&self.bytes[offset..offset + written]);
        let mut reply = CmReply { status: STATUS_SUCCESS, information: written as u32, detail0: self.bytes.len() as u64,
            detail1: if offset == 0 && written == self.bytes.len() { 0 } else { 42 } };
        match self.mode {
            1 => reply.information = 0,
            2 if offset != 0 => reply.detail0 += 1,
            3 if offset != 0 => reply.detail1 = 43,
            4 if offset != 0 => reply.information = CM_DRIVER_SERVICE_CHUNK_BYTES as u32 + 1,
            5 => reply.status = STATUS_DEVICE_NOT_READY,
            6 => reply.detail0 = u64::MAX,
            7 if offset + written == self.bytes.len() => reply.detail1 = 43,
            _ => {}
        }
        reply
    }
}

#[test]
fn complete_snapshot_reassembles_unbounded_devnodes_without_any_lease_calls() {
    let bytes = snapshot(PATH, 73);
    assert!(bytes.len() > CM_DRIVER_SERVICE_CHUNK_BYTES);
    let mut client = ConfigClient::new(Bank::new(bytes, 0));
    let result = client.query_active_driver_service_by_registry_path(PATH).unwrap();
    assert_eq!(result.mount_generation, 7);
    assert_eq!(result.physical_path, PATH);
    assert_eq!(result.binding.service_name, "Stable");
    assert_eq!(result.binding.devnodes.len(), 73);
    assert!(result.binding.devnodes.last().unwrap().instance_id.ends_with("0072"));
    assert!(client.backend.offsets.windows(2).all(|pair| pair[1] > pair[0]));
    assert!(client.backend.aborts.is_empty());
}

#[test]
fn malformed_banks_abort_original_token_and_never_return_partial_binding() {
    for mode in 1..=7 {
        let mut client = ConfigClient::new(Bank::new(snapshot(PATH, 3), mode));
        let status = if mode == 5 { STATUS_DEVICE_NOT_READY } else { STATUS_INVALID_PARAMETER };
        assert_eq!(client.query_active_driver_service_by_registry_path(PATH), Err(status));
        assert_eq!(client.backend.aborts, [42]);
    }
}

#[test]
fn invalid_input_never_reaches_backend() {
    let mut client = ConfigClient::new(Bank::new(snapshot(PATH, 0), 0));
    for path in ["", "bad\0key"] {
        assert_eq!(client.query_active_driver_service_by_registry_path(path), Err(STATUS_INVALID_PARAMETER));
    }
    assert_eq!(client.query_active_driver_service_by_registry_path(&"x".repeat(CM_MAX_HIVE_PATH_UNITS + 1)), Err(STATUS_INVALID_PARAMETER));
    assert!(client.backend.operations.is_empty());
}

#[test]
fn snapshot_header_lengths_version_generation_reserved_and_trailing_bytes_are_checked() {
    for field in [0, 4, 6, 8, 16, 20, 24] {
        let mut bytes = snapshot(PATH, 0);
        if field == 8 { bytes[8..16].fill(0); } else { bytes[field] ^= 1; }
        assert!(decode(&bytes).is_err(), "field {field}");
    }
    let mut bytes = snapshot(PATH, 0);
    bytes.push(0);
    assert!(decode(&bytes).is_err());
    assert!(decode(&bytes[..31]).is_err());
}

#[test]
fn snapshot_physical_path_must_name_exact_service_leaf() {
    for path in [
        r"\Registry\Machine\System\ControlSet002\Services",
        r"\Registry\Machine\System\ControlSet002\Services\Stable\Parameters",
        r"\Registry\Machine\System\ControlSet002\Services\Nested\Stable",
        r"\Registry\Machine\System\ControlSet002\Services\Other",
        r"\Registry\Machine\Software\ControlSet002\Services\Stable",
        r"\Registry\Machine\System\\Services\Stable",
        r"Stable",
    ] { assert!(decode(&snapshot(path, 0)).is_err(), "{path}"); }
    assert!(decode(&snapshot(r"\registry\machine\system\controlset002\services\stable", 0)).is_ok());
    let mut bytes = snapshot(PATH, 0);
    bytes[CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES] = 0xff;
    assert!(decode(&bytes).is_err());
    bytes[CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES] = 0;
    assert!(decode(&bytes).is_err());
}

#[test]
fn malformed_embedded_driver_binding_is_not_published() {
    let mut bytes = snapshot(PATH, 0);
    bytes[CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES + PATH.len()] ^= 1;
    assert!(decode(&bytes).is_err());
}
