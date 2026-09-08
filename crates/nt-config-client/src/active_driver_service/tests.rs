use super::*;
use alloc::format;

const PATH: &str = r"\Registry\Machine\System\ControlSet002\Services\Stable";

fn string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

pub(crate) fn snapshot(path: &str, count: u32) -> Vec<u8> {
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
