//! Host-side build tool: emit a minimal NT registry hive (nt-hive-core image format) for the
//! Config Manager to read off the boot disk. Writes `argv[1]` (default `hive.dat`). Uses std
//! (a host tool); the nt-hive-core *library* stays `no_std` — cargo builds bins only for the
//! host, and path-dep builds (the executive) don't build bins, so this is invisible there.

use nt_config_manager::{
    encode_multi_sz, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START,
};
use nt_hive_core::{encode_image, Hive, HiveKind, RegistryValueType};

fn utf16le_sz(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in s.encode_utf16().chain(core::iter::once(0)) {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn build_hive() -> Hive {
    let mut hive = Hive::new(HiveKind::System);
    // A recognizable marker the executive reads back: ...\NtosTest\Answer = REG_DWORD 42.
    let key = hive.create_key(r"ControlSet001\Services\NtosTest");
    hive.set_dword(key, "Answer", 42);

    // Driver-launch proof fixture. The executive must discover this through service metadata just
    // like a boot/system driver, not through a compiled-in driver list.
    let key = hive.create_key(r"ControlSet001\Services\IrpFsdTest");
    hive.set_value(
        key,
        "ImagePath",
        RegistryValueType::ExpandSz,
        utf16le_sz(r"system32\drivers\IrpFsdTest.sys"),
    );
    hive.set_dword(key, "Type", SERVICE_FILE_SYSTEM_DRIVER);
    hive.set_dword(key, "Start", SERVICE_SYSTEM_START);
    hive.set_dword(key, "ErrorControl", 0x1);

    // Device-driver hardware proof fixture. This is boot registry data, not executive policy:
    // the kernel must discover it through the same service/devnode selectors used for real hives.
    let key = hive.create_key(r"ControlSet001\Services\DmaPnpPowerTest");
    hive.set_value(
        key,
        "ImagePath",
        RegistryValueType::ExpandSz,
        utf16le_sz(r"system32\drivers\DmaPnpPowerTest.sys"),
    );
    hive.set_dword(key, "Type", SERVICE_KERNEL_DRIVER);
    hive.set_dword(key, "Start", SERVICE_SYSTEM_START);
    hive.set_dword(key, "ErrorControl", 0x1);

    let devnode = hive.create_key(r"ControlSet001\Enum\ROOT\USERSPACE_NTOS_DMA\0001");
    hive.set_value(
        devnode,
        "Service",
        RegistryValueType::Sz,
        utf16le_sz("DmaPnpPowerTest"),
    );
    hive.set_value(
        devnode,
        "PdoName",
        RegistryValueType::Sz,
        utf16le_sz(r"\Device\NTPNP_ROOT0001"),
    );
    hive.set_value(
        devnode,
        "HardwareID",
        RegistryValueType::MultiSz,
        encode_multi_sz(&[r"ROOT\USERSPACE_NTOS_DMA"]),
    );
    hive.set_value(
        devnode,
        "CompatibleIDs",
        RegistryValueType::MultiSz,
        encode_multi_sz(&[r"ROOT\USERSPACE_NTOS_TEST_DEVICE"]),
    );

    hive
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "hive.dat".to_string());
    let hive = build_hive();
    let bytes = encode_image(&hive);
    std::fs::write(&out, &bytes).expect("write hive image");
    eprintln!("gen_hive: wrote {} ({} bytes)", out, bytes.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_hive_declares_irp_fsd_test_service() {
        let hive = build_hive();
        let key = hive
            .open_key(r"ControlSet001\Services\IrpFsdTest")
            .expect("service key");
        assert_eq!(hive.query_dword(key, "Type"), Some(0x2));
        assert_eq!(hive.query_dword(key, "Start"), Some(0x1));
        assert_eq!(
            hive.query_value(key, "ImagePath"),
            Some((
                RegistryValueType::ExpandSz,
                utf16le_sz(r"system32\drivers\IrpFsdTest.sys").as_slice()
            ))
        );
    }

    #[test]
    fn generated_hive_declares_registry_selected_dma_pnp_driver() {
        let hive = build_hive();
        let key = hive
            .open_key(r"ControlSet001\Services\DmaPnpPowerTest")
            .expect("service key");
        assert_eq!(hive.query_dword(key, "Type"), Some(SERVICE_KERNEL_DRIVER));
        assert_eq!(hive.query_dword(key, "Start"), Some(SERVICE_SYSTEM_START));
        assert_eq!(
            hive.query_value(key, "ImagePath"),
            Some((
                RegistryValueType::ExpandSz,
                utf16le_sz(r"system32\drivers\DmaPnpPowerTest.sys").as_slice()
            ))
        );

        let dn = hive
            .open_key(r"ControlSet001\Enum\ROOT\USERSPACE_NTOS_DMA\0001")
            .expect("devnode key");
        assert_eq!(
            hive.query_value(dn, "Service"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz("DmaPnpPowerTest").as_slice()
            ))
        );
    }
}
