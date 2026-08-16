//! Host-side build tool: emit a minimal NT registry hive (nt-hive-core image format) for the
//! Config Manager to read off the boot disk. Writes `argv[1]` (default `hive.dat`). Uses std
//! (a host tool); the nt-hive-core *library* stays `no_std` — cargo builds bins only for the
//! host, and path-dep builds (the executive) don't build bins, so this is invisible there.

use nt_config_manager::{
    encode_multi_sz, SERVICE_DEMAND_START, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_KERNEL_DRIVER,
    SERVICE_SYSTEM_START,
};
use nt_hive_core::{encode_image, Hive, HiveKind, RegistryValueType};
use std::collections::BTreeMap;
use std::path::PathBuf;

const NET_CLASS_GUID: &str = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
const E1000_DRIVER_KEY: &str = r"{4D36E972-E325-11CE-BFC1-08002BE10318}\0000";
const E1000_INSTANCE_ID: &str = r"PCI\VEN_8086&DEV_100E\3&11583659&0&18";
const E1000_EXPORT_NAME: &str = r"\Device\E1000_0000";
const BOCHS_INF_RELATIVE_PATH: &str = "rust-micro/.tmp/reactos/reactos/inf/bochsmp.inf";
const BOCHS_INSTANCE_ID: &str = r"PCI\VEN_1234&DEV_1111\3&11583659&0&08";
const BOCHS_DRIVER_KEY_INDEX: &str = "0000";
const BOCHS_PDO_NAME: &str = r"\Device\NTPNP_PCI0002";
const GENERATED_HIVE_STORAGE_WINDOW: usize = 7 * 4096;

#[derive(Debug)]
struct InfEntry {
    key: String,
    values: Vec<String>,
}

#[derive(Debug)]
struct InfFile {
    sections: BTreeMap<String, Vec<InfEntry>>,
    strings: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
struct DisplayMiniportInstall {
    class_guid: String,
    device_desc: String,
    hardware_id: String,
    service_name: String,
    service_binary: String,
    service_type: u32,
    start_type: u32,
    error_control: u32,
    load_order_group: String,
    installed_display_drivers: Vec<String>,
    vga_compatible: u32,
}

fn utf16le_sz(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in s.encode_utf16().chain(core::iter::once(0)) {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn workspace_relative_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn bochs_inf_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        out.push(cwd.join(BOCHS_INF_RELATIVE_PATH));
    }
    out.push(workspace_relative_path(BOCHS_INF_RELATIVE_PATH));
    out
}

fn decode_inf_text(bytes: &[u8]) -> Result<String, String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return String::from_utf16(&units).map_err(|err| err.to_string());
    }
    if bytes.len() % 2 == 0
        && bytes
            .chunks_exact(2)
            .take(32)
            .filter(|chunk| chunk[1] == 0)
            .count()
            >= 8
    {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return String::from_utf16(&units).map_err(|err| err.to_string());
    }
    String::from_utf8(bytes.to_vec()).map_err(|err| err.to_string())
}

fn read_bochs_inf_text() -> Result<String, String> {
    let mut checked = Vec::new();
    for path in bochs_inf_candidates() {
        checked.push(path.display().to_string());
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|err| err.to_string())?;
            return decode_inf_text(&bytes);
        }
    }
    Err(format!(
        "bochsmp.inf not found; checked {}",
        checked.join(", ")
    ))
}

fn strip_inf_comment(line: &str) -> &str {
    let mut in_quote = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' => in_quote = !in_quote,
            ';' if !in_quote => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn strip_quotes(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

fn split_inf_values(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    for ch in value.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                current.push(ch);
            }
            ',' if !in_quote => {
                values.push(strip_quotes(&current));
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    values.push(strip_quotes(&current));
    values
}

fn parse_inf_file(text: &str) -> InfFile {
    let mut sections: BTreeMap<String, Vec<InfEntry>> = BTreeMap::new();
    let mut current = String::new();
    for raw in text.lines() {
        let line = strip_inf_comment(raw)
            .trim()
            .trim_start_matches('\u{feff}')
            .trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].trim().to_ascii_lowercase();
            sections.entry(current.clone()).or_default();
            continue;
        }
        if current.is_empty() {
            continue;
        }
        let entry = if let Some(eq) = line.find('=') {
            InfEntry {
                key: line[..eq].trim().to_string(),
                values: split_inf_values(&line[eq + 1..]),
            }
        } else {
            let mut fields = split_inf_values(line);
            if fields.is_empty() {
                continue;
            }
            let key = fields.remove(0);
            InfEntry {
                key,
                values: fields,
            }
        };
        sections.entry(current.clone()).or_default().push(entry);
    }

    let mut strings = BTreeMap::new();
    if let Some(entries) = sections.get("strings") {
        for entry in entries {
            if let Some(value) = entry.values.first() {
                strings.insert(entry.key.to_ascii_lowercase(), strip_quotes(value));
            }
        }
    }
    InfFile { sections, strings }
}

fn resolve_inf_value(inf: &InfFile, value: &str) -> String {
    let value = strip_quotes(value);
    let mut out = String::new();
    let mut rest = value.as_str();
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after_start = &rest[start + 1..];
        if let Some(end) = after_start.find('%') {
            let token = &after_start[..end];
            if let Some(replacement) = inf.strings.get(&token.to_ascii_lowercase()) {
                out.push_str(replacement);
            } else {
                out.push('%');
                out.push_str(token);
                out.push('%');
            }
            rest = &after_start[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

fn inf_section<'a>(inf: &'a InfFile, name: &str) -> Option<&'a [InfEntry]> {
    inf.sections
        .get(&name.to_ascii_lowercase())
        .map(Vec::as_slice)
}

fn inf_value(inf: &InfFile, section: &str, key: &str) -> Option<String> {
    inf_section(inf, section)?
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case(key))
        .and_then(|entry| entry.values.first())
        .map(|value| resolve_inf_value(inf, value))
}

fn parse_inf_u32(value: &str) -> Option<u32> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

fn normalize_service_binary(path: &str) -> Option<String> {
    let path = path.trim().replace('/', r"\");
    if let Some(suffix) = path.strip_prefix(r"%12%\") {
        Some(format!(r"system32\drivers\{}", suffix))
    } else if path
        .get(..9)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"system32\"))
    {
        Some(path)
    } else {
        None
    }
}

fn display_install_from_inf(inf: &InfFile) -> Result<DisplayMiniportInstall, String> {
    let class_guid = inf_value(inf, "Version", "ClassGUID").ok_or("missing Version/ClassGUID")?;
    let model = inf_section(inf, "Bochs")
        .ok_or("missing Bochs model section")?
        .iter()
        .find(|entry| {
            entry
                .values
                .first()
                .is_some_and(|value| value.eq_ignore_ascii_case("Bochs"))
                && entry.values.len() >= 2
        })
        .ok_or("missing Bochs hardware model entry")?;
    let device_desc = resolve_inf_value(inf, &model.key);
    let install_section = resolve_inf_value(inf, &model.values[0]);
    let hardware_id = resolve_inf_value(inf, &model.values[1]);

    let services_section = format!("{}.Services", install_section);
    let add_service = inf_section(inf, &services_section)
        .ok_or("missing Bochs.Services section")?
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case("AddService"))
        .ok_or("missing AddService")?;
    if add_service.values.len() < 3 {
        return Err("malformed AddService".into());
    }
    let service_name = resolve_inf_value(inf, &add_service.values[0]);
    let service_section = resolve_inf_value(inf, &add_service.values[2]);
    let service_type = inf_value(inf, &service_section, "ServiceType")
        .and_then(|value| parse_inf_u32(&value))
        .ok_or("missing ServiceType")?;
    let start_type = inf_value(inf, &service_section, "StartType")
        .and_then(|value| parse_inf_u32(&value))
        .ok_or("missing StartType")?;
    let error_control = inf_value(inf, &service_section, "ErrorControl")
        .and_then(|value| parse_inf_u32(&value))
        .ok_or("missing ErrorControl")?;
    let service_binary = inf_value(inf, &service_section, "ServiceBinary")
        .and_then(|value| normalize_service_binary(&value))
        .ok_or("missing ServiceBinary")?;
    let load_order_group =
        inf_value(inf, &service_section, "LoadOrderGroup").ok_or("missing LoadOrderGroup")?;

    let software_section = format!("{}.SoftwareSettings", install_section);
    let add_reg_section =
        inf_value(inf, &software_section, "AddReg").ok_or("missing SoftwareSettings/AddReg")?;
    let mut installed_display_drivers = Vec::new();
    let mut vga_compatible = None;
    for row in inf_section(inf, &add_reg_section).ok_or("missing AddReg section")? {
        if !row.key.eq_ignore_ascii_case("HKR") || row.values.len() < 4 {
            continue;
        }
        let value_name = resolve_inf_value(inf, &row.values[1]);
        let value_type = resolve_inf_value(inf, &row.values[2]);
        if value_name.eq_ignore_ascii_case("InstalledDisplayDrivers") {
            if parse_inf_u32(&value_type) != Some(0x0001_0000) {
                return Err("InstalledDisplayDrivers is not REG_MULTI_SZ".into());
            }
            installed_display_drivers = row.values[3..]
                .iter()
                .map(|value| resolve_inf_value(inf, value))
                .collect();
        } else if value_name.eq_ignore_ascii_case("VgaCompatible") {
            if parse_inf_u32(&value_type) != Some(0x0001_0001) {
                return Err("VgaCompatible is not REG_DWORD".into());
            }
            vga_compatible = row
                .values
                .get(3)
                .map(|value| resolve_inf_value(inf, value))
                .and_then(|value| parse_inf_u32(&value));
        }
    }
    if installed_display_drivers.is_empty() {
        return Err("missing InstalledDisplayDrivers".into());
    }

    Ok(DisplayMiniportInstall {
        class_guid,
        device_desc,
        hardware_id,
        service_name,
        service_binary,
        service_type,
        start_type,
        error_control,
        load_order_group,
        installed_display_drivers,
        vga_compatible: vga_compatible.ok_or("missing VgaCompatible")?,
    })
}

fn bochs_display_install_from_staged_inf() -> Result<DisplayMiniportInstall, String> {
    let text = read_bochs_inf_text()?;
    let inf = parse_inf_file(&text);
    display_install_from_inf(&inf)
}

fn install_display_miniport(hive: &mut Hive, install: &DisplayMiniportInstall) {
    let service = hive.create_key(&format!(r"ControlSet001\Services\{}", install.service_name));
    hive.set_value(
        service,
        "ImagePath",
        RegistryValueType::ExpandSz,
        utf16le_sz(&install.service_binary),
    );
    hive.set_dword(service, "Type", install.service_type);
    hive.set_dword(service, "Start", install.start_type);
    hive.set_dword(service, "ErrorControl", install.error_control);
    hive.set_value(
        service,
        "Group",
        RegistryValueType::Sz,
        utf16le_sz(&install.load_order_group),
    );
    hive.set_value(
        service,
        "ClassGUID",
        RegistryValueType::Sz,
        utf16le_sz(&install.class_guid),
    );

    let driver_key = format!(r"{}\{}", install.class_guid, BOCHS_DRIVER_KEY_INDEX);
    let devnode = hive.create_key(&format!(r"ControlSet001\Enum\{}", BOCHS_INSTANCE_ID));
    hive.set_value(
        devnode,
        "Service",
        RegistryValueType::Sz,
        utf16le_sz(&install.service_name),
    );
    hive.set_value(
        devnode,
        "PdoName",
        RegistryValueType::Sz,
        utf16le_sz(BOCHS_PDO_NAME),
    );
    hive.set_value(
        devnode,
        "Driver",
        RegistryValueType::Sz,
        utf16le_sz(&driver_key),
    );
    hive.set_value(
        devnode,
        "DeviceDesc",
        RegistryValueType::Sz,
        utf16le_sz(&install.device_desc),
    );
    hive.set_value(
        devnode,
        "HardwareID",
        RegistryValueType::MultiSz,
        encode_multi_sz(&[install.hardware_id.as_str()]),
    );
    hive.set_value(
        devnode,
        "CompatibleIDs",
        RegistryValueType::MultiSz,
        encode_multi_sz(&[r"PCI\CC_030000", r"PCI\CC_0300"]),
    );

    let class_key = hive.create_key(&format!(r"ControlSet001\Control\Class\{}", driver_key));
    hive.set_value(
        class_key,
        "DriverDesc",
        RegistryValueType::Sz,
        utf16le_sz(&install.device_desc),
    );
    hive.set_value(
        class_key,
        "MatchingDeviceId",
        RegistryValueType::Sz,
        utf16le_sz(&install.hardware_id),
    );
    hive.set_value(
        class_key,
        "InstalledDisplayDrivers",
        RegistryValueType::MultiSz,
        encode_multi_sz(
            &install
                .installed_display_drivers
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ),
    );
    hive.set_dword(class_key, "VgaCompatible", install.vga_compatible);

    let device = hive.create_key(&format!(
        r"ControlSet001\Services\{}\Device0",
        install.service_name
    ));
    hive.set_value(
        device,
        "InstalledDisplayDrivers",
        RegistryValueType::MultiSz,
        encode_multi_sz(
            &install
                .installed_display_drivers
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ),
    );
    hive.set_value(
        device,
        "Device Description",
        RegistryValueType::Sz,
        utf16le_sz(&install.device_desc),
    );
    hive.set_dword(device, "VgaCompatible", install.vga_compatible);
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

    // ReactOS Intel PRO/1000 miniport. The kernel discovers this via ordinary boot/system driver
    // and devnode metadata; NDIS consumes the class Linkage\Export value during AddDevice.
    let key = hive.create_key(r"ControlSet001\Services\E1000");
    hive.set_value(
        key,
        "ImagePath",
        RegistryValueType::ExpandSz,
        utf16le_sz(r"system32\drivers\e1000.sys"),
    );
    hive.set_dword(key, "Type", SERVICE_KERNEL_DRIVER);
    hive.set_dword(key, "Start", SERVICE_SYSTEM_START);
    hive.set_dword(key, "ErrorControl", 0x1);
    hive.set_value(key, "Group", RegistryValueType::Sz, utf16le_sz("NDIS"));
    hive.set_value(
        key,
        "ClassGUID",
        RegistryValueType::Sz,
        utf16le_sz(NET_CLASS_GUID),
    );

    let devnode_path = format!(r"ControlSet001\Enum\{}", E1000_INSTANCE_ID);
    let devnode = hive.create_key(&devnode_path);
    hive.set_value(
        devnode,
        "Service",
        RegistryValueType::Sz,
        utf16le_sz("E1000"),
    );
    hive.set_value(
        devnode,
        "PdoName",
        RegistryValueType::Sz,
        utf16le_sz(r"\Device\NTPNP_PCI0001"),
    );
    hive.set_value(
        devnode,
        "Driver",
        RegistryValueType::Sz,
        utf16le_sz(E1000_DRIVER_KEY),
    );
    hive.set_value(
        devnode,
        "HardwareID",
        RegistryValueType::MultiSz,
        encode_multi_sz(&[r"PCI\VEN_8086&DEV_100E"]),
    );
    hive.set_value(
        devnode,
        "CompatibleIDs",
        RegistryValueType::MultiSz,
        encode_multi_sz(&[r"PCI\CC_020000", r"PCI\CC_0200"]),
    );

    let linkage_path =
        r"ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0000\Linkage";
    let linkage = hive.create_key(linkage_path);
    hive.set_value(
        linkage,
        "Export",
        RegistryValueType::Sz,
        utf16le_sz(E1000_EXPORT_NAME),
    );

    let bochs = bochs_display_install_from_staged_inf()
        .expect("staged ReactOS bochsmp.inf must describe the display miniport");
    install_display_miniport(&mut hive, &bochs);

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
    use nt_hive_core::decode_image;

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

    #[test]
    fn generated_hive_declares_registry_selected_e1000_pci_driver() {
        let hive = build_hive();
        let key = hive
            .open_key(r"ControlSet001\Services\E1000")
            .expect("service key");
        assert_eq!(hive.query_dword(key, "Type"), Some(SERVICE_KERNEL_DRIVER));
        assert_eq!(hive.query_dword(key, "Start"), Some(SERVICE_SYSTEM_START));
        assert_eq!(
            hive.query_value(key, "ImagePath"),
            Some((
                RegistryValueType::ExpandSz,
                utf16le_sz(r"system32\drivers\e1000.sys").as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(key, "Group"),
            Some((RegistryValueType::Sz, utf16le_sz("NDIS").as_slice()))
        );
        assert_eq!(
            hive.query_value(key, "ClassGUID"),
            Some((RegistryValueType::Sz, utf16le_sz(NET_CLASS_GUID).as_slice()))
        );

        let dn = hive
            .open_key(&format!(r"ControlSet001\Enum\{}", E1000_INSTANCE_ID))
            .expect("devnode key");
        assert_eq!(
            hive.query_value(dn, "Service"),
            Some((RegistryValueType::Sz, utf16le_sz("E1000").as_slice()))
        );
        assert_eq!(
            hive.query_value(dn, "Driver"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz(E1000_DRIVER_KEY).as_slice()
            ))
        );

        let linkage = hive
            .open_key(
                r"ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0000\Linkage",
            )
            .expect("linkage key");
        assert_eq!(
            hive.query_value(linkage, "Export"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz(E1000_EXPORT_NAME).as_slice()
            ))
        );
    }

    #[test]
    fn generated_hive_declares_inf_installed_bochs_display_driver() {
        let install = bochs_display_install_from_staged_inf().expect("bochs INF parses");
        assert_eq!(install.class_guid, "{4D36E968-E325-11CE-BFC1-08002BE10318}");
        assert_eq!(install.hardware_id, r"PCI\VEN_1234&DEV_1111");
        assert_eq!(install.service_name, "bochsmp");
        assert_eq!(install.service_binary, r"system32\drivers\bochsmp.sys");
        assert_eq!(install.service_type, SERVICE_KERNEL_DRIVER);
        assert_eq!(install.start_type, SERVICE_DEMAND_START);
        assert_eq!(
            install.installed_display_drivers,
            vec![String::from("framebuf")]
        );

        let hive = build_hive();
        let service = hive
            .open_key(r"ControlSet001\Services\bochsmp")
            .expect("display service");
        assert_eq!(
            hive.query_dword(service, "Type"),
            Some(SERVICE_KERNEL_DRIVER)
        );
        assert_eq!(
            hive.query_dword(service, "Start"),
            Some(SERVICE_DEMAND_START)
        );
        assert_eq!(
            hive.query_value(service, "ImagePath"),
            Some((
                RegistryValueType::ExpandSz,
                utf16le_sz(r"system32\drivers\bochsmp.sys").as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(service, "ClassGUID"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz("{4D36E968-E325-11CE-BFC1-08002BE10318}").as_slice()
            ))
        );

        let devnode = hive
            .open_key(&format!(r"ControlSet001\Enum\{}", BOCHS_INSTANCE_ID))
            .expect("display devnode");
        assert_eq!(
            hive.query_value(devnode, "Service"),
            Some((RegistryValueType::Sz, utf16le_sz("bochsmp").as_slice()))
        );
        assert_eq!(
            hive.query_value(devnode, "HardwareID"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[r"PCI\VEN_1234&DEV_1111"]).as_slice()
            ))
        );

        let device0 = hive
            .open_key(r"ControlSet001\Services\bochsmp\Device0")
            .expect("display Device0");
        assert_eq!(
            hive.query_value(device0, "InstalledDisplayDrivers"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&["framebuf"]).as_slice()
            ))
        );
        assert_eq!(hive.query_dword(device0, "VgaCompatible"), Some(0));
    }

    #[test]
    fn generated_hive_image_decodes_and_fits_storage_window() {
        let bytes = encode_image(&build_hive());
        assert!(bytes.len() <= GENERATED_HIVE_STORAGE_WINDOW);
        let hive = decode_image(&bytes).expect("generated hive decodes");
        let linkage = hive
            .open_key(
                r"ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0000\Linkage",
            )
            .expect("linkage key");
        assert_eq!(
            hive.query_value(linkage, "Export"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz(E1000_EXPORT_NAME).as_slice()
            ))
        );
    }
}
