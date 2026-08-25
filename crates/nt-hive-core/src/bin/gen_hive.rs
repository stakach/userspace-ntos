//! Host-side build tool: emit a minimal NT registry hive (nt-hive-core image format) for the
//! Config Manager to read off the boot disk. Writes `argv[1]` (default `hive.dat`). Uses std
//! (a host tool); the nt-hive-core *library* stays `no_std` — cargo builds bins only for the
//! host, and path-dep builds (the executive) don't build bins, so this is invisible there.

use nt_config_manager::{
    encode_multi_sz, ConfigManager, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_KERNEL_DRIVER,
    SERVICE_SYSTEM_START,
};
#[cfg(test)]
use nt_config_manager::{SERVICE_BOOT_START, SERVICE_DEMAND_START};
#[cfg(test)]
use nt_hive_core::reactos_network_ipv4_defaults_for_interface;
use nt_hive_core::{
    encode_image, import_control_set_class_into_config_manager,
    import_control_set_enum_into_config_manager, import_control_set_network_into_config_manager,
    import_control_set_services_into_config_manager,
    seed_reactos_network_bindings_from_config_manager_into_target,
    seed_reactos_network_setup_into_target, CellId, Hive, HiveKind, ReactOsSetupSeedTarget,
    RegistryValueType, CURRENT_CONTROL_SET_TARGET,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

const NET_CLASS_GUID: &str = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
const E1000_DRIVER_KEY: &str = r"{4D36E972-E325-11CE-BFC1-08002BE10318}\0000";
const E1000_INSTANCE_ID: &str = r"PCI\VEN_8086&DEV_100E\3&11583659&0&18";
const E1000_EXPORT_NAME: &str = r"\Device\E1000_0000";
const E1000_INTERFACE_NAME: &str = "E1000_0000";
const E1000_DRIVER_DESC: &str = "ReactOS Intel PRO/1000 Adapter";
const DC21X4_DRIVER_DESC: &str = "Intel 21143-based PCI Ethernet Adapter";
const BOCHS_INF_RELATIVE_PATH: &str = "rust-micro/.tmp/reactos/reactos/inf/bochsmp.inf";
const BOCHS_INSTANCE_ID: &str = r"PCI\VEN_1234&DEV_1111\3&11583659&0&08";
const BOCHS_DRIVER_KEY_INDEX: &str = "0000";
const BOCHS_PDO_NAME: &str = r"\Device\NTPNP_PCI0002";
#[cfg(test)]
const GENERATED_HIVE_STORAGE_WINDOW: usize = 7 * 4096;

struct GeneratedNetworkAdapter {
    service_name: String,
    service_image_path: &'static str,
    driver_key: String,
    instance_id: String,
    pdo_name: String,
    hardware_ids: &'static [&'static str],
    compatible_ids: &'static [&'static str],
    export_name: String,
    root_device: String,
    driver_desc: &'static str,
}

const GENERATED_NETWORK_ADAPTER_MAX_COUNT: usize = 29;
const GENERATED_E1000_HARDWARE_IDS: &[&str] = &[r"PCI\VEN_8086&DEV_100E"];
const GENERATED_E1000_COMPATIBLE_IDS: &[&str] = &[r"PCI\CC_020000", r"PCI\CC_0200"];
const GENERATED_DC21X4_HARDWARE_IDS: &[&str] = &[r"PCI\VEN_1011&DEV_0019"];
const GENERATED_DC21X4_COMPATIBLE_IDS: &[&str] = &[r"PCI\CC_020000", r"PCI\CC_0200"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GeneratedNetworkAdapterKind {
    E1000,
    Dc21x4,
}

const GENERATED_SERVICE_GROUP_ORDER: &[&str] = &[
    "Video",
    "File System",
    "NDIS Wrapper",
    "PNP_TDI",
    "NDIS",
    "TDI",
];

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GeneratedDisplayMode {
    bits_per_pel: u32,
    width: u32,
    height: u32,
    refresh_hz: u32,
}

impl GeneratedDisplayMode {
    const DEFAULT: Self = Self {
        bits_per_pel: 32,
        width: 1024,
        height: 768,
        refresh_hz: 60,
    };

    fn validate(self) -> Self {
        assert!(
            self.bits_per_pel != 0 && self.width != 0 && self.height != 0 && self.refresh_hz != 0,
            "generated display mode fields must be nonzero"
        );
        self
    }
}

fn utf16le_sz(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in s.encode_utf16().chain(core::iter::once(0)) {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn set_expand_sz(hive: &mut Hive, key: CellId, name: &str, value: &str) {
    hive.set_value(key, name, RegistryValueType::ExpandSz, utf16le_sz(value));
}

fn generated_hive_system_path(path: &str) -> Option<String> {
    let mut components = path.split('\\').filter(|component| !component.is_empty());
    if !components.next()?.eq_ignore_ascii_case("Registry")
        || !components.next()?.eq_ignore_ascii_case("Machine")
        || !components.next()?.eq_ignore_ascii_case("System")
        || !components.next()?.eq_ignore_ascii_case("CurrentControlSet")
    {
        return None;
    }

    let mut out = String::from("ControlSet001");
    for component in components {
        out.push('\\');
        out.push_str(component);
    }
    Some(out)
}

struct GeneratedHiveSetupSeedTarget<'a> {
    hive: &'a mut Hive,
}

impl ReactOsSetupSeedTarget for GeneratedHiveSetupSeedTarget<'_> {
    fn create_key(&mut self, path: &str) -> bool {
        let Some(path) = generated_hive_system_path(path) else {
            return false;
        };
        self.hive.create_key(&path);
        true
    }

    fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        if self.value_matches(path, name, value_type, &data) {
            return false;
        }
        let Some(path) = generated_hive_system_path(path) else {
            return false;
        };
        let key = self.hive.create_key(&path);
        self.hive.set_value(key, name, value_type, data)
    }

    fn has_value(&self, path: &str, name: &str) -> bool {
        let Some(path) = generated_hive_system_path(path) else {
            return false;
        };
        self.hive
            .open_key(&path)
            .and_then(|key| self.hive.query_value(key, name))
            .is_some()
    }

    fn value_matches(
        &self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: &[u8],
    ) -> bool {
        let Some(path) = generated_hive_system_path(path) else {
            return false;
        };
        self.hive
            .open_key(&path)
            .and_then(|key| self.hive.query_value(key, name))
            .is_some_and(|(existing_type, existing_data)| {
                existing_type == value_type && existing_data == data
            })
    }

    fn query_value(&self, path: &str, name: &str) -> Option<(RegistryValueType, Vec<u8>)> {
        let path = generated_hive_system_path(path)?;
        self.hive
            .open_key(&path)
            .and_then(|key| self.hive.query_value(key, name))
            .map(|(value_type, data)| (value_type, data.to_vec()))
    }
}

fn install_service_group_order(hive: &mut Hive) {
    let key = hive.create_key(r"ControlSet001\Control\ServiceGroupOrder");
    hive.set_value(
        key,
        "List",
        RegistryValueType::MultiSz,
        encode_multi_sz(GENERATED_SERVICE_GROUP_ORDER),
    );
}

fn generated_pci_request(adapter_index: usize) -> u8 {
    assert!(
        adapter_index < GENERATED_NETWORK_ADAPTER_MAX_COUNT,
        "generated NIC index exceeds one PCI bus"
    );
    let dev = 3 + adapter_index as u8;
    dev << 3
}

fn generated_network_driver_key(class_index: usize) -> String {
    format!(r"{}\{:04}", NET_CLASS_GUID, class_index)
}

fn generated_e1000_adapter(
    class_index: usize,
    model_index: usize,
    adapter_index: usize,
) -> GeneratedNetworkAdapter {
    let request = generated_pci_request(adapter_index);
    let driver_key = if class_index == 0 {
        String::from(E1000_DRIVER_KEY)
    } else {
        generated_network_driver_key(class_index)
    };
    let instance_id = if adapter_index == 0 {
        String::from(E1000_INSTANCE_ID)
    } else {
        format!(r"PCI\VEN_8086&DEV_100E\3&11583659&0&{:02X}", request)
    };
    let pdo_name = if adapter_index == 0 {
        String::from(r"\Device\NTPNP_PCI0001")
    } else {
        format!(r"\Device\NTPNP_E1000_{:04}", model_index)
    };
    let export_name = if model_index == 0 {
        String::from(E1000_EXPORT_NAME)
    } else {
        format!(r"\Device\E1000_{:04}", model_index)
    };
    let root_device = if model_index == 0 {
        String::from(E1000_INTERFACE_NAME)
    } else {
        format!("E1000_{:04}", model_index)
    };
    GeneratedNetworkAdapter {
        service_name: String::from("E1000"),
        service_image_path: r"system32\drivers\e1000.sys",
        driver_key,
        instance_id,
        pdo_name,
        hardware_ids: GENERATED_E1000_HARDWARE_IDS,
        compatible_ids: GENERATED_E1000_COMPATIBLE_IDS,
        export_name,
        root_device,
        driver_desc: E1000_DRIVER_DESC,
    }
}

fn generated_dc21x4_adapter(
    class_index: usize,
    model_index: usize,
    adapter_index: usize,
) -> GeneratedNetworkAdapter {
    let request = generated_pci_request(adapter_index);
    GeneratedNetworkAdapter {
        service_name: String::from("dc21x4"),
        service_image_path: r"system32\drivers\dc21x4.sys",
        driver_key: generated_network_driver_key(class_index),
        instance_id: format!(r"PCI\VEN_1011&DEV_0019\3&11583659&0&{:02X}", request),
        pdo_name: format!(r"\Device\NTPNP_DC21X4_{:04}", model_index),
        hardware_ids: GENERATED_DC21X4_HARDWARE_IDS,
        compatible_ids: GENERATED_DC21X4_COMPATIBLE_IDS,
        export_name: format!(r"\Device\DC21X4_{:04}", model_index),
        root_device: format!("DC21X4_{:04}", model_index),
        driver_desc: DC21X4_DRIVER_DESC,
    }
}

fn generated_network_adapter(
    kind: GeneratedNetworkAdapterKind,
    class_index: usize,
    model_index: usize,
    adapter_index: usize,
) -> GeneratedNetworkAdapter {
    match kind {
        GeneratedNetworkAdapterKind::E1000 => {
            generated_e1000_adapter(class_index, model_index, adapter_index)
        }
        GeneratedNetworkAdapterKind::Dc21x4 => {
            generated_dc21x4_adapter(class_index, model_index, adapter_index)
        }
    }
}

fn generated_network_adapters(
    kinds: &[GeneratedNetworkAdapterKind],
) -> Vec<GeneratedNetworkAdapter> {
    assert!(
        !kinds.is_empty() && kinds.len() <= GENERATED_NETWORK_ADAPTER_MAX_COUNT,
        "NTOS_GENERATED_NETWORK_ADAPTERS must name 1..=29 NICs"
    );

    let mut e1000_count = 0usize;
    let mut dc21x4_count = 0usize;
    kinds
        .iter()
        .enumerate()
        .map(|(adapter_index, kind)| {
            let model_index = match kind {
                GeneratedNetworkAdapterKind::E1000 => {
                    let index = e1000_count;
                    e1000_count += 1;
                    index
                }
                GeneratedNetworkAdapterKind::Dc21x4 => {
                    let index = dc21x4_count;
                    dc21x4_count += 1;
                    index
                }
            };
            generated_network_adapter(*kind, adapter_index, model_index, adapter_index)
        })
        .collect()
}

fn generated_e1000_adapters(count: usize) -> Vec<GeneratedNetworkAdapter> {
    assert!(
        count > 0 && count <= GENERATED_NETWORK_ADAPTER_MAX_COUNT,
        "NTOS_GENERATED_E1000_COUNT must be in 1..=29"
    );
    let kinds = vec![GeneratedNetworkAdapterKind::E1000; count];
    generated_network_adapters(&kinds)
}

fn generated_e1000_count_from_env() -> usize {
    match std::env::var("NTOS_GENERATED_E1000_COUNT") {
        Ok(value) => value
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("NTOS_GENERATED_E1000_COUNT must be an integer in 1..=29")),
        Err(std::env::VarError::NotPresent) => 1,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("NTOS_GENERATED_E1000_COUNT must be valid UTF-8")
        }
    }
}

fn generated_network_adapter_kind_from_name(name: &str) -> Option<GeneratedNetworkAdapterKind> {
    match name.trim().to_ascii_lowercase().as_str() {
        "e1000" | "e1000.sys" => Some(GeneratedNetworkAdapterKind::E1000),
        "dc21x4" | "dc21x4.sys" | "tulip" => Some(GeneratedNetworkAdapterKind::Dc21x4),
        _ => None,
    }
}

fn generated_network_adapter_kinds_from_spec(spec: &str) -> Vec<GeneratedNetworkAdapterKind> {
    let mut kinds = Vec::new();
    for raw in spec.split(',') {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        let Some(kind) = generated_network_adapter_kind_from_name(name) else {
            panic!("unsupported generated NIC '{name}'; supported: e1000, dc21x4");
        };
        kinds.push(kind);
    }
    assert!(
        !kinds.is_empty() && kinds.len() <= GENERATED_NETWORK_ADAPTER_MAX_COUNT,
        "NTOS_GENERATED_NETWORK_ADAPTERS must name 1..=29 NICs"
    );
    kinds
}

fn generated_network_adapters_from_env() -> Vec<GeneratedNetworkAdapter> {
    match std::env::var("NTOS_GENERATED_NETWORK_ADAPTERS") {
        Ok(value) => {
            let kinds = generated_network_adapter_kinds_from_spec(&value);
            generated_network_adapters(&kinds)
        }
        Err(std::env::VarError::NotPresent) => {
            generated_e1000_adapters(generated_e1000_count_from_env())
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("NTOS_GENERATED_NETWORK_ADAPTERS must be valid UTF-8")
        }
    }
}

fn generated_display_mode_from_env() -> GeneratedDisplayMode {
    fn read(name: &str, default: u32) -> u32 {
        match std::env::var(name) {
            Ok(value) => value
                .parse::<u32>()
                .unwrap_or_else(|_| panic!("{name} must be a positive 32-bit integer")),
            Err(std::env::VarError::NotPresent) => default,
            Err(std::env::VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8"),
        }
    }

    GeneratedDisplayMode {
        bits_per_pel: read(
            "NTOS_GENERATED_DISPLAY_BITS_PER_PEL",
            GeneratedDisplayMode::DEFAULT.bits_per_pel,
        ),
        width: read(
            "NTOS_GENERATED_DISPLAY_WIDTH",
            GeneratedDisplayMode::DEFAULT.width,
        ),
        height: read(
            "NTOS_GENERATED_DISPLAY_HEIGHT",
            GeneratedDisplayMode::DEFAULT.height,
        ),
        refresh_hz: read(
            "NTOS_GENERATED_DISPLAY_REFRESH_HZ",
            GeneratedDisplayMode::DEFAULT.refresh_hz,
        ),
    }
    .validate()
}

fn install_generated_network_adapter(hive: &mut Hive, adapter: &GeneratedNetworkAdapter) {
    let key = hive.create_key(&format!(r"ControlSet001\Services\{}", adapter.service_name));
    set_expand_sz(hive, key, "ImagePath", adapter.service_image_path);
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

    let devnode = hive.create_key(&format!(r"ControlSet001\Enum\{}", adapter.instance_id));
    hive.set_value(
        devnode,
        "Service",
        RegistryValueType::Sz,
        utf16le_sz(&adapter.service_name),
    );
    hive.set_value(
        devnode,
        "PdoName",
        RegistryValueType::Sz,
        utf16le_sz(&adapter.pdo_name),
    );
    hive.set_value(
        devnode,
        "Driver",
        RegistryValueType::Sz,
        utf16le_sz(&adapter.driver_key),
    );
    hive.set_value(
        devnode,
        "HardwareID",
        RegistryValueType::MultiSz,
        encode_multi_sz(adapter.hardware_ids),
    );
    hive.set_value(
        devnode,
        "CompatibleIDs",
        RegistryValueType::MultiSz,
        encode_multi_sz(adapter.compatible_ids),
    );

    let class_key = hive.create_key(&format!(
        r"ControlSet001\Control\Class\{}",
        adapter.driver_key
    ));
    hive.set_value(
        class_key,
        "DriverDesc",
        RegistryValueType::Sz,
        utf16le_sz(adapter.driver_desc),
    );
    let linkage = hive.create_key(&format!(
        r"ControlSet001\Control\Class\{}\Linkage",
        adapter.driver_key
    ));
    hive.set_value(
        linkage,
        "Export",
        RegistryValueType::Sz,
        utf16le_sz(&adapter.export_name),
    );
    hive.set_value(
        linkage,
        "RootDevice",
        RegistryValueType::Sz,
        utf16le_sz(&adapter.root_device),
    );
}

fn install_generated_network_adapters(hive: &mut Hive, adapters: &[GeneratedNetworkAdapter]) {
    for adapter in adapters {
        install_generated_network_adapter(hive, adapter);
    }
}

fn import_generated_hive_config_manager(hive: &Hive) -> ConfigManager {
    let mut cm = ConfigManager::new();
    let _ =
        import_control_set_services_into_config_manager(hive, &mut cm, CURRENT_CONTROL_SET_TARGET);
    let _ = import_control_set_enum_into_config_manager(hive, &mut cm, CURRENT_CONTROL_SET_TARGET);
    let _ = import_control_set_class_into_config_manager(hive, &mut cm, CURRENT_CONTROL_SET_TARGET);
    let _ =
        import_control_set_network_into_config_manager(hive, &mut cm, CURRENT_CONTROL_SET_TARGET);
    cm
}

fn seed_generated_network_setup(hive: &mut Hive) {
    let cm = import_generated_hive_config_manager(hive);
    let mut target = GeneratedHiveSetupSeedTarget { hive };
    let mut stats = seed_reactos_network_setup_into_target(&mut target);
    seed_reactos_network_bindings_from_config_manager_into_target(&mut target, &cm, &mut stats);
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

fn install_display_miniport(
    hive: &mut Hive,
    install: &DisplayMiniportInstall,
    mode: GeneratedDisplayMode,
) {
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
    for (name, value) in [
        ("DefaultSettings.BitsPerPel", mode.bits_per_pel),
        ("DefaultSettings.XResolution", mode.width),
        ("DefaultSettings.YResolution", mode.height),
        ("DefaultSettings.VRefresh", mode.refresh_hz),
        ("DefaultSettings.Flags", 0),
        ("DefaultSettings.XPanning", 0),
        ("DefaultSettings.YPanning", 0),
        ("DefaultSettings.Orientation", 0),
        ("DefaultSettings.FixedOutput", 0),
    ] {
        hive.set_dword(device, name, value);
    }
}

fn build_hive_with_configuration(
    network_adapters: Vec<GeneratedNetworkAdapter>,
    display_mode: GeneratedDisplayMode,
) -> Hive {
    let mut hive = Hive::new(HiveKind::System);
    // A recognizable marker the executive reads back: ...\NtosTest\Answer = REG_DWORD 42.
    let key = hive.create_key(r"ControlSet001\Services\NtosTest");
    hive.set_dword(key, "Answer", 42);

    install_service_group_order(&mut hive);

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

    install_generated_network_adapters(&mut hive, &network_adapters);
    seed_generated_network_setup(&mut hive);

    let bochs = bochs_display_install_from_staged_inf()
        .expect("staged ReactOS bochsmp.inf must describe the display miniport");
    install_display_miniport(&mut hive, &bochs, display_mode.validate());

    hive
}

#[cfg(test)]
fn build_hive_with_network_adapters(network_adapters: Vec<GeneratedNetworkAdapter>) -> Hive {
    build_hive_with_configuration(network_adapters, GeneratedDisplayMode::DEFAULT)
}

#[cfg(test)]
fn build_hive() -> Hive {
    build_hive_with_network_adapters(generated_e1000_adapters(1))
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "hive.dat".to_string());
    let hive = build_hive_with_configuration(
        generated_network_adapters_from_env(),
        generated_display_mode_from_env(),
    );
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

        let class_key = hive
            .open_key(r"ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0000")
            .expect("network class key");
        assert_eq!(
            hive.query_value(class_key, "DriverDesc"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz(E1000_DRIVER_DESC).as_slice()
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
        assert_eq!(
            hive.query_value(linkage, "RootDevice"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz(E1000_INTERFACE_NAME).as_slice()
            ))
        );
    }

    #[test]
    fn generated_network_adapter_spec_accepts_packet_array_miniport_model() {
        assert_eq!(
            generated_network_adapter_kinds_from_spec("e1000, dc21x4, tulip"),
            vec![
                GeneratedNetworkAdapterKind::E1000,
                GeneratedNetworkAdapterKind::Dc21x4,
                GeneratedNetworkAdapterKind::Dc21x4,
            ]
        );
    }

    #[test]
    fn generated_hive_can_declare_registry_selected_dc21x4_packet_array_driver() {
        let adapters = generated_network_adapters(&[
            GeneratedNetworkAdapterKind::E1000,
            GeneratedNetworkAdapterKind::Dc21x4,
        ]);
        let mut hive = Hive::new(HiveKind::System);
        install_service_group_order(&mut hive);
        install_generated_network_adapters(&mut hive, &adapters);
        seed_generated_network_setup(&mut hive);

        let service = hive
            .open_key(r"ControlSet001\Services\dc21x4")
            .expect("dc21x4 service key");
        assert_eq!(
            hive.query_dword(service, "Type"),
            Some(SERVICE_KERNEL_DRIVER)
        );
        assert_eq!(
            hive.query_dword(service, "Start"),
            Some(SERVICE_SYSTEM_START)
        );
        assert_eq!(
            hive.query_value(service, "ImagePath"),
            Some((
                RegistryValueType::ExpandSz,
                utf16le_sz(r"system32\drivers\dc21x4.sys").as_slice()
            ))
        );

        let devnode = hive
            .open_key(r"ControlSet001\Enum\PCI\VEN_1011&DEV_0019\3&11583659&0&20")
            .expect("dc21x4 PCI devnode");
        assert_eq!(
            hive.query_value(devnode, "Service"),
            Some((RegistryValueType::Sz, utf16le_sz("dc21x4").as_slice()))
        );
        assert_eq!(
            hive.query_value(devnode, "Driver"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz(r"{4D36E972-E325-11CE-BFC1-08002BE10318}\0001").as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(devnode, "HardwareID"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[r"PCI\VEN_1011&DEV_0019"]).as_slice()
            ))
        );

        let class_key = hive
            .open_key(r"ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0001")
            .expect("dc21x4 class key");
        assert_eq!(
            hive.query_value(class_key, "DriverDesc"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz(DC21X4_DRIVER_DESC).as_slice()
            ))
        );
        let linkage = hive
            .open_key(
                r"ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0001\Linkage",
            )
            .expect("dc21x4 linkage key");
        assert_eq!(
            hive.query_value(linkage, "Export"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz(r"\Device\DC21X4_0000").as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(linkage, "RootDevice"),
            Some((RegistryValueType::Sz, utf16le_sz("DC21X4_0000").as_slice()))
        );

        let tcpip_linkage = hive
            .open_key(r"ControlSet001\Services\Tcpip\Linkage")
            .expect("Tcpip linkage");
        assert_eq!(
            hive.query_value(tcpip_linkage, "Bind"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[r"\Device\DC21X4_0000", E1000_EXPORT_NAME]).as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(tcpip_linkage, "Export"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[r"\Device\Tcpip_DC21X4_0000", r"\Device\Tcpip_E1000_0000"])
                    .as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(tcpip_linkage, "Route"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&["DC21X4_0000", E1000_INTERFACE_NAME]).as_slice()
            ))
        );
    }

    #[test]
    fn generated_hive_declares_network_stack_driver_services() {
        let hive = build_hive();
        let group_key = hive
            .open_key(r"ControlSet001\Control\ServiceGroupOrder")
            .expect("service group order");
        assert_eq!(
            hive.query_value(group_key, "List"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(GENERATED_SERVICE_GROUP_ORDER).as_slice()
            ))
        );

        let ndis = hive
            .open_key(r"ControlSet001\Services\Ndis")
            .expect("Ndis service");
        assert_eq!(hive.query_dword(ndis, "Type"), Some(SERVICE_KERNEL_DRIVER));
        assert_eq!(hive.query_dword(ndis, "Start"), Some(SERVICE_BOOT_START));
        assert_eq!(
            hive.query_value(ndis, "ImagePath"),
            Some((
                RegistryValueType::ExpandSz,
                utf16le_sz(r"system32\drivers\ndis.sys").as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(ndis, "Group"),
            Some((RegistryValueType::Sz, utf16le_sz("NDIS Wrapper").as_slice()))
        );

        let tcpip = hive
            .open_key(r"ControlSet001\Services\Tcpip")
            .expect("Tcpip service");
        assert_eq!(hive.query_dword(tcpip, "Type"), Some(SERVICE_KERNEL_DRIVER));
        assert_eq!(hive.query_dword(tcpip, "Start"), Some(SERVICE_SYSTEM_START));
        assert_eq!(
            hive.query_value(tcpip, "Group"),
            Some((RegistryValueType::Sz, utf16le_sz("PNP_TDI").as_slice()))
        );
        let tcpip_params = hive
            .open_key(r"ControlSet001\Services\Tcpip\Parameters")
            .expect("Tcpip Parameters");
        assert_eq!(
            hive.query_value(tcpip_params, "DataBasePath"),
            Some((
                RegistryValueType::ExpandSz,
                utf16le_sz(r"%SystemRoot%\System32\drivers\etc").as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(tcpip_params, "Hostname"),
            Some((RegistryValueType::Sz, utf16le_sz("ROSHost").as_slice()))
        );
        assert_eq!(hive.query_dword(tcpip_params, "IPEnableRouter"), Some(0));
        let tcpip_linkage = hive
            .open_key(r"ControlSet001\Services\Tcpip\Linkage")
            .expect("Tcpip Linkage");
        assert_eq!(
            hive.query_value(tcpip_linkage, "Bind"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[E1000_EXPORT_NAME]).as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(tcpip_linkage, "Export"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[r"\Device\Tcpip_E1000_0000"]).as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(tcpip_linkage, "Route"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[E1000_INTERFACE_NAME]).as_slice()
            ))
        );
        let tcpip_interface = hive
            .open_key(r"ControlSet001\Services\Tcpip\Parameters\Interfaces\E1000_0000")
            .expect("Tcpip interface");
        let ipv4 = reactos_network_ipv4_defaults_for_interface(E1000_INTERFACE_NAME);
        assert_eq!(hive.query_dword(tcpip_interface, "EnableDHCP"), Some(0));
        assert_eq!(
            hive.query_value(tcpip_interface, "IPAddress"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[ipv4.address_string().as_str()]).as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(tcpip_interface, "DefaultGateway"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[ipv4.default_gateway_string().as_str()]).as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(tcpip_interface, "SubnetMask"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[ipv4.subnet_mask_string().as_str()]).as_slice()
            ))
        );
        assert_eq!(
            hive.query_dword(tcpip_interface, "InterfaceMetric"),
            Some(0)
        );

        let afd = hive
            .open_key(r"ControlSet001\Services\Afd")
            .expect("Afd service");
        assert_eq!(hive.query_dword(afd, "Type"), Some(SERVICE_KERNEL_DRIVER));
        assert_eq!(hive.query_dword(afd, "Start"), Some(SERVICE_SYSTEM_START));
        assert_eq!(
            hive.query_value(afd, "ImagePath"),
            Some((
                RegistryValueType::ExpandSz,
                utf16le_sz(r"system32\drivers\afd.sys").as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(afd, "Group"),
            Some((RegistryValueType::Sz, utf16le_sz("TDI").as_slice()))
        );
    }

    #[test]
    fn generated_hive_orders_network_drivers_through_config_manager() {
        let hive = build_hive();
        let mut cm = nt_config_manager::ConfigManager::new();
        assert_ne!(
            nt_hive_core::import_control_set_services_into_config_manager(
                &hive,
                &mut cm,
                nt_hive_core::CURRENT_CONTROL_SET_TARGET
            ),
            0
        );
        assert_eq!(
            nt_hive_core::import_control_set_service_group_order_into_config_manager(
                &hive,
                &mut cm,
                nt_hive_core::CURRENT_CONTROL_SET_TARGET
            ),
            1
        );
        let names: Vec<String> = cm
            .boot_system_driver_candidates()
            .into_iter()
            .map(|service| service.name)
            .collect();

        let position = |name: &str| {
            names
                .iter()
                .position(|candidate| candidate.eq_ignore_ascii_case(name))
                .expect("driver service present")
        };
        assert!(position("Ndis") < position("Tcpip"));
        assert!(position("Tcpip") < position("E1000"));
        assert!(position("E1000") < position("Afd"));
    }

    #[test]
    fn generated_network_setup_derives_multiple_adapter_bindings() {
        let adapters = generated_e1000_adapters(2);
        let mut hive = Hive::new(HiveKind::System);
        install_service_group_order(&mut hive);
        install_generated_network_adapters(&mut hive, &adapters);
        seed_generated_network_setup(&mut hive);

        let tcpip_linkage = hive
            .open_key(r"ControlSet001\Services\Tcpip\Linkage")
            .expect("Tcpip linkage");
        assert_eq!(
            hive.query_value(tcpip_linkage, "Bind"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[E1000_EXPORT_NAME, r"\Device\E1000_0001"]).as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(tcpip_linkage, "Export"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[r"\Device\Tcpip_E1000_0000", r"\Device\Tcpip_E1000_0001"])
                    .as_slice()
            ))
        );
        assert_eq!(
            hive.query_value(tcpip_linkage, "Route"),
            Some((
                RegistryValueType::MultiSz,
                encode_multi_sz(&[E1000_INTERFACE_NAME, "E1000_0001"]).as_slice()
            ))
        );

        for interface in [E1000_INTERFACE_NAME, "E1000_0001"] {
            let key = hive
                .open_key(&format!(
                    r"ControlSet001\Services\Tcpip\Parameters\Interfaces\{}",
                    interface
                ))
                .expect("TCPIP interface");
            let ipv4 = reactos_network_ipv4_defaults_for_interface(interface);
            assert_eq!(hive.query_dword(key, "EnableDHCP"), Some(0));
            assert_eq!(
                hive.query_value(key, "IPAddress"),
                Some((
                    RegistryValueType::MultiSz,
                    encode_multi_sz(&[ipv4.address_string().as_str()]).as_slice()
                ))
            );
            assert_eq!(
                hive.query_value(key, "DefaultGateway"),
                Some((
                    RegistryValueType::MultiSz,
                    encode_multi_sz(&[ipv4.default_gateway_string().as_str()]).as_slice()
                ))
            );
        }
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
        for (name, value) in [
            ("DefaultSettings.BitsPerPel", 32),
            ("DefaultSettings.XResolution", 1024),
            ("DefaultSettings.YResolution", 768),
            ("DefaultSettings.VRefresh", 60),
            ("DefaultSettings.Flags", 0),
            ("DefaultSettings.XPanning", 0),
            ("DefaultSettings.YPanning", 0),
            ("DefaultSettings.Orientation", 0),
            ("DefaultSettings.FixedOutput", 0),
        ] {
            assert_eq!(hive.query_dword(device0, name), Some(value));
        }
    }

    #[test]
    fn generated_hive_display_defaults_are_image_configuration() {
        let mode = GeneratedDisplayMode {
            bits_per_pel: 16,
            width: 800,
            height: 600,
            refresh_hz: 75,
        };
        let hive = build_hive_with_configuration(generated_e1000_adapters(1), mode);
        let device0 = hive
            .open_key(r"ControlSet001\Services\bochsmp\Device0")
            .expect("display Device0");

        assert_eq!(
            hive.query_dword(device0, "DefaultSettings.BitsPerPel"),
            Some(mode.bits_per_pel)
        );
        assert_eq!(
            hive.query_dword(device0, "DefaultSettings.XResolution"),
            Some(mode.width)
        );
        assert_eq!(
            hive.query_dword(device0, "DefaultSettings.YResolution"),
            Some(mode.height)
        );
        assert_eq!(
            hive.query_dword(device0, "DefaultSettings.VRefresh"),
            Some(mode.refresh_hz)
        );
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
        assert_eq!(
            hive.query_value(linkage, "RootDevice"),
            Some((
                RegistryValueType::Sz,
                utf16le_sz(E1000_INTERFACE_NAME).as_slice()
            ))
        );
    }

    #[test]
    fn decoded_generated_hive_import_keeps_network_setup_idempotent() {
        let bytes = encode_image(&build_hive());
        let hive = decode_image(&bytes).expect("generated hive decodes");
        let mut cm = import_generated_hive_config_manager(&hive);

        assert_eq!(cm.devnode_count(), 3);
        let stats = nt_hive_core::seed_reactos_network_setup_in_config_manager(&mut cm);
        assert_eq!(stats, nt_hive_core::ReactOsNetworkSetupSeedStats::default());

        let tcpip_linkage = cm
            .registry()
            .open_key(r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Linkage")
            .expect("TCPIP linkage");
        assert_eq!(
            cm.registry().query_multi_string(tcpip_linkage, "Bind"),
            Some(vec![String::from(E1000_EXPORT_NAME)])
        );
        let e1000 = cm
            .devnode(E1000_INSTANCE_ID)
            .expect("generated E1000 devnode");
        assert_eq!(e1000.service.as_deref(), Some("E1000"));
    }
}
