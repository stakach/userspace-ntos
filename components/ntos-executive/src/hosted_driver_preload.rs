//! Resident source bytes for drivers that may start while boot AHCI is draining.
//!
//! This catalog never chooses a service. Mounted CM policy chooses the driver later; the
//! catalog only supplies the exact source bytes already read while boot storage was active.

use alloc::{string::String, vec::Vec};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Source {
    pub va: u64,
    pub len: u32,
    pub pin: PoolPin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PoolPin {
    pub epoch: u64,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    pub cluster: u32,
    pub len: u32,
    pub modified: u64,
    pub file_id: u64,
}

struct Entry {
    path: Vec<u8>,
    file: FileIdentity,
    source: Source,
}

pub(super) struct Catalog {
    generation: u64,
    pool_base: u64,
    pool_epoch: u64,
    capacity: u64,
    bytes: u64,
    entries: Vec<Entry>,
    complete: bool,
    receipt: Option<PreloadReceipt>,
}

impl Catalog {
    pub fn new(generation: u64, pool_base: u64, pool_epoch: u64, capacity: u64) -> Option<Self> {
        (generation != 0 && pool_base != 0 && pool_epoch != 0 && capacity != 0).then(|| Self {
            generation,
            pool_base,
            pool_epoch,
            capacity,
            bytes: 0,
            entries: Vec::new(),
            complete: false,
            receipt: None,
        })
    }

    pub fn get(&self, generation: u64, path: &[u8], pool_epoch: u64, watermark: u64) -> Option<Source> {
        if generation != self.generation || pool_epoch != self.pool_epoch {
            return None;
        }
        self.entries.iter().find(|entry| entry.path.eq_ignore_ascii_case(path))
            .and_then(|entry| {
                let source = entry.source;
                (source.pin.epoch == pool_epoch
                    && source.pin.end <= watermark
                    && source.pin.end <= self.capacity
                    && source.va == self.pool_base.checked_add(source.pin.start)?
                    && source.pin.end.checked_sub(source.pin.start)?
                        == ((source.len as u64).checked_add(0xfff)? & !0xfff))
                    .then_some(source)
            })
    }

    /// Reserve all accounting before invoking a reader that may enter native AHCI.
    pub fn stage(
        &mut self,
        generation: u64,
        path: &[u8],
        file: FileIdentity,
        watermark: u64,
        mut read: impl FnMut() -> Option<(Source, u64)>,
    ) -> Option<Source> {
        if generation != self.generation || path.is_empty() || file.len == 0 {
            return None;
        }
        if let Some(entry) = self.entries.iter().find(|entry| entry.path.eq_ignore_ascii_case(path)) {
            return (entry.file == file)
                .then(|| self.get(generation, path, self.pool_epoch, watermark)).flatten();
        }
        let rounded = (file.len as u64).checked_add(0xfff)? & !0xfff;
        let next = self.bytes.checked_add(rounded)?;
        if rounded > self.capacity.checked_sub(watermark)? {
            return None;
        }
        self.entries.try_reserve(1).ok()?;
        let mut owned_path = Vec::new();
        owned_path.try_reserve_exact(path.len()).ok()?;
        owned_path.extend_from_slice(path);
        let (source, after) = read()?;
        if source.len != file.len
            || source.pin.epoch != self.pool_epoch
            || source.pin.end > self.capacity
            || source.pin.end > after
            || source.pin.start < watermark
            || source.pin.end.checked_sub(source.pin.start) != Some(rounded)
            || self.pool_base.checked_add(source.pin.start) != Some(source.va)
        {
            return None;
        }
        self.entries.push(Entry { path: owned_path, file, source });
        self.bytes = next;
        Some(source)
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreloadReceipt {
    pub(crate) generation: u64,
    pub(crate) pool_epoch: u64,
    pub(crate) watermark: u64,
    pub(crate) services: usize,
    pub(crate) bytes: u64,
}

pub(crate) unsafe fn receipt_is_current(receipt: PreloadReceipt) -> bool {
    let Some(catalog) = (*core::ptr::addr_of!(SOURCES)).as_ref() else { return false; };
    catalog.complete
        && catalog.receipt == Some(receipt)
        && catalog.generation == receipt.generation
        && catalog.pool_epoch == receipt.pool_epoch
        && catalog.bytes == receipt.bytes
        && LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire) == receipt.generation
        && crate::fs_loader::POOL_EPOCH.load(Ordering::Acquire) == receipt.pool_epoch
        && crate::fs_loader::POOL_NEXT.load(Ordering::Acquire) >= receipt.watermark
}

pub(crate) unsafe fn current_receipt() -> Option<PreloadReceipt> {
    let receipt = (*core::ptr::addr_of!(SOURCES)).as_ref()?.receipt?;
    receipt_is_current(receipt).then_some(receipt)
}

static mut SOURCES: Option<Catalog> = None;

fn preload_failure(stage: &[u8], subject: &[u8], status: u64) {
    print_str(b"[driver-preload-fail] stage=");
    print_str(stage);
    print_str(b" subject=");
    print_str(subject);
    print_str(b" status=0x");
    print_hex_u64(status);
    print_str(b"\n");
}

macro_rules! preload_or_fail {
    ($value:expr, $stage:expr, $subject:expr) => {
        match $value {
            Some(value) => value,
            None => {
                preload_failure($stage, $subject, 0);
                return None;
            }
        }
    };
}

fn dword(snapshot: &nt_config_client::HiveKeySnapshot, name: &str) -> Option<u32> {
    let value = snapshot.values.iter().find(|value| value.name.eq_ignore_ascii_case(name))?;
    (value.value_type == 4 && value.data.len() == 4)
        .then(|| u32::from_le_bytes(value.data.as_slice().try_into().unwrap()))
}

fn class_filters(snapshot: &nt_config_client::HiveKeySnapshot, value_name: &str) -> Option<Vec<String>> {
    let Some(value) = snapshot.values.iter().find(|value| value.name.eq_ignore_ascii_case(value_name)) else {
        return Some(Vec::new());
    };
    parse_filter_services(value.value_type, &value.data)
}

fn parse_filter_services(value_type: u32, data: &[u8]) -> Option<Vec<String>> {
    if value_type != 7 || data.len() < 4 || data.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = data.chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]])).collect();
    if !units.ends_with(&[0, 0]) {
        return None;
    }
    let mut names = Vec::new();
    let mut first = 0;
    for index in 0..units.len() - 1 {
        if units[index] != 0 {
            continue;
        }
        if index == first {
            return (units.len() == 2).then_some(names);
        }
        let name = String::from_utf16(&units[first..index]).ok()?;
        if name.is_empty() || name.contains('\\') || name.contains('/') {
            return None;
        }
        names.try_reserve(1).ok()?;
        names.push(name);
        first = index + 1;
    }
    (first == units.len() - 1).then_some(names)
}

unsafe fn stage_file(
    fs: &Fat32,
    generation: u64,
    path: &[u8],
) -> Option<Source> {
    let metadata = preload_or_fail!(crate::fs_loader::fat_open_path_metadata(fs, path), b"file-metadata", path);
    if metadata.metadata.is_directory || metadata.metadata.end_of_file == 0 {
        preload_failure(b"file-not-source", path, metadata.metadata.end_of_file);
        return None;
    }
    let file = FileIdentity {
        cluster: metadata.first_cluster,
        len: u32::try_from(metadata.metadata.end_of_file).ok()?,
        modified: metadata.metadata.last_write_time,
        file_id: metadata.metadata.file_id,
    };
    let before = crate::fs_loader::POOL_NEXT.load(Ordering::Acquire);
    let epoch = crate::fs_loader::POOL_EPOCH.load(Ordering::Acquire);
    let source = (*core::ptr::addr_of_mut!(SOURCES)).as_mut()?.stage(generation, path, file, before, || {
        let (va, len) = preload_or_fail!(load_file_to_pool(fs, path), b"file-read", path);
        let again = preload_or_fail!(crate::fs_loader::fat_open_path_metadata(fs, path), b"file-recheck", path);
        if again != metadata {
            preload_failure(b"file-identity-changed", path, 0);
            return None;
        }
        let start = va.checked_sub(crate::fs_loader::POOL_VADDR)?;
        let end = start.checked_add((len as u64).checked_add(0xfff)? & !0xfff)?;
        let after = crate::fs_loader::POOL_NEXT.load(Ordering::Acquire);
        Some((Source { va, len, pin: PoolPin { epoch, start, end } }, after))
    });
    if source.is_none() {
        preload_failure(b"catalog-stage", path, before);
    }
    source
}

unsafe fn stage_pe_closure(
    fs: &Fat32,
    generation: u64,
    path: &[u8],
    depth: usize,
) -> Option<()> {
    if depth > 32 {
        preload_failure(b"pe-depth", path, depth as u64);
        return None;
    }
    let epoch = crate::fs_loader::POOL_EPOCH.load(Ordering::Acquire);
    let watermark = crate::fs_loader::POOL_NEXT.load(Ordering::Acquire);
    let already = (*core::ptr::addr_of!(SOURCES)).as_ref()?.get(generation, path, epoch, watermark).is_some();
    let source = stage_file(fs, generation, path)?;
    if already {
        return Some(());
    }
    let mut dependencies = Vec::<HostedAscii<HOSTED_DEP_PROVIDER_MAX>>::new();
    preload_or_fail!(raw_pe_collect_hosted_dependencies(source.va, source.len, &mut dependencies), b"pe-imports", path);
    for dependency in dependencies {
        if let Some((_index, singleton)) = find_hosted_provider_singleton(&dependency) {
            if singleton.image_frames == 0 || singleton.image_frames > FSD_IMAGE_MAX_FRAMES {
                preload_failure(b"provider-frames", dependency.as_str().as_bytes(), singleton.image_frames);
                return None;
            }
            match preload_or_fail!(classify_hosted_provider_domain(Some(hosted_provider_domain_descriptor(singleton))).ok(), b"provider-domain", dependency.as_str().as_bytes()) {
                HostedProviderDomainStatus::Callable(_) => continue,
                HostedProviderDomainStatus::Absent | HostedProviderDomainStatus::MetadataOnly => {}
            }
        }
        let mut dep_path = [0; HOSTED_DEP_PATH_MAX];
        let len = preload_or_fail!(hosted_dependency_path(dependency.as_str(), &mut dep_path), b"pe-import-path", dependency.as_str().as_bytes());
        stage_pe_closure(fs, generation, &dep_path[..len], depth + 1)?;
    }
    Some(())
}

unsafe fn stage_service(
    fs: &Fat32,
    generation: u64,
    name: &str,
) -> Option<()> {
    let binding = match crate::config_manager_query_driver_service(name) {
        Ok(binding) => binding,
        Err(status) => {
            preload_failure(b"service-query", name.as_bytes(), status as u32 as u64);
            return None;
        }
    };
    if !binding.service_name.eq_ignore_ascii_case(name) {
        preload_failure(b"service-name", name.as_bytes(), 0);
        return None;
    }
    if binding.class != nt_config_client::DriverServiceClass::Device {
        preload_failure(b"service-class", name.as_bytes(), 1);
        return None;
    }
    if binding.start_type >= 4 {
        preload_failure(b"service-start", name.as_bytes(), binding.start_type as u64);
        return None;
    }
    let path = preload_or_fail!(crate::registry_ascii_path(&binding.image_path), b"service-path", name.as_bytes());
    stage_pe_closure(fs, generation, &path, 0)
}

/// Stage boot-start kernel services and setup-class filter services from one mounted CM
/// generation. PnP still selects the actual service for each child when it starts.
pub(super) unsafe fn stage_registry_boot_sources(fs: &Fat32, generation: u64) -> Option<PreloadReceipt> {
    if generation == 0 || (*core::ptr::addr_of!(SOURCES)).is_some() {
        preload_failure(b"entry-authority", b"boot-disk", generation);
        return None;
    }
    let capacity = preload_or_fail!(crate::fs_loader::POOL_PTS.checked_mul(0x20_0000), b"pool-capacity", b"pool");
    let epoch = crate::fs_loader::POOL_EPOCH.load(Ordering::Acquire);
    SOURCES = Some(preload_or_fail!(Catalog::new(generation, crate::fs_loader::POOL_VADDR, epoch, capacity), b"catalog-create", b"pool"));
    let services_path = r"\Registry\Machine\System\CurrentControlSet\Services";
    let services = match crate::config_manager_query_system_hive_key(services_path) {
        Ok(services) => services,
        Err(status) => {
            preload_failure(b"services-query", services_path.as_bytes(), status as u32 as u64);
            return None;
        }
    };
    if services.mount_generation != generation {
        preload_failure(b"services-generation", services_path.as_bytes(), services.mount_generation);
        return None;
    }
    let mut selected = 0usize;
    for service in &services.subkeys {
        let path = alloc::format!(r"{}\{}", services_path, service.name);
        let snapshot = match crate::config_manager_query_system_hive_key(&path) {
            Ok(snapshot) => snapshot,
            Err(status) => {
                preload_failure(b"key-query", path.as_bytes(), status as u32 as u64);
                return None;
            }
        };
        if snapshot.mount_generation != generation {
            preload_failure(b"key-generation", path.as_bytes(), snapshot.mount_generation);
            return None;
        }
        if dword(&snapshot, "Start") == Some(0) && dword(&snapshot, "Type") == Some(1) {
            stage_service(fs, generation, &service.name)?;
            selected += 1;
        }
    }
    let classes_path = r"\Registry\Machine\System\CurrentControlSet\Control\Class";
    let classes = match crate::config_manager_query_system_hive_key(classes_path) {
        Ok(classes) => classes,
        Err(status) => {
            preload_failure(b"classes-query", classes_path.as_bytes(), status as u32 as u64);
            return None;
        }
    };
    if classes.mount_generation != generation {
        preload_failure(b"classes-generation", classes_path.as_bytes(), classes.mount_generation);
        return None;
    }
    for class in &classes.subkeys {
        let path = alloc::format!(r"{}\{}", classes_path, class.name);
        let snapshot = match crate::config_manager_query_system_hive_key(&path) {
            Ok(snapshot) => snapshot,
            Err(status) => {
                preload_failure(b"key-query", path.as_bytes(), status as u32 as u64);
                return None;
            }
        };
        if snapshot.mount_generation != generation {
            preload_failure(b"key-generation", path.as_bytes(), snapshot.mount_generation);
            return None;
        }
        for value_name in ["UpperFilters", "LowerFilters"] {
            for service in preload_or_fail!(class_filters(&snapshot, value_name), b"class-filter-format", class.name.as_bytes()) {
                stage_service(fs, generation, &service)?;
                selected += 1;
            }
        }
    }
    stage_file(fs, generation, HOSTED_AUXILIARY_PE_PATH)?;
    if LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire) != generation {
        preload_failure(b"final-generation", b"system", LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire));
        return None;
    }
    let catalog = (*core::ptr::addr_of_mut!(SOURCES)).as_mut()?;
    catalog.complete = true;
    let receipt = PreloadReceipt {
        generation,
        pool_epoch: epoch,
        watermark: crate::fs_loader::POOL_NEXT.load(Ordering::Acquire),
        services: selected,
        bytes: catalog.bytes(),
    };
    catalog.receipt = Some(receipt);
    receipt_is_current(receipt).then_some(receipt)
}

/// The boot controller may not issue a late source read once it begins draining. Native block
/// routing will replace this loader path after the real controller stack is active.
pub(super) unsafe fn source_for_launch(fs: &Fat32, path: &[u8]) -> Option<(u64, u32)> {
    let generation = LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
    let canonical = crate::registry_ascii_path(core::str::from_utf8(path).ok()?)?;
    let epoch = crate::fs_loader::POOL_EPOCH.load(Ordering::Acquire);
    let watermark = crate::fs_loader::POOL_NEXT.load(Ordering::Acquire);
    if let Some(source) = (*core::ptr::addr_of!(SOURCES)).as_ref()
        .and_then(|catalog| catalog.get(generation, &canonical, epoch, watermark))
    {
        return Some((source.va, source.len));
    }
    if !crate::boot_storage_dma_handoff::boot_disk_reads_admitted() {
        return None;
    }
    load_file_to_pool(fs, &canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: FileIdentity = FileIdentity { cluster: 8, len: 0x801, modified: 9, file_id: 10 };
    const SOURCE: Source = Source {
        va: 0x2000,
        len: FILE.len,
        pin: PoolPin { epoch: 1, start: 0x1000, end: 0x2000 },
    };

    #[test]
    fn exact_generation_and_path_only() {
        let mut sources = Catalog::new(17, 0x1000, 1, 0x3000).unwrap();
        assert_eq!(sources.stage(17, b"windows\\drivers\\one.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))), Some(SOURCE));
        assert_eq!(sources.get(17, b"WINDOWS\\DRIVERS\\ONE.SYS", 1, 0x2000), Some(SOURCE));
        assert_eq!(sources.get(18, b"windows\\drivers\\one.sys", 1, 0x2000), None);
        assert_eq!(sources.get(17, b"windows\\drivers\\other.sys", 1, 0x2000), None);
        assert_eq!(sources.get(17, b"windows/drivers/one.sys", 1, 0x2000), None);
        assert_eq!(sources.bytes(), 0x1000);
    }

    #[test]
    fn duplicate_does_not_read_or_charge_twice() {
        let mut sources = Catalog::new(1, 0x1000, 1, 0x3000).unwrap();
        assert_eq!(sources.stage(1, b"a.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))), Some(SOURCE));
        assert_eq!(sources.stage(1, b"A.SYS", FILE, 0x2000, || panic!("duplicate read")), Some(SOURCE));
        assert_eq!(sources.stage(1, b"a.sys", FileIdentity { len: 0x802, ..FILE }, 0x2000, || panic!("identity changed")), None);
        assert_eq!(sources.bytes(), 0x1000);
    }

    #[test]
    fn capacity_refuses_before_read() {
        let mut sources = Catalog::new(1, 0x1000, 1, 0x2000).unwrap();
        let large = FileIdentity { len: 0x1001, ..FILE };
        assert_eq!(sources.stage(1, b"large.sys", large, 0x1000, || panic!("capacity exceeded")), None);
        assert_eq!(sources.bytes(), 0);
    }

    #[test]
    fn stale_pool_identity_or_reused_watermark_cannot_serve_source() {
        let mut sources = Catalog::new(1, 0x1000, 1, 0x3000).unwrap();
        sources.stage(1, b"a.sys", FILE, 0x1000, || Some((SOURCE, 0x2000))).unwrap();
        assert_eq!(sources.get(1, b"a.sys", 2, 0x2000), None);
        assert_eq!(sources.get(1, b"a.sys", 1, 0x1000), None);
    }

    #[test]
    fn loader_normalizes_registry_and_dos_aliases_to_one_source_path() {
        let a = crate::registry_ascii_path(r"C:\Windows\System32\drivers\disk.sys").unwrap();
        let b = crate::registry_ascii_path(r"system32\drivers\disk.sys").unwrap();
        assert_eq!(a, b);
        let mut sources = Catalog::new(1, 0x1000, 1, 0x3000).unwrap();
        sources.stage(1, &a, FILE, 0x1000, || Some((SOURCE, 0x2000))).unwrap();
        assert_eq!(sources.get(1, &b, 1, 0x2000), Some(SOURCE));
    }

    #[test]
    fn upper_and_lower_filter_multisz_requires_exact_termination() {
        let words = [b'd' as u16, b'i' as u16, b's' as u16, b'k' as u16, 0, b'p' as u16, 0, 0];
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert_eq!(parse_filter_services(7, &bytes).unwrap(), ["disk", "p"]);
        assert_eq!(parse_filter_services(1, &bytes), None);
        assert_eq!(parse_filter_services(7, &bytes[..bytes.len() - 2]), None);
    }
}
