//! ACPI physical authority owned by the executive.
//!
//! `nt-acpi` validates firmware bytes and derives platform resources. This module is the seL4
//! mechanism boundary: it claims only BootInfo device untypeds, retains canonical frame caps, and
//! creates exact component/broker projections for the eventual registry-selected ACPI bus driver.

use crate::*;
use alloc::vec::Vec;

const PAGE_SIZE: u64 = nt_acpi::ACPI_PAGE_SIZE;
const MAX_CANONICAL_PAGES: u64 = 4096;
const BIOS_DATA_AREA_POINTER: u64 = 0x40e;
const EBDA_SCAN_BYTES: u64 = 1024;
const HIGH_BIOS_BASE: u64 = 0xe0000;
const HIGH_BIOS_BYTES: u64 = 0x20000;

pub(crate) const ACPI_ROOT_INSTANCE_PATH: &str = r"ACPI_HAL\PNP0C08\0";
pub(crate) const ACPI_ROOT_HARDWARE_ID: &str = r"ACPI_HAL\PNP0C08";
pub(crate) const ACPI_ROOT_COMPATIBLE_ID: &str = r"*PNP0C08";
const ACPI_ROOT_ENUM_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Enum\ACPI_HAL\PNP0C08\0";

#[derive(Clone, Copy)]
struct ClaimedDeviceRegion {
    paddr: u64,
    pages: u64,
    frame_base: u64,
    validation_va: u64,
}

impl ClaimedDeviceRegion {
    fn end(self) -> Option<u64> {
        self.paddr.checked_add(self.pages.checked_mul(PAGE_SIZE)?)
    }

    fn contains(self, paddr: u64) -> bool {
        self.end()
            .is_some_and(|end| paddr >= self.paddr && paddr < end)
    }

    fn frame_for(self, paddr: u64) -> Option<u64> {
        self.contains(paddr)
            .then(|| self.frame_base + (paddr - self.paddr) / PAGE_SIZE)
    }
}

struct AcpiPhysicalReader<'a> {
    bi: &'a BootInfo,
    owner: &'a mut HostedPnpContextOwner,
    regions: Vec<ClaimedDeviceRegion>,
    validation_base: u64,
    validation_pages: u64,
    failure: Option<nt_status::NtStatus>,
}

impl<'a> AcpiPhysicalReader<'a> {
    unsafe fn new(
        bi: &'a BootInfo,
        owner: &'a mut HostedPnpContextOwner,
    ) -> Result<Self, nt_status::NtStatus> {
        let bytes = MAX_CANONICAL_PAGES
            .checked_mul(PAGE_SIZE)
            .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        let validation_base = reserve_hosted_pnp_root_seed_span(owner, bytes)
            .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        Ok(Self {
            bi,
            owner,
            regions: Vec::new(),
            validation_base,
            validation_pages: 0,
            failure: None,
        })
    }

    fn fail(&mut self, status: nt_status::NtStatus) -> nt_acpi::AcpiError {
        self.failure.get_or_insert(status);
        nt_acpi::AcpiError::PhysicalRead
    }

    unsafe fn claim_page(
        &mut self,
        page_paddr: u64,
    ) -> Result<ClaimedDeviceRegion, nt_acpi::AcpiError> {
        if let Some(region) = self
            .regions
            .iter()
            .copied()
            .find(|region| region.contains(page_paddr))
        {
            return Ok(region);
        }
        let region = unique_device_untyped_containing(self.bi, page_paddr, PAGE_SIZE)
            .ok_or_else(|| self.fail(nt_status::NtStatus::CONFLICTING_ADDRESSES))?;
        let next_validation_pages = self
            .validation_pages
            .checked_add(region.pages)
            .filter(|pages| *pages <= MAX_CANONICAL_PAGES)
            .ok_or_else(|| self.fail(nt_status::NtStatus::INSUFFICIENT_RESOURCES))?;
        let pages = usize::try_from(region.pages)
            .map_err(|_| self.fail(nt_status::NtStatus::INSUFFICIENT_RESOURCES))?;
        if !self.owner.reserve_root_frames(pages) || !self.owner.reserve_alias_caps(pages) {
            return Err(self.fail(nt_status::NtStatus::INSUFFICIENT_RESOURCES));
        }
        self.regions
            .try_reserve(1)
            .map_err(|_| self.fail(nt_status::NtStatus::INSUFFICIENT_RESOURCES))?;
        let checkpoint = self.owner.checkpoint();
        let Some(frame_base) = try_alloc_slot_run(region.pages) else {
            return Err(self.fail(nt_status::NtStatus::INSUFFICIENT_RESOURCES));
        };
        let validation_va = self.validation_base + self.validation_pages * PAGE_SIZE;
        let mut page = 0;
        while page < region.pages {
            let frame = frame_base + page;
            let error = untyped_retype_from_r(region.cap, OBJ_X86_4K_PAGE, PAGING_BITS, 1, frame);
            if error != 0 {
                recycle_unoccupied_run(frame, region.pages - page);
                let _ = self.owner.rollback_to(checkpoint);
                return Err(self.fail(nt_status::NtStatus::UNSUCCESSFUL));
            }
            self.owner.adopt_root_frame(frame, false);
            let expected_paddr = region.paddr + page * PAGE_SIZE;
            if get_frame_paddr(frame) != expected_paddr {
                recycle_unoccupied_run(frame + 1, region.pages - page - 1);
                let _ = self.owner.rollback_to(checkpoint);
                return Err(self.fail(nt_status::NtStatus::CONFLICTING_ADDRESSES));
            }
            let va = validation_va + page * PAGE_SIZE;
            if !ensure_executive_paging(va) {
                recycle_unoccupied_run(frame + 1, region.pages - page - 1);
                let _ = self.owner.rollback_to(checkpoint);
                return Err(self.fail(nt_status::NtStatus::INSUFFICIENT_RESOURCES));
            }
            let (alias, copy_error) = copy_cap_r(frame);
            if copy_error != 0 {
                recycle_unoccupied_run(frame + 1, region.pages - page - 1);
                let _ = self.owner.rollback_to(checkpoint);
                return Err(self.fail(nt_status::NtStatus::UNSUCCESSFUL));
            }
            if page_map_r(alias, va, RO_NX, CAP_INIT_THREAD_VSPACE) != 0 {
                self.owner.adopt_alias_cap(alias, false);
                recycle_unoccupied_run(frame + 1, region.pages - page - 1);
                let _ = self.owner.rollback_to(checkpoint);
                return Err(self.fail(nt_status::NtStatus::UNSUCCESSFUL));
            }
            self.owner.adopt_alias_cap(alias, true);
            page += 1;
        }
        let claimed = ClaimedDeviceRegion {
            paddr: region.paddr,
            pages: region.pages,
            frame_base,
            validation_va,
        };
        self.regions.push(claimed);
        self.validation_pages = next_validation_pages;
        Ok(claimed)
    }

    unsafe fn retain_range(
        &mut self,
        range: nt_acpi::PhysicalRange,
    ) -> Result<(), nt_acpi::AcpiError> {
        let normalized = nt_acpi::normalize_physical_ranges(core::slice::from_ref(&range))?;
        let range = normalized
            .first()
            .copied()
            .ok_or(nt_acpi::AcpiError::InvalidLength)?;
        let end = range
            .start
            .checked_add(range.length)
            .ok_or(nt_acpi::AcpiError::InvalidLength)?;
        let mut page = range.start;
        while page < end {
            let region = self.claim_page(page)?;
            page = region
                .end()
                .ok_or(nt_acpi::AcpiError::InvalidLength)?
                .min(end);
        }
        Ok(())
    }
}

impl nt_acpi::PhysicalMemoryReader for AcpiPhysicalReader<'_> {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, nt_acpi::AcpiError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let end = address
            .checked_add(length as u64)
            .ok_or(nt_acpi::AcpiError::PhysicalRead)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| self.fail(nt_status::NtStatus::INSUFFICIENT_RESOURCES))?;
        bytes.resize(length, 0);
        let mut current = address;
        let mut output_offset = 0usize;
        while current < end {
            let page = current & !(PAGE_SIZE - 1);
            let region = unsafe { self.claim_page(page)? };
            let region_end = region.end().ok_or(nt_acpi::AcpiError::PhysicalRead)?;
            let chunk_end = region_end.min(end);
            let chunk = usize::try_from(chunk_end - current)
                .map_err(|_| nt_acpi::AcpiError::PhysicalRead)?;
            let source = region.validation_va + current - region.paddr;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source as *const u8,
                    bytes.as_mut_ptr().add(output_offset),
                    chunk,
                );
            }
            current = chunk_end;
            output_offset += chunk;
        }
        Ok(bytes)
    }
}

#[derive(Clone)]
pub(crate) struct AcpiMemoryAuthority {
    pub(crate) resource_index: u8,
    pub(crate) paddr: u64,
    pub(crate) length: u64,
    pub(crate) writable: bool,
    pub(crate) frame_base: u64,
    pub(crate) pages: u64,
    pub(crate) component_va: u64,
    pub(crate) broker_va: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct AcpiPortAuthority {
    pub(crate) resource_index: u8,
    pub(crate) base: u64,
    pub(crate) length: u32,
}

pub(crate) struct PreparedAcpiPlatformAuthority {
    pub(crate) discovery: nt_acpi::AcpiPlatformResources,
    pub(crate) memory: Vec<AcpiMemoryAuthority>,
    pub(crate) ports: Vec<AcpiPortAuthority>,
    pub(crate) owner: HostedPnpContextOwner,
}

unsafe fn recycle_unoccupied_run(base: u64, pages: u64) {
    let mut page = 0;
    while page < pages {
        recycle_deleted_root_slot(base + page);
        page += 1;
    }
}

fn canonical_frame_for(regions: &[ClaimedDeviceRegion], paddr: u64) -> Option<u64> {
    let mut result = None;
    for region in regions {
        if let Some(frame) = region.frame_for(paddr) {
            if result.replace(frame).is_some() {
                return None;
            }
        }
    }
    result
}

unsafe fn prepare_memory_authority(
    owner: &mut HostedPnpContextOwner,
    regions: &[ClaimedDeviceRegion],
    resource_index: u8,
    range: nt_acpi::PhysicalRange,
    writable: bool,
) -> Result<AcpiMemoryAuthority, nt_status::NtStatus> {
    if range.start & (PAGE_SIZE - 1) != 0
        || range.length == 0
        || range.length & (PAGE_SIZE - 1) != 0
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let pages = range.length / PAGE_SIZE;
    let pages_usize =
        usize::try_from(pages).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let checkpoint = owner.checkpoint();
    let alias_count = pages_usize
        .checked_mul(2)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    if !owner.reserve_alias_caps(alias_count) {
        return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    }
    let Some(component_va) = reserve_hosted_pnp_component_span(owner, range.length) else {
        let _ = owner.rollback_to(checkpoint);
        return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    };
    let Some(broker_va) = reserve_hosted_pnp_root_seed_span(owner, range.length) else {
        let _ = owner.rollback_to(checkpoint);
        return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    };
    let Some(frame_base) = try_alloc_slot_run(pages) else {
        let _ = owner.rollback_to(checkpoint);
        return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    };
    let mut page = 0;
    while page < pages {
        let paddr = range.start + page * PAGE_SIZE;
        let Some(canonical) = canonical_frame_for(regions, paddr) else {
            recycle_unoccupied_run(frame_base + page, pages - page);
            let _ = owner.rollback_to(checkpoint);
            return Err(nt_status::NtStatus::CONFLICTING_ADDRESSES);
        };
        let source = frame_base + page;
        if copy_cap_into_r(canonical, source) != 0 {
            recycle_unoccupied_run(source, pages - page);
            let _ = owner.rollback_to(checkpoint);
            return Err(nt_status::NtStatus::UNSUCCESSFUL);
        }
        owner.adopt_alias_cap(source, false);
        let va = broker_va + page * PAGE_SIZE;
        if !ensure_executive_paging(va) {
            recycle_unoccupied_run(source + 1, pages - page - 1);
            let _ = owner.rollback_to(checkpoint);
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        }
        let (alias, copy_error) = copy_cap_r(canonical);
        if copy_error != 0 {
            recycle_unoccupied_run(source + 1, pages - page - 1);
            let _ = owner.rollback_to(checkpoint);
            return Err(nt_status::NtStatus::UNSUCCESSFUL);
        }
        let rights = if writable { RW_NX } else { RO_NX };
        if page_map_r(alias, va, rights, CAP_INIT_THREAD_VSPACE) != 0 {
            owner.adopt_alias_cap(alias, false);
            recycle_unoccupied_run(source + 1, pages - page - 1);
            let _ = owner.rollback_to(checkpoint);
            return Err(nt_status::NtStatus::UNSUCCESSFUL);
        }
        owner.adopt_alias_cap(alias, true);
        page += 1;
    }
    Ok(AcpiMemoryAuthority {
        resource_index,
        paddr: range.start,
        length: range.length,
        writable,
        frame_base,
        pages,
        component_va,
        broker_va,
    })
}

unsafe fn discover_acpi_platform_authority_inner(
    bi: &BootInfo,
    owner: &mut HostedPnpContextOwner,
) -> Result<PreparedAcpiPlatformAuthority, nt_status::NtStatus> {
    let root = bi
        .acpi_root_table()
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let mut reader = AcpiPhysicalReader::new(bi, owner)?;
    let discovery = match nt_acpi::discover_platform_resources(
        &mut reader,
        root.paddr,
        root.length,
        nt_acpi::DiscoveryLimits::default(),
    ) {
        Ok(discovery) => discovery,
        Err(_) => return Err(reader.failure.unwrap_or(nt_status::NtStatus::UNSUCCESSFUL)),
    };
    let expected_root_signature = match root.kind {
        BootAcpiRootKind::Rsdt => *b"RSDT",
        BootAcpiRootKind::Xsdt => *b"XSDT",
    };
    if discovery.root.signature != expected_root_signature {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }

    let bda = nt_acpi::PhysicalMemoryReader::read(&mut reader, BIOS_DATA_AREA_POINTER, 2)
        .map_err(|_| reader.failure.unwrap_or(nt_status::NtStatus::UNSUCCESSFUL))?;
    let ebda = u16::from_le_bytes([bda[0], bda[1]]) as u64 * 16;
    let mut bios_ranges = Vec::new();
    bios_ranges
        .try_reserve_exact(3)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    bios_ranges.push(nt_acpi::PhysicalRange {
        start: 0,
        length: PAGE_SIZE,
    });
    if ebda > 0x400 && ebda < 0xa0000 {
        bios_ranges.push(nt_acpi::PhysicalRange {
            start: ebda,
            length: EBDA_SCAN_BYTES.min(0xa0000 - ebda),
        });
    }
    bios_ranges.push(nt_acpi::PhysicalRange {
        start: HIGH_BIOS_BASE,
        length: HIGH_BIOS_BYTES,
    });
    let bios_ranges = nt_acpi::normalize_physical_ranges(&bios_ranges)
        .map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
    for range in &bios_ranges {
        reader
            .retain_range(*range)
            .map_err(|_| reader.failure.unwrap_or(nt_status::NtStatus::UNSUCCESSFUL))?;
    }

    let mut writable_ranges = Vec::new();
    writable_ranges
        .try_reserve_exact(discovery.fixed_registers.len().saturating_add(1))
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    if let Some(facs) = discovery.facs {
        // FACS contains the firmware global lock and waking vector; unlike checksum-validated
        // SDTs, ACPICA is allowed to update it.
        writable_ranges.push(facs);
    }
    let mut ports = Vec::new();
    ports
        .try_reserve_exact(discovery.fixed_registers.len())
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    for block in &discovery.fixed_registers {
        match block.address_space {
            nt_acpi::ADDRESS_SPACE_SYSTEM_MEMORY => {
                writable_ranges.push(nt_acpi::PhysicalRange {
                    start: block.address,
                    length: block.length as u64,
                });
            }
            nt_acpi::ADDRESS_SPACE_SYSTEM_IO => {
                ports.push(AcpiPortAuthority {
                    resource_index: ports.len() as u8,
                    base: block.address,
                    length: block.length as u32,
                });
            }
            _ => return Err(nt_status::NtStatus::INVALID_PARAMETER),
        }
    }
    let writable_ranges = nt_acpi::normalize_physical_ranges(&writable_ranges)
        .map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
    for range in &writable_ranges {
        reader
            .retain_range(*range)
            .map_err(|_| reader.failure.unwrap_or(nt_status::NtStatus::UNSUCCESSFUL))?;
    }
    let mut read_only_ranges = Vec::new();
    read_only_ranges
        .try_reserve_exact(
            discovery
                .tables
                .len()
                .saturating_add(bios_ranges.len())
                .saturating_add(1),
        )
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    read_only_ranges.push(nt_acpi::PhysicalRange {
        start: discovery.root.address,
        length: discovery.root.length as u64,
    });
    read_only_ranges.extend(discovery.tables.iter().map(|table| nt_acpi::PhysicalRange {
        start: table.address,
        length: table.length as u64,
    }));
    read_only_ranges.extend_from_slice(&bios_ranges);
    let read_only_ranges = nt_acpi::subtract_physical_ranges(&read_only_ranges, &writable_ranges)
        .map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
    let memory_resource_count = read_only_ranges
        .len()
        .checked_add(writable_ranges.len())
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    if memory_resource_count > driver_launch::SH_RESOURCE_KIND_CAPACITY as usize
        || ports.len() > driver_launch::SH_RESOURCE_KIND_CAPACITY as usize
    {
        return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    }
    let regions = core::mem::take(&mut reader.regions);
    drop(reader);

    let mut memory = Vec::new();
    memory
        .try_reserve_exact(memory_resource_count)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    for range in read_only_ranges {
        memory.push(prepare_memory_authority(
            owner,
            &regions,
            memory.len() as u8,
            range,
            false,
        )?);
    }
    for range in writable_ranges {
        memory.push(prepare_memory_authority(
            owner,
            &regions,
            memory.len() as u8,
            range,
            true,
        )?);
    }
    Ok(PreparedAcpiPlatformAuthority {
        discovery,
        memory,
        ports,
        owner: core::mem::replace(owner, HostedPnpContextOwner::new()),
    })
}

pub(crate) unsafe fn discover_acpi_platform_authority(
    bi: &BootInfo,
) -> Result<PreparedAcpiPlatformAuthority, nt_status::NtStatus> {
    let mut owner = HostedPnpContextOwner::new();
    let checkpoint = owner.checkpoint();
    match discover_acpi_platform_authority_inner(bi, &mut owner) {
        Ok(authority) => Ok(authority),
        Err(status) => {
            let _ = owner.rollback_to(checkpoint);
            Err(status)
        }
    }
}

fn encode_registry_sz(value: &str) -> Result<Vec<u8>, nt_status::NtStatus> {
    let units = value
        .encode_utf16()
        .count()
        .checked_add(1)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(
            units
                .checked_mul(2)
                .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?,
        )
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    for unit in value.encode_utf16().chain(core::iter::once(0)) {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(encoded)
}

fn encode_registry_multi_sz(values: &[&str]) -> Result<Vec<u8>, nt_status::NtStatus> {
    let units = values.iter().try_fold(1usize, |total, value| {
        total
            .checked_add(value.encode_utf16().count())
            .and_then(|total| total.checked_add(1))
    });
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(
            units
                .and_then(|units| units.checked_mul(2))
                .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?,
        )
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    for value in values {
        for unit in value.encode_utf16().chain(core::iter::once(0)) {
            encoded.extend_from_slice(&unit.to_le_bytes());
        }
    }
    encoded.extend_from_slice(&0u16.to_le_bytes());
    Ok(encoded)
}

/// Publish the firmware-discovered ACPI root identity through normal CriticalDeviceDatabase
/// policy before the boot-driver launch snapshot is taken. No service name is embedded here.
pub(crate) unsafe fn publish_acpi_root_devnode_from_registry_policy(
) -> Result<(), nt_status::NtStatus> {
    let policy = config_manager_query_critical_device_binding(ACPI_ROOT_COMPATIBLE_ID)
        .map_err(nt_status::NtStatus)?
        .ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    let service = policy
        .service_name
        .as_deref()
        .filter(|service| !service.is_empty())
        .ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    if policy.class_guid.is_empty() {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let existing = match config_manager_query_system_hive_key(ACPI_ROOT_ENUM_PATH) {
        Ok(snapshot) => Some(snapshot),
        Err(status) if status as u32 == nt_status::NtStatus::OBJECT_NAME_NOT_FOUND.raw() as u32 => {
            None
        }
        Err(status) => return Err(nt_status::NtStatus(status)),
    };
    let hardware = encode_registry_multi_sz(&[ACPI_ROOT_HARDWARE_ID])?;
    let compatible = encode_registry_multi_sz(&[ACPI_ROOT_COMPATIBLE_ID])?;
    let class = encode_registry_sz(&policy.class_guid)?;
    let service = encode_registry_sz(service)?;
    let values = [
        (
            "HardwareID",
            nt_config_manager::RegistryValueType::MultiSz as u32,
            hardware.as_slice(),
        ),
        (
            "CompatibleIDs",
            nt_config_manager::RegistryValueType::MultiSz as u32,
            compatible.as_slice(),
        ),
        (
            "ClassGUID",
            nt_config_manager::RegistryValueType::Sz as u32,
            class.as_slice(),
        ),
        (
            "Service",
            nt_config_manager::RegistryValueType::Sz as u32,
            service.as_slice(),
        ),
    ];
    if existing.as_ref().is_some_and(|snapshot| {
        values.iter().all(|(name, value_type, data)| {
            snapshot.values.iter().any(|value| {
                value.name.eq_ignore_ascii_case(name)
                    && value.value_type == *value_type
                    && value.data == *data
            })
        })
    }) {
        return Ok(());
    }
    let mut mutations = Vec::new();
    mutations
        .try_reserve_exact(5)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    if existing.is_none() {
        mutations.push(nt_config_client::SystemHiveMutation::CreateKey {
            path: ACPI_ROOT_ENUM_PATH,
        });
    }
    for (name, value_type, data) in values {
        mutations.push(nt_config_client::SystemHiveMutation::SetValue {
            path: ACPI_ROOT_ENUM_PATH,
            name,
            value_type,
            data,
        });
    }
    let outcome = persist_and_publish_system_hive_mutation(&mutations)
        .map_err(|status| nt_status::NtStatus(status as i32))?;
    if outcome.wake_device_action {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(())
}
