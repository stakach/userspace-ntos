//! Native ownership for helper, display, and keyboard system images.

use super::*;
use nt_pe_loader::load_failure::LoadFailure;
use nt_pe_loader::module_namespace::{self, DependencyStack, ImageExports, Symbol};
use nt_pe_loader::system_module::{SystemImageIdentity, SystemModule, SystemModuleHandleIdentity};

struct NativeBacking {
    handle: crate::win32k_subsystem::ProviderPoolPacketLease,
    handle_pin: crate::win32k_subsystem::SharedPoolPin,
    vspace_cap: u64,
    frame_base: u64,
    frame_count: u64,
    frames_created: u64,
    exec_mapped: u64,
    host_mapped: u64,
    exec_maps: Vec<u64>,
    host_maps: Vec<u64>,
    rights: Vec<u64>,
    exec_pt: Option<(u64, bool)>,
    host_pt: Option<(u64, bool)>,
    provider: nt_provider_wait::ProviderDomainIdentity,
    pml4: u64,
    base: u64,
    exception_image: Option<(u64, u32)>,
    exports: ImageExports,
}

static mut LOADED: Vec<SystemModule<NativeBacking>> = Vec::new();
static mut QUARANTINED: Vec<Option<NativeBacking>> = Vec::new();
static mut DEPENDENCIES: Option<DependencyStack> = None;
const DEMAND_BASE: u64 = 0x0000_0100_08b0_0000;
const DEMAND_LIMIT: u64 = win32k_subsystem::WIN32K_FB_VA;
static mut DEMAND_NEXT: u64 = DEMAND_BASE;
const _: () = assert!(WIN32K_STATIC_IMPORT_BASE_VA < WIN32K_STATIC_IMPORT_LIMIT_VA);
const _: () = assert!(WIN32K_STATIC_IMPORT_LIMIT_VA <= DEMAND_BASE);
const _: () = assert!(DEMAND_BASE < DEMAND_LIMIT);

struct DependencyGuard(alloc::string::String);
impl Drop for DependencyGuard {
    fn drop(&mut self) {
        unsafe {
            if (&mut *core::ptr::addr_of_mut!(DEPENDENCIES))
                .as_mut()
                .unwrap()
                .leave(&self.0)
                .is_err()
            {
                crate::provider_bugcheck::report(0xc4, [0, 0, 0, 111]);
            }
        }
    }
}

unsafe fn enter_dependency(name: &str) -> Option<DependencyGuard> {
    let slot = &mut *core::ptr::addr_of_mut!(DEPENDENCIES);
    if slot.is_none() {
        *slot = Some(DependencyStack::default());
    }
    slot.as_mut()?.enter(name).ok()?;
    Some(DependencyGuard(module_namespace::module_leaf(name).ok()?))
}

unsafe fn loaded_name(name: &str, pml4: u64) -> Option<(u64, u32)> {
    let provider = crate::current_win32k_provider_domain()?;
    (&*core::ptr::addr_of!(LOADED))
        .iter()
        .find(|module| {
            module.backing().exports.name == name
                && module.backing().pml4 == pml4
                && module.backing().provider == provider
                && crate::win32k_subsystem::provider_pool_packet_lease_live(module.backing().handle)
        })
        .map(|module| (module.image().base, module.image().size))
}

/// File discovery is shared FS policy, not a driver-name dispatch table.
pub(crate) unsafe fn load_installed(name: &str, pml4: u64) -> Result<(u64, u32), LoadFailure> {
    let name = module_namespace::module_leaf(name).map_err(|_| LoadFailure::InvalidImage)?;
    if let Some(image) = loaded_name(&name, pml4) {
        return Ok(image);
    }
    if module_namespace::core_role(&name).is_some() {
        return Err(LoadFailure::InvalidImage);
    }
    let fs = exec_fs().ok_or(LoadFailure::NativeFailure)?;
    let mut path = b"reactos\\system32\\".to_vec();
    path.extend_from_slice(name.as_bytes());
    let location = fat_open_path(&fs, &path)
        .or_else(|| {
            let mut driver_path = b"reactos\\system32\\drivers\\".to_vec();
            driver_path.extend_from_slice(name.as_bytes());
            fat_open_path(&fs, &driver_path)
        })
        .ok_or(LoadFailure::FileMissing)?;
    if location.1 == 0 {
        return Err(LoadFailure::InvalidImage);
    }
    let source =
        crate::fs_loader::pool_alloc(location.1).ok_or(LoadFailure::InsufficientResources)?;
    if fat_read_file(&fs, location.0, location.1, source) != location.1 {
        return Err(LoadFailure::NativeFailure);
    }
    let file = (source, location.1);
    let bytes = core::slice::from_raw_parts(file.0 as *const u8, file.1 as usize);
    let pe = nt_pe_loader::PeFile::parse(bytes).map_err(|_| LoadFailure::InvalidImage)?;
    let frames = (u64::from(pe.size_of_image()) + 0xfff) / 0x1000;
    let base = DEMAND_NEXT;
    let end = base
        .checked_add(
            frames
                .checked_mul(0x1000)
                .ok_or(LoadFailure::InsufficientResources)?,
        )
        .ok_or(LoadFailure::InsufficientResources)?;
    if end > DEMAND_LIMIT {
        return Err(LoadFailure::InsufficientResources);
    }
    // Never reuse an address after native construction may have partially mapped it.
    DEMAND_NEXT = end
        .checked_add(0xfff)
        .ok_or(LoadFailure::InsufficientResources)?
        & !0xfff;
    let result = load_one_driver_result(file.0, file.1, &name, base, frames, pml4)?;
    let _ = register_system_module(&path, base, result.2);
    Ok((base, result.2))
}

unsafe fn checked_image(
    src: u64,
    length: u32,
    name: &str,
    base: u64,
    frames: u64,
    pml4: u64,
) -> Result<(nt_pe_loader::MappedImage, ImageExports, Vec<u64>, u32), LoadFailure> {
    let bytes = core::slice::from_raw_parts(src as *const u8, length as usize);
    let pe = nt_pe_loader::PeFile::parse(bytes).map_err(|_| LoadFailure::InvalidImage)?;
    if u64::from(pe.size_of_image())
        > frames
            .checked_mul(0x1000)
            .ok_or(LoadFailure::InvalidImage)?
    {
        return Err(LoadFailure::InvalidImage);
    }
    let mut mapped = pe.map(base).map_err(|_| LoadFailure::InvalidImage)?;
    let imports = pe.imports().map_err(|_| LoadFailure::InvalidImage)?;
    for dll in &imports {
        let name =
            module_namespace::module_leaf(&dll.name).map_err(|_| LoadFailure::InvalidImage)?;
        if module_namespace::core_role(&name).is_none() && name != "win32k.sys" {
            load_installed(&name, pml4)?;
        }
    }
    for dll in imports {
        for function in dll.functions {
            let symbol = match &function {
                nt_pe_loader::ImportRef::ByName { name, .. } => Symbol::Name(name.clone()),
                nt_pe_loader::ImportRef::ByOrdinal { ordinal, .. } => Symbol::Ordinal(*ordinal),
            };
            let address = resolve_import(&dll.name, symbol, pml4, &mut Vec::new())?;
            mapped
                .patch_iat(function.iat_slot_rva(), address)
                .map_err(|_| LoadFailure::InvalidImage)?;
        }
    }
    if let Some(rva) = pe.security_cookie_rva() {
        mapped
            .bytes
            .get_mut(
                rva as usize
                    ..(rva as usize)
                        .checked_add(8)
                        .ok_or(LoadFailure::InvalidImage)?,
            )
            .ok_or(LoadFailure::InvalidImage)?
            .copy_from_slice(&nt_pe_loader::SECURITY_COOKIE_SEED.to_le_bytes());
    }
    let exports = ImageExports::from_mapped(name, base, &mapped.bytes)
        .map_err(|_| LoadFailure::InvalidImage)?;
    let mut rights = frame_records(
        usize::try_from(frames).map_err(|_| LoadFailure::InsufficientResources)?,
        RO_NX,
    )
    .ok_or(LoadFailure::InsufficientResources)?;
    for (index, rights) in rights.iter_mut().enumerate() {
        *rights = match pe.protection_at(
            u32::try_from(index.checked_mul(0x1000).ok_or(LoadFailure::InvalidImage)?)
                .map_err(|_| LoadFailure::InvalidImage)?,
        ) {
            nt_pe_loader::Protection::ReadOnly => RO_NX,
            nt_pe_loader::Protection::ReadWrite => RW_NX,
            nt_pe_loader::Protection::ReadExecute => 2,
        };
    }
    let export_rva = pe
        .headers()
        .data_directory(nt_pe_loader::DIRECTORY_ENTRY_EXPORT)
        .virtual_address;
    Ok((mapped, exports, rights, export_rva))
}

unsafe fn resolve_import(
    module: &str,
    symbol: Symbol,
    pml4: u64,
    seen: &mut Vec<(alloc::string::String, Symbol)>,
) -> Result<u64, LoadFailure> {
    let module = module_namespace::module_leaf(module).map_err(|_| LoadFailure::InvalidImage)?;
    if seen.len() >= 64 || seen.iter().any(|pair| pair.0 == module && pair.1 == symbol) {
        return Err(LoadFailure::InvalidImage);
    }
    seen.push((module.clone(), symbol.clone()));
    if let Some(role) = module_namespace::core_role(&module) {
        let Symbol::Name(name) = symbol else {
            return Err(LoadFailure::MissingExport);
        };
        let names = match role {
            module_namespace::CoreRole::Kernel => nt_compat_exports::WIN32K_NTOSKRNL_IMPORTS,
            module_namespace::CoreRole::Hal => nt_compat_exports::WIN32K_HAL_IMPORTS,
        };
        if !names.contains(&name.as_str()) {
            return Err(LoadFailure::MissingExport);
        }
        let address = win32k_subsystem::export_addr(&name);
        return (address != 0)
            .then_some(address)
            .ok_or(LoadFailure::MissingExport);
    }
    let image = if module == "win32k.sys" {
        crate::win32k_seh_image::win32k_exports(pml4).ok_or(LoadFailure::NativeFailure)?
    } else {
        load_installed(&module, pml4)?;
        let provider = crate::current_win32k_provider_domain().ok_or(LoadFailure::NativeFailure)?;
        (&*core::ptr::addr_of!(LOADED))
            .iter()
            .find(|record| {
                record.backing().exports.name == module
                    && record.backing().provider == provider
                    && record.backing().pml4 == pml4
                    && crate::win32k_subsystem::provider_pool_packet_lease_live(
                        record.backing().handle,
                    )
            })
            .ok_or(LoadFailure::NativeFailure)?
            .backing()
            .exports
            .clone()
    };
    let export = image
        .exports
        .iter()
        .find(|export| match &symbol {
            Symbol::Name(name) => export.name == *name,
            Symbol::Ordinal(ordinal) => export.ordinal == *ordinal,
        })
        .ok_or(LoadFailure::MissingExport)?;
    match &export.target {
        module_namespace::ExportTarget::Rva(rva) => {
            if *rva == 0 || *rva >= image.size {
                return Err(LoadFailure::InvalidImage);
            }
            image
                .base
                .checked_add(u64::from(*rva))
                .ok_or(LoadFailure::InvalidImage)
        }
        module_namespace::ExportTarget::Forwarder(target) => {
            let (module, name) = target.rsplit_once('.').ok_or(LoadFailure::InvalidImage)?;
            let module = module_namespace::forwarder_module(module)
                .map_err(|_| LoadFailure::InvalidImage)?;
            let symbol = if let Some(ordinal) = name.strip_prefix('#') {
                Symbol::Ordinal(ordinal.parse().map_err(|_| LoadFailure::InvalidImage)?)
            } else {
                Symbol::Name(alloc::string::String::from(name))
            };
            resolve_import(&module, symbol, pml4, seen)
        }
    }
}

struct Loading {
    backing: Option<NativeBacking>,
    quarantine: usize,
}

impl Drop for Loading {
    fn drop(&mut self) {
        if let Some(mut backing) = self.backing.take() {
            unsafe {
                if rollback_known(&mut backing) {
                    return;
                }
                // Published exception readers or failed exact rollback forbid resource reuse.
                (&mut *core::ptr::addr_of_mut!(QUARANTINED))[self.quarantine] = Some(backing);
            }
        }
    }
}

unsafe fn rollback_known(backing: &mut NativeBacking) -> bool {
    if backing.exception_image.is_some() {
        return false;
    }
    for (maps, mapped) in [
        (&mut backing.host_maps, &mut backing.host_mapped),
        (&mut backing.exec_maps, &mut backing.exec_mapped),
    ] {
        for index in (0..maps.len()).rev() {
            let cap = maps[index];
            if cap == 0 {
                continue;
            }
            if (index as u64) < *mapped {
                if page_unmap_r(cap) != 0 {
                    return false;
                }
                *mapped -= 1;
            }
            if cnode_delete_recycle_r(cap) != 0 {
                return false;
            }
            maps[index] = 0;
        }
    }
    if backing.frame_base != 0 {
        for index in backing.frames_created..backing.frame_count {
            recycle_deleted_root_slot(backing.frame_base + index);
        }
        backing.frame_count = backing.frames_created;
        while backing.frames_created != 0 {
            let cap = backing.frame_base + backing.frames_created - 1;
            if cnode_delete_recycle_r(cap) != 0 {
                return false;
            }
            backing.frames_created -= 1;
            backing.frame_count -= 1;
        }
    }
    // Page-table objects belong to DRIVER_LOAD_PAGE_TABLES, including reusable empty tables.
    if backing.vspace_cap != 0 {
        if cnode_delete_recycle_r(backing.vspace_cap) != 0 {
            return false;
        }
        backing.vspace_cap = 0;
    }
    crate::win32k_subsystem::retire_pinned_root_provider_pool_packet(
        backing.handle,
        backing.handle_pin,
    )
}

fn image_identity(backing: &NativeBacking, res: (u32, u32, u32)) -> SystemImageIdentity {
    SystemImageIdentity {
        provider_domain: backing.provider.domain,
        provider_generation: backing.provider.generation,
        vspace: backing.pml4,
        image_owner: WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire),
        base: backing.base,
        size: res.2,
        entry_rva: res.0,
        export_rva: res.1,
    }
}

fn handle_identity(
    lease: crate::win32k_subsystem::ProviderPoolPacketLease,
) -> SystemModuleHandleIdentity {
    let native = lease.native_identity();
    SystemModuleHandleIdentity {
        address: lease.address(),
        allocation_id: native.allocation_id,
        allocation_generation: native.allocation_generation,
    }
}

pub(crate) unsafe fn module_handle(base: u64, size: u32) -> Option<u64> {
    let provider = crate::current_win32k_provider_domain()?;
    (&*core::ptr::addr_of!(LOADED))
        .iter()
        .find(|module| {
            let image = module.image();
            image.base == base
                && image.size == size
                && image.provider_domain == provider.domain
                && image.provider_generation == provider.generation
                && crate::win32k_subsystem::provider_pool_packet_lease_live(module.backing().handle)
        })
        .map(|module| module.handle().address)
}

pub(crate) unsafe fn acquire_load(handle: u64) -> Result<(), i32> {
    let provider = crate::current_win32k_provider_domain().ok_or(0xc000_0008u32 as i32)?;
    let Some(module) = (&mut *core::ptr::addr_of_mut!(LOADED))
        .iter_mut()
        .find(|module| module.handle().address == handle)
    else {
        return Err(0xc000_0008u32 as i32);
    };
    let image = module.image();
    if image.provider_domain != provider.domain
        || image.provider_generation != provider.generation
        || image.image_owner != WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire)
        || !crate::win32k_subsystem::provider_pool_packet_lease_live(module.backing().handle)
    {
        return Err(0xc000_0008u32 as i32);
    }
    module
        .retain_load(image, handle_identity(module.backing().handle))
        .map(|_| ())
        .map_err(|_| 0xc000_009au32 as i32)
}

pub(crate) unsafe fn unload(handle: u64) -> i32 {
    let Some(module) = (&mut *core::ptr::addr_of_mut!(LOADED))
        .iter_mut()
        .find(|module| module.handle().address == handle)
    else {
        return 0xc000_0008u32 as i32;
    };
    let image = module.image();
    let provider = nt_provider_wait::ProviderDomainIdentity {
        domain: image.provider_domain,
        generation: image.provider_generation,
    };
    if !crate::win32k_provider_domain_is_current(provider)
        || !crate::win32k_subsystem::provider_pool_packet_lease_live(module.backing().handle)
    {
        return 0xc000_0008u32 as i32;
    }
    match module.request_unload(handle_identity(module.backing().handle)) {
        Err(nt_pe_loader::system_module::SystemModuleError::TeardownUnsupported) => {
            0xc000_00bbu32 as i32
        }
        _ => 0xc000_0008u32 as i32,
    }
}

pub(crate) unsafe fn service_request(pointer: u64, length: u64) -> (i32, u64) {
    use nt_pe_loader::system_image_request::{self, Request};
    if length != system_image_request::PACKET_BYTES as u64 {
        return (0xc000_000du32 as i32, 0);
    }
    let _durable = crate::allocator::enter_durable();
    let Ok((lease, bytes)) =
        win32k_subsystem::capture_provider_pool_packet(pointer, length as usize)
    else {
        return (0xc000_000du32 as i32, 0);
    };
    let Some(request) = system_image_request::decode(&bytes) else {
        return (0xc000_000du32 as i32, 0);
    };
    if !win32k_subsystem::provider_pool_packet_lease_live(lease) {
        return (0xc000_000du32 as i32, 0);
    }
    match request {
        Request::Unload(handle) => (unload(handle), 0),
        Request::Load(name) => {
            let pml4 = WIN32K_GDI_LOADER_PML4.load(Ordering::Acquire);
            if pml4 == 0 {
                return (0xc000_00a3u32 as i32, 0);
            }
            let (base, size) = match load_installed(&name, pml4) {
                Ok(image) => image,
                Err(error) => return (error.ntstatus(), 0),
            };
            let Some(handle) = module_handle(base, size) else {
                return (0xc000_0008u32 as i32, 0);
            };
            let Some(module) = (&*core::ptr::addr_of!(LOADED))
                .iter()
                .find(|record| record.handle().address == handle)
            else {
                return (0xc000_0008u32 as i32, 0);
            };
            let image = module.image();
            if !win32k_subsystem::register_gdi_driver_image(
                name.as_bytes(),
                base,
                base + u64::from(image.entry_rva),
                if image.export_rva == 0 {
                    0
                } else {
                    base + u64::from(image.export_rva)
                },
                size,
            ) {
                return (0xc000_009au32 as i32, 0);
            }
            match acquire_load(handle) {
                Ok(()) => (0, handle),
                Err(status) => (status, 0),
            }
        }
    }
}

#[inline(never)]
unsafe fn load_one_driver_fail<T>(
    stage: &[u8],
    subject: u64,
    error: u64,
) -> Result<T, LoadFailure> {
    print_str(b"[win32k-svc] driver image load ");
    print_str(stage);
    print_str(b" failed subject=0x");
    print_hex((subject >> 32) as u32);
    print_hex(subject as u32);
    print_str(b" error=");
    print_u64(error);
    print_str(b"\n");
    Err(LoadFailure::from_native_error(error))
}

#[derive(Clone, Copy)]
struct DriverLoadPageTable {
    pml4: u64,
    base: u64,
    cap: u64,
    mapped: bool,
    provider: Option<nt_provider_wait::ProviderDomainIdentity>,
    image_owner: u64,
}

const DRIVER_LOAD_PT_SPAN: u64 = 0x20_0000;
static mut DRIVER_LOAD_PAGE_TABLES: Option<Vec<DriverLoadPageTable>> = None;

#[inline]
fn driver_load_pt_base(va: u64) -> u64 {
    va & !(DRIVER_LOAD_PT_SPAN - 1)
}

unsafe fn driver_load_page_tables_mut() -> &'static mut Vec<DriverLoadPageTable> {
    let slot = &mut *core::ptr::addr_of_mut!(DRIVER_LOAD_PAGE_TABLES);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn driver_load_page_table_find(pml4: u64, base: u64) -> Option<u64> {
    let provider = if pml4 == CAP_INIT_THREAD_VSPACE {
        None
    } else {
        crate::current_win32k_provider_domain()
    };
    let owner = if provider.is_some() {
        WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire)
    } else {
        0
    };
    (&*core::ptr::addr_of!(DRIVER_LOAD_PAGE_TABLES))
        .as_ref()
        .and_then(|records| {
            records
                .iter()
                .find(|record| {
                    record.pml4 == pml4
                        && record.base == base
                        && record.mapped
                        && record.provider == provider
                        && record.image_owner == owner
                })
                .map(|record| record.cap)
        })
}

unsafe fn driver_load_page_table_insert(pml4: u64, base: u64, cap: u64) -> bool {
    let records = driver_load_page_tables_mut();
    if records.try_reserve(1).is_err() {
        print_str(b"[driver-load] page-table record allocation failed pml4=0x");
        print_hex((pml4 >> 32) as u32);
        print_hex(pml4 as u32);
        print_str(b" base=0x");
        print_hex((base >> 32) as u32);
        print_hex(base as u32);
        print_str(b"\n");
        return false;
    }
    let provider = if pml4 == CAP_INIT_THREAD_VSPACE {
        None
    } else {
        crate::current_win32k_provider_domain()
    };
    if pml4 != CAP_INIT_THREAD_VSPACE && provider.is_none() {
        return false;
    }
    let image_owner = if provider.is_some() {
        WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire)
    } else {
        0
    };
    records.push(DriverLoadPageTable {
        pml4,
        base,
        cap,
        mapped: false,
        provider,
        image_owner,
    });
    true
}

unsafe fn ensure_driver_load_page_table(
    pml4: u64,
    va: u64,
    stage_prefix: &[u8],
    map_pml4: u64,
) -> Result<(u64, bool), LoadFailure> {
    let base = driver_load_pt_base(va);
    if let Some(existing) = driver_load_page_table_find(pml4, base) {
        return Ok((existing, false));
    }
    driver_load_page_tables_mut()
        .try_reserve(1)
        .map_err(|_| LoadFailure::InsufficientResources)?;
    let Some(pt) = try_alloc_slot() else {
        return Err(LoadFailure::InsufficientResources);
    };
    let error = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    if error != 0 {
        recycle_deleted_root_slot(pt);
        return load_one_driver_fail(stage_prefix, pt, error);
    }
    if !driver_load_page_table_insert(pml4, base, pt) {
        crate::provider_bugcheck::report(0xc4, [pml4, base, pt, 110]);
    }
    let error = paging_struct_map_r(pt, LBL_X86_PAGE_TABLE_MAP, base, map_pml4);
    if error != 0 {
        return load_one_driver_fail(stage_prefix, base, error);
    }
    driver_load_page_tables_mut()
        .iter_mut()
        .find(|row| row.cap == pt && row.pml4 == pml4 && row.base == base)
        .expect("retained driver page table")
        .mapped = true;
    Ok((pt, true))
}

fn frame_records(count: usize, value: u64) -> Option<Vec<u64>> {
    let mut records = Vec::new();
    records.try_reserve_exact(count).ok()?;
    records.resize(count, value);
    Some(records)
}

pub(super) unsafe fn load_one_driver_result(
    src_va: u64,
    source_len: u32,
    name: &str,
    dst_va: u64,
    frames: u64,
    host_pml4: u64,
) -> Result<(u32, u32, u32), LoadFailure> {
    let _durable = crate::allocator::enter_durable();
    let _dependency = enter_dependency(name).ok_or(LoadFailure::InvalidImage)?;
    let provider = crate::current_win32k_provider_domain().ok_or(LoadFailure::NativeFailure)?;
    let count = usize::try_from(frames).map_err(|_| LoadFailure::InsufficientResources)?;
    if count == 0
        || dst_va == 0
        || dst_va & 0xfff != 0
        || host_pml4 == 0
        || dst_va
            .checked_add(
                frames
                    .checked_mul(0x1000)
                    .ok_or(LoadFailure::InsufficientResources)?,
            )
            .is_none()
        || WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire) == 0
        || (&*core::ptr::addr_of!(LOADED))
            .iter()
            .any(|module| module.image().base == dst_va)
        || (&*core::ptr::addr_of!(QUARANTINED))
            .iter()
            .flatten()
            .any(|backing| {
                let end = backing
                    .base
                    .saturating_add(backing.frame_count.saturating_mul(0x1000));
                dst_va < end && backing.base < dst_va.saturating_add(frames.saturating_mul(0x1000))
            })
    {
        return Err(LoadFailure::NativeFailure);
    }
    let (mapped, exports, rights, export_rva) =
        checked_image(src_va, source_len, name, dst_va, frames, host_pml4)?;
    let res = (
        mapped.entry_rva,
        export_rva,
        u32::try_from(mapped.bytes.len()).map_err(|_| LoadFailure::InsufficientResources)?,
    );
    let exec_maps = frame_records(count, 0).ok_or(LoadFailure::InsufficientResources)?;
    let host_maps = frame_records(count, 0).ok_or(LoadFailure::InsufficientResources)?;
    (&mut *core::ptr::addr_of_mut!(LOADED))
        .try_reserve(1)
        .map_err(|_| LoadFailure::InsufficientResources)?;
    let failures = &mut *core::ptr::addr_of_mut!(QUARANTINED);
    failures
        .try_reserve(1)
        .map_err(|_| LoadFailure::InsufficientResources)?;
    let index = failures.len();
    failures.push(None);
    let (handle, mut handle_bytes) =
        crate::win32k_subsystem::allocate_root_provider_pool_packet(64)
            .ok_or(LoadFailure::InsufficientResources)?;
    let Some(handle_pin) = crate::win32k_subsystem::pin_root_provider_pool_packet(handle) else {
        if !crate::win32k_subsystem::retire_root_provider_pool_packet(handle) {
            crate::provider_bugcheck::report(0xc4, [handle.address(), 0, 0, 112]);
        }
        return Err(LoadFailure::InsufficientResources);
    };
    let mut loading = Loading {
        quarantine: index,
        backing: Some(NativeBacking {
            handle,
            handle_pin,
            vspace_cap: 0,
            frame_base: 0,
            frame_count: frames,
            frames_created: 0,
            exec_mapped: 0,
            host_mapped: 0,
            exec_maps,
            host_maps,
            rights,
            exec_pt: None,
            host_pt: None,
            provider,
            pml4: host_pml4,
            base: dst_va,
            exception_image: None,
            exports,
        }),
    };
    let backing = loading.backing.as_mut().unwrap();
    let (vspace_cap, error) = copy_cap_r(host_pml4);
    if error != 0 {
        return load_one_driver_fail(b"vspace-retain", host_pml4, error);
    }
    backing.vspace_cap = vspace_cap;
    backing.exec_pt = Some(ensure_driver_load_page_table(
        CAP_INIT_THREAD_VSPACE,
        dst_va,
        b"exec-pt-map",
        CAP_INIT_THREAD_VSPACE,
    )?);
    backing.frame_base = try_alloc_slot_run(frames).ok_or(LoadFailure::InsufficientResources)?;
    for i in 0..frames {
        let error = untyped_retype_r(
            CAP_INIT_UNTYPED,
            OBJ_X86_4K_PAGE,
            PAGING_BITS,
            1,
            backing.frame_base + i,
        );
        if error != 0 {
            return load_one_driver_fail(b"frame-retype", backing.frame_base + i, error);
        }
        backing.frames_created += 1;
    }
    for i in 0..count {
        let (cap, error) = copy_cap_r(backing.frame_base + i as u64);
        if error != 0 {
            return load_one_driver_fail(b"exec-frame-copy", backing.frame_base + i as u64, error);
        }
        backing.exec_maps[i] = cap;
        let va = dst_va + i as u64 * 0x1000;
        ensure_driver_load_page_table(
            CAP_INIT_THREAD_VSPACE,
            va,
            b"exec-pt-map",
            CAP_INIT_THREAD_VSPACE,
        )?;
        let error = page_map_r(cap, va, RW_NX, CAP_INIT_THREAD_VSPACE);
        if error != 0 {
            return load_one_driver_fail(b"exec-frame-map", va, error);
        }
        backing.exec_mapped += 1;
    }
    core::ptr::write_bytes(
        dst_va as *mut u8,
        0,
        count
            .checked_mul(0x1000)
            .ok_or(LoadFailure::InsufficientResources)?,
    );
    core::ptr::copy_nonoverlapping(mapped.bytes.as_ptr(), dst_va as *mut u8, mapped.bytes.len());
    backing.host_pt = Some(ensure_driver_load_page_table(
        host_pml4,
        dst_va,
        b"host-pt-map",
        backing.vspace_cap,
    )?);
    for i in 0..count {
        let (cap, error) = copy_cap_r(backing.frame_base + i as u64);
        if error != 0 {
            return load_one_driver_fail(b"host-frame-copy", backing.frame_base + i as u64, error);
        }
        backing.host_maps[i] = cap;
        let va = dst_va + i as u64 * 0x1000;
        ensure_driver_load_page_table(host_pml4, va, b"host-pt-map", backing.vspace_cap)?;
        let error = page_map_r(cap, va, backing.rights[i], backing.vspace_cap);
        if error != 0 {
            return load_one_driver_fail(b"host-frame-map", va, error);
        }
        backing.host_mapped += 1;
    }
    crate::win32k_seh_image::register_dynamic_image(host_pml4, dst_va, res.2, &backing.rights)
        .ok_or(LoadFailure::NativeFailure)?;
    backing.exception_image = Some((dst_va, res.2));
    if !crate::win32k_provider_domain_is_current(provider) {
        return Err(LoadFailure::NativeFailure);
    }
    for (chunk, value) in handle_bytes.chunks_exact_mut(8).zip([
        0x4744_494d_4f44_554c,
        handle.native_identity().allocation_generation,
        provider.domain,
        provider.generation,
        host_pml4,
        dst_va,
        u64::from(res.2),
        0,
    ]) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    if !crate::win32k_subsystem::publish_provider_pool_packet(handle, &handle_bytes) {
        return Err(LoadFailure::NativeFailure);
    }
    let identity = image_identity(backing, res);
    let owned = loading.backing.take().unwrap();
    let module = match SystemModule::new(identity, handle_identity(handle), owned) {
        Ok(module) => module,
        Err((_, owned)) => {
            loading.backing = Some(owned);
            return Err(LoadFailure::NativeFailure);
        }
    };
    (&mut *core::ptr::addr_of_mut!(LOADED)).push(module);
    Ok(res)
}
