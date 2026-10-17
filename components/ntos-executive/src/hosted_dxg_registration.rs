//! Typed admission for the function pointer returned by DxgKrnl's resolver IRP.
//!
//! The source receives an executable thunk only after the provider PE section,
//! source IRP, target DeviceObject projection, both domains and publication
//! have been checked as one registration authority.

use super::*;
use nt_hosted_runtime::{
    DxgEntryAuthority, DxgInitializationData, DxgPdoAliasAuthority,
    DxgRegistrationKey, DxgSourceDriverObject,
    encode_hosted_dxg_registration_thunk,
    hosted_dxg_registration_marshal_policy,
};
use nt_io_manager::{HostedDevicePointerRegistration,
    source_irp_ledger::SourceIrpForwardIdentity};

const DXG_REGISTRATION_IOCTL: u32 = 0x230047;
const PE_EXECUTE: u32 = 0x2000_0000;
static NEXT_AUTHORITY_COOKIE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct DxgResolution {
    cookie: u32,
    binding: HostedExecutableThunkBinding,
    authority: DxgEntryAuthority,
    source: SourceIrpForwardIdentity,
    target: HostedDevicePointerRegistration,
    provider_instance: usize,
    dependent_instance: usize,
    provider_domain: HostedDomainIdentity,
    dependent_domain: HostedDomainIdentity,
    provider_publication_cookie: u64,
    provider_entry_rva: u64,
    driver_object: DxgSourceDriverObject,
}

static mut RESOLUTIONS: Vec<DxgResolution> = Vec::new();

struct DxgPdoAlias {
    provider_instance: usize,
    dependent_instance: usize,
    provider_pdo: HostedDevicePointerRegistration,
    dependent_domain: HostedDomainIdentity,
    dependent_alias: Option<HostedDevicePointerRegistration>,
    alias_allocation: Option<nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity>,
    authority: Option<DxgPdoAliasAuthority>,
    context: u64,
    callback_entered: bool,
    pointer_retired: bool,
    blocked: bool,
}

static mut PDO_ALIASES: Vec<DxgPdoAlias> = Vec::new();

unsafe fn pdo_aliases_mut() -> &'static mut Vec<DxgPdoAlias> {
    &mut *core::ptr::addr_of_mut!(PDO_ALIASES)
}

fn reject(stage: &[u8], status: i32) -> i32 {
    print_str(b"[dxg-bridge] reject stage=");
    print_str(stage);
    print_str(b" status=0x");
    print_hex(status as u32);
    print_str(b"\n");
    status
}

fn read_pe_u16(base: u64, image_len: u64, offset: u64) -> Option<u16> {
    (offset.checked_add(2)? <= image_len)
        .then(|| unsafe { read_unaligned((base + offset) as *const u16) })
}

fn read_pe_u32(base: u64, image_len: u64, offset: u64) -> Option<u32> {
    (offset.checked_add(4)? <= image_len)
        .then(|| unsafe { read_unaligned((base + offset) as *const u32) })
}

/// The mapped PE retains its section headers. Require the entry to be inside
/// the exact current image's executable section, not merely image allocation.
fn executable_extent(singleton: HostedProviderSingleton, entry_rva: u64) -> Option<(u64, u64)> {
    let image_len = singleton.image_len as u64;
    let base = singleton.exec_va;
    if image_len < 0x100 || read_pe_u16(base, image_len, 0)? != 0x5a4d {
        return None;
    }
    let nt = read_pe_u32(base, image_len, 0x3c)? as u64;
    if read_pe_u32(base, image_len, nt)? != 0x4550 {
        return None;
    }
    let count = read_pe_u16(base, image_len, nt.checked_add(6)?)? as u64;
    let optional_len = read_pe_u16(base, image_len, nt.checked_add(20)?)? as u64;
    let section_base = nt.checked_add(24)?.checked_add(optional_len)?;
    for index in 0..count {
        let section = section_base.checked_add(index.checked_mul(40)?)?;
        let end = section.checked_add(40)?;
        if end > image_len { return None; }
        let size = u64::from(read_pe_u32(base, image_len, section + 8)?
            .max(read_pe_u32(base, image_len, section + 16)?));
        let rva = u64::from(read_pe_u32(base, image_len, section + 12)?);
        let characteristics = read_pe_u32(base, image_len, section + 36)?;
        let section_end = rva.checked_add(size)?;
        if characteristics & PE_EXECUTE != 0
            && size != 0 && section_end <= image_len
            && entry_rva >= rva && entry_rva < section_end
        {
            return Some((singleton.run_va.checked_add(rva)?, size));
        }
    }
    None
}

/// The component preamble publishes SH_DRVOBJ before entering DriverEntry.
/// Capture its live pool allocation and generation under the pool lock;
/// post-entry DriverInstance.driver_object may still be zero.
unsafe fn source_driver_object(
    source_index: usize,
    inst: DriverInstance,
) -> Option<DxgSourceDriverObject> {
    if io_manager_mut().driver(DriverId(inst.driver_id)).is_none()
        || !hosted_pretransport_retirement::has_canonical_driver(source_index)
    {
        return None;
    }
    let shared = read_volatile((inst.exec_shared_va + SH_DRVOBJ) as *const u64);
    let _guard = hosted_instance_pool_lock(inst.exec_pool_va)?;
    if hosted_instance_pool_allocation_is_free_unlocked(inst, shared) != Some(false) {
        return None;
    }
    let exec = hosted_pool_allocation_exec_va(inst.exec_pool_va,
        shared, WDM_X64_DRIVER_OBJECT_SIZE as u64)?;
    if read_unaligned((exec + 2) as *const u16) != WDM_X64_DRIVER_OBJECT_SIZE as u16 {
        return None;
    }
    let generation = read_volatile((exec - 8) as *const u64);
    DxgSourceDriverObject::admit(inst.driver_object, shared, generation, inst.driver_id)
}

pub(crate) unsafe fn bridge_dxg_registration_entry(
    source_index: usize,
    provider_index: usize,
    source_identity: SourceIrpForwardIdentity,
    target: HostedDevicePointerRegistration,
    ioctl_code: u32,
    provider_entry_va: u64,
) -> Result<u64, i32> {
    print_str(b"[dxg-bridge] resolve entry=0x");
    print_hex64(provider_entry_va);
    print_str(b" source=");
    print_u64(source_index as u64);
    print_str(b" provider=");
    print_u64(provider_index as u64);
    print_str(b" target-gen=");
    print_u64(target.generation());
    print_str(b"\n");
    if ioctl_code != DXG_REGISTRATION_IOCTL { return Err(reject(b"protocol", STATUS_NOT_SUPPORTED)); }
    let dependent = instance(source_index).ok_or_else(|| reject(b"source-instance", STATUS_DEVICE_NOT_READY))?;
    let provider = instance(provider_index).ok_or_else(|| reject(b"provider-instance", STATUS_DEVICE_NOT_READY))?;
    let dependent_domain = instance_domain_identity(dependent).ok_or_else(|| reject(b"source-domain", STATUS_DEVICE_NOT_READY))?;
    let provider_domain = instance_domain_identity(provider).ok_or_else(|| reject(b"provider-domain", STATUS_DEVICE_NOT_READY))?;
    if source_index == provider_index
        || source_identity.allocation().domain != dependent_domain
        || source_identity.ticket().domain != dependent_domain
    { return Err(reject(b"source-identity", STATUS_INVALID_PARAMETER)); }
    if target.domain() != dependent_domain
        || io_manager_mut().hosted_device_pointer_registration(target.domain(), target.address()) != Some(target)
    { return Err(reject(b"target-registration", STATUS_INVALID_PARAMETER)); }
    let driver_object = source_driver_object(source_index, dependent)
        .ok_or_else(|| reject(b"source-driver-bootstrap", STATUS_INVALID_PARAMETER))?;
    let singleton = hosted_provider_singletons()
        .and_then(|rows| rows.iter().copied().find(|row| {
            row.present && row.instance == provider_index && row.owner_domain == provider_domain
        }))
        .ok_or_else(|| reject(b"singleton", STATUS_DEVICE_NOT_READY))?;
    let entry_rva = provider_entry_va.checked_sub(singleton.run_va)
        .ok_or_else(|| reject(b"entry-base", STATUS_INVALID_PARAMETER))?;
    let (exec_start, exec_len) = executable_extent(singleton, entry_rva)
        .ok_or_else(|| reject(b"executable-section", STATUS_INVALID_PARAMETER))?;
    ensure_hosted_provider_domain_dependency(provider_index,
        singleton.provider_publication_cookie, source_index)
        .map_err(|status| reject(b"dependency", status))?;
    let owner = hosted_provider_object_owner_for_pair(provider_index, source_index)
        .ok_or_else(|| reject(b"owner", STATUS_DEVICE_NOT_READY))?;
    let registration = DxgRegistrationKey::new(owner, singleton.provider_publication_cookie,
        driver_object.address(), driver_object.generation())
        .ok_or_else(|| reject(b"registration-key", STATUS_INVALID_PARAMETER))?;
    let authority = DxgEntryAuthority::new(registration, target.device_id().raw(),
        target.generation(), source_identity.ticket().generation.get(), provider_entry_va,
        exec_start, exec_len).ok_or_else(|| reject(b"entry-authority", STATUS_INVALID_PARAMETER))?;
    let descriptor = hosted_provider_domain_descriptor(singleton);
    let plan = match plan_hosted_provider_import_binding(Some(descriptor), entry_rva) {
        Ok(HostedProviderImportBinding::ProviderDomainCall(plan)) => plan,
        _ => return Err(reject(b"import-plan", STATUS_DEVICE_NOT_READY)),
    };
    let cookie = NEXT_AUTHORITY_COOKIE.fetch_add(1, Ordering::Relaxed);
    if cookie == 0 || cookie > u32::MAX as u64 { return Err(STATUS_INSUFFICIENT_RESOURCES); }
    let key = HostedThunkSlotKey::new(owner, HOSTED_THUNK_PURPOSE_DXG_REGISTRATION,
        provider_entry_va, cookie).ok_or(STATUS_INVALID_PARAMETER)?;
    let reservation = reserve_instance_executable_thunk(source_index, key)?;
    if reservation.existing {
        abort_instance_executable_thunk(source_index, reservation);
        return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
    }
    let thunk = match plan_hosted_provider_import_thunk(dependent.run_thunk_va,
        dependent.thunk_len, reservation.thunk_index, plan) {
        Ok(thunk) => thunk,
        Err(_) => {
            abort_instance_executable_thunk(source_index, reservation);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let slot = core::slice::from_raw_parts_mut(reservation.exec_va as *mut u8,
        HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN as usize);
    if encode_hosted_dxg_registration_thunk(thunk, cookie as u32, slot).is_err() {
        abort_instance_executable_thunk(source_index, reservation);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let resolutions = &mut *core::ptr::addr_of_mut!(RESOLUTIONS);
    if resolutions.try_reserve(1).is_err() {
        abort_instance_executable_thunk(source_index, reservation);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    if !register_hosted_provider_internal_marshal_policy(provider_domain,
        singleton.provider_publication_cookie, entry_rva,
        hosted_dxg_registration_marshal_policy())
        || !commit_instance_executable_thunk(source_index, reservation)
    {
        abort_instance_executable_thunk(source_index, reservation);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    resolutions.push(DxgResolution {
        cookie: cookie as u32, binding: reservation.address(source_index).binding,
        authority, source: source_identity, target,
        provider_instance: provider_index, dependent_instance: source_index,
        provider_domain, dependent_domain,
        provider_publication_cookie: singleton.provider_publication_cookie,
        provider_entry_rva: entry_rva, driver_object,
    });
    Ok(reservation.run_va)
}

/// Called only after clear_instance has quiesced file ownership and marked the
/// provider dependency retiring. Keep a failed binding in the table so neither
/// its slot nor its generation can be reused on an uncertain release.
pub(super) unsafe fn retire_for_instance(
    instance_index: usize,
    domain: HostedDomainIdentity,
) -> u64 {
    let resolutions = &mut *core::ptr::addr_of_mut!(RESOLUTIONS);
    let mut failures = 0u64;
    let mut index = 0usize;
    while index < resolutions.len() {
        let record = resolutions[index];
        if record.provider_instance != instance_index
            && record.dependent_instance != instance_index
        {
            index += 1;
            continue;
        }
        let exact_domain = (record.provider_instance == instance_index
            && record.provider_domain == domain)
            || (record.dependent_instance == instance_index
                && record.dependent_domain == domain);
        if !exact_domain || !release_instance_executable_thunk_binding(record.binding, true) {
            failures += 1;
            index += 1;
            continue;
        }
        resolutions.swap_remove(index);
    }
    failures
}

pub(super) unsafe fn validate_call(
    provider_instance: usize,
    dependent_instance: usize,
    publication_cookie: u64,
    entry_rva: u64,
    args: &[u64; HOSTED_PROVIDER_EXPORT_ARG_CAP],
) -> bool {
    let Some(record) = (&*core::ptr::addr_of!(RESOLUTIONS))
        .iter().find(|record| record.cookie as u64 == args[3]) else { return false; };
    let Some(dependent) = instance(dependent_instance) else { return false; };
    let Some(provider) = instance(provider_instance) else { return false; };
    let Some(dependent_domain) = instance_domain_identity(dependent) else { return false; };
    let Some(provider_domain) = instance_domain_identity(provider) else { return false; };
    let Some(owner) = hosted_provider_object_owner_for_pair(provider_instance, dependent_instance)
        else { return false; };
    let Some(driver_object) = source_driver_object(dependent_instance, dependent) else { return false; };
    let Some(singleton) = hosted_provider_singletons().and_then(|rows| rows.iter().copied().find(|row| {
        row.present && row.instance == provider_instance
            && row.owner_domain == provider_domain
            && row.provider_publication_cookie == publication_cookie
    })) else { return false; };
    let Some(provider_entry_va) = singleton.run_va.checked_add(entry_rva) else { return false; };
    let Some(key) = DxgRegistrationKey::new(owner, publication_cookie,
        driver_object.address(), driver_object.generation()) else { return false; };
    record.provider_instance == provider_instance
        && record.dependent_instance == dependent_instance
        && record.provider_publication_cookie == publication_cookie
        && record.provider_entry_rva == entry_rva
        && record.driver_object == driver_object
        && record.driver_object.address() == args[0]
        && record.source.allocation().domain == dependent_domain
        && record.target.domain() == dependent_domain
        && io_manager_mut().hosted_device_pointer_registration(record.target.domain(), record.target.address()) == Some(record.target)
        && record.authority.matches(key, record.target.device_id().raw(),
            record.target.generation(), record.source.ticket().generation.get(),
            provider_entry_va)
        && driver_instance_thunk_slots().and_then(|rows| rows.get(dependent_instance))
            .is_some_and(|slots| slots.is_live(record.binding.token, record.binding.key))
}

/// DxgKrnl supplies its PDO and an out cell in the provider VSpace. The
/// miniport receives a separate PDO projection of the same canonical Device.
/// The alias owner is recorded before entering either component and retained
/// on every uncertain result.
pub(super) unsafe fn service_add_device_callback(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    marshal_window: HostedProviderMarshalWindow,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    provider_pdo_address: u64,
    provider_context_out: u64,
) -> Result<u64, i32> {
    let provider_pdo = hosted_add_device_rollback::active_pdo_registration(
        record.provider_instance, record.provider_domain, provider_pdo_address)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let (_, output_allocation) = hosted_add_device_rollback::active_created_output(
        record.provider_instance, record.provider_domain, provider_pdo,
        provider_context_out).ok_or(STATUS_INVALID_PARAMETER)?;
    let owner = hosted_provider_object_owner_for_pair(
        record.provider_instance, record.dependent_instance)
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    if instance_domain_identity(provider_inst) != Some(record.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(record.dependent_domain)
        || provider_pdo.device_id().raw() == 0
        || provider_callback_marshal_window(marshal_window, 8, 0).is_err()
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let alias_index = {
        let aliases = pdo_aliases_mut();
        if aliases.iter().any(|alias| {
            alias.provider_instance == record.provider_instance
                && alias.dependent_instance == record.dependent_instance
                && alias.provider_pdo == provider_pdo
        }) {
            return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
        }
        aliases.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let index = aliases.len();
        aliases.push(DxgPdoAlias {
            provider_instance: record.provider_instance,
            dependent_instance: record.dependent_instance,
            provider_pdo,
            dependent_domain: record.dependent_domain,
            dependent_alias: None,
            alias_allocation: None,
            authority: None,
            context: 0,
            callback_entered: false,
            pointer_retired: false,
            blocked: true,
        });
        index
    };
    let dependent_pdo = create_hosted_pdo_projection(
        record.dependent_instance, crate::initial_system_driver_caller())
        .map_err(|status| status.raw())?;
    let alias_allocation = hosted_device_allocations::capture_allocation(
        dependent_inst, dependent_pdo).map_err(|status| status.raw())?;
    pdo_aliases_mut()[alias_index].alias_allocation = Some(alias_allocation);
    let dependent_alias = match register_unlinked_hosted_device_projection(
        dependent_inst, record.dependent_domain, dependent_pdo, provider_pdo.device_id()) {
        Ok(registration) => registration,
        Err(error) => {
            pdo_aliases_mut()[alias_index].dependent_alias = error.accepted_registration();
            return Err(error.status.raw());
        }
    };
    pdo_aliases_mut()[alias_index].dependent_alias = Some(dependent_alias);
    let authority = DxgPdoAliasAuthority::new(
        owner, record.provider_publication_cookie, provider_pdo.device_id().raw(),
        provider_pdo.address(), provider_pdo.generation(),
        dependent_alias.address(), dependent_alias.generation())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    pdo_aliases_mut()[alias_index].authority = Some(authority);
    if hosted_device_allocations::capture_allocation(dependent_inst, dependent_pdo)
        .ok() != Some(alias_allocation)
        || io_manager_mut().hosted_device_pointer_registration(
            record.dependent_domain, dependent_pdo) != Some(dependent_alias)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    write_unaligned(marshal_window.exec_base as *mut u64, 0);
    pdo_aliases_mut()[alias_index].callback_entered = true;
    let result = dispatch_dependent_provider_callback(
        dispatch, record, dependent_inst, exec_code_va,
        [dependent_pdo, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS],
    )?;
    let status = result as u32 as i32;
    if status >= 0 {
        let current_provider = hosted_add_device_rollback::active_created_output(
            record.provider_instance, record.provider_domain, provider_pdo,
            provider_context_out).ok_or(STATUS_INVALID_PARAMETER)?;
        if current_provider.1 != output_allocation
            || hosted_device_allocations::capture_allocation(
                dependent_inst, dependent_pdo).ok() != Some(alias_allocation)
            || io_manager_mut().hosted_device_pointer_registration(
                record.dependent_domain, dependent_pdo) != Some(dependent_alias)
            || !authority.matches(owner, record.provider_publication_cookie,
                provider_pdo.device_id().raw(), provider_pdo.address(),
                provider_pdo.generation(), dependent_alias.address(),
                dependent_alias.generation())
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let context = read_unaligned(marshal_window.exec_base as *const u64);
        write_unaligned(current_provider.0 as *mut u64, context);
        pdo_aliases_mut()[alias_index].context = context;
        pdo_aliases_mut()[alias_index].blocked = false;
    }
    Ok(result)
}

/// After clear_instance drains the dependency, remove only fully published
/// aliases whose exact registration and physical allocation still match.
/// A lost callback result keeps its owner and prevents domain reuse.
pub(super) unsafe fn retire_pdo_aliases_for_instance(
    instance_index: usize,
    domain: HostedDomainIdentity,
) -> u64 {
    let mut failures = 0u64;
    let mut index = 0usize;
    while index < pdo_aliases_mut().len() {
        let row = &pdo_aliases_mut()[index];
        if row.provider_instance != instance_index
            && row.dependent_instance != instance_index
        {
            index += 1;
            continue;
        }
        let dependent = row.dependent_instance;
        let alias = row.dependent_alias;
        let allocation = row.alias_allocation;
        let domain_matches = row.dependent_instance == instance_index
            && row.dependent_domain == domain;
        if !domain_matches || row.blocked || !row.callback_entered {
            failures += 1;
            index += 1;
            continue;
        }
        let Some(alias) = alias else {
            failures += 1;
            index += 1;
            continue;
        };
        let Some(inst) = instance(dependent) else {
            failures += 1;
            index += 1;
            continue;
        };
        if hosted_device_allocations::capture_allocation(inst, alias.address()).ok()
            != allocation
        {
            pdo_aliases_mut()[index].blocked = true;
            failures += 1;
            index += 1;
            continue;
        }
        if !pdo_aliases_mut()[index].pointer_retired {
            if io_manager_mut().hosted_device_pointer_registration(domain, alias.address())
                != Some(alias)
                || io_manager_mut().retire_hosted_device_pointer(alias).is_err()
            {
                pdo_aliases_mut()[index].blocked = true;
                failures += 1;
                index += 1;
                continue;
            }
            pdo_aliases_mut()[index].pointer_retired = true;
        }
        if retire_hosted_device_projection(inst, alias.address(),
            CanonicalRetirement::Retired { registration: alias }, None).is_err()
        {
            pdo_aliases_mut()[index].blocked = true;
            failures += 1;
            index += 1;
            continue;
        }
        pdo_aliases_mut().swap_remove(index);
    }
    failures
}

pub(super) unsafe fn marshal_initialization_data(
    state: &mut ProviderMarshalState,
    provider_instance: usize,
    dependent_instance: usize,
    dependent_inst: DriverInstance,
    marshal_window: HostedProviderMarshalWindow,
    source_va: u64,
) -> Result<u64, i32> {
    let header_exec = provider_marshal_source_to_exec(state, dependent_instance,
        dependent_inst, source_va, 4).ok_or(STATUS_INVALID_PARAMETER)?;
    let version = read_unaligned(header_exec as *const u32);
    let prefix_len = DxgInitializationData::required_prefix_len(version)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let source_exec = provider_marshal_source_to_exec(state, dependent_instance,
        dependent_inst, source_va, prefix_len as u64).ok_or(STATUS_INVALID_PARAMETER)?;
    let source = core::slice::from_raw_parts(source_exec as *const u8, prefix_len);
    let table = DxgInitializationData::parse(source).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let owner = hosted_provider_object_owner_for_pair(provider_instance, dependent_instance)
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    let mut callbacks = Vec::new();
    callbacks.try_reserve_exact(table.callback_slot_count())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let mut keys = Vec::new();
    keys.try_reserve_exact(table.callback_slot_count())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for slot in table.callbacks() {
        // Only an executable image mapping may become a reverse-call target.
        let image_end = FSD_CODE_VA
            .checked_add(dependent_inst.image_frames.checked_mul(0x1000)
                .ok_or(STATUS_INVALID_PARAMETER)?)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if slot.target < FSD_CODE_VA || slot.target >= image_end {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let discriminator = hosted_provider_callback_discriminator(
            slot.offset as u64, HOSTED_PROVIDER_CALLBACK_KIND_DXG, table.version())
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let key = HostedThunkSlotKey::new(owner, HOSTED_THUNK_PURPOSE_PROVIDER_CALLBACK,
            slot.target, discriminator).ok_or(STATUS_INVALID_PARAMETER)?;
        callbacks.push(slot);
        keys.push(key);
    }
    let reservations = reserve_instance_executable_thunk_batch(provider_instance, &keys)?;
    let (provider_va, provider_exec) = match provider_marshal_alloc(state, marshal_window,
        prefix_len as u64) {
        Some(addresses) => addresses,
        None => {
            for reservation in reservations { abort_instance_executable_thunk(provider_instance, reservation); }
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    copy_bytes(provider_exec, source_exec, prefix_len as u64);
    if !callbacks.is_empty() {
        match reserve_hosted_provider_callback_parent(provider_instance,
            dependent_instance, HOSTED_PROVIDER_CALLBACK_PARENT_KIND_DXG) {
            Ok(index) => state.callback_parent_construction_index = index,
            Err(error) => {
                for reservation in reservations { abort_instance_executable_thunk(provider_instance, reservation); }
                return Err(error);
            }
        }
    }
    for index in 0..reservations.len() {
        let callback = callbacks[index];
        let reservation = reservations[index];
        let thunk = match provider_marshal_emit_callback_thunk_reserved(
            provider_instance, dependent_instance, callback.target,
            callback.offset as u64, HOSTED_PROVIDER_CALLBACK_KIND_DXG,
            table.version(), reservation) {
            Ok(thunk) => thunk,
            Err(error) => {
                for pending in reservations.iter().skip(index + 1).copied() {
                    abort_instance_executable_thunk(provider_instance, pending);
                }
                return Err(error);
            }
        };
        if !retain_hosted_provider_callback_parent_binding(
            state.callback_parent_construction_index, thunk.binding) {
            let _ = release_instance_executable_thunk_binding(thunk.binding, true);
            for pending in reservations.iter().skip(index + 1).copied() {
                abort_instance_executable_thunk(provider_instance, pending);
            }
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        write_unaligned((provider_exec + callback.offset as u64) as *mut u64, thunk.run_va);
    }
    Ok(provider_va)
}
