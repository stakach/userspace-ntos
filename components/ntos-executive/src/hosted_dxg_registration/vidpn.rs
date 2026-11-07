//! One exact provider-owned VidPN for a miniport EnumCofuncModality call.
//!
//! The argument has no nested pointer. Its hConstrainingVidPn is an opaque
//! provider handle; the DXGK_VIDPN_INTERFACE it names is projected separately
//! through the registered DxgkCbQueryVidPnInterface callback.

use super::*;
use nt_hosted_runtime::{DxgEnumVidPnRequest, DxgIsSupportedVidPnRequest,
    DxgVidPnInterfaceLayout, DxgVidPnMethodRouteKey,
    DxgVidPnPathLayout, DxgVidPnTableKind, encode_hosted_provider_import_thunk};

#[path = "vidpn_modes.rs"]
pub(in crate::driver_launch) mod modes;
#[path = "vidpn_timing.rs"]
pub(in crate::driver_launch) mod timing;
#[path = "vidpn_visibility.rs"]
pub(in crate::driver_launch) mod visibility;

struct VidPnMethodCallback {
    kind: DxgVidPnTableKind,
    slot: usize,
    provider_rva: u64,
    binding: Option<HostedExecutableThunkBinding>,
}

struct VidPnProjectedInterface {
    kind: DxgVidPnTableKind,
    provider_table: u64,
    dependent_table: Option<u64>,
    dependent_table_allocation: nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity,
    callbacks: Vec<VidPnMethodCallback>,
}

#[derive(Clone, Copy)]
pub(in crate::driver_launch) struct VidPnMethodFrame {
    alias_index: usize,
    kind: DxgVidPnTableKind,
    slot: usize,
    provider_out: [u64; 2],
    dependent_out: [u64; 2],
}

struct VidPnPathReceipt {
    provider_path: u64,
    dependent_path: Option<u64>,
    provider_allocation: nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity,
    dependent_allocation: nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity,
    pending: bool,
    terminal: bool,
}

#[derive(Clone, Copy)]
pub(in crate::driver_launch) struct TopologyMethodFrame {
    alias_index: usize,
    slot: usize,
    provider_output: u64,
    dependent_output: u64,
    output_bytes: u64,
    input_path: Option<usize>,
}

impl VidPnProjectedInterface {
    unsafe fn release(&mut self, dependent_inst: DriverInstance) -> Result<(), i32> {
        for callback in self.callbacks.iter_mut().rev() {
            if let Some(binding) = callback.binding {
                if !release_instance_executable_thunk_binding(binding, true) {
                    return Err(STATUS_DEVICE_NOT_READY);
                }
                callback.binding = None;
            }
        }
        if let Some(table) = self.dependent_table {
            if hosted_device_allocations::capture_range_allocation(
                dependent_inst, table, self.kind.bytes() as u64).ok()
                != Some(self.dependent_table_allocation)
            { return Err(STATUS_DEVICE_NOT_READY); }
            if !hosted_instance_pool_free(dependent_inst, table) {
                return Err(STATUS_DEVICE_NOT_READY);
            }
            self.dependent_table = None;
        }
        Ok(())
    }
}

pub(super) struct VidPnInFlight {
    request: DxgQueryOutputGuard,
    vidpn: Option<StartOutputGuard>,
    provider_vidpn: u64,
    timing_results: Option<DxgQueryOutputGuard>,
    timing_paths: Option<DxgQueryOutputGuard>,
    dependent_instance: usize,
    dependent_domain: HostedDomainIdentity,
    topology_handle: Option<u64>,
    topology_allocation: Option<nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity>,
    mode_sets: Vec<modes::ModeSetReceipt>,
    mode_objects: Vec<modes::ModeObjectReceipt>,
    paths: Vec<VidPnPathReceipt>,
    terminal: bool,
    nested_uncertain: bool,
    interfaces: Vec<VidPnProjectedInterface>,
}

impl VidPnInFlight {
    pub(super) fn may_settle(&self) -> bool { self.terminal && !self.nested_uncertain }
    pub(super) fn handle(&self) -> u64 { self.provider_vidpn }

    unsafe fn live(&self, inst: DriverInstance, domain: HostedDomainIdentity) -> bool {
        self.request.live(inst, domain)
            && self.vidpn.as_ref().is_none_or(|guard| guard.live(inst, domain))
            && self.timing_results.as_ref().is_none_or(|guard| guard.live(inst, domain))
            && self.timing_paths.as_ref().is_none_or(|guard| guard.live(inst, domain))
    }

    fn retain_uncertain(&mut self) {
        self.nested_uncertain = true;
        self.request.retain_uncertain();
        if let Some(vidpn) = self.vidpn.as_mut() { vidpn.retain_uncertain(); }
        if let Some(results) = self.timing_results.as_ref() { results.retain_uncertain(); }
        if let Some(paths) = self.timing_paths.as_ref() { paths.retain_uncertain(); }
    }

    pub(super) unsafe fn release(&mut self) -> Result<(), i32> {
        // Thunks are unpublished only after the callback has returned and the
        // dependent can no longer call them. Each successful release is
        // recorded, so process retirement may settle a partial release.
        let dependent_inst = instance(self.dependent_instance)
            .ok_or(STATUS_DEVICE_NOT_READY)?;
        if instance_domain_identity(dependent_inst) != Some(self.dependent_domain) {
            return Err(STATUS_DEVICE_NOT_READY);
        }
        modes::release_mode_receipts(self, dependent_inst)?;
        for path in self.paths.iter_mut().rev() {
            if !path.terminal { return Err(STATUS_DEVICE_NOT_READY); }
            if let Some(pointer) = path.dependent_path {
                if hosted_device_allocations::capture_range_allocation(
                    dependent_inst, pointer, DxgVidPnPathLayout::BYTES as u64).ok()
                    != Some(path.dependent_allocation)
                    || !hosted_instance_pool_free(dependent_inst, pointer)
                { return Err(STATUS_DEVICE_NOT_READY); }
                path.dependent_path = None;
            }
        }
        for interface in self.interfaces.iter_mut().rev() {
            interface.release(dependent_inst)?;
        }
        self.request.release()?;
        if let Some(vidpn) = self.vidpn.as_mut() { vidpn.release()?; }
        if let Some(results) = self.timing_results.as_mut() { results.release()?; }
        if let Some(paths) = self.timing_paths.as_mut() { paths.release()?; }
        Ok(())
    }
}

/// Admit one started miniport callback through its exact PDO, context,
/// publication cookie, domain pair, and physical device registration before
/// dereferencing any provider-supplied request pointer.
pub(super) unsafe fn admit_callback_alias(
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    provider_context: u64,
) -> Result<usize, i32> {
    let owner = hosted_provider_object_owner_for_pair(
        record.provider_instance, record.dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let alias_index = pdo_aliases_mut().iter().position(|alias| {
        alias.provider_instance == record.provider_instance
            && alias.dependent_instance == record.dependent_instance
            && alias.provider_domain == record.provider_domain
            && alias.dependent_domain == record.dependent_domain
            && alias.provider_publication_cookie == record.provider_publication_cookie
            && alias.context == provider_context && alias.context_allocation.is_some()
            && alias.start_entered && alias.start_succeeded
            && !alias.start_callback_active && !alias.blocked && !alias.pointer_retired
            && alias.interface_handle != 0 && alias.vidpn.is_none()
    }).ok_or(STATUS_INVALID_PARAMETER)?;
    let alias = &pdo_aliases_mut()[alias_index];
    let dependent_pdo = alias.dependent_alias.ok_or(STATUS_INVALID_PARAMETER)?;
    let authority = alias.authority.ok_or(STATUS_INVALID_PARAMETER)?;
    if instance_domain_identity(provider_inst) != Some(record.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(record.dependent_domain)
        || hosted_device_allocations::capture_allocation(dependent_inst, provider_context)
            .ok() != alias.context_allocation
        || io_manager_mut().hosted_device_pointer_registration(
            record.provider_domain, alias.provider_pdo.address()) != Some(alias.provider_pdo)
        || io_manager_mut().hosted_device_pointer_registration(
            record.dependent_domain, dependent_pdo.address()) != Some(dependent_pdo)
        || !authority.matches(owner, record.provider_publication_cookie,
            alias.provider_pdo.device_id().raw(), alias.provider_pdo.address(),
            alias.provider_pdo.generation(), dependent_pdo.address(),
            dependent_pdo.generation())
    { return Err(STATUS_INVALID_PARAMETER); }
    Ok(alias_index)
}

pub(super) unsafe fn is_method_rva(
    publication_cookie: u64,
    provider_rva: u64,
) -> bool {
    (&*core::ptr::addr_of!(PDO_ALIASES)).iter().any(|alias| {
        alias.provider_publication_cookie == publication_cookie
            && alias.vidpn.as_ref().is_some_and(|held| held.interfaces.iter().any(|table| {
                table.callbacks.iter().any(|method| method.binding.is_some()
                    && method.provider_rva == provider_rva)
            }))
    })
}

/// Translate a nested call before provider dispatch. Each method is selected
/// from a live, exact interface table receipt, never merely by matching RVA.
pub(in crate::driver_launch) unsafe fn prepare_method(
    provider_instance: usize,
    dependent_instance: usize,
    publication_cookie: u64,
    provider_rva: u64,
    dependent_inst: DriverInstance,
    window: HostedProviderMarshalWindow,
    state: &mut ProviderMarshalState,
    args: &mut [u64; HOSTED_PROVIDER_EXPORT_ARG_CAP],
) -> Result<(), i32> {
    let provider_inst = instance(provider_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let provider_domain = instance_domain_identity(provider_inst).ok_or(STATUS_DEVICE_NOT_READY)?;
    let dependent_domain = instance_domain_identity(dependent_inst).ok_or(STATUS_DEVICE_NOT_READY)?;
    let owner = hosted_provider_object_owner_for_pair(provider_instance,
        dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let requested_generation = hosted_device_allocations::capture_range_allocation(
        provider_inst, args[0], 8).map_err(|status| status.raw())?.pool_generation;
    let mut candidates = Vec::new();
    for (alias_index, alias) in pdo_aliases_mut().iter().enumerate() {
        let Some(held) = alias.vidpn.as_ref() else { continue; };
        let Some(dependent_pdo) = alias.dependent_alias else { continue; };
        let Some(authority) = alias.authority else { continue; };
        if !(alias.provider_instance == provider_instance
            && alias.dependent_instance == dependent_instance
            && alias.provider_domain == provider_domain
            && alias.dependent_domain == dependent_domain
            && alias.provider_publication_cookie == publication_cookie
            && alias.blocked && !alias.pointer_retired
            && !held.nested_uncertain && !held.terminal
            && held.live(provider_inst, provider_domain)
            && hosted_device_allocations::capture_allocation(dependent_inst,
                alias.context).ok() == alias.context_allocation
            && io_manager_mut().hosted_device_pointer_registration(
                provider_domain, alias.provider_pdo.address()) == Some(alias.provider_pdo)
            && io_manager_mut().hosted_device_pointer_registration(
                dependent_domain, dependent_pdo.address()) == Some(dependent_pdo)
            && authority.matches(owner, publication_cookie,
                alias.provider_pdo.device_id().raw(), alias.provider_pdo.address(),
                alias.provider_pdo.generation(), dependent_pdo.address(),
                dependent_pdo.generation()))
        { continue; }
        for table in held.interfaces.iter() {
            let Some(dependent_table) = table.dependent_table else { continue; };
            if hosted_device_allocations::capture_range_allocation(
                dependent_inst, dependent_table, table.kind.bytes() as u64).ok()
                != Some(table.dependent_table_allocation)
            { continue; }
            let owner_generation = match table.kind {
                DxgVidPnTableKind::VidPn if held.provider_vidpn == args[0] =>
                    held.vidpn.as_ref().map(|guard| guard.allocation.pool_generation),
                DxgVidPnTableKind::Topology if held.topology_handle == Some(args[0]) =>
                    held.topology_allocation.map(|allocation| allocation.pool_generation),
                DxgVidPnTableKind::SourceModeSet | DxgVidPnTableKind::TargetModeSet =>
                    modes::route_generation(held, provider_inst, table.kind, args[0]),
                _ => None,
            };
            let Some(owner_generation) = owner_generation else { continue; };
            for method in table.callbacks.iter() {
                if method.provider_rva != provider_rva || !method.binding.is_some_and(|binding| {
                    driver_instance_thunk_slots()
                        .and_then(|rows| rows.get(dependent_instance))
                        .is_some_and(|slots| slots.is_live(binding.token, binding.key))
                }) { continue; }
                candidates.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                candidates.push(((alias_index, method.kind, method.slot),
                    DxgVidPnMethodRouteKey::new(method.provider_rva, args[0],
                        owner_generation)));
            }
        }
    }
    let (alias_index, kind, slot) = DxgVidPnMethodRouteKey::select_unique_route(
        candidates.into_iter(), provider_rva, args[0], requested_generation)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let held = pdo_aliases_mut()[alias_index].vidpn.as_ref().unwrap();
    // Only methods whose pointer and ownership transformations are installed
    // can execute. This initial method is the provider's real GetTopology.
    if kind == DxgVidPnTableKind::Topology {
        return prepare_topology_method(provider_instance, dependent_instance,
            provider_inst, dependent_inst, alias_index, slot, window, state, args);
    }
    if kind != DxgVidPnTableKind::VidPn || slot != 0 {
        return modes::prepare(provider_instance, dependent_instance,
            publication_cookie, provider_rva, dependent_inst, window,
            state, args, alias_index, kind, slot);
    }
    if args[0] != held.provider_vidpn { return Err(STATUS_INVALID_PARAMETER); }
    let mut provider_out = [0u64; 2];
    let mut dependent_out = [0u64; 2];
    for output in 0..2 {
        dependent_out[output] = provider_marshal_source_to_exec(state,
            dependent_instance, dependent_inst, args[output + 1], 8)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let (component, exec) = provider_marshal_alloc(state, window, 8)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        write_unaligned(exec as *mut u64, 0);
        args[output + 1] = component;
        provider_out[output] = exec;
    }
    state.vidpn_method = Some(VidPnMethodFrame {
        alias_index, kind, slot, provider_out, dependent_out,
    });
    Ok(())
}

pub(in crate::driver_launch) unsafe fn complete_method(
    provider_instance: usize,
    dependent_instance: usize,
    publication_cookie: u64,
    state: &ProviderMarshalState,
    result: u64,
) -> Result<(), i32> {
    if state.topology_method.is_some() {
        return complete_topology_method(provider_instance, dependent_instance,
            publication_cookie, state, result);
    }
    if state.mode_method.is_some() {
        return modes::complete(provider_instance, dependent_instance,
            publication_cookie, state, result);
    }
    let frame = state.vidpn_method.ok_or(STATUS_INVALID_PARAMETER)?;
    if frame.kind != DxgVidPnTableKind::VidPn || frame.slot != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    if (result as u32 as i32) < 0 {
        write_unaligned(frame.dependent_out[0] as *mut u64, 0);
        write_unaligned(frame.dependent_out[1] as *mut u64, 0);
        return Ok(());
    }
    let provider_inst = instance(provider_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let dependent_inst = instance(dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let alias = pdo_aliases_mut().get(frame.alias_index).ok_or(STATUS_DEVICE_NOT_READY)?;
    if alias.provider_instance != provider_instance
        || alias.dependent_instance != dependent_instance
        || alias.provider_publication_cookie != publication_cookie
        || instance_domain_identity(provider_inst) != Some(alias.provider_domain)
        || instance_domain_identity(dependent_inst) != Some(alias.dependent_domain)
    { return Err(STATUS_DEVICE_NOT_READY); }
    let held = alias.vidpn.as_ref().ok_or(STATUS_DEVICE_NOT_READY)?;
    let topology = read_unaligned(frame.provider_out[0] as *const u64);
    let provider_table = read_unaligned(frame.provider_out[1] as *const u64);
    if topology == 0 || provider_table == 0 { return Err(STATUS_INVALID_PARAMETER); }
    let topology_allocation = hosted_device_allocations::capture_range_allocation(
        provider_inst, topology, 8).map_err(|status| status.raw())?;
    if held.topology_handle.is_some_and(|handle| handle != topology)
        || held.topology_allocation.is_some_and(|identity| identity != topology_allocation)
    { return Err(STATUS_INVALID_PARAMETER); }
    let provider_vidpn = held.provider_vidpn;
    let dependent_table = project_vidpn_interface(provider_instance,
        dependent_instance, publication_cookie, provider_vidpn,
        DxgVidPnTableKind::Topology, provider_table)?;
    let held = pdo_aliases_mut()[frame.alias_index].vidpn.as_mut().unwrap();
    held.topology_handle = Some(topology);
    held.topology_allocation = Some(topology_allocation);
    write_unaligned(frame.dependent_out[0] as *mut u64, topology);
    write_unaligned(frame.dependent_out[1] as *mut u64, dependent_table);
    Ok(())
}

pub(in crate::driver_launch) unsafe fn retain_uncertain_method(
    state: &ProviderMarshalState,
) {
    let alias_index = state.vidpn_method.map(|frame| frame.alias_index)
        .or_else(|| state.topology_method.map(|frame| frame.alias_index))
        .or_else(|| state.mode_method.map(|frame| frame.alias_index()));
    if let Some(alias_index) = alias_index {
        if let Some(held) = pdo_aliases_mut().get_mut(alias_index)
            .and_then(|alias| alias.vidpn.as_mut())
        {
            held.retain_uncertain();
        }
    }
}

unsafe fn prepare_topology_method(
    provider_instance: usize,
    dependent_instance: usize,
    provider_inst: DriverInstance,
    dependent_inst: DriverInstance,
    alias_index: usize,
    slot: usize,
    window: HostedProviderMarshalWindow,
    state: &mut ProviderMarshalState,
    args: &mut [u64; HOSTED_PROVIDER_EXPORT_ARG_CAP],
) -> Result<(), i32> {
    let held = pdo_aliases_mut()[alias_index].vidpn.as_ref().unwrap();
    let topology = held.topology_handle.ok_or(STATUS_INVALID_PARAMETER)?;
    let topology_allocation = held.topology_allocation.ok_or(STATUS_INVALID_PARAMETER)?;
    if args[0] != topology
        || hosted_device_allocations::capture_range_allocation(provider_inst,
            topology, 8).ok() != Some(topology_allocation)
    { return Err(STATUS_INVALID_PARAMETER); }
    if slot == 11 && held.paths.iter().any(|path| !path.terminal) {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    let mut input_path = None;
    let mut add_path_copy = None;
    if matches!(slot, 6 | 8 | 10) && args[1] != 0 {
        let index = held.paths.iter().position(|path| {
            path.dependent_path == Some(args[1]) && !path.terminal
                && hosted_device_allocations::capture_range_allocation(dependent_inst,
                    args[1], DxgVidPnPathLayout::BYTES as u64).ok()
                    == Some(path.dependent_allocation)
                && hosted_device_allocations::capture_range_allocation(provider_inst,
                    path.provider_path, DxgVidPnPathLayout::BYTES as u64).ok()
                    == Some(path.provider_allocation)
        }).ok_or(STATUS_INVALID_PARAMETER)?;
        if slot == 10 && !held.paths[index].pending {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if slot == 10 && held.paths.iter().enumerate().any(|(other, path)|
            other != index && !path.terminal)
        { return Err(STATUS_DEVICE_NOT_READY); }
        input_path = Some(index);
        if slot == 10 {
            let dependent_exec = component_to_exec_va_for_instance(dependent_instance,
                dependent_inst, args[1], DxgVidPnPathLayout::BYTES as u64)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            let path_bytes = core::slice::from_raw_parts(dependent_exec as *const u8,
                DxgVidPnPathLayout::BYTES);
            if !DxgVidPnPathLayout::has_no_nested_data(path_bytes) {
                return Err(STATUS_NOT_SUPPORTED);
            }
            let provider_exec = component_to_exec_va_for_instance(provider_instance,
                provider_inst, held.paths[index].provider_path,
                DxgVidPnPathLayout::BYTES as u64).ok_or(STATUS_INVALID_PARAMETER)?;
            add_path_copy = Some((provider_exec, dependent_exec));
        }
        args[1] = held.paths[index].provider_path;
    }
    if slot == 7 {
        let dependent_exec = provider_marshal_source_to_exec(state,
            dependent_instance, dependent_inst, args[1],
            DxgVidPnPathLayout::BYTES as u64).ok_or(STATUS_INVALID_PARAMETER)?;
        let path_bytes = core::slice::from_raw_parts(dependent_exec as *const u8,
            DxgVidPnPathLayout::BYTES);
        if !DxgVidPnPathLayout::has_no_nested_data(path_bytes) {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let (component, exec) = provider_marshal_alloc(state, window,
            DxgVidPnPathLayout::BYTES as u64).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        copy_bytes(exec, dependent_exec, DxgVidPnPathLayout::BYTES as u64);
        args[1] = component;
    }
    let output = match slot {
        0 | 5 | 9 => Some((1, 8)),
        1 | 6 => Some((2, 8)),
        3 => Some((2, 4)),
        2 | 4 => Some((3, if slot == 2 { 4 } else { 8 })),
        7 | 8 | 10 | 11 => None,
        _ => return Err(STATUS_NOT_SUPPORTED),
    };
    let mut provider_output = 0;
    let mut dependent_output = 0;
    let mut output_bytes = 0;
    if let Some((position, bytes)) = output {
        dependent_output = provider_marshal_source_to_exec(state,
            dependent_instance, dependent_inst, args[position], bytes)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let (component, exec) = provider_marshal_alloc(state, window, bytes)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        core::ptr::write_bytes(exec as *mut u8, 0, bytes as usize);
        args[position] = component;
        provider_output = exec;
        output_bytes = bytes;
    }
    state.topology_method = Some(TopologyMethodFrame {
        alias_index, slot, provider_output, dependent_output, output_bytes,
        input_path,
    });
    if let Some((provider_exec, dependent_exec)) = add_path_copy {
        // AddPath reads the provider's pending object. Record its receipt in
        // the method frame before copying the miniport's edits into that
        // exact object for the native call.
        copy_bytes(provider_exec, dependent_exec, DxgVidPnPathLayout::BYTES as u64);
    }
    Ok(())
}

unsafe fn project_path(
    provider_instance: usize,
    dependent_instance: usize,
    alias_index: usize,
    provider_path: u64,
    pending: bool,
) -> Result<u64, i32> {
    let provider_inst = instance(provider_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let dependent_inst = instance(dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let bytes = DxgVidPnPathLayout::BYTES as u64;
    let provider_allocation = hosted_device_allocations::capture_range_allocation(
        provider_inst, provider_path, bytes).map_err(|status| status.raw())?;
    let provider_exec = component_to_exec_va_for_instance(provider_instance,
        provider_inst, provider_path, bytes).ok_or(STATUS_INVALID_PARAMETER)?;
    let provider_bytes = core::slice::from_raw_parts(provider_exec as *const u8,
        DxgVidPnPathLayout::BYTES);
    if !DxgVidPnPathLayout::has_no_nested_data(provider_bytes) {
        return Err(STATUS_NOT_SUPPORTED);
    }
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().paths
        .try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let dependent_path = hosted_instance_pool_alloc(dependent_inst, bytes)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let Some(dependent_exec) = component_to_exec_va_for_instance(dependent_instance,
        dependent_inst, dependent_path, bytes) else {
        let _ = hosted_instance_pool_free(dependent_inst, dependent_path);
        return Err(STATUS_DEVICE_NOT_READY);
    };
    let Some(dependent_allocation) = hosted_device_allocations::capture_range_allocation(
        dependent_inst, dependent_path, bytes).ok() else {
        let _ = hosted_instance_pool_free(dependent_inst, dependent_path);
        return Err(STATUS_DEVICE_NOT_READY);
    };
    copy_bytes(dependent_exec, provider_exec, bytes);
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().paths.push(VidPnPathReceipt {
        provider_path, dependent_path: Some(dependent_path),
        provider_allocation, dependent_allocation, pending, terminal: false,
    });
    Ok(dependent_path)
}

unsafe fn complete_topology_method(
    provider_instance: usize,
    dependent_instance: usize,
    publication_cookie: u64,
    state: &ProviderMarshalState,
    result: u64,
) -> Result<(), i32> {
    let frame = state.topology_method.ok_or(STATUS_INVALID_PARAMETER)?;
    let alias = pdo_aliases_mut().get(frame.alias_index).ok_or(STATUS_DEVICE_NOT_READY)?;
    if alias.provider_instance != provider_instance
        || alias.dependent_instance != dependent_instance
        || alias.provider_publication_cookie != publication_cookie
        || alias.vidpn.is_none()
    { return Err(STATUS_DEVICE_NOT_READY); }
    if (result as u32 as i32) < 0 {
        if matches!(frame.slot, 4 | 5 | 6 | 9)
            && read_unaligned(frame.provider_output as *const u64) != 0
        { return Err(STATUS_DEVICE_NOT_READY); }
        if frame.output_bytes != 0 {
            core::ptr::write_bytes(frame.dependent_output as *mut u8, 0,
                frame.output_bytes as usize);
        }
        return Ok(());
    }
    if matches!(frame.slot, 4 | 5 | 6 | 9) {
        let provider_path = read_unaligned(frame.provider_output as *const u64);
        let dependent_path = if provider_path == 0 { 0 } else {
            project_path(provider_instance, dependent_instance, frame.alias_index,
                provider_path, frame.slot == 9)?
        };
        write_unaligned(frame.dependent_output as *mut u64, dependent_path);
    } else if frame.output_bytes != 0 {
        copy_bytes(frame.dependent_output, frame.provider_output, frame.output_bytes);
    }
    if matches!(frame.slot, 8 | 10) {
        if let Some(index) = frame.input_path {
            pdo_aliases_mut()[frame.alias_index].vidpn.as_mut().unwrap()
                .paths[index].terminal = true;
        }
    }
    Ok(())
}

/// Complete the provider's *actual* V1 query by replacing its static table
/// address with a dependent-owned table of executable, owner-bound thunks.
/// No provider code or data pointer is copied into the miniport VSpace.
pub(super) unsafe fn project_vidpn_interface(
    provider_instance: usize,
    dependent_instance: usize,
    publication_cookie: u64,
    provider_vidpn: u64,
    kind: DxgVidPnTableKind,
    table_address: u64,
) -> Result<u64, i32> {
    let provider_inst = instance(provider_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let dependent_inst = instance(dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let provider_domain = instance_domain_identity(provider_inst).ok_or(STATUS_DEVICE_NOT_READY)?;
    let dependent_domain = instance_domain_identity(dependent_inst).ok_or(STATUS_DEVICE_NOT_READY)?;
    let owner = hosted_provider_object_owner_for_pair(provider_instance,
        dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let alias_index = pdo_aliases_mut().iter().position(|alias| {
        alias.provider_instance == provider_instance
            && alias.dependent_instance == dependent_instance
            && alias.provider_domain == provider_domain
            && alias.dependent_domain == dependent_domain
            && alias.provider_publication_cookie == publication_cookie
            && alias.blocked && !alias.pointer_retired
            && alias.vidpn.as_ref().is_some_and(|held| {
                held.provider_vidpn == provider_vidpn && !held.nested_uncertain
            })
    }).ok_or(STATUS_INVALID_PARAMETER)?;
    let table_exec = component_to_exec_va_for_instance(provider_instance,
        provider_inst, table_address, kind.bytes() as u64)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let table_bytes = core::slice::from_raw_parts(table_exec as *const u8,
        kind.bytes());
    let layout = DxgVidPnInterfaceLayout::parse(kind,
        table_bytes).ok_or(STATUS_INVALID_PARAMETER)?;
    let singleton = hosted_provider_singletons().and_then(|rows| rows.iter().copied().find(|row| {
        row.present && row.instance == provider_instance
            && row.owner_domain == provider_domain
            && row.provider_publication_cookie == publication_cookie
    })).ok_or(STATUS_DEVICE_NOT_READY)?;
    if let Some(table) = pdo_aliases_mut()[alias_index].vidpn.as_ref().unwrap()
        .interfaces.iter().find(|row| {
            row.kind == kind && row.provider_table == table_address
        })
    {
        let dependent_table = table.dependent_table.ok_or(STATUS_DEVICE_NOT_READY)?;
        return Ok(dependent_table);
    }

    let mut callbacks = Vec::new();
    let mut projected_callbacks = Vec::new();
    let mut keys = Vec::new();
    callbacks.try_reserve_exact(layout.kind().slot_count())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    projected_callbacks.try_reserve_exact(layout.kind().slot_count())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    keys.try_reserve_exact(layout.kind().slot_count())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for slot in 0..layout.kind().slot_count() {
        let target = layout.callback_at(slot).ok_or(STATUS_INVALID_PARAMETER)?;
        let rva = target.checked_sub(singleton.run_va).ok_or(STATUS_INVALID_PARAMETER)?;
        executable_extent(singleton, rva).ok_or(STATUS_INVALID_PARAMETER)?;
        let cookie = NEXT_AUTHORITY_COOKIE.fetch_add(1, Ordering::Relaxed);
        if cookie == 0 || cookie > u32::MAX as u64 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let key = HostedThunkSlotKey::new(owner, HOSTED_THUNK_PURPOSE_DXG_INTERFACE,
            target, cookie).ok_or(STATUS_INVALID_PARAMETER)?;
        callbacks.push((slot, rva));
        keys.push(key);
    }
    let reservations = reserve_instance_executable_thunk_batch(dependent_instance, &keys)?;
    let Some(dependent_table) = hosted_instance_pool_alloc(dependent_inst,
        layout.kind().bytes() as u64) else {
        for reservation in reservations { abort_instance_executable_thunk(
            dependent_instance, reservation); }
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    let Some(dependent_table_exec) = component_to_exec_va_for_instance(dependent_instance,
        dependent_inst, dependent_table, layout.kind().bytes() as u64) else {
        for reservation in reservations { abort_instance_executable_thunk(
            dependent_instance, reservation); }
        let _ = hosted_instance_pool_free(dependent_inst, dependent_table);
        return Err(STATUS_DEVICE_NOT_READY);
    };
    let Some(dependent_table_allocation) = hosted_device_allocations::capture_range_allocation(
        dependent_inst, dependent_table, layout.kind().bytes() as u64).ok() else {
        for reservation in reservations { abort_instance_executable_thunk(
            dependent_instance, reservation); }
        let _ = hosted_instance_pool_free(dependent_inst, dependent_table);
        return Err(STATUS_DEVICE_NOT_READY);
    };
    core::ptr::write_bytes(dependent_table_exec as *mut u8, 0, layout.kind().bytes());
    if kind == DxgVidPnTableKind::VidPn {
        write_unaligned(dependent_table_exec as *mut u32, 1);
    }

    // Retain the table and each committed binding before publication. An
    // incomplete construction is kept blocked for exact process retirement.
    let in_flight = pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap();
    if in_flight.interfaces.try_reserve(1).is_err() {
        for reservation in reservations { abort_instance_executable_thunk(
            dependent_instance, reservation); }
        let _ = hosted_instance_pool_free(dependent_inst, dependent_table);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    in_flight.interfaces.push(VidPnProjectedInterface {
        kind,
        provider_table: table_address,
        dependent_table: Some(dependent_table),
        dependent_table_allocation,
        callbacks: projected_callbacks,
    });
    let interface_index = in_flight.interfaces.len() - 1;
    let descriptor = hosted_provider_domain_descriptor(singleton);
    for (index, reservation) in reservations.iter().copied().enumerate() {
        let (slot, rva) = callbacks[index];
        let construct = (|| -> Result<(), i32> {
            let thunk = match plan_hosted_provider_import_binding(Some(descriptor), rva) {
                Ok(HostedProviderImportBinding::ProviderDomainCall(plan)) =>
                    plan_hosted_provider_import_thunk(dependent_inst.run_thunk_va,
                        dependent_inst.thunk_len, reservation.thunk_index, plan)
                        .map_err(|_| STATUS_INVALID_PARAMETER)?,
                _ => return Err(STATUS_DEVICE_NOT_READY),
            };
            let encoded = core::slice::from_raw_parts_mut(reservation.exec_va as *mut u8,
                HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN as usize);
            encode_hosted_provider_import_thunk(thunk, encoded)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            if reservation.existing
                || !commit_instance_executable_thunk(dependent_instance, reservation)
            { return Err(STATUS_DEVICE_NOT_READY); }
            in_flight.interfaces[interface_index].callbacks.push(VidPnMethodCallback {
                kind,
                slot,
                provider_rva: rva,
                binding: Some(reservation.address(dependent_instance).binding),
            });
            let policy = hosted_dxg_vidpn_method_marshal_policy(
                layout.kind().argument_count(slot).ok_or(STATUS_INVALID_PARAMETER)?)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            if !register_hosted_provider_internal_marshal_policy(provider_domain,
                publication_cookie, rva, policy)
            { return Err(STATUS_INSUFFICIENT_RESOURCES); }
            let offset = layout.kind().slot_offset(slot).ok_or(STATUS_INVALID_PARAMETER)?;
            write_unaligned((dependent_table_exec + offset as u64) as *mut u64,
                reservation.run_va);
            Ok(())
        })();
        if let Err(status) = construct {
            if !in_flight.interfaces[interface_index].callbacks.iter()
                .any(|callback| callback.slot == slot)
            {
                abort_instance_executable_thunk(dependent_instance, reservation);
            }
            for uncommitted in reservations.iter().copied().skip(index + 1) {
                abort_instance_executable_thunk(dependent_instance, uncommitted);
            }
            in_flight.nested_uncertain = true;
            return Err(status);
        }
    }
    Ok(dependent_table)
}

pub(in crate::driver_launch) unsafe fn complete_query_vidpn_interface(
    provider_instance: usize,
    dependent_instance: usize,
    publication_cookie: u64,
    provider_vidpn: u64,
    version: u64,
    provider_output_exec: u64,
) -> Result<(), i32> {
    if version != 1 || provider_output_exec == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let provider_table = read_unaligned(provider_output_exec as *const u64);
    let dependent_table = project_vidpn_interface(provider_instance,
        dependent_instance, publication_cookie, provider_vidpn,
        DxgVidPnTableKind::VidPn, provider_table)?;
    write_unaligned(provider_output_exec as *mut u64, dependent_table);
    Ok(())
}

pub(in crate::driver_launch) unsafe fn service_enum_cofunc_callback(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    marshal_window: HostedProviderMarshalWindow,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    provider_context: u64,
    provider_request: u64,
) -> Result<u64, i32> {
    let alias_index = admit_callback_alias(provider_inst, record,
        dependent_inst, provider_context)?;
    let alias = &pdo_aliases_mut()[alias_index];

    let request_len = DxgEnumVidPnRequest::BYTES as u64;
    provider_callback_marshal_window(marshal_window, request_len, 0)?;
    let request_guard = DxgQueryOutputGuard::capture(provider_inst,
        record.provider_domain, provider_request, request_len,
        alias.provider_fdo_allocation, alias.provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, provider_request, request_len).ok_or(STATUS_INVALID_PARAMETER)?;
    let request_bytes = core::slice::from_raw_parts(
        request_exec as *const u8, DxgEnumVidPnRequest::BYTES);
    let request = DxgEnumVidPnRequest::parse(request_bytes).ok_or(STATUS_INVALID_PARAMETER)?;
    let vidpn_guard = StartOutputGuard::capture(provider_inst,
        record.provider_domain, request.vidpn(), 8,
        alias.provider_fdo_allocation, alias.provider_fdo)?;
    copy_bytes(marshal_window.exec_base, request_exec, request_len);
    let mut expected = [0u8; DxgEnumVidPnRequest::BYTES];
    expected.copy_from_slice(core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, DxgEnumVidPnRequest::BYTES));
    pdo_aliases_mut()[alias_index].vidpn = Some(VidPnInFlight {
        request: request_guard,
        vidpn: Some(vidpn_guard),
        provider_vidpn: request.vidpn(),
        timing_results: None,
        timing_paths: None,
        dependent_instance: record.dependent_instance,
        dependent_domain: record.dependent_domain,
        topology_handle: None,
        topology_allocation: None,
        mode_sets: Vec::new(),
        mode_objects: Vec::new(),
        paths: Vec::new(),
        terminal: false,
        nested_uncertain: false,
        interfaces: Vec::new(),
    });
    pdo_aliases_mut()[alias_index].blocked = true;
    let result = match dispatch_dependent_provider_callback(
        dispatch, record, dependent_inst, exec_code_va,
        [provider_context, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS],
    ) {
        Ok(value) => value,
        Err(status) => {
            pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
            return Err(status);
        }
    };
    let in_flight = pdo_aliases_mut()[alias_index].vidpn.as_ref().unwrap();
    let unchanged = core::slice::from_raw_parts(marshal_window.exec_base as *const u8,
        DxgEnumVidPnRequest::BYTES) == expected;
    if !unchanged || !in_flight.live(provider_inst, record.provider_domain)
        || in_flight.nested_uncertain
    {
        pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
        return Err(STATUS_DEVICE_NOT_READY);
    }
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().terminal = true;
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().release()?;
    pdo_aliases_mut()[alias_index].vidpn = None;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}

/// The provider decides support. Its 16-byte request carries an opaque VidPN
/// handle and one BOOLEAN output; C padding is never copied back or treated as
/// an authority token. A null handle is a real query in the released miniport.
pub(in crate::driver_launch) unsafe fn service_is_supported_callback(
    dispatch: &mut HostedProviderCallbackDispatcher<'_>,
    marshal_window: HostedProviderMarshalWindow,
    provider_inst: DriverInstance,
    record: HostedProviderCallbackRecord,
    dependent_inst: DriverInstance,
    exec_code_va: u64,
    provider_context: u64,
    provider_request: u64,
) -> Result<u64, i32> {
    let alias_index = admit_callback_alias(provider_inst, record,
        dependent_inst, provider_context)?;
    let alias = &pdo_aliases_mut()[alias_index];

    let request_len = DxgIsSupportedVidPnRequest::BYTES as u64;
    provider_callback_marshal_window(marshal_window, request_len, 0)?;
    let request_guard = DxgQueryOutputGuard::capture(provider_inst,
        record.provider_domain, provider_request, request_len,
        alias.provider_fdo_allocation, alias.provider_fdo)?;
    let request_exec = component_to_exec_va_for_instance(record.provider_instance,
        provider_inst, provider_request, request_len).ok_or(STATUS_INVALID_PARAMETER)?;
    let request_bytes = core::slice::from_raw_parts(
        request_exec as *const u8, DxgIsSupportedVidPnRequest::BYTES);
    let request = DxgIsSupportedVidPnRequest::parse(request_bytes)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let vidpn_guard = if request.vidpn() == 0 { None } else {
        Some(StartOutputGuard::capture(provider_inst,
            record.provider_domain, request.vidpn(), 8,
            alias.provider_fdo_allocation, alias.provider_fdo)?)
    };
    copy_bytes(marshal_window.exec_base, request_exec, request_len);
    pdo_aliases_mut()[alias_index].vidpn = Some(VidPnInFlight {
        request: request_guard,
        vidpn: vidpn_guard,
        provider_vidpn: request.vidpn(),
        timing_results: None,
        timing_paths: None,
        dependent_instance: record.dependent_instance,
        dependent_domain: record.dependent_domain,
        topology_handle: None,
        topology_allocation: None,
        mode_sets: Vec::new(),
        mode_objects: Vec::new(),
        paths: Vec::new(),
        terminal: false,
        nested_uncertain: false,
        interfaces: Vec::new(),
    });
    pdo_aliases_mut()[alias_index].blocked = true;
    let result = match dispatch_dependent_provider_callback(
        dispatch, record, dependent_inst, exec_code_va,
        [provider_context, marshal_window.component_base, 0, 0],
        [0; PROVIDER_CALLBACK_STACK_QWORDS],
    ) {
        Ok(value) => value,
        Err(status) => {
            pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
            return Err(status);
        }
    };
    let in_flight = pdo_aliases_mut()[alias_index].vidpn.as_ref().unwrap();
    let returned_bytes = core::slice::from_raw_parts(
        marshal_window.exec_base as *const u8, DxgIsSupportedVidPnRequest::BYTES);
    if returned_bytes[..8] != request_bytes[..8]
        || !in_flight.live(provider_inst, record.provider_domain)
        || in_flight.nested_uncertain
    {
        pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
        return Err(STATUS_DEVICE_NOT_READY);
    }
    if (result as u32 as i32) >= 0 {
        if DxgIsSupportedVidPnRequest::supported(returned_bytes).is_none() {
            pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().retain_uncertain();
            return Err(STATUS_INVALID_PARAMETER);
        }
        write_unaligned((request_exec + 8) as *mut u8, returned_bytes[8]);
    }
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().terminal = true;
    pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap().release()?;
    pdo_aliases_mut()[alias_index].vidpn = None;
    pdo_aliases_mut()[alias_index].blocked = false;
    Ok(result)
}
