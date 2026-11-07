//! Source and target mode-set interfaces belonging to one exact VidPN call.
//!
//! LiberNT returns mode-set handles as opaque values, but its mode-info
//! pointers refer to provider-owned pool/array storage. Each mode-info
//! receipt below binds that pointer to the exact set, allocation generation,
//! and a separate dependent-owned copy. A pending mode is copied back to its
//! provider object immediately before AddMode, whose success consumes it.

use super::*;

type Allocation = nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;

pub(super) struct ModeSetReceipt {
    kind: DxgVidPnTableKind,
    provider_handle: u64,
    provider_allocation: Allocation,
    source_or_target_id: u32,
    references: usize,
    assigned: bool,
}

pub(super) struct ModeObjectReceipt {
    kind: DxgVidPnTableKind,
    set_handle: u64,
    provider_pointer: u64,
    provider_allocation: Allocation,
    dependent_pointer: Option<u64>,
    dependent_allocation: Option<Allocation>,
    pending: bool,
    references: usize,
    /// The provider has consumed/released its final reference, but the
    /// dependent mirror may still require an idempotent local free.
    provider_consumed: bool,
}

#[derive(Clone, Copy)]
pub(in crate::driver_launch) struct ModeMethodFrame {
    alias_index: usize,
    kind: DxgVidPnTableKind,
    slot: usize,
    set_index: Option<usize>,
    object_index: Option<usize>,
    source_or_target_id: u32,
    provider_out: [u64; 2],
    dependent_out: [u64; 2],
}

impl ModeMethodFrame {
    pub(super) fn alias_index(&self) -> usize { self.alias_index }
}

fn is_mode_set(kind: DxgVidPnTableKind) -> bool {
    matches!(kind, DxgVidPnTableKind::SourceModeSet | DxgVidPnTableKind::TargetModeSet)
}

fn mode_kind(top_slot: usize) -> Option<DxgVidPnTableKind> {
    match top_slot {
        1 | 2 | 3 | 4 => Some(DxgVidPnTableKind::SourceModeSet),
        6 | 7 | 8 | 9 => Some(DxgVidPnTableKind::TargetModeSet),
        _ => None,
    }
}

unsafe fn exact_set(
    held: &VidPnInFlight,
    provider_inst: DriverInstance,
    kind: DxgVidPnTableKind,
    handle: u64,
) -> Option<usize> {
    held.mode_sets.iter().position(|set| set.kind == kind
        && set.provider_handle == handle && set.references != 0
        && hosted_device_allocations::capture_range_allocation(
            provider_inst, handle, 8).ok() == Some(set.provider_allocation))
}

pub(super) unsafe fn route_generation(
    held: &VidPnInFlight,
    provider_inst: DriverInstance,
    kind: DxgVidPnTableKind,
    handle: u64,
) -> Option<u64> {
    let index = exact_set(held, provider_inst, kind, handle)?;
    Some(held.mode_sets[index].provider_allocation.pool_generation)
}

unsafe fn exact_object(
    held: &VidPnInFlight,
    provider_inst: DriverInstance,
    dependent_inst: DriverInstance,
    kind: DxgVidPnTableKind,
    set_handle: u64,
    pointer: u64,
) -> Option<usize> {
    let bytes = kind.object_bytes() as u64;
    held.mode_objects.iter().position(|object| object.kind == kind
        && object.set_handle == set_handle && object.references != 0
        && !object.provider_consumed
        && object.dependent_pointer == Some(pointer)
        && hosted_device_allocations::capture_range_allocation(
            dependent_inst, pointer, bytes).ok() == object.dependent_allocation
        && hosted_device_allocations::capture_range_allocation(
            provider_inst, object.provider_pointer, bytes).ok()
            == Some(object.provider_allocation))
}

unsafe fn output_cell(
    dependent_instance: usize,
    dependent_inst: DriverInstance,
    window: HostedProviderMarshalWindow,
    state: &mut ProviderMarshalState,
    argument: &mut u64,
) -> Result<(u64, u64), i32> {
    let dependent = provider_marshal_source_to_exec(state, dependent_instance,
        dependent_inst, *argument, 8).ok_or(STATUS_INVALID_PARAMETER)?;
    let (component, provider) = provider_marshal_alloc(state, window, 8)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    write_unaligned(provider as *mut u64, 0);
    *argument = component;
    Ok((provider, dependent))
}

pub(super) unsafe fn prepare(
    provider_instance: usize,
    dependent_instance: usize,
    _publication_cookie: u64,
    _provider_rva: u64,
    dependent_inst: DriverInstance,
    window: HostedProviderMarshalWindow,
    state: &mut ProviderMarshalState,
    args: &mut [u64; HOSTED_PROVIDER_EXPORT_ARG_CAP],
    alias_index: usize,
    kind: DxgVidPnTableKind,
    slot: usize,
) -> Result<(), i32> {
    let provider_inst = instance(provider_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let held = pdo_aliases_mut().get(alias_index)
        .and_then(|alias| alias.vidpn.as_ref()).ok_or(STATUS_DEVICE_NOT_READY)?;
    let mut frame = ModeMethodFrame {
        alias_index, kind, slot, set_index: None, object_index: None,
        source_or_target_id: 0, provider_out: [0; 2], dependent_out: [0; 2],
    };
    let mut add_mode_copy = None;
    if kind == DxgVidPnTableKind::VidPn {
        if args[0] != held.provider_vidpn { return Err(STATUS_INVALID_PARAMETER); }
        if slot == 5 {
            frame.source_or_target_id =
                u32::try_from(args[1]).map_err(|_| STATUS_INVALID_PARAMETER)?;
            // The pinned LiberNT d3dukmdt.h defines two UINTs (8 bytes)
            // per entry; vidpn.h bounds the array at 32 entries.
            let count = usize::try_from(args[2]).map_err(|_| STATUS_INVALID_PARAMETER)?;
            if count > 32 { return Err(STATUS_INVALID_PARAMETER); }
            if count != 0 {
                let bytes = (count * 8) as u64;
                let dependent_exec = provider_marshal_source_to_exec(state,
                    dependent_instance, dependent_inst, args[3], bytes)
                    .ok_or(STATUS_INVALID_PARAMETER)?;
                let (component, provider_exec) = provider_marshal_alloc(state,
                    window, bytes).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
                copy_bytes(provider_exec, dependent_exec, bytes);
                args[3] = component;
            } else {
                args[3] = 0;
            }
        } else if matches!(slot, 1 | 3 | 6 | 8) {
            let id = u32::try_from(args[1]).map_err(|_| STATUS_INVALID_PARAMETER)?;
            frame.source_or_target_id = id;
            for output in 0..2 {
                let (provider, dependent) = output_cell(dependent_instance,
                    dependent_inst, window, state, &mut args[output + 2])?;
                frame.provider_out[output] = provider;
                frame.dependent_out[output] = dependent;
            }
        } else {
            let set_kind = mode_kind(slot).ok_or(STATUS_NOT_SUPPORTED)?;
            let set_arg = if matches!(slot, 2 | 7) { 1 } else { 2 };
            let set_index = exact_set(held, provider_inst, set_kind, args[set_arg])
                .ok_or(STATUS_INVALID_PARAMETER)?;
            if matches!(slot, 4 | 9) {
                let id = u32::try_from(args[1]).map_err(|_| STATUS_INVALID_PARAMETER)?;
                if id != held.mode_sets[set_index].source_or_target_id {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                frame.source_or_target_id = id;
            }
            if held.mode_objects.iter().any(|object| object.references != 0
                && object.set_handle == args[set_arg]) {
                return Err(STATUS_DEVICE_NOT_READY);
            }
            frame.set_index = Some(set_index);
        }
    } else if is_mode_set(kind) {
        let set_index = exact_set(held, provider_inst, kind, args[0])
            .ok_or(STATUS_INVALID_PARAMETER)?;
        frame.set_index = Some(set_index);
        match slot {
            0 | 1 | 3 | 5 => {
                let (provider, dependent) = output_cell(dependent_instance,
                    dependent_inst, window, state, &mut args[1])?;
                frame.provider_out[0] = provider;
                frame.dependent_out[0] = dependent;
            }
            2 => {
                let object_index = exact_object(held, provider_inst, dependent_inst,
                    kind, args[0], args[1]).ok_or(STATUS_INVALID_PARAMETER)?;
                frame.object_index = Some(object_index);
                args[1] = held.mode_objects[object_index].provider_pointer;
                let (provider, dependent) = output_cell(dependent_instance,
                    dependent_inst, window, state, &mut args[2])?;
                frame.provider_out[0] = provider;
                frame.dependent_out[0] = dependent;
            }
            4 | 6 => {
                let object_index = exact_object(held, provider_inst, dependent_inst,
                    kind, args[0], args[1]).ok_or(STATUS_INVALID_PARAMETER)?;
                let object = &held.mode_objects[object_index];
                if slot == 6 && !object.pending { return Err(STATUS_INVALID_PARAMETER); }
                if slot == 6 {
                    let dependent_exec = component_to_exec_va_for_instance(dependent_instance,
                        dependent_inst, args[1], kind.object_bytes() as u64)
                        .ok_or(STATUS_INVALID_PARAMETER)?;
                    let provider_exec = component_to_exec_va_for_instance(provider_instance,
                        provider_inst, object.provider_pointer, kind.object_bytes() as u64)
                        .ok_or(STATUS_INVALID_PARAMETER)?;
                    add_mode_copy = Some((provider_exec, dependent_exec,
                        kind.object_bytes() as u64));
                }
                frame.object_index = Some(object_index);
                args[1] = object.provider_pointer;
            }
            7 => {
                let _ = u32::try_from(args[1]).map_err(|_| STATUS_INVALID_PARAMETER)?;
            }
            _ => return Err(STATUS_NOT_SUPPORTED),
        }
    } else {
        return Err(STATUS_NOT_SUPPORTED);
    }
    // Reserve ownership receipts before the native call can create or
    // acquire an object. Completion must not allocate vector capacity after
    // the provider effect has become irrevocable.
    if kind == DxgVidPnTableKind::VidPn && matches!(slot, 1 | 3 | 6 | 8) {
        pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap()
            .mode_sets.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    } else if is_mode_set(kind) && matches!(slot, 1 | 2 | 3 | 5) {
        pdo_aliases_mut()[alias_index].vidpn.as_mut().unwrap()
            .mode_objects.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    }
    state.mode_method = Some(frame);
    if let Some((provider_exec, dependent_exec, bytes)) = add_mode_copy {
        // AddMode consumes this exact pending provider object. Record the
        // frame before mutating it, so uncertain dispatch retains ownership.
        copy_bytes(provider_exec, dependent_exec, bytes);
    }
    Ok(())
}

unsafe fn project_set(
    provider_instance: usize,
    dependent_instance: usize,
    publication_cookie: u64,
    held_index: usize,
    kind: DxgVidPnTableKind,
    id: u32,
    provider_handle: u64,
    provider_table: u64,
) -> Result<u64, i32> {
    if provider_handle == 0 || provider_table == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let provider_inst = instance(provider_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let allocation = hosted_device_allocations::capture_range_allocation(
        provider_inst, provider_handle, 8).map_err(|status| status.raw())?;
    let held = pdo_aliases_mut()[held_index].vidpn.as_mut().ok_or(STATUS_DEVICE_NOT_READY)?;
    let provider_vidpn = held.provider_vidpn;
    // Native Acquire/Create has already succeeded. Retain its exact handle
    // and generation before projecting the static interface table, which can
    // fail independently. A projection failure leaves a live reference that
    // prevents ordinary settlement without a reciprocal native release.
    if let Some(set) = held.mode_sets.iter_mut().find(|set| set.kind == kind
        && set.provider_handle == provider_handle && set.references != 0) {
        if set.provider_allocation != allocation || set.source_or_target_id != id {
            return Err(STATUS_INVALID_PARAMETER);
        }
        set.references = set.references.checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    } else {
        if held.mode_sets.len() == held.mode_sets.capacity() {
            return Err(STATUS_DEVICE_NOT_READY);
        }
        held.mode_sets.push(ModeSetReceipt { kind,
            provider_handle, provider_allocation: allocation,
            source_or_target_id: id, references: 1, assigned: false });
    }
    let dependent_table = project_vidpn_interface(provider_instance,
        dependent_instance, publication_cookie, provider_vidpn, kind,
        provider_table)?;
    Ok(dependent_table)
}

unsafe fn project_object(
    provider_instance: usize,
    dependent_instance: usize,
    held_index: usize,
    kind: DxgVidPnTableKind,
    set_handle: u64,
    provider_pointer: u64,
    pending: bool,
) -> Result<u64, i32> {
    if provider_pointer == 0 { return Err(STATUS_INVALID_PARAMETER); }
    let bytes = kind.object_bytes() as u64;
    let provider_inst = instance(provider_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let dependent_inst = instance(dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
    let provider_allocation = hosted_device_allocations::capture_range_allocation(
        provider_inst, provider_pointer, bytes).map_err(|status| status.raw())?;
    let held = pdo_aliases_mut()[held_index].vidpn.as_mut().ok_or(STATUS_DEVICE_NOT_READY)?;
    if let Some(object) = held.mode_objects.iter_mut().find(|object|
        object.kind == kind && object.set_handle == set_handle
        && object.provider_pointer == provider_pointer && object.references != 0) {
        if object.provider_allocation != provider_allocation || object.pending != pending
            || object.provider_consumed || pending {
            return Err(STATUS_INVALID_PARAMETER);
        }
        object.references = object.references.checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        return object.dependent_pointer.ok_or(STATUS_DEVICE_NOT_READY);
    }
    if held.mode_objects.len() == held.mode_objects.capacity() {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    // The native Acquire/Create effect exists at this point. Record its
    // provider-side ownership before allocating or copying a local mirror.
    // A projection failure leaves an exact live reference that blocks
    // settlement rather than losing the provider pointer.
    held.mode_objects.push(ModeObjectReceipt { kind, set_handle,
        provider_pointer, provider_allocation,
        dependent_pointer: None, dependent_allocation: None,
        pending, references: 1, provider_consumed: false });
    let index = held.mode_objects.len() - 1;
    let provider_exec = component_to_exec_va_for_instance(provider_instance,
        provider_inst, provider_pointer, bytes).ok_or(STATUS_INVALID_PARAMETER)?;
    let dependent_pointer = hosted_instance_pool_alloc(dependent_inst, bytes)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    held.mode_objects[index].dependent_pointer = Some(dependent_pointer);
    let Some(dependent_exec) = component_to_exec_va_for_instance(dependent_instance,
        dependent_inst, dependent_pointer, bytes) else {
        if hosted_instance_pool_free(dependent_inst, dependent_pointer) {
            held.mode_objects[index].dependent_pointer = None;
        }
        return Err(STATUS_DEVICE_NOT_READY);
    };
    let dependent_allocation = match hosted_device_allocations::capture_range_allocation(
        dependent_inst, dependent_pointer, bytes) {
        Ok(identity) => identity,
        Err(status) => {
            if hosted_instance_pool_free(dependent_inst, dependent_pointer) {
                held.mode_objects[index].dependent_pointer = None;
            }
            return Err(status.raw());
        }
    };
    held.mode_objects[index].dependent_allocation = Some(dependent_allocation);
    copy_bytes(dependent_exec, provider_exec, bytes);
    Ok(dependent_pointer)
}

unsafe fn retire_object(
    held: &mut VidPnInFlight,
    dependent_inst: DriverInstance,
    index: usize,
) -> Result<(), i32> {
    let object = held.mode_objects.get_mut(index).ok_or(STATUS_DEVICE_NOT_READY)?;
    if object.references == 0 { return Err(STATUS_INVALID_PARAMETER); }
    if object.references > 1 {
        if object.provider_consumed { return Err(STATUS_DEVICE_NOT_READY); }
        object.references -= 1;
        return Ok(());
    }
    let pointer = object.dependent_pointer.ok_or(STATUS_DEVICE_NOT_READY)?;
    let allocation = hosted_device_allocations::capture_range_allocation(
        dependent_inst, pointer, object.kind.object_bytes() as u64)
        .map_err(|status| status.raw())?;
    if Some(allocation) != object.dependent_allocation ||
        !hosted_instance_pool_free(dependent_inst, pointer) {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    object.dependent_pointer = None;
    object.references = 0;
    Ok(())
}

pub(super) unsafe fn complete(
    provider_instance: usize,
    dependent_instance: usize,
    publication_cookie: u64,
    state: &ProviderMarshalState,
    result: u64,
) -> Result<(), i32> {
    let frame = state.mode_method.ok_or(STATUS_INVALID_PARAMETER)?;
    let alias = pdo_aliases_mut().get(frame.alias_index).ok_or(STATUS_DEVICE_NOT_READY)?;
    if alias.provider_instance != provider_instance
        || alias.dependent_instance != dependent_instance
        || alias.provider_publication_cookie != publication_cookie
        || alias.vidpn.as_ref().is_none_or(|held| held.nested_uncertain)
    { return Err(STATUS_DEVICE_NOT_READY); }
    let success = result == 0;
    if frame.kind == DxgVidPnTableKind::VidPn {
        if matches!(frame.slot, 1 | 3 | 6 | 8) {
            let provider_handle = read_unaligned(frame.provider_out[0] as *const u64);
            let provider_table = read_unaligned(frame.provider_out[1] as *const u64);
            if !success {
                if provider_handle != 0 || provider_table != 0 { return Err(STATUS_DEVICE_NOT_READY); }
                write_unaligned(frame.dependent_out[0] as *mut u64, 0);
                write_unaligned(frame.dependent_out[1] as *mut u64, 0);
                return Ok(());
            }
            let kind = mode_kind(frame.slot).ok_or(STATUS_NOT_SUPPORTED)?;
            let table = project_set(provider_instance, dependent_instance,
                publication_cookie, frame.alias_index, kind,
                frame.source_or_target_id, provider_handle, provider_table)?;
            write_unaligned(frame.dependent_out[0] as *mut u64, provider_handle);
            write_unaligned(frame.dependent_out[1] as *mut u64, table);
        } else if success {
            let set = pdo_aliases_mut()[frame.alias_index].vidpn.as_mut().unwrap()
                .mode_sets.get_mut(frame.set_index.ok_or(STATUS_INVALID_PARAMETER)?)
                .ok_or(STATUS_DEVICE_NOT_READY)?;
            if matches!(frame.slot, 2 | 7) {
                if set.references == 0 { return Err(STATUS_DEVICE_NOT_READY); }
                set.references -= 1;
            } else if matches!(frame.slot, 4 | 9) {
                set.assigned = true;
                set.references = 0; // Assignment transfers ownership to VidPN.
            }
        }
    } else if is_mode_set(frame.kind) {
        let set_handle = {
            let held = pdo_aliases_mut()[frame.alias_index].vidpn.as_ref().unwrap();
            held.mode_sets.get(frame.set_index.ok_or(STATUS_INVALID_PARAMETER)?)
                .ok_or(STATUS_DEVICE_NOT_READY)?.provider_handle
        };
        if matches!(frame.slot, 0 | 1 | 2 | 3 | 5) {
            if frame.slot == 0 {
                let count = read_unaligned(frame.provider_out[0] as *const u64);
                if success { write_unaligned(frame.dependent_out[0] as *mut u64, count); }
                return Ok(());
            }
            let pointer = read_unaligned(frame.provider_out[0] as *const u64);
            if !success {
                // Includes STATUS_GRAPHICS_MODE_NOT_PINNED, which carries a
                // null pointer even though its NTSTATUS is informational.
                if pointer != 0 { return Err(STATUS_DEVICE_NOT_READY); }
                write_unaligned(frame.dependent_out[0] as *mut u64, 0);
                return Ok(());
            }
            let dependent_pointer = project_object(provider_instance,
                dependent_instance, frame.alias_index, frame.kind, set_handle,
                pointer, frame.slot == 5)?;
            write_unaligned(frame.dependent_out[0] as *mut u64, dependent_pointer);
        } else if success && matches!(frame.slot, 4 | 6) {
            let dependent_inst = instance(dependent_instance).ok_or(STATUS_DEVICE_NOT_READY)?;
            let held = pdo_aliases_mut()[frame.alias_index].vidpn.as_mut().unwrap();
            let index = frame.object_index.ok_or(STATUS_INVALID_PARAMETER)?;
            let object = held.mode_objects.get_mut(index).ok_or(STATUS_DEVICE_NOT_READY)?;
            if object.references == 1 {
                // Record the terminal native effect before freeing the mirror.
                // If the free fails, retirement retries only this local step.
                object.provider_consumed = true;
            }
            if let Err(status) = retire_object(held, dependent_inst, index) {
                if held.mode_objects[index].provider_consumed
                    && held.mode_objects[index].references == 1 {
                    // The provider returned success and its effect is final.
                    // Preserve its status for the miniport; the exact mirror
                    // receipt is settled when this VidPN call retires. No
                    // native ReleaseModeInfo/AddMode may be replayed.
                    return Ok(());
                }
                return Err(status);
            }
        }
    }
    Ok(())
}

pub(super) unsafe fn release_mode_receipts(
    held: &mut VidPnInFlight,
    dependent_inst: DriverInstance,
) -> Result<(), i32> {
    // All provider acquisitions and pending creations need a reciprocal
    // native call. An already consumed native object may only need its local
    // mirror freed, so settlement is idempotent after a partial failure.
    if held.mode_objects.iter().any(|object| object.references != 0
            && !object.provider_consumed)
        || held.mode_sets.iter().any(|set| set.references != 0 && !set.assigned) {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    for index in (0..held.mode_objects.len()).rev() {
        if held.mode_objects[index].references != 0 {
            retire_object(held, dependent_inst, index)?;
        }
    }
    Ok(())
}
