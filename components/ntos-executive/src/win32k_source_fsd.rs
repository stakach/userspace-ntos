//! Exact source lease for file-less READ/WRITE IRPs built by win32k.

use super::*;
use nt_io_abi::major;
use nt_io_manager::win32k_source_fsd_wire as wire;
use nt_io_manager::win32k_source_irp_ioctl_wire::EventIdentity;
use nt_io_manager::{WdmIoStackParameters, WDM_X64_IO_STACK_LOCATION_SIZE};

#[must_use = "retain source and caller targets through terminal acknowledgement"]
pub(crate) struct SourceFsdDispatchLease {
    source: Option<source_irp::SourceIrpDispatchLease>,
    pub device: u64,
    pub major: u8,
    pub transfer_mode: u32,
    pub byte_offset: u64,
    pub input: Vec<u8>,
    pub output_initial: Vec<u8>,
    pub output_capacity: u32,
    pub output_va: u64,
    pub iosb_va: u64,
    pub event: Option<EventIdentity>,
    event_va: u64,
    image_map_owner: u64,
    auxiliary: source_irp_aux::AuxiliarySnapshot,
    system_buffer: Option<source_irp::PinnedSystemBuffer>,
    output_pin: file_ioctl_target::PinnedIoctlOutput,
    iosb_pin: file_ioctl_target::PinnedIoctlOutput,
    event_lease: Option<nt_provider_wait::ProviderLocalEventLease>,
}

impl SourceFsdDispatchLease {
    pub(crate) fn source_address(&self) -> u64 {
        self.source.as_ref().unwrap().allocation.catalog.base
    }

    pub(crate) fn source_ticket_serial(&self) -> u64 {
        self.source.as_ref().unwrap().ticket.serial.get()
    }

    pub(crate) fn source_native_generation(&self) -> u64 {
        self.source.as_ref().unwrap().allocation.native.allocation_generation
    }

    pub(crate) fn event_body(&self) -> Option<u64> {
        self.event_lease.map(|_| self.event_va)
    }

    pub(crate) unsafe fn validate(&self) -> bool {
        let Some(source) = self.source.as_ref() else { return false };
        if !source_irp::dispatch_lease_live(source)
            || source_irp_aux::snapshot_exact(source.ticket, source.allocation)
                .is_none_or(|snapshot| !snapshot.same_identity(&self.auxiliary))
            || self.system_buffer.as_ref().is_some_and(|buffer| !source_irp::system_buffer_live(buffer))
            || !source_irp::target_live(&self.iosb_pin, self.image_map_owner, self.iosb_va, 16)
            || !source_irp::target_live(
                &self.output_pin,
                self.image_map_owner,
                self.output_va,
                u64::from(self.output_capacity),
            )
        {
            return false;
        }
        if let Some(event) = self.event_lease {
            let _metadata = ProviderMetadataGuard::acquire();
            provider_local_events().is_some_and(|events| {
                events.snapshot(event.id).is_ok_and(|snapshot| {
                    snapshot.body == self.event_va && snapshot.canonical == Some(event.canonical)
                })
            })
        } else {
            true
        }
    }

    /// Root proves physical aliases and canonical terminal before invoking this once.
    pub(crate) unsafe fn publish_terminal(
        &self,
        status: u32,
        information: u64,
        output: &[u8],
        output_address: u64,
        iosb_address: u64,
    ) -> bool {
        let copy_len = if self.major == major::IRP_MJ_READ {
            information.min(u64::from(self.output_capacity)) as usize
        } else {
            0
        };
        if status == wire::STATUS_PENDING
            || information > (if self.major == major::IRP_MJ_READ {
                u64::from(self.output_capacity)
            } else {
                self.input.len() as u64
            })
            || !self.validate()
            || output.len() != copy_len
            || iosb_address == 0
            || iosb_address.checked_add(16).is_none()
            || (copy_len != 0 && (output_address == 0
                || output_address.checked_add(copy_len as u64).is_none()))
        {
            return false;
        }
        if copy_len != 0 {
            if self.transfer_mode == wire::BUFFERED {
                let Some(buffer) = self.system_buffer.as_ref() else { return false };
                core::ptr::copy_nonoverlapping(output.as_ptr(), buffer.address() as *mut u8, copy_len);
            }
            core::ptr::copy_nonoverlapping(output.as_ptr(), output_address as *mut u8, copy_len);
        }
        write_unaligned(iosb_address as *mut u32, status);
        write_unaligned((iosb_address + 8) as *mut u64, information);
        true
    }

}

pub(crate) unsafe fn admit(
    address: u64,
    device: u64,
    stack_pointer: u64,
    route: Option<nt_component_suspension::peer_registry::PeerRoute>,
) -> Result<SourceFsdDispatchLease, i32> {
    let mut source = Some(source_irp::retain_dispatch(address).ok_or(STATUS_INVALID_PARAMETER_I32)?);
    let result = (|| {
        let source_ref = source.as_ref().unwrap();
        let auxiliary = source_irp_aux::snapshot_exact(source_ref.ticket, source_ref.allocation)
            .ok_or(STATUS_INVALID_PARAMETER_I32)?;
        let stack_address = address + source_ref.cursor.next_stack_offset as u64;
        let stack = nt_io_manager::decode_wdm_kernel_built_io_stack(
            core::slice::from_raw_parts(stack_address as *const u8, WDM_X64_IO_STACK_LOCATION_SIZE),
        ).map_err(|_| STATUS_INVALID_PARAMETER_I32)?;
        let (length, key, byte_offset) = match stack.parameters {
            WdmIoStackParameters::Read { length, key, byte_offset }
                if stack.major == major::IRP_MJ_READ => (length, key, byte_offset),
            WdmIoStackParameters::Write { length, key, byte_offset }
                if stack.major == major::IRP_MJ_WRITE => (length, key, byte_offset),
            _ => return Err(STATUS_INVALID_PARAMETER_I32),
        };
        if device == 0
            || !provider_pool_contains(device)
            || device.checked_add(0x50).is_none_or(|end| {
                end > WIN32K_POOL_VADDR + WIN32K_POOL_FRAMES * 0x1000
            })
            || stack.device_object != device || stack.file_object != 0 || key != 0
            || length > wire::MAX_BUFFER_BYTES
        {
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
        crate::driver_launch::win32k_device_pointers::reference(device)
            .map_err(|_| STATUS_INVALID_PARAMETER_I32)?;
        let device_flags = read_volatile((device + 0x30) as *const u32);
        if crate::driver_launch::win32k_device_pointers::dereference(device).is_err() {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, device, 0, 14]);
        }
        let mode = if device_flags & nt_io_manager::kernel_irp_builder::DO_BUFFERED_IO != 0 {
            wire::BUFFERED
        } else if device_flags & nt_io_manager::kernel_irp_builder::DO_DIRECT_IO != 0 {
            wire::DIRECT
        } else {
            wire::NEITHER
        };
        let system_address = read_volatile((address + 0x18) as *const u64);
        let mdl_address = read_volatile((address + 0x08) as *const u64);
        let user_buffer = read_volatile((address + 0x70) as *const u64);
        let flags = read_volatile((address + 0x10) as *const u32);
        let iosb_va = read_volatile((address + 0x48) as *const u64);
        let event_va = read_volatile((address + 0x50) as *const u64);
        if iosb_va == 0 { return Err(STATUS_INVALID_PARAMETER_I32); }
        let read = stack.major == major::IRP_MJ_READ;
        let expected_flags = if mode == wire::BUFFERED {
            nt_io_manager::kernel_irp_builder::IRP_BUFFERED_IO
                | nt_io_manager::kernel_irp_builder::IRP_DEALLOCATE_BUFFER
                | if read { nt_io_manager::kernel_irp_builder::IRP_INPUT_OPERATION } else { 0 }
        } else { 0 };
        if flags != expected_flags { return Err(STATUS_INVALID_PARAMETER_I32); }
        let output_va = if read {
            if mode == wire::DIRECT && length != 0 {
                if user_buffer != 0
                    || auxiliary.mdl.is_none_or(|(va, _)| va != mdl_address)
                    || read_unaligned((mdl_address + nt_mdl::MDL_OFF_SIZE) as *const i16)
                        != nt_mdl::MDL_SIZE as i16
                    || read_unaligned((mdl_address + nt_mdl::MDL_OFF_FLAGS) as *const i16)
                        != (nt_mdl::MDL_MAPPED_TO_SYSTEM_VA | nt_mdl::MDL_PAGES_LOCKED)
                { return Err(STATUS_INVALID_PARAMETER_I32); }
                let mapped = read_unaligned((mdl_address + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *const u64);
                if mapped == 0
                    || read_unaligned((mdl_address + nt_mdl::MDL_OFF_START_VA) as *const u64) != (mapped & !0xfff)
                    || read_unaligned((mdl_address + nt_mdl::MDL_OFF_BYTE_COUNT) as *const u32) != length
                    || read_unaligned((mdl_address + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32) != (mapped & 0xfff) as u32
                { return Err(STATUS_INVALID_PARAMETER_I32); }
                mapped
            } else { user_buffer }
        } else { 0 };
        if read && length != 0 && (output_va == 0
            || auxiliary.output_target != Some((output_va, u64::from(length))))
        { return Err(STATUS_INVALID_PARAMETER_I32); }
        if !read && length != 0 {
            let input_va = if mode == wire::DIRECT {
                if user_buffer != 0 || auxiliary.mdl.is_none_or(|(va, _)| va != mdl_address) {
                    return Err(STATUS_INVALID_PARAMETER_I32);
                }
                let mapped = read_unaligned((mdl_address + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *const u64);
                if read_unaligned((mdl_address + nt_mdl::MDL_OFF_SIZE) as *const i16) != nt_mdl::MDL_SIZE as i16
                    || read_unaligned((mdl_address + nt_mdl::MDL_OFF_FLAGS) as *const i16)
                        != (nt_mdl::MDL_MAPPED_TO_SYSTEM_VA | nt_mdl::MDL_PAGES_LOCKED)
                    || read_unaligned((mdl_address + nt_mdl::MDL_OFF_START_VA) as *const u64) != (mapped & !0xfff)
                    || read_unaligned((mdl_address + nt_mdl::MDL_OFF_BYTE_COUNT) as *const u32) != length
                    || read_unaligned((mdl_address + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32) != (mapped & 0xfff) as u32
                { return Err(STATUS_INVALID_PARAMETER_I32); }
                mapped
            } else { user_buffer };
            if mode != wire::BUFFERED && (input_va == 0
                || auxiliary.input_target != Some((input_va, u64::from(length))))
            { return Err(STATUS_INVALID_PARAMETER_I32); }
        }
        if (mode == wire::BUFFERED && ((length == 0) != (system_address == 0)
            || mdl_address != 0 || auxiliary.mdl.is_some()
            || (read && user_buffer != output_va) || (!read && user_buffer != 0)))
            || (mode != wire::BUFFERED && (system_address != 0 || auxiliary.system_buffer.is_some()))
            || (mode == wire::NEITHER && mdl_address != 0)
            || (mode == wire::DIRECT && length == 0 && mdl_address != 0)
            || (read && auxiliary.input_target.is_some())
            || (!read && auxiliary.output_target.is_some())
        { return Err(STATUS_INVALID_PARAMETER_I32); }
        let system_buffer = if system_address == 0 { None } else {
            Some(source_irp::pin_system_buffer(system_address, u64::from(length))
                .ok_or(STATUS_ACCESS_VIOLATION_I32)?)
        };
        if auxiliary.system_buffer != system_buffer.as_ref().map(|pin| (pin.address(), pin.native_identity())) {
            if let Some(pin) = system_buffer { if !source_irp::release_system_buffer(pin) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 1]);
            }}
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
        let activation = {
            let _metadata = ProviderMetadataGuard::acquire();
            (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS)).as_ref().and_then(|catalog| {
                let (binding, _) = catalog.resolve(stack_pointer, 1).ok()?;
                catalog.active(binding.handle).ok()
            })
        };
        let Some(activation) = activation else {
            if let Some(pin) = system_buffer { if !source_irp::release_system_buffer(pin) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 2]);
            }}
            return Err(STATUS_NOT_SUPPORTED_I32);
        };
        let iosb_pin = match file_ioctl_target::pin_output(activation, iosb_va, 16) {
            Ok(pin) => pin,
            Err(status) => {
                if let Some(pin) = system_buffer { if !source_irp::release_system_buffer(pin) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 3]);
                }}
                return Err(status);
            }
        };
        let output_pin = if read {
            file_ioctl_target::pin_output(activation, output_va, u64::from(length))
        } else {
            Ok(file_ioctl_target::PinnedIoctlOutput::None)
        };
        let output_pin = match output_pin {
            Ok(pin) => pin,
            Err(status) => {
                file_ioctl_target::release_output(iosb_pin);
                if let Some(pin) = system_buffer { if !source_irp::release_system_buffer(pin) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 4]);
                }}
                return Err(status);
            }
        };
        let event_lease = if event_va == 0 { None } else {
            match source_irp::try_signal_event_lease(event_va) {
                Some(lease) => Some(lease),
                None => {
                    file_ioctl_target::release_output(output_pin);
                    file_ioctl_target::release_output(iosb_pin);
                    if let Some(pin) = system_buffer { if !source_irp::release_system_buffer(pin) {
                        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 5]);
                    }}
                    return Err(STATUS_INVALID_PARAMETER_I32);
                }
            }
        };
        let event = event_lease.map(|lease| EventIdentity {
            local_id: lease.id.raw(),
            object_slot_plus_one: lease.canonical.object_id,
            object_generation: lease.canonical.object_generation,
        });
        let captured = (|| {
            let input = if !read && length != 0 {
                if let Some(pin) = system_buffer.as_ref() {
                    if !source_irp::system_buffer_live(pin) { return Err(STATUS_ACCESS_VIOLATION_I32); }
                    source_irp::capture_pinned_target(pin.address(), length, route)?
                } else {
                    let input_va = if mode == wire::DIRECT {
                        read_unaligned((mdl_address + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *const u64)
                    } else { user_buffer };
                    source_irp::capture_pinned_target(input_va, length, route)?
                }
            } else { Vec::new() };
            let output_initial = if read && mode != wire::BUFFERED {
                source_irp::capture_pinned_target(output_va, length, route)?
            } else { Vec::new() };
            Ok::<_, i32>((input, output_initial))
        })();
        let (input, output_initial) = match captured {
            Ok(captured) => captured,
            Err(status) => {
                if let Some(lease) = event_lease {
                    let _metadata = ProviderMetadataGuard::acquire();
                    if provider_local_events_mut().is_none_or(|events| events.release_lease(lease).is_err()) {
                        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 6]);
                    }
                }
                file_ioctl_target::release_output(output_pin);
                file_ioctl_target::release_output(iosb_pin);
                if let Some(pin) = system_buffer { if !source_irp::release_system_buffer(pin) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 7]);
                }}
                return Err(status);
            }
        };
        Ok(SourceFsdDispatchLease {
            source: source.take(), device, major: stack.major, transfer_mode: mode,
            byte_offset, input, output_initial,
            output_capacity: if read { length } else { 0 },
            output_va, iosb_va, event, event_va,
            image_map_owner: WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire),
            auxiliary, system_buffer, output_pin, iosb_pin, event_lease,
        })
    })();
    if result.is_err() && !source_irp::release_dispatch(source.take().unwrap()) {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 8]);
    }
    result
}

unsafe fn finish(lease: &mut SourceFsdDispatchLease, retire_source: bool, mirror_event: Option<u64>) -> bool {
    if !lease.validate() { return false; }
    let event = lease.event_lease.take();
    file_ioctl_target::release_output(core::mem::replace(
        &mut lease.output_pin, file_ioctl_target::PinnedIoctlOutput::None,
    ));
    file_ioctl_target::release_output(core::mem::replace(
        &mut lease.iosb_pin, file_ioctl_target::PinnedIoctlOutput::None,
    ));
    if let Some(pin) = lease.system_buffer.take() {
        let address = pin.address();
        if !source_irp::release_system_buffer(pin) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 10]);
        }
    }
    let source = lease.source.take().unwrap();
    let address = source.allocation.catalog.base;
    let ticket = source.ticket;
    let allocation = source.allocation;
    if !source_irp::release_dispatch(source)
        || (retire_source && (!source_irp_aux::retire_exact(ticket, allocation)
            || !source_irp::retire(address, ticket)))
    {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, address, 0, 11]);
    }
    source_irp::finish_terminal_event(event, lease.event_va, mirror_event)
}

pub(crate) unsafe fn release(lease: &mut SourceFsdDispatchLease) -> bool {
    finish(lease, true, None)
}

pub(crate) unsafe fn commit(lease: &mut SourceFsdDispatchLease, sequence: u64) -> bool {
    if lease.event_lease.is_some() != (sequence != 0) { return false; }
    finish(lease, true, Some(sequence))
}

pub(crate) unsafe fn abort(lease: &mut SourceFsdDispatchLease) -> bool {
    finish(lease, false, None)
}
