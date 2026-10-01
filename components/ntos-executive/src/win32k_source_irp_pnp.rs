//! Exact PnP TargetDeviceRelation source dispatch lifetime.

use super::*;

#[must_use = "retain the PnP source through terminal acknowledgement"]
pub(crate) struct SourcePnpDispatchLease {
    source: Option<SourceIrpDispatchLease>,
    pub device: u64,
    pub iosb_va: u64,
    pub event: Option<EventIdentity>,
    event_va: u64,
    image_map_owner: u64,
    auxiliary: source_irp_aux::AuxiliarySnapshot,
    iosb_pin: file_ioctl_target::PinnedIoctlOutput,
    event_lease: Option<nt_provider_wait::ProviderLocalEventLease>,
}

impl SourcePnpDispatchLease {
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
        if !dispatch_lease_live(source)
            || source_irp_aux::snapshot_exact(source.ticket, source.allocation)
                .is_none_or(|snapshot| !snapshot.same_identity(&self.auxiliary))
            || !target_live(&self.iosb_pin, self.image_map_owner, self.iosb_va, 16)
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

    /// Root has already validated the projected relation allocation, PDO reference,
    /// canonical terminal, and the physical alias of this IOSB target.
    pub(crate) unsafe fn publish_terminal(
        &self,
        status: u32,
        information: u64,
        iosb_address: u64,
    ) -> bool {
        if status == wire::STATUS_PENDING
            || (status & 0x8000_0000 == 0 && information == 0)
            || (status & 0x8000_0000 != 0 && information != 0)
            || !self.validate()
            || iosb_address == 0
            || iosb_address.checked_add(16).is_none()
        {
            return false;
        }
        write_unaligned(iosb_address as *mut u32, status);
        write_unaligned((iosb_address + 8) as *mut u64, information);
        true
    }

}

pub(crate) unsafe fn admit_pnp_target_relation(
    address: u64,
    device: u64,
    stack_pointer: u64,
) -> Result<SourcePnpDispatchLease, i32> {
    use nt_io_abi::major;
    let mut source = Some(match retain_dispatch(address) {
        Some(source) => source,
        None => {
            print_str(b"[source-pnp-admit] exact IRP retention failed\n");
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
    });
    let result = (|| {
        let source_ref = source.as_ref().unwrap();
        let auxiliary = source_irp_aux::snapshot_exact(source_ref.ticket, source_ref.allocation)
            .ok_or_else(|| {
                print_str(b"[source-pnp-admit] auxiliary identity missing\n");
                STATUS_INVALID_PARAMETER_I32
            })?;
        if auxiliary.system_buffer.is_some()
            || auxiliary.mdl.is_some()
            || auxiliary.input_target.is_some()
            || auxiliary.output_target.is_some()
        {
            print_str(b"[source-pnp-admit] unexpected transfer backing\n");
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
        let stack_address = address + source_ref.cursor.next_stack_offset as u64;
        let stack = nt_io_manager::decode_wdm_kernel_built_io_stack(
            core::slice::from_raw_parts(stack_address as *const u8, WDM_X64_IO_STACK_LOCATION_SIZE),
        )
        .map_err(|_| {
            print_str(b"[source-pnp-admit] WDM stack decode failed\n");
            STATUS_INVALID_PARAMETER_I32
        })?;
        if stack.major != major::IRP_MJ_PNP
            || stack.minor != nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS
            || stack.device_object != device
            || stack.file_object != 0
            || !matches!(
                stack.parameters,
                nt_io_manager::WdmIoStackParameters::PnpQueryDeviceRelations {
                    relation_type: nt_pnp_abi::TARGET_DEVICE_RELATION
                }
            )
            || read_volatile((address + 0x08) as *const u64) != 0
            || read_volatile((address + 0x10) as *const u32) != 0
            || read_volatile((address + 0x18) as *const u64) != 0
            || read_volatile((address + 0x70) as *const u64) != 0
        {
            print_str(b"[source-pnp-admit] WDM stack fields mismatch\n");
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
        let iosb_va = read_volatile((address + 0x48) as *const u64);
        let event_va = read_volatile((address + 0x50) as *const u64);
        let activation = {
            let _metadata = ProviderMetadataGuard::acquire();
            (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS))
                .as_ref()
                .and_then(|catalog| {
                    let (binding, _) = catalog.resolve(stack_pointer, 1).ok()?;
                    catalog.active(binding.handle).ok()
                })
        }
        .ok_or_else(|| {
            print_str(b"[source-pnp-admit] stack activation missing\n");
            STATUS_NOT_SUPPORTED_I32
        })?;
        let iosb_pin = file_ioctl_target::pin_output(activation, iosb_va, 16)
            .map_err(|status| {
                print_str(b"[source-pnp-admit] IOSB pin rejected status=0x");
                print_hex(status as u32);
                print_str(b" address=0x");
                print_hex_u64(iosb_va);
                print_str(b"\n");
                status
            })?;
        let event_lease = if event_va == 0 {
            None
        } else if let Some(event) = try_signal_event_lease(event_va) {
            Some(event)
        } else {
            print_str(b"[source-pnp-admit] Event lease unavailable\n");
            file_ioctl_target::release_output(iosb_pin);
            return Err(STATUS_INVALID_PARAMETER_I32);
        };
        let event = event_lease.map(|lease| EventIdentity {
            local_id: lease.id.raw(),
            object_slot_plus_one: lease.canonical.object_id,
            object_generation: lease.canonical.object_generation,
        });
        Ok(SourcePnpDispatchLease {
            source: source.take(),
            device,
            iosb_va,
            event,
            event_va,
            image_map_owner: WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire),
            auxiliary,
            iosb_pin,
            event_lease,
        })
    })();
    if result.is_err() && !release_dispatch(source.take().unwrap()) {
        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 34]);
    }
    result
}

unsafe fn finish_pnp_dispatch(lease: &mut SourcePnpDispatchLease, retire_source: bool, mirror_event: Option<u64>) -> bool {
    if !lease.validate() {
        return false;
    }
    let event = lease.event_lease.take();
    file_ioctl_target::release_output(core::mem::replace(
        &mut lease.iosb_pin,
        file_ioctl_target::PinnedIoctlOutput::None,
    ));
    let source = lease.source.take().unwrap();
    let address = source.allocation.catalog.base;
    let ticket = source.ticket;
    let allocation = source.allocation;
    if !release_dispatch(source)
        || (retire_source
            && (!source_irp_aux::retire_exact(ticket, allocation) || !retire(address, ticket)))
    {
        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 36]);
    }
    finish_terminal_event(event, lease.event_va, mirror_event)
}

pub(crate) unsafe fn release_pnp_dispatch(lease: &mut SourcePnpDispatchLease) -> bool {
    finish_pnp_dispatch(lease, true, None)
}

pub(crate) unsafe fn commit_pnp_dispatch(lease: &mut SourcePnpDispatchLease, sequence: u64) -> bool {
    if lease.event_lease.is_some() != (sequence != 0) { return false; }
    finish_pnp_dispatch(lease, true, Some(sequence))
}

pub(crate) unsafe fn abort_pnp_dispatch(lease: &mut SourcePnpDispatchLease) -> bool {
    finish_pnp_dispatch(lease, false, None)
}
