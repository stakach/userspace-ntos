//! Root-owned physical resource leaves shared by exact device/context owners.

use super::*;
use nt_pnp_context::resource_mapping::{
    Admission, MappingDomain, MappingError, MappingKey, MappingOwner, OwnerReceipt, ReleaseAction,
    ResourceMappingTable,
};

static mut MAPPINGS: ResourceMappingTable = ResourceMappingTable::new();

pub(super) unsafe fn table() -> &'static ResourceMappingTable {
    &*core::ptr::addr_of!(MAPPINGS)
}

unsafe fn table_mut() -> &'static mut ResourceMappingTable {
    &mut *core::ptr::addr_of_mut!(MAPPINGS)
}

pub(super) unsafe fn checked_frame_address(source_cap: u64) -> Result<u64, nt_status::NtStatus> {
    let information: u64;
    let physical: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_CALL as u64,
        inout("rdi") source_cap => _,
        inout("rsi") (LBL_X86_PAGE_GET_ADDRESS << 12) => information,
        out("r10") physical,
        in("r12") 0u64, in("r13") 0u64,
        lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    if information != 1 || physical & 0xfff != 0 {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(physical)
}

fn status(error: MappingError) -> nt_status::NtStatus {
    match error {
        MappingError::InsufficientResources | MappingError::IdExhausted => {
            nt_status::NtStatus::INSUFFICIENT_RESOURCES
        }
        MappingError::Conflict => nt_status::NtStatus::CONFLICTING_ADDRESSES,
        _ => nt_status::NtStatus::UNSUCCESSFUL,
    }
}

pub(super) unsafe fn reserve(additional: usize) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    table_mut().try_reserve(additional).map_err(status)
}

unsafe fn release(receipt: OwnerReceipt) -> Result<(), nt_status::NtStatus> {
    match table_mut().begin_release(receipt).map_err(status)? {
        ReleaseAction::OwnerReleased | ReleaseAction::UnmappedReleased => Ok(()),
        ReleaseAction::DeleteCap(cap) => {
            if cnode_delete_recycle_r(cap) != 0 {
                let _ = table_mut().mark_delete_uncertain(receipt);
                return Err(nt_status::NtStatus::UNSUCCESSFUL);
            }
            table_mut()
                .acknowledge_delete(receipt)
                .expect("resource cap deletion lost its exact ownership receipt");
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn map_run(
    instance_index: usize,
    inst: DriverInstance,
    domain: HostedDomainIdentity,
    device_id: u64,
    context_lease: nt_pnp_context::ContextLeaseIdentity,
    component_va: u64,
    frame_base: u64,
    pages: u64,
    rights: u64,
) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let bytes = pages
        .checked_mul(0x1000)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let end = component_va
        .checked_add(bytes)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    if component_va == 0
        || component_va & 0xfff != 0
        || frame_base == 0
        || pages == 0
        || frame_base.checked_add(pages - 1).is_none()
        || instance_domain_identity(inst) != Some(domain)
        || !crate::hosted_pnp_context::hosted_pnp_context_lease_is_live(context_lease)
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let owner = MappingOwner {
        instance: instance_index,
        device_id,
        context_lease,
    };
    let mut virtual_page = component_va;
    let mut source_cap = frame_base;
    while virtual_page < end {
        let expected = crate::hosted_pnp_context::hosted_pnp_mapping_frame(
            context_lease,
            source_cap,
            virtual_page,
        )?;
        let physical_page = checked_frame_address(source_cap)?;
        if expected.is_some_and(|expected| expected != physical_page) {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let key = MappingKey {
            domain: MappingDomain {
                id: domain.domain_id.raw(),
                cookie: domain.cookie,
            },
            pml4: inst.pml4,
            virtual_page,
            physical_page,
            source_cap,
            rights,
            attributes: 0,
        };
        let receipt = match table_mut().prepare(key, owner).map_err(status)? {
            Admission::Joined(_) => {
                virtual_page += 0x1000;
                source_cap += 1;
                continue;
            }
            Admission::New(receipt) => receipt,
        };
        if !ensure_paging(virtual_page, inst.pml4, domain) {
            let _ = release(receipt);
            return Err(nt_status::NtStatus::UNSUCCESSFUL);
        }
        let (cap, copy_error) = copy_cap_r(source_cap);
        if cap != 0 {
            table_mut()
                .attach_cap(receipt, cap)
                .expect("resource copy cap must remain owned before mapping");
        }
        if copy_error != 0 || cap == 0 {
            let _ = release(receipt);
            return Err(nt_status::NtStatus::UNSUCCESSFUL);
        }
        let (cap, effect) = table_mut()
            .begin_map(receipt)
            .expect("resource cap must be recorded before entering PageMap");
        let error = page_map_r(cap, virtual_page, rights, inst.pml4);
        if error != 0 {
            let _ = table_mut().mark_map_uncertain(effect);
            return Err(nt_status::NtStatus::UNSUCCESSFUL);
        }
        table_mut()
            .acknowledge_map(effect)
            .expect("resource PageMap receipt lost its retained owner");
        virtual_page += 0x1000;
        source_cap += 1;
    }
    Ok(())
}

pub(super) unsafe fn clear(
    instance: usize,
    domain: HostedDomainIdentity,
    device: Option<u64>,
    context: Option<nt_pnp_context::ContextLeaseIdentity>,
) -> u64 {
    loop {
        let candidate = table().iter().find_map(|row| {
            if row.key().domain
                != (MappingDomain {
                    id: domain.domain_id.raw(),
                    cookie: domain.cookie,
                })
            {
                return None;
            }
            row.owners().find(|(_, owner)| {
                owner.instance == instance && device.is_none_or(|device| owner.device_id == device)
            })
        });
        let Some((receipt, owner)) = candidate else {
            return 0;
        };
        if context.is_some_and(|context| owner.context_lease != context)
            || release(receipt).is_err()
        {
            return 1;
        }
    }
}

pub(super) unsafe fn begin_remap(
    receipt: OwnerReceipt,
) -> Option<(u64, nt_pnp_context::resource_mapping::MapEffectReceipt)> {
    table_mut().begin_remap(receipt).ok()
}

pub(super) unsafe fn finish_remap(
    effect: nt_pnp_context::resource_mapping::MapEffectReceipt,
    error: u64,
) -> bool {
    if error != 0 {
        let _ = table_mut().mark_map_uncertain(effect);
        return false;
    }
    table_mut()
        .acknowledge_map(effect)
        .expect("resource remap lost its retained original cap");
    true
}
