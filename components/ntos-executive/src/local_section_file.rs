//! Local File references retained by Section backing owners.

use crate::ExecNtHandler;
use nt_memory_manager::{
    GenericSectionBacking, RoutedSectionLease, SectionFileIdentity, SectionIdentity,
};
use nt_user_host::routed_section_owner::RoutedSectionOwners;

struct DiskSectionSource {
    file: LocalSectionFile,
    identity: SectionFileIdentity,
}

static mut DATA_SOURCES: RoutedSectionOwners<DiskSectionSource> = RoutedSectionOwners::new();

/// Reserve the owner before acquiring the exact opened File's additional body reference.
pub(crate) unsafe fn reserve_disk_source(
    handler: &mut ExecNtHandler,
    object_id: u32,
    first_cluster: u32,
    size: u32,
) -> Result<(GenericSectionBacking, RoutedSectionLease), u32> {
    let open = handler.readonly_file_opens.get(object_id)?;
    if open.first_cluster != first_cluster || open.size != size {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    if open.metadata.is_directory {
        return Err(0xc000_0020);
    }
    let identity =
        crate::exec_fs_file_identity(open.metadata.file_id).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let _durable = crate::allocator::enter_durable();
    let owners = &mut *core::ptr::addr_of_mut!(DATA_SOURCES);
    let lease = owners
        .reserve(DiskSectionSource {
            file: LocalSectionFile::Disk {
                object_id,
                first_cluster,
                size,
            },
            identity,
        })
        .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
    if let Err(status) = handler.readonly_file_opens.retain_io(object_id) {
        // retain_io validates before mutation, so this owner has no acquired reference.
        assert!(owners.cancel_unbound(lease).is_some());
        return Err(status);
    }
    let mut backing = GenericSectionBacking::disk(first_cluster, size, identity);
    backing.local_lease = Some(lease);
    Ok((backing, lease))
}

pub(crate) unsafe fn bind(lease: RoutedSectionLease, section: SectionIdentity) -> bool {
    (&mut *core::ptr::addr_of_mut!(DATA_SOURCES)).bind(lease, section)
}

pub(crate) unsafe fn cancel_unbound(
    handler: &mut ExecNtHandler,
    lease: RoutedSectionLease,
) -> Result<(), u32> {
    let released = (&mut *core::ptr::addr_of_mut!(DATA_SOURCES))
        .cancel_unbound_checked(lease, |source| {
            release_disk_source(source, &mut handler.readonly_file_opens)
        })?;
    if released {
        Ok(())
    } else {
        Err(nt_fs::STATUS_INVALID_HANDLE)
    }
}

pub(crate) unsafe fn validate_bound(
    lease: RoutedSectionLease,
    section: SectionIdentity,
    backing: GenericSectionBacking,
) -> Result<(), u32> {
    let source = (&*core::ptr::addr_of!(DATA_SOURCES))
        .get(lease, section)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    if crate::exec_fs_file_identity(source.identity.file_id) != Some(source.identity) {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    match &source.file {
        LocalSectionFile::Disk {
            first_cluster,
            size,
            ..
        } if backing.kind == nt_memory_manager::GENERIC_SECTION_BACKING_DISK
            && backing.local_lease == Some(lease)
            && backing.first_cluster == *first_cluster
            && backing.file_size == *size
            && backing.file == Some(source.identity) =>
        {
            Ok(())
        }
        _ => Err(nt_fs::STATUS_INVALID_HANDLE),
    }
}

pub(crate) unsafe fn release_bound(
    files: &mut crate::ExecReadOnlyFileOpens,
    lease: RoutedSectionLease,
    section: SectionIdentity,
) -> Result<(), u32> {
    let released = (&mut *core::ptr::addr_of_mut!(DATA_SOURCES)).release_checked(
        lease,
        section,
        |source| release_disk_source(source, files),
    )?;
    if released {
        Ok(())
    } else {
        Err(nt_fs::STATUS_INVALID_HANDLE)
    }
}

fn release_disk_source(
    source: &mut DiskSectionSource,
    files: &mut crate::ExecReadOnlyFileOpens,
) -> Result<(), u32> {
    match &source.file {
        LocalSectionFile::Disk {
            object_id,
            first_cluster,
            size,
        } => {
            let open = files.get(*object_id)?;
            if open.first_cluster != *first_cluster
                || open.size != *size
                || unsafe { crate::exec_fs_file_identity(open.metadata.file_id) }
                    != Some(source.identity)
            {
                return Err(nt_fs::STATUS_INVALID_HANDLE);
            }
            files.release_io(*object_id)
        }
        _ => Err(nt_fs::STATUS_INVALID_HANDLE),
    }
}

pub(crate) unsafe fn data_sources_empty() -> bool {
    (&*core::ptr::addr_of!(DATA_SOURCES)).is_empty()
}

#[must_use = "release the retained local File only after exact Section backing retirement"]
pub(crate) enum LocalSectionFile {
    Disk {
        object_id: u32,
        first_cluster: u32,
        size: u32,
    },
    Overlay {
        object_id: u64,
    },
}

impl LocalSectionFile {
    pub(crate) fn read_exact(
        &self,
        handler: &ExecNtHandler,
        backing: GenericSectionBacking,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), u32> {
        let Self::Disk {
            object_id,
            first_cluster,
            size,
        } = self
        else {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        };
        let open = handler.readonly_file_opens.get(*object_id)?;
        let identity = unsafe { crate::exec_fs_file_identity(open.metadata.file_id) }
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        if open.metadata.is_directory
            || open.first_cluster != *first_cluster
            || open.size != *size
            || backing.kind != nt_memory_manager::GENERIC_SECTION_BACKING_DISK
            || backing.file != Some(identity)
            || backing.first_cluster != *first_cluster
            || backing.file_size != *size
            || backing.file_extent != u64::from(*size)
            || offset
                .checked_add(output.len() as u64)
                .is_none_or(|end| end > u64::from(*size))
        {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        let fs = unsafe { crate::exec_fs() }.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        let offset = u32::try_from(offset).map_err(|_| nt_fs::STATUS_INVALID_HANDLE)?;
        let copied = unsafe {
            crate::fs_loader::fat_read_file_range(&fs, *first_cluster, *size, offset, output)
        };
        if copied != output.len() {
            return Err(0xc000_0185);
        }
        Ok(())
    }

    pub(crate) unsafe fn release(self, handler: &mut ExecNtHandler) {
        match self {
            Self::Disk { object_id, .. } => handler
                .readonly_file_opens
                .release_io(object_id)
                .expect("retained image disk File"),
            Self::Overlay { object_id } => crate::writable_fs::release_io_reference(object_id)
                .expect("retained image overlay File"),
        }
    }
}
