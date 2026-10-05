//! Directory query admission and enumeration for the mounted layered volume.

use super::*;

impl MountedVolumeBackend {
    pub(super) fn query_directory(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let (context, binding) = self.binding(irp)?;
        if !binding.is_directory {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        if !nt_io_manager::directory_notify_access_granted(nt_types::AccessMask::from_bits_retain(
            binding.granted_access,
        )) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let IoParameters::QueryDirectory(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        if irp.minor != nt_io_manager::IRP_MN_QUERY_DIRECTORY {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        if irp
            .flags
            .contains(nt_io_manager::StackFlags::INDEX_SPECIFIED)
            || parameters.file_index != 0
        {
            return Err(NtStatus::NOT_SUPPORTED);
        }
        let length = parameters.length as usize;
        if length > ctx.system_buffer.len() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let file_id = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let record = self.opens.get(context, file_id.raw()).map_err(status)?;
        {
            // First use may restore and publish the persistent writable filesystem.
            let _durable = crate::allocator::enter_durable();
            unsafe { crate::writable_fs::ensure_mounted() }.map_err(status)?;
        }
        let (query, result) = {
            let _transient = crate::allocator::enter_transient();
            let mut installed = Vec::new();
            if let Some(cluster) = binding.installed_directory_cluster {
                let mut allocation_error = None;
                let end = unsafe {
                    fat_visit_directory_checked(&self.fs, cluster, |entry, _| {
                        if installed.try_reserve(1).is_err() {
                            allocation_error = Some(nt_fs::STATUS_INSUFFICIENT_RESOURCES);
                            return false;
                        }
                        installed.push(entry);
                        true
                    })
                }
                .map_err(status)?;
                if let Some(error) = allocation_error {
                    return Err(status(error));
                }
                if end != nt_fs::FatDirectoryWalkEnd::Complete {
                    return Err(status(nt_fs::STATUS_DATA_ERROR));
                }
            }
            let overlay = match record.source {
                nt_fs::LayeredOpenSource::Overlay { file_id } => {
                    if !binding.overlay_open {
                        return Err(NtStatus::INVALID_HANDLE);
                    }
                    Some(
                        unsafe { crate::writable_fs::directory_entries_opened(file_id) }
                            .map_err(status)?,
                    )
                }
                nt_fs::LayeredOpenSource::Installed { .. } => {
                    let open = self
                        .directories
                        .get(binding.directory_open.ok_or(NtStatus::INVALID_HANDLE)?)
                        .map_err(status)?;
                    unsafe {
                        crate::writable_fs::directory_entries_relative(open.volume_relative_path())
                    }
                    .map_err(status)?
                }
            };
            let entries = nt_fs::merge_layered_directory_entries(
                &installed,
                overlay.as_deref().unwrap_or(&[]),
            )
            .map_err(status)?;
            let mut query = binding.directory_query;
            let result = nt_fs::query_directory(
                &mut query,
                &entries,
                parameters.information_class,
                irp.flags
                    .contains(nt_io_manager::StackFlags::RETURN_SINGLE_ENTRY),
                parameters
                    .pattern
                    .as_ref()
                    .map(|pattern| pattern.as_units()),
                irp.flags.contains(nt_io_manager::StackFlags::RESTART_SCAN),
                &mut ctx.system_buffer[..length],
            );
            (query, result)
        };
        self.bindings[context_index(context).ok_or(NtStatus::INVALID_HANDLE)?]
            .as_mut()
            .expect("validated binding")
            .directory_query = query;
        Ok(DispatchOutcome::Completed {
            status: status(result.status),
            information: result.information as u64,
            file_context: None,
        })
    }
}
