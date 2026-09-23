//! Native directory enumeration over the executive's canonical object namespace.

use super::*;
use nt_object_manager::directory::pack_directory_entries;

impl ExecNtHandler {
    pub(super) unsafe fn nt_query_directory_object(
        &mut self,
        ctx: &NativeCallContext,
        args: &[u64],
    ) -> u32 {
        SERVICES_QUERY_DIR_OBJECT.fetch_add(1, Ordering::Relaxed);
        let dir_handle = args[0];
        let buffer = args[1];
        let length = nt_ulong_arg(args[2]) as usize;
        let single = nt_boolean_arg(args[3]);
        let restart = nt_boolean_arg(args[4]);
        let context_ptr = args[5];
        let return_length_ptr = args[6];

        let caller = match self.native_directory_caller(ctx.previous_mode) {
            Ok(caller) => caller,
            Err(status) => return status,
        };
        let identity = match self.pm.lookup_native_object_directory_handle(
            caller,
            dir_handle,
            DIRECTORY_QUERY_ACCESS,
        ) {
            Ok(identity) => identity,
            Err(status) => return status,
        };
        let dir_idx = match self.directory_namespace_index_for_identity(identity) {
            Ok(index) => index,
            Err(status) => return status,
        };

        if length != 0 {
            if buffer & 1 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            if let Err(status) = self.probe_copy_output(self.pi, buffer, length as u64) {
                return status;
            }
        }
        if context_ptr == 0 {
            return STATUS_ACCESS_VIOLATION;
        }
        if context_ptr & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if let Err(status) = self.probe_copy_scalar::<4>(context_ptr) {
            return status;
        }
        if return_length_ptr != 0 {
            if return_length_ptr & 3 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            if let Err(status) = self.probe_copy_scalar::<4>(return_length_ptr) {
                return status;
            }
        }
        let context = if restart {
            0
        } else {
            let mut bytes = [0u8; 4];
            if !self.xas_read(context_ptr, &mut bytes) {
                return STATUS_ACCESS_VIOLATION;
            }
            u32::from_le_bytes(bytes)
        };

        let _transient = allocator::enter_transient();
        let mut entries = alloc::vec::Vec::new();
        if entries.try_reserve(self.obj_ns.len()).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        for entry in self
            .obj_ns
            .iter()
            .filter(|entry| entry.is_live() && entry.parent == dir_idx)
        {
            let name: alloc::vec::Vec<u16> =
                entry.name().iter().map(|byte| u16::from(*byte)).collect();
            let type_name = match entry.kind {
                OBJ_KIND_EVENT => "Event",
                OBJ_KIND_SYMBOLIC_LINK => "SymbolicLink",
                OBJ_KIND_SEMAPHORE => "Semaphore",
                OBJ_KIND_MUTANT => "Mutant",
                OBJ_KIND_LPC_PORT => "Port",
                OBJ_KIND_TIMER => "Timer",
                OBJ_KIND_IO_COMPLETION => "IoCompletion",
                OBJ_KIND_JOB => "Job",
                _ => "Directory",
            };
            entries.push((
                nt_types::UnicodeString::from_units(&name),
                nt_types::UnicodeString::from_str(type_name),
            ));
        }

        let Some(max_length) = entries.iter().try_fold(32usize, |total, (name, ty)| {
            total
                .checked_add(32)?
                .checked_add(name.len().checked_mul(2)?)?
                .checked_add(ty.len().checked_mul(2)?)?
                .checked_add(4)
        }) else {
            return STATUS_INVALID_PARAMETER;
        };
        let output_length = length.min(max_length);
        let mut output = alloc::vec::Vec::new();
        if output.try_reserve_exact(output_length).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        output.resize(output_length, 0);
        let packed =
            match pack_directory_entries(&entries, context, restart, single, buffer, &mut output) {
                Ok(packed) => packed,
                Err(status) => return status.raw() as u32,
            };
        if packed.written != 0
            && !self.xas_try_write_buf(buffer, &output[..packed.written as usize])
        {
            return STATUS_ACCESS_VIOLATION;
        }
        if packed.status.is_success()
            && !self.xas_try_write_buf(context_ptr, &packed.context.to_le_bytes())
        {
            return STATUS_ACCESS_VIOLATION;
        }
        if return_length_ptr != 0
            && !self.xas_try_write_buf(return_length_ptr, &packed.return_length.to_le_bytes())
        {
            return STATUS_ACCESS_VIOLATION;
        }
        packed.status.raw() as u32
    }
}
