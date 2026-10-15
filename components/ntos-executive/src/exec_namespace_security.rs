//! Checked namespace captures and exact Directory body references shared by object admission.

use super::*;

impl ExecNtHandler {
    pub(super) fn capture_named_creator_security_descriptor(
        &mut self,
        address: u64,
    ) -> Result<Vec<u8>, u32> {
        let _durable = allocator::enter_durable();
        struct Memory<'a> {
            handler: core::cell::RefCell<&'a mut ExecNtHandler>,
            fault: core::cell::Cell<Option<u32>>,
        }
        impl nt_security::ClientMemory for Memory<'_> {
            fn read(&self, address: u64, bytes: &mut [u8]) -> bool {
                if self.fault.get().is_some() {
                    return false;
                }
                let mut handler = self.handler.borrow_mut();
                let pi = handler.pi;
                match unsafe { handler.process_memory_read_status(pi, address, bytes) } {
                    Ok(()) => true,
                    Err(status) => {
                        self.fault.set(Some(status));
                        false
                    }
                }
            }
        }
        let memory = Memory {
            handler: core::cell::RefCell::new(self),
            fault: core::cell::Cell::new(None),
        };
        let result = nt_security::capture_security_descriptor_bytes(&memory, address);
        match memory.fault.get() {
            Some(status) => Err(status),
            None => result,
        }
    }

    pub(super) fn directory_security_descriptor(&self, index: usize) -> Result<&[u8], u32> {
        let entry = self.obj_ns.get(index).ok_or(0xC000_0008u32)?;
        if !entry.is_live() || entry.kind != OBJ_KIND_DIRECTORY {
            return Err(0xC000_0024);
        }
        self.directory_security
            .iter()
            .find(|record| record.identity == entry.identity)
            .map(|record| record.descriptor.as_slice())
            .ok_or(0xC000_0022)
    }

    pub(super) fn prepare_namespace_directory_references(
        &self,
        indices: [Option<usize>; 3],
    ) -> Result<Vec<(usize, u64)>, u32> {
        let _durable = allocator::enter_durable();
        let mut references = Vec::new();
        references
            .try_reserve_exact(3)
            .map_err(|_| 0xC000_009Au32)?;
        for index in indices.into_iter().flatten() {
            if references.iter().any(|&(owned, _)| owned == index) {
                continue;
            }
            let identity = self.obj_ns[index].identity;
            let record = self
                .directory_security
                .iter()
                .find(|record| record.identity == identity)
                .ok_or(0xC000_0022u32)?;
            record.references.checked_add(1).ok_or(0xC000_009Au32)?;
            references.push((index, identity));
        }
        Ok(references)
    }

    pub(super) fn retain_namespace_directory_references(&mut self, references: &[(usize, u64)]) {
        for &(_, identity) in references {
            self.directory_security
                .iter_mut()
                .find(|record| record.identity == identity)
                .expect("prevalidated directory body reference")
                .references += 1;
        }
    }

    pub(super) fn release_namespace_directory_references(&mut self, references: &[(usize, u64)]) {
        for &(index, identity) in references {
            let record = self
                .directory_security
                .iter_mut()
                .find(|record| record.identity == identity)
                .expect("retained exact directory body and descriptor");
            record.references = record
                .references
                .checked_sub(1)
                .expect("one namespace admission reference release");
            self.release_directory_namespace_reference(identity);
            self.retire_directory_security_body(index, identity);
        }
    }

    pub(super) fn native_directory_root_and_path<'a>(
        &self,
        caller: nt_process::native_handle::NativeHandleCaller,
        root: u64,
        path: &'a [u8],
    ) -> Result<(usize, &'a [u8]), u32> {
        if root == 0 {
            return if path.first() == Some(&b'\\') {
                Ok((0, path))
            } else {
                Err(0xC000_0033)
            };
        }
        if path.first() == Some(&b'\\') {
            return Err(0xC000_0033);
        }
        let identity = self
            .pm
            .lookup_native_object_directory_handle(caller, root, 0)?;
        Ok((self.directory_namespace_index_for_identity(identity)?, path))
    }

    pub(super) fn obj_resolve_authorized(
        &self,
        path: &[u8],
        root_idx: usize,
        follow_final_link: bool,
        mut traverse: impl FnMut(usize) -> Result<(), u32>,
    ) -> Result<Option<usize>, u32> {
        const SYMLINK_LIMIT: u32 = 32;
        let mut components = Self::object_path_components(path);
        let mut cur = if path.first() == Some(&b'\\') {
            0
        } else {
            root_idx
        };
        let mut index = 0usize;
        let mut hops = 0u32;
        while index < components.len() {
            let Some(cur_entry) = self.obj_ns.get(cur) else {
                return Ok(None);
            };
            if !cur_entry.is_live() || cur_entry.kind != OBJ_KIND_DIRECTORY {
                return Ok(None);
            }
            traverse(cur)?;
            let Some(child) = self.obj_child(cur, &components[index]) else {
                return Ok(None);
            };
            let Some(entry) = self.obj_ns.get(child) else {
                return Ok(None);
            };
            if !entry.is_live() {
                return Ok(None);
            }
            let final_component = index + 1 == components.len();
            if entry.kind == OBJ_KIND_SYMBOLIC_LINK && (!final_component || follow_final_link) {
                hops += 1;
                if hops > SYMLINK_LIMIT {
                    return Ok(None);
                }
                let target = entry.target();
                let target_absolute = target.first() == Some(&b'\\');
                let mut rebuilt = Self::object_path_components(target);
                rebuilt.extend(components[index + 1..].iter().cloned());
                components = rebuilt;
                cur = if target_absolute {
                    0
                } else if entry.parent == OBJ_PARENT_ROOT {
                    0
                } else {
                    entry.parent
                };
                index = 0;
                continue;
            }
            cur = child;
            index += 1;
        }
        Ok(Some(cur))
    }
}
