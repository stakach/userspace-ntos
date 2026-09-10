//! Prepare all returned-error boundaries before changing namespace, data or file identities.

use super::*;

#[derive(Default)]
pub(super) struct CreateAllocator {
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    step: usize,
}

impl CreateAllocator {
    fn checkpoint(&mut self) -> Result<(), u32> {
        #[cfg(test)]
        {
            let step = self.step;
            self.step += 1;
            if self.fail_at == Some(step) {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        }
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<String, u32> {
        self.checkpoint()?;
        let mut result = String::new();
        result
            .try_reserve_exact(value.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        result.push_str(value);
        Ok(result)
    }

    fn reserve<T>(&mut self, values: &mut Vec<T>) -> Result<(), u32> {
        self.checkpoint()?;
        values
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)
    }
}

pub(super) enum PreparedCreate {
    Existing {
        node: u64,
        entry: u64,
        information: u32,
    },
    New {
        parent: u64,
        node: MemFsNode,
        entry: MemFsDirEntry,
    },
}

impl MemFs {
    fn existing_create(
        &self,
        existing: Option<(u64, u64)>,
        disposition: u32,
        options: u32,
    ) -> Result<Option<PreparedCreate>, u32> {
        let Some((node, entry)) = existing else {
            return match disposition {
                FILE_OPEN | FILE_OVERWRITE => Err(STATUS_OBJECT_NAME_NOT_FOUND),
                FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE => Ok(None),
                _ => Err(STATUS_INVALID_PARAMETER),
            };
        };
        let is_dir = self.node(node).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?.is_dir;
        if options & FILE_DIRECTORY_FILE != 0 && !is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if options & FILE_DIRECTORY_FILE == 0 && is_dir && options & FILE_NON_DIRECTORY_FILE != 0 {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let information = match disposition {
            FILE_OPEN | FILE_OPEN_IF => FILE_OPENED,
            FILE_CREATE => return Err(STATUS_OBJECT_NAME_COLLISION),
            FILE_OVERWRITE | FILE_OVERWRITE_IF => FILE_OVERWRITTEN,
            FILE_SUPERSEDE => FILE_SUPERSEDED,
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        Ok(Some(PreparedCreate::Existing {
            node,
            entry,
            information,
        }))
    }

    pub(super) fn prepare_create(
        &mut self,
        path: &str,
        disposition: u32,
        options: u32,
        attributes: u32,
        allocator: &mut CreateAllocator,
    ) -> Result<PreparedCreate, u32> {
        if let Some(plan) =
            self.existing_create(self.lookup_entry_from(0, path), disposition, options)?
        {
            return Ok(plan);
        }
        let (parent_path, leaf) = Self::parent_and_leaf(path).ok_or(STATUS_INVALID_PARAMETER)?;
        let parent = self
            .lookup(parent_path)
            .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        self.prepare_create_child(parent, leaf, options, attributes, allocator)
    }

    pub(super) fn prepare_create_folded(
        &mut self,
        start: u64,
        path: &[u8],
        disposition: u32,
        options: u32,
        attributes: u32,
        allocator: &mut CreateAllocator,
    ) -> Result<PreparedCreate, u32> {
        if let Some(plan) = self.existing_create(
            self.lookup_folded_entry_from(start, path),
            disposition,
            options,
        )? {
            return Ok(plan);
        }
        let (parent_path, leaf) =
            Self::parent_and_leaf_bytes(path).ok_or(STATUS_INVALID_PARAMETER)?;
        let parent = self
            .lookup_folded_from(start, parent_path)
            .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        let leaf = core::str::from_utf8(leaf).map_err(|_| STATUS_INVALID_PARAMETER)?;
        self.prepare_create_child(parent, leaf, options, attributes, allocator)
    }

    pub(super) fn prepare_create_child(
        &mut self,
        parent: u64,
        leaf: &str,
        options: u32,
        attributes: u32,
        allocator: &mut CreateAllocator,
    ) -> Result<PreparedCreate, u32> {
        if !self.node(parent).is_some_and(|node| node.is_dir) {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        if leaf.is_empty() || leaf == "." || leaf == ".." || leaf.contains('\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.child_entry(parent, leaf).is_some() {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        self.next_file_id
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        self.next_entry_id
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let node_id = u64::try_from(self.nodes.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let mut folded = allocator.string(leaf)?;
        folded.make_ascii_lowercase();
        let created_name = allocator.string(leaf)?;
        allocator.reserve(&mut self.nodes)?;
        allocator.reserve(&mut self.node_mut(parent).unwrap().children)?;
        let is_dir = options & FILE_DIRECTORY_FILE != 0;
        let requested = attributes & FILE_ATTRIBUTE_SETTABLE;
        let attributes = match (requested, is_dir) {
            (0, true) => FILE_ATTRIBUTE_DIRECTORY,
            (0, false) => FILE_ATTRIBUTE_ARCHIVE,
            (_, true) => requested | FILE_ATTRIBUTE_DIRECTORY,
            (_, false) => requested,
        };
        let now = self.current_time_100ns;
        Ok(PreparedCreate::New {
            parent,
            node: MemFsNode {
                file_id: self.next_file_id,
                is_dir,
                attributes,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
                link_count: 1,
                parent,
                allocation_size: 0,
                valid_data_length: 0,
                data: FileData::empty(),
                children: Vec::new(),
            },
            entry: MemFsDirEntry {
                id: self.next_entry_id,
                folded_name: folded,
                created_name,
                folded_short_name: String::new(),
                short_name: FileShortName::EMPTY,
                node_id,
            },
        })
    }

    fn create_opened_name(
        &self,
        plan: &PreparedCreate,
        allocator: &mut CreateAllocator,
    ) -> Result<String, u32> {
        allocator.checkpoint()?;
        let (parent, leaf) = match plan {
            PreparedCreate::Existing { entry, .. } => {
                return self
                    .opened_name(*entry)
                    .ok_or(STATUS_INSUFFICIENT_RESOURCES);
            }
            PreparedCreate::New { parent, entry, .. } => (*parent, entry.created_name.as_str()),
        };
        let parent_entry = if parent == 0 {
            0
        } else {
            let grandparent = self
                .node(parent)
                .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?
                .parent;
            self.node(grandparent)
                .and_then(|node| node.children.iter().find(|entry| entry.node_id == parent))
                .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?
                .id
        };
        let mut name = self
            .opened_name(parent_entry)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let separator = usize::from(parent != 0);
        let additional = leaf
            .len()
            .checked_add(separator)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        allocator.checkpoint()?;
        name.try_reserve_exact(additional)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        if separator != 0 {
            name.push('\\');
        }
        name.push_str(leaf);
        Ok(name)
    }

    // A plan never escapes the exclusive filesystem operation. Only capacity/name preparation
    // runs between planning and apply, so all identities and slots are still exactly those admitted.
    pub(super) fn apply_create(&mut self, plan: PreparedCreate) -> (u64, u64, u32) {
        match plan {
            PreparedCreate::Existing {
                node,
                entry,
                information,
            } => {
                if matches!(information, FILE_OVERWRITTEN | FILE_SUPERSEDED) {
                    let target = self.node_mut(node).expect("admitted create target");
                    if !target.is_dir {
                        target.data = FileData::empty();
                        target.allocation_size = 0;
                        target.valid_data_length = 0;
                    }
                }
                (node, entry, information)
            }
            PreparedCreate::New {
                parent,
                node,
                entry,
            } => {
                let id = entry.node_id;
                let entry_id = entry.id;
                self.next_file_id += 1;
                self.next_entry_id += 1;
                self.nodes.push(Some(node));
                self.node_mut(parent).unwrap().children.push(entry);
                (id, entry_id, FILE_CREATED)
            }
        }
    }
}

impl FileSystem {
    pub(super) fn create_and_publish(
        &mut self,
        options: u32,
        share: FileShareAccess,
        prepare: impl FnOnce(&mut MemFs, &mut CreateAllocator) -> Result<PreparedCreate, u32>,
    ) -> CreateResult {
        let mut allocator = CreateAllocator::default();
        #[cfg(test)]
        {
            allocator.fail_at = self.create_fail_at.take();
        }
        let admission = (|| {
            let plan = prepare(&mut self.volume, &mut allocator)?;
            let opened_name = self.volume.create_opened_name(&plan, &mut allocator)?;
            let handle = match self.handles.iter().position(|slot| slot.is_none()) {
                Some(free) => free,
                None => {
                    allocator.reserve(&mut self.handles)?;
                    self.handles.len()
                }
            };
            Ok((plan, opened_name, handle))
        })();
        let (plan, opened_name, handle) = match admission {
            Ok(admitted) => admitted,
            Err(status) => {
                return CreateResult {
                    status,
                    handle: INVALID_HANDLE,
                    information: 0,
                }
            }
        };
        let (node_id, entry_id, information) = self.volume.apply_create(plan);
        if handle == self.handles.len() {
            self.handles.push(None);
        }
        self.handles[handle] = Some(FileObject {
            node_id,
            entry_id,
            opened_name,
            current_offset: 0,
            signaled: true,
            create_options: options,
            share,
            open_privileges: FileOpenPrivileges::default(),
            handle_references: 1,
            references: 1,
            serialization: nt_io_completion::FileIoSerialization::new(),
            cleanup_reference_held: false,
            cleanup_error: None,
            delete_pending: options & FILE_DELETE_ON_CLOSE != 0,
            query: DirectoryQueryState::new(),
        });
        let notify = match information {
            FILE_CREATED => Some((
                if self.volume.is_dir(node_id) {
                    crate::FILE_NOTIFY_CHANGE_DIR_NAME
                } else {
                    crate::FILE_NOTIFY_CHANGE_FILE_NAME
                },
                crate::FILE_ACTION_ADDED,
            )),
            FILE_OVERWRITTEN | FILE_SUPERSEDED => Some((
                crate::FILE_NOTIFY_CHANGE_SIZE | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
                crate::FILE_ACTION_MODIFIED,
            )),
            _ => None,
        };
        if let Some((filter, action)) = notify {
            self.notifications.report_change(crate::DirectoryChange {
                full_path: &self.handles[handle].as_ref().unwrap().opened_name,
                filter,
                action,
            });
        }
        CreateResult {
            status: STATUS_SUCCESS,
            handle: handle as u64,
            information,
        }
    }
}

#[cfg(test)]
#[path = "file_create/tests.rs"]
mod tests;
