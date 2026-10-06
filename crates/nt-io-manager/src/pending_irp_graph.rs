//! Ordered exact allocation-base inventory from one retained pending IRP snapshot.
//! This metadata is not transfer authority: native callers must retain/authenticate the actual
//! graph generation and physical allocation arena before observing or releasing its pointers.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PendingIrpGraphPointers {
    pub reclaim: u64,
    pub mdl: u64,
    pub aux_data: u64,
    pub data: u64,
    pub create_parameters: u64,
    pub create_access_state: u64,
    pub create_security_context: u64,
    pub pnp_resource_list: u64,
    pub irp: u64,
    pub file_object: u64,
    pub owns_file: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphReleaseKind {
    Pool,
    FileStorage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphAllocation {
    pub pointer: u64,
    pub release_kind: GraphReleaseKind,
}

pub struct PendingIrpAllocationGraph {
    allocations: [GraphAllocation; 10],
    len: usize,
}

impl PendingIrpAllocationGraph {
    pub fn new(pointers: PendingIrpGraphPointers) -> Self {
        let candidates = [
            pointers.reclaim,
            pointers.mdl,
            pointers.aux_data,
            pointers.data,
            pointers.create_parameters,
            pointers.create_access_state,
            pointers.create_security_context,
            pointers.pnp_resource_list,
            pointers.irp,
            if pointers.owns_file {
                pointers.file_object
            } else {
                0
            },
        ];
        let mut graph = Self {
            allocations: [GraphAllocation {
                pointer: 0,
                release_kind: GraphReleaseKind::Pool,
            }; 10],
            len: 0,
        };
        for pointer in candidates {
            if pointer == 0 || graph.contains_pointer(pointer) {
                continue;
            }
            graph.allocations[graph.len] = GraphAllocation {
                pointer,
                // An owned File alias in an earlier candidate still uses the File finalizer.
                release_kind: if pointers.owns_file && pointer == pointers.file_object {
                    GraphReleaseKind::FileStorage
                } else {
                    GraphReleaseKind::Pool
                },
            };
            graph.len += 1;
        }
        graph
    }

    pub fn allocations(&self) -> &[GraphAllocation] {
        &self.allocations[..self.len]
    }

    /// Exact allocation-base equality only, not a range or physical ownership check.
    pub fn contains_pointer(&self, pointer: u64) -> bool {
        pointer != 0 && self.allocations().iter().any(|row| row.pointer == pointer)
    }
}

#[cfg(test)]
#[path = "pending_irp_graph_tests.rs"]
mod tests;
