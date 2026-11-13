//! Select how an entered shared receive services nested hosted File work.
//!
//! This is a scheduling decision only. The native adapter owns the physical parent,
//! Reply, and any child receipt until it has observed an exact terminal.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedFileWorkPath {
    NoWork,
    Inline,
    RetainForRoot,
}

pub const fn nested_file_work_path(
    ready: bool,
    child_work_capable: bool,
) -> NestedFileWorkPath {
    if !ready {
        NestedFileWorkPath::NoWork
    } else if child_work_capable {
        NestedFileWorkPath::RetainForRoot
    } else {
        NestedFileWorkPath::Inline
    }
}
