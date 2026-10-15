//! Output surfaces for a finalized IopCreateFile result.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileCreateOutputPlan {
    None,
    IoStatus,
    HandleAndIoStatus,
}

/// PENDING is not a finalized result; ordinary errors preserve both output surfaces.
pub const fn file_create_output_plan(status: u32) -> FileCreateOutputPlan {
    if status == crate::STATUS_PENDING {
        return FileCreateOutputPlan::None;
    }
    match status >> 30 {
        3 => FileCreateOutputPlan::None,
        2 => FileCreateOutputPlan::IoStatus,
        _ => FileCreateOutputPlan::HandleAndIoStatus,
    }
}
