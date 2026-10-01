//! Physical ownership acquired before a hosted driver's primary route exists.

use super::*;
use nt_hosted_runtime::{DriverLoadPhase, RetainedEffectState};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Frame,
    Table,
}

#[derive(Clone, Copy)]
struct Cap {
    slot: u64,
    kind: Kind,
    mapped: bool,
    effect: RetainedEffectState,
}

struct Receipt {
    caps: Vec<Cap>,
    enrolled_frames: Vec<u64>,
    phase: DriverLoadPhase,
    canonical_driver: Option<u64>,
    canonical_release_entered: bool,
}

static mut RECEIPTS: Vec<Option<Receipt>> = Vec::new();

unsafe fn receipt(index: usize) -> Option<&'static mut Receipt> {
    (&mut *core::ptr::addr_of_mut!(RECEIPTS))
        .get_mut(index)?
        .as_mut()
}

pub(super) unsafe fn begin(index: usize) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(RECEIPTS);
    if rows
        .try_reserve(index.saturating_add(1).saturating_sub(rows.len()))
        .is_err()
    {
        return false;
    }
    while rows.len() <= index {
        rows.push(None);
    }
    if rows[index].is_some() {
        return false;
    }
    rows[index] = Some(Receipt {
        caps: Vec::new(),
        enrolled_frames: Vec::new(),
        phase: DriverLoadPhase::Allocating,
        canonical_driver: None,
        canonical_release_entered: false,
    });
    true
}

pub(super) unsafe fn reserve(index: usize, count: usize) -> bool {
    receipt(index)
        .is_some_and(|row| row.phase.pre_enrollment() && row.caps.try_reserve(count).is_ok())
}

/// Frame runs acquired after enrollment are transferred to primary retirement.
/// Reserve before retyping so each successful batch can be recorded without allocation.
pub(super) unsafe fn reserve_frame_run(index: usize, count: usize) -> bool {
    let Some(row) = receipt(index) else { return false };
    match row.phase {
        DriverLoadPhase::Enrolled => row.enrolled_frames.try_reserve(count).is_ok(),
        _ => row.phase.pre_enrollment() && row.caps.try_reserve(count).is_ok(),
    }
}

pub(super) unsafe fn own_frame(index: usize, slot: u64) -> bool {
    let Some(row) = receipt(index) else { return false };
    if row.phase == DriverLoadPhase::Enrolled {
        if slot == 0 || row.enrolled_frames.contains(&slot) || row.enrolled_frames.try_reserve(1).is_err() {
            return false;
        }
        row.enrolled_frames.push(slot);
        return true;
    }
    own(index, slot, Kind::Frame)
}

pub(super) unsafe fn own_table(index: usize, slot: u64) -> bool {
    own(index, slot, Kind::Table)
}

unsafe fn own(index: usize, slot: u64, kind: Kind) -> bool {
    let Some(row) = receipt(index) else {
        return false;
    };
    if !row.phase.pre_enrollment()
        || slot == 0
        || row.caps.iter().any(|cap| cap.slot == slot)
        || row.caps.try_reserve(1).is_err()
    {
        return false;
    }
    row.caps.push(Cap {
        slot,
        kind,
        mapped: false,
        effect: RetainedEffectState::Ready,
    });
    true
}

pub(super) unsafe fn mapped(index: usize, slot: u64, kind: bool) -> bool {
    let Some(row) = receipt(index) else {
        return false;
    };
    let Some(cap) = row.caps.iter_mut().find(|cap| cap.slot == slot) else {
        return false;
    };
    if !row.phase.pre_enrollment()
        || cap.mapped
        || cap.kind != (if kind { Kind::Table } else { Kind::Frame })
    {
        return false;
    }
    cap.mapped = true;
    true
}

pub(super) unsafe fn canonical_published(index: usize, driver_id: u64) -> bool {
    let Some(row) = receipt(index) else {
        return false;
    };
    if driver_id == 0 || row.canonical_driver.is_some() {
        return false;
    }
    let Some(next) = row.phase.publish_canonical() else {
        return false;
    };
    row.canonical_driver = Some(driver_id);
    row.phase = next;
    true
}

pub(super) unsafe fn suspended(index: usize) -> bool {
    let Some(row) = receipt(index) else {
        return false;
    };
    let Some(next) = row.phase.record_suspended() else {
        return false;
    };
    row.phase = next;
    true
}

pub(super) unsafe fn early_rollback_eligible(index: usize) -> bool {
    receipt(index).is_some_and(|row| row.phase.pre_enrollment())
}

pub(super) unsafe fn claim_canonical_release(index: usize) -> Option<u64> {
    let row = receipt(index)?;
    if !row.phase.pre_enrollment() || row.canonical_release_entered {
        return None;
    }
    let driver = row.canonical_driver?;
    row.canonical_release_entered = true;
    Some(driver)
}

pub(super) unsafe fn canonical_released(index: usize, driver_id: u64) -> bool {
    let Some(row) = receipt(index) else {
        return false;
    };
    if row.canonical_driver != Some(driver_id) || !row.canonical_release_entered {
        return false;
    }
    row.canonical_driver = None;
    row.canonical_release_entered = false;
    true
}

pub(super) unsafe fn has_canonical_driver(index: usize) -> bool {
    receipt(index).is_some_and(|row| row.canonical_driver.is_some())
}

/// The transport owns frame runs and aliases after registration. Keep page-table caps here;
/// these executive-side tables are not part of DriverInstance's frame-run ledger.
pub(super) unsafe fn transport_registered(index: usize) -> bool {
    let Some(row) = receipt(index) else {
        return false;
    };
    let Some(next) = row.phase.enroll() else {
        return false;
    };
    if row.canonical_driver.is_none() {
        return false;
    }
    row.caps.retain(|cap| cap.kind == Kind::Table);
    row.phase = next;
    true
}

pub(super) unsafe fn table_count(index: usize) -> usize {
    receipt(index).map_or(0, |row| row.caps.len())
}

pub(super) unsafe fn enrolled_frame_count(index: usize) -> usize {
    receipt(index).map_or(0, |row| row.enrolled_frames.len())
}

/// Move confirmed post-enrollment retypes to the primary release before native effects.
pub(super) unsafe fn take_enrolled_frames(index: usize) -> Option<Vec<u64>> {
    let row = receipt(index)?;
    (row.phase == DriverLoadPhase::Enrolled).then(|| core::mem::take(&mut row.enrolled_frames))
}

/// Transfer table ownership to the primary physical release receipt before its first effect.
pub(super) unsafe fn take_transport_tables(index: usize) -> Option<Vec<(u64, bool)>> {
    let row = receipt(index)?;
    if row.phase != DriverLoadPhase::Enrolled
        || row
            .caps
            .iter()
            .any(|cap| cap.effect == RetainedEffectState::Entered || cap.kind != Kind::Table)
    {
        return None;
    }
    let tables = row.caps.iter().map(|cap| (cap.slot, cap.mapped)).collect();
    row.caps.clear();
    Some(tables)
}

/// A failed native effect is indeterminate. Never replay it or free the cap's slot.
pub(super) unsafe fn retire_early(index: usize) -> bool {
    let Some(row) = receipt(index) else {
        return false;
    };
    if !row.phase.pre_enrollment()
        || row.canonical_driver.is_some()
        || row.canonical_release_entered
    {
        return false;
    }
    while let Some(cap) = row.caps.last_mut() {
        if !cap.effect.begin() {
            return false;
        }
        if cap.mapped {
            let result = match cap.kind {
                Kind::Frame => page_unmap_r(cap.slot),
                Kind::Table => {
                    paging_struct_map_r(cap.slot, sel4_rt::LBL_X86_PAGE_TABLE_UNMAP, 0, 0)
                }
            };
            if !cap.effect.acknowledge(result == 0) {
                return false;
            }
            cap.mapped = false;
            if !cap.effect.begin() {
                return false;
            }
        }
        let deleted = cnode_delete_r(cap.slot) == 0;
        if !cap.effect.acknowledge(deleted) {
            return false;
        }
        let slot = cap.slot;
        row.caps.pop();
        recycle_deleted_root_slot(slot);
    }
    true
}

pub(super) unsafe fn finish(index: usize) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(RECEIPTS);
    let Some(slot) = rows.get_mut(index) else {
        return false;
    };
    if slot.as_ref().is_none_or(|row| !row.caps.is_empty() || !row.enrolled_frames.is_empty()) {
        return false;
    }
    *slot = None;
    true
}
