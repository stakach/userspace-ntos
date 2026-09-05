//! Protection-range application against a stable metadata snapshot.

use crate::{PAGE_SIZE, STATUS_INVALID_PARAMETER};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtectionChangeFailure {
    pub status: u32,
    pub rollback_status: Option<u32>,
}

/// Apply a validated, uniform protection change. The metadata reader must remain stable during
/// rollback. A failed remap must preserve that page's prior rights; completed earlier remaps are
/// reversed here. The adapter decides how to handle cold pages without materializing them.
pub fn apply_protection_range(
    base: u64,
    size: u64,
    new_protection: u32,
    old_protection: impl Fn(u64) -> Result<u32, u32>,
    mut remap: impl FnMut(u64, u32, u32) -> Result<(), u32>,
) -> Result<(), ProtectionChangeFailure> {
    let invalid = ProtectionChangeFailure {
        status: STATUS_INVALID_PARAMETER,
        rollback_status: None,
    };
    let end = base.checked_add(size).ok_or(invalid)?;
    if base % PAGE_SIZE != 0 || size == 0 || size % PAGE_SIZE != 0 {
        return Err(invalid);
    }
    let mut page = base;
    while page < end {
        let result = old_protection(page).and_then(|old| {
            if old == new_protection {
                Ok(())
            } else {
                remap(page, old, new_protection)
            }
        });
        if let Err(status) = result {
            let mut rollback_status = None;
            let mut restore = base;
            while restore < page {
                let result = old_protection(restore).and_then(|old| {
                    if old == new_protection {
                        Ok(())
                    } else {
                        remap(restore, new_protection, old)
                    }
                });
                if let Err(error) = result {
                    rollback_status.get_or_insert(error);
                }
                restore += PAGE_SIZE;
            }
            return Err(ProtectionChangeFailure {
                status,
                rollback_status,
            });
        }
        page += PAGE_SIZE;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, STATUS_ACCESS_VIOLATION,
    };
    use alloc::{collections::BTreeMap, vec::Vec};

    #[test]
    fn mixed_residency_changes_only_existing_frames() {
        let mut resident = BTreeMap::from([(0x1000, PAGE_READWRITE), (0x3000, PAGE_READWRITE)]);
        assert_eq!(
            apply_protection_range(
                0x1000,
                0x4000,
                PAGE_READONLY,
                |_| Ok(PAGE_READWRITE),
                |page, _, new| {
                    if let Some(protection) = resident.get_mut(&page) {
                        *protection = new;
                    }
                    Ok(())
                }
            ),
            Ok(())
        );
        assert_eq!(
            resident,
            BTreeMap::from([(0x1000, PAGE_READONLY), (0x3000, PAGE_READONLY)])
        );
    }

    #[test]
    fn first_page_failure_has_no_completed_prefix_to_restore() {
        let mut attempts = Vec::new();
        let result = apply_protection_range(
            0x1000,
            0x3000,
            PAGE_READONLY,
            |_| Ok(PAGE_READWRITE),
            |page, old, new| {
                attempts.push((page, old, new));
                Err(STATUS_ACCESS_VIOLATION)
            },
        );
        assert_eq!(
            result,
            Err(ProtectionChangeFailure {
                status: STATUS_ACCESS_VIOLATION,
                rollback_status: None,
            })
        );
        assert_eq!(attempts, [(0x1000, PAGE_READWRITE, PAGE_READONLY)]);
    }

    #[test]
    fn failure_restores_each_prior_protection_from_the_snapshot() {
        let before = [PAGE_READWRITE, PAGE_READONLY | PAGE_GUARD, PAGE_NOACCESS];
        let mut resident = before;
        assert_eq!(
            apply_protection_range(
                0x1000,
                0x3000,
                PAGE_READONLY,
                |page| Ok(before[(page / PAGE_SIZE - 1) as usize]),
                |page, _, new| {
                    let index = (page / PAGE_SIZE - 1) as usize;
                    if index == 2 {
                        return Err(STATUS_ACCESS_VIOLATION);
                    }
                    resident[index] = new;
                    Ok(())
                }
            ),
            Err(ProtectionChangeFailure {
                status: STATUS_ACCESS_VIOLATION,
                rollback_status: None
            })
        );
        assert_eq!(resident, before);
    }

    #[test]
    fn failed_rollback_is_reported_and_remaining_pages_are_still_restored() {
        let mut restored = Vec::new();
        let result = apply_protection_range(
            0x1000,
            0x4000,
            PAGE_READONLY,
            |_| Ok(PAGE_READWRITE),
            |page, _, new| {
                if page == 0x4000 {
                    return Err(STATUS_ACCESS_VIOLATION);
                }
                if new == PAGE_READWRITE {
                    if page == 0x1000 {
                        return Err(0xdead);
                    }
                    restored.push(page);
                }
                Ok(())
            },
        );
        assert_eq!(
            result,
            Err(ProtectionChangeFailure {
                status: STATUS_ACCESS_VIOLATION,
                rollback_status: Some(0xdead),
            })
        );
        assert_eq!(restored, [0x2000, 0x3000]);
    }

    #[test]
    fn invalid_snapshot_entry_rolls_back_the_completed_prefix() {
        let mut protection = PAGE_READWRITE;
        let result = apply_protection_range(
            0x1000,
            0x2000,
            PAGE_READONLY,
            |page| {
                if page == 0x1000 {
                    Ok(PAGE_READWRITE)
                } else {
                    Err(STATUS_ACCESS_VIOLATION)
                }
            },
            |_, _, new| {
                protection = new;
                Ok(())
            },
        );
        assert_eq!(
            result,
            Err(ProtectionChangeFailure {
                status: STATUS_ACCESS_VIOLATION,
                rollback_status: None
            })
        );
        assert_eq!(protection, PAGE_READWRITE);
    }

    #[test]
    fn unchanged_pages_do_not_remap() {
        assert_eq!(
            apply_protection_range(
                0x1000,
                0x2000,
                PAGE_READWRITE,
                |_| Ok(PAGE_READWRITE),
                |_, _, _| panic!("unchanged protection must not remap")
            ),
            Ok(())
        );
    }

    #[test]
    fn invalid_ranges_do_not_touch_metadata_or_backing() {
        for (base, size) in [
            (0x1001, 0x1000),
            (0x1000, 0),
            (0x1000, 0x1001),
            (u64::MAX & !0xfff, 0x1000),
        ] {
            assert_eq!(
                apply_protection_range(
                    base,
                    size,
                    PAGE_READONLY,
                    |_| panic!("invalid range must not read"),
                    |_, _, _| panic!("invalid range must not remap")
                ),
                Err(ProtectionChangeFailure {
                    status: STATUS_INVALID_PARAMETER,
                    rollback_status: None
                })
            );
        }
    }
}
