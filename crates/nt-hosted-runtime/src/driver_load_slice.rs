//! What a driver load does after one DriverEntry slice (#420).
//!
//! DriverEntry is an irreversible native effect. A load whose DriverEntry pump stopped before
//! the driver returned has no result yet: it must neither publish the driver nor roll the
//! instance back, and the caller that parked its lane for the load stays parked. Only a
//! returned DriverEntry decides between publication and rollback.

/// How one DriverEntry (or post-DriverEntry reinitialization) slice ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverLoadSliceEnd {
    /// The pump stopped unfinished and the calling service keeps it.
    Kept,
    /// The pump returned this receipt.
    Returned { completed: bool, status: i32 },
}

/// The load's next step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverLoadStep {
    /// Keep every load resource and the caller's parked lane; no rollback, no reply.
    KeepParked,
    /// DriverEntry returned success: publish the driver.
    Publish,
    /// DriverEntry returned (or walled) without success: roll the instance back with this.
    RollBack(i32),
}

pub const fn driver_load_step(end: DriverLoadSliceEnd) -> DriverLoadStep {
    match end {
        DriverLoadSliceEnd::Kept => DriverLoadStep::KeepParked,
        DriverLoadSliceEnd::Returned { completed: false, .. } =>
            DriverLoadStep::RollBack(0xc000_0001u32 as i32),
        DriverLoadSliceEnd::Returned { completed: true, status } if status < 0 =>
            DriverLoadStep::RollBack(status),
        DriverLoadSliceEnd::Returned { .. } => DriverLoadStep::Publish,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unfinished_driver_entry_is_kept_not_rolled_back() {
        assert_eq!(driver_load_step(DriverLoadSliceEnd::Kept), DriverLoadStep::KeepParked,
            "a DriverEntry still running must not report failure or free its instance");
    }

    #[test]
    fn only_a_returned_driver_entry_publishes_or_rolls_back() {
        assert_eq!(driver_load_step(DriverLoadSliceEnd::Returned { completed: true, status: 0 }),
            DriverLoadStep::Publish);
        assert_eq!(driver_load_step(DriverLoadSliceEnd::Returned {
            completed: true, status: 0xc000_0022u32 as i32 }),
            DriverLoadStep::RollBack(0xc000_0022u32 as i32));
        assert_eq!(driver_load_step(DriverLoadSliceEnd::Returned { completed: false, status: 0 }),
            DriverLoadStep::RollBack(0xc000_0001u32 as i32));
    }
}
