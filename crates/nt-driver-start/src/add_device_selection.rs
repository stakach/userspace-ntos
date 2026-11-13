//! Which pending START row the flat root AddDevice phase admits next.
//!
//! The root admits one row per turn, in table order. This module owns only that choice: the
//! caller classifies each row and drives the selected one.

/// What one pending row offers the flat root AddDevice phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddDeviceReadiness {
    /// No unentered devnode is on offer: the row is inside native work, awaits a completion, or
    /// is ordered behind a live predecessor.
    NotReady,
    /// The next devnode is a bus child whose parent bus has not reported its PDO.
    AwaitingBusPdo,
    /// The next devnode may enter AddDevice now.
    Ready,
}

/// Rows whose next devnode waits for a bus driver to report its PDO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AwaitingBusPdo<O> {
    /// First such row in table order.
    pub first: O,
    pub rows: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddDeviceSelection<O> {
    /// Admit this exact row. `passed_over` describes the rows before it that await a bus PDO.
    Selected {
        owner: O,
        passed_over: Option<AwaitingBusPdo<O>>,
    },
    /// No row can enter AddDevice until a bus driver reports the PDO these rows wait for.
    AwaitingBusRelations(AwaitingBusPdo<O>),
    /// No row has an unentered devnode.
    Idle,
}

/// Choose the row to admit from `rows` in table order. Rows after the selected one are not
/// inspected.
pub fn select_add_device_row<O: Copy>(
    rows: impl IntoIterator<Item = (O, AddDeviceReadiness)>,
) -> AddDeviceSelection<O> {
    for (owner, readiness) in rows {
        if readiness != AddDeviceReadiness::NotReady {
            return AddDeviceSelection::Selected {
                owner,
                passed_over: None,
            };
        }
    }
    AddDeviceSelection::Idle
}
