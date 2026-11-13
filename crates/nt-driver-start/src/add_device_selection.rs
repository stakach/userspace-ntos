//! Which pending START row the flat root AddDevice phase admits next.
//!
//! The root admits one row per turn, in table order. This module owns only that choice: the
//! caller supplies each row's facts and drives the selected one.
//!
//! A bus child cannot enter AddDevice before its parent bus driver has reported its PDO, and
//! only another row's progress can make the bus driver report it. Such a row is passed over
//! instead of being retried at the head of the table, where it would starve the bus driver.

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

impl AddDeviceReadiness {
    /// Classify a row standing at an unentered devnode.
    pub fn for_unentered_devnode(requires_bus_pdo: bool, bus_pdo_reported: bool) -> Self {
        if requires_bus_pdo && !bus_pdo_reported {
            Self::AwaitingBusPdo
        } else {
            Self::Ready
        }
    }
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
    let mut awaiting: Option<AwaitingBusPdo<O>> = None;
    for (owner, readiness) in rows {
        match readiness {
            AddDeviceReadiness::NotReady => {}
            AddDeviceReadiness::AwaitingBusPdo => match awaiting.as_mut() {
                Some(awaiting) => awaiting.rows += 1,
                None => awaiting = Some(AwaitingBusPdo { first: owner, rows: 1 }),
            },
            AddDeviceReadiness::Ready => {
                return AddDeviceSelection::Selected {
                    owner,
                    passed_over: awaiting,
                };
            }
        }
    }
    awaiting.map_or(AddDeviceSelection::Idle, AddDeviceSelection::AwaitingBusRelations)
}

/// Bounds the boot-log evidence for selections that involve a row awaiting its bus PDO.
#[derive(Debug)]
pub struct AddDeviceSelectionEvidence<O> {
    last: Option<AddDeviceSelection<O>>,
    remaining: u32,
}

impl<O: Copy + PartialEq> AddDeviceSelectionEvidence<O> {
    pub const fn new(limit: u32) -> Self {
        Self {
            last: None,
            remaining: limit,
        }
    }

    /// Whether `selection` is worth one trace line: it passes over or stops at a row awaiting
    /// its bus PDO, differs from the last selection reported, and the budget is not spent.
    pub fn report(&mut self, selection: AddDeviceSelection<O>) -> bool {
        let involves_awaiting_row = match selection {
            AddDeviceSelection::Selected { passed_over, .. } => passed_over.is_some(),
            AddDeviceSelection::AwaitingBusRelations(_) => true,
            AddDeviceSelection::Idle => false,
        };
        if !involves_awaiting_row || self.remaining == 0 || self.last == Some(selection) {
            return false;
        }
        self.last = Some(selection);
        self.remaining -= 1;
        true
    }
}
