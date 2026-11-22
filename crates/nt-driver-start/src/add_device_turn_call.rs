//! Which root Calls the parked AddDevice turn admits (#420).
//!
//! NT serialises only PnP enumeration of the devnode in AddDevice (the PnP worker runs
//! `PiDevNodeStateMachine` for one devnode at a time). Every other thread and driver keeps
//! running. That includes the driver a nested child targets, which may need the root to
//! service its own Calls before it can admit that child. A parked parent's physical hold is
//! its own Reply, its leased bank pages and its lane. A Call from another lane touches none of
//! these, so the turn admits it. It defers only what the root defers for every Call.

/// What the parked AddDevice turn does with an unexecuted Call it received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddDeviceTurnCall {
    /// Run it now, as the ordinary loop would.
    Admit,
    /// Return it to its ingress row; the root delivers it once its own gate clears.
    Defer,
}

/// `win32k_publication_busy`: a win32k Call while the shared publication is being settled.
/// `journal_owns_volume`: the registry journal owns the mounted volume.
pub const fn add_device_turn_call(
    win32k_publication_busy: bool,
    journal_owns_volume: bool,
) -> AddDeviceTurnCall {
    if win32k_publication_busy || journal_owns_volume {
        AddDeviceTurnCall::Defer
    } else {
        AddDeviceTurnCall::Admit
    }
}
