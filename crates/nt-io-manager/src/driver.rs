//! Driver records + the major-function dispatch table (spec §10).

use alloc::vec::Vec;

use nt_io_abi::{major::IO_MAJOR_FUNCTION_COUNT, DeviceId, DriverId};
use nt_types::{NtPath, ObjectId};

/// Identifies a registered dispatch backend for a driver (mock or driver-peer).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct DriverBackendId(pub u64);

/// Identifies a configured mock dispatch handler (test backend).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct MockDispatchId(pub u64);

/// Identifies a driver peer (future Driver Host bridge).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct DriverPeerId(pub u64);

/// The dispatch target for one major function (spec §10.2). Never a raw function
/// pointer — only ids, so nothing crosses a component boundary.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum DispatchTarget {
    /// The driver does not handle this major function.
    #[default]
    Unsupported,
    /// Handled by an in-process mock backend (tests / bring-up).
    Mock(MockDispatchId),
    /// Handled by an isolated driver peer over SURT.
    DriverPeer(DriverPeerId),
}

/// The per-driver major-function dispatch table (spec §10.2). Abstract — indexed
/// by major function code, each entry a [`DispatchTarget`].
#[derive(Clone)]
pub struct MajorFunctionTable {
    entries: [DispatchTarget; IO_MAJOR_FUNCTION_COUNT],
}

impl Default for MajorFunctionTable {
    fn default() -> Self {
        Self {
            entries: [DispatchTarget::Unsupported; IO_MAJOR_FUNCTION_COUNT],
        }
    }
}

impl MajorFunctionTable {
    /// A table with every major function unsupported.
    pub fn new() -> Self {
        Self::default()
    }

    /// The target for `major`, or `Unsupported` if out of range.
    pub fn get(&self, major: u8) -> DispatchTarget {
        self.entries
            .get(major as usize)
            .copied()
            .unwrap_or(DispatchTarget::Unsupported)
    }

    /// Set the target for `major`. No-op if `major` is out of range.
    pub fn set(&mut self, major: u8, target: DispatchTarget) {
        if let Some(slot) = self.entries.get_mut(major as usize) {
            *slot = target;
        }
    }

    /// Set the same target for every major function (a catch-all backend).
    pub fn set_all(&mut self, target: DispatchTarget) {
        self.entries = [target; IO_MAJOR_FUNCTION_COUNT];
    }
}

bitflags::bitflags! {
    /// Driver-record flags.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct DriverFlags: u32 {
        /// Still initialising (no devices dispatchable yet).
        const INITIALIZING = 0x0000_0001;
        /// The driver (peer) has faulted; its devices are failing.
        const FAULTED = 0x0000_0002;
    }
}

/// Driver unload lifecycle (spec §10.1).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum DriverUnloadState {
    #[default]
    Loaded,
    UnloadRequested,
    Unloaded,
}

/// The devices owned by a driver (spec §10.1).
pub type DeviceList = Vec<DeviceId>;

/// Canonical I/O Manager driver record (spec §10.1). `object_id` points at the
/// Object Manager `Driver` object that owns identity/name/lifetime.
pub struct DriverRecord {
    pub id: DriverId,
    pub object_id: ObjectId,
    pub name: NtPath,
    pub dispatch: MajorFunctionTable,
    pub devices: DeviceList,
    pub backend: DriverBackendId,
    pub flags: DriverFlags,
    pub unload_state: DriverUnloadState,
}

impl DriverRecord {
    /// A newly-registered driver (id filled in by the store's caller).
    pub fn new(
        object_id: ObjectId,
        name: NtPath,
        backend: DriverBackendId,
        dispatch: MajorFunctionTable,
    ) -> Self {
        Self {
            id: DriverId::NULL,
            object_id,
            name,
            dispatch,
            devices: DeviceList::new(),
            backend,
            flags: DriverFlags::empty(),
            unload_state: DriverUnloadState::Loaded,
        }
    }
}
