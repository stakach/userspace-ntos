//! Driver records + the major-function dispatch table (spec §10).

use alloc::boxed::Box;
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

const DISPATCH_TARGET_TAG_SHIFT: u64 = 62;
const DISPATCH_TARGET_ID_MASK: u64 = (1u64 << DISPATCH_TARGET_TAG_SHIFT) - 1;
const DISPATCH_TARGET_UNSUPPORTED: u64 = 0;
const DISPATCH_TARGET_MOCK: u64 = 1;
const DISPATCH_TARGET_KERNEL: u64 = 2;
const DISPATCH_TARGET_DRIVER_PEER: u64 = 3;

/// The dispatch target for one major function (spec §10.2). Never a raw function pointer: only
/// compactly encoded backend ids cross component boundaries.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct DispatchTarget(u64);

impl DispatchTarget {
    /// The driver does not handle this major function.
    #[allow(non_upper_case_globals)]
    pub const Unsupported: Self = Self(DISPATCH_TARGET_UNSUPPORTED << DISPATCH_TARGET_TAG_SHIFT);

    /// Handled by an in-process mock backend (tests / bring-up).
    #[allow(non_snake_case)]
    pub const fn Mock(id: MockDispatchId) -> Self {
        Self::encode(DISPATCH_TARGET_MOCK, id.0)
    }

    /// Handled by a kernel-owned in-process backend.
    #[allow(non_snake_case)]
    pub const fn Kernel(id: DriverBackendId) -> Self {
        Self::encode(DISPATCH_TARGET_KERNEL, id.0)
    }

    /// Handled by an isolated driver peer over SURT.
    #[allow(non_snake_case)]
    pub const fn DriverPeer(id: DriverPeerId) -> Self {
        Self::encode(DISPATCH_TARGET_DRIVER_PEER, id.0)
    }

    const fn encode(tag: u64, id: u64) -> Self {
        Self((tag << DISPATCH_TARGET_TAG_SHIFT) | (id & DISPATCH_TARGET_ID_MASK))
    }

    const fn tag(self) -> u64 {
        self.0 >> DISPATCH_TARGET_TAG_SHIFT
    }

    const fn id(self) -> u64 {
        self.0 & DISPATCH_TARGET_ID_MASK
    }

    pub const fn is_supported(self) -> bool {
        self.tag() != DISPATCH_TARGET_UNSUPPORTED
    }

    pub const fn mock_id(self) -> Option<MockDispatchId> {
        if self.tag() == DISPATCH_TARGET_MOCK {
            Some(MockDispatchId(self.id()))
        } else {
            None
        }
    }

    pub const fn kernel_id(self) -> Option<DriverBackendId> {
        if self.tag() == DISPATCH_TARGET_KERNEL {
            Some(DriverBackendId(self.id()))
        } else {
            None
        }
    }

    pub const fn driver_peer_id(self) -> Option<DriverPeerId> {
        if self.tag() == DISPATCH_TARGET_DRIVER_PEER {
            Some(DriverPeerId(self.id()))
        } else {
            None
        }
    }
}

impl core::fmt::Debug for DispatchTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.tag() {
            DISPATCH_TARGET_MOCK => f
                .debug_tuple("Mock")
                .field(&MockDispatchId(self.id()))
                .finish(),
            DISPATCH_TARGET_KERNEL => f
                .debug_tuple("Kernel")
                .field(&DriverBackendId(self.id()))
                .finish(),
            DISPATCH_TARGET_DRIVER_PEER => f
                .debug_tuple("DriverPeer")
                .field(&DriverPeerId(self.id()))
                .finish(),
            _ => f.write_str("Unsupported"),
        }
    }
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

    /// Allocate and initialize a dispatch table without materializing the array on the caller's
    /// stack. This is used by boot-time kernel paths that run on deliberately small stacks.
    pub fn boxed_with_majors(majors: &[u8], target: DispatchTarget) -> Box<Self> {
        let mut table = Self::boxed_filled(DispatchTarget::Unsupported);
        for &major in majors {
            table.set(major, target);
        }
        table
    }

    pub fn boxed_from(table: Self) -> Box<Self> {
        Box::new(table)
    }

    pub fn boxed_filled(target: DispatchTarget) -> Box<Self> {
        let mut boxed = Box::<Self>::new_uninit();
        unsafe {
            let entries =
                core::ptr::addr_of_mut!((*boxed.as_mut_ptr()).entries) as *mut DispatchTarget;
            for idx in 0..IO_MAJOR_FUNCTION_COUNT {
                entries.add(idx).write(target);
            }
            boxed.assume_init()
        }
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

    /// Replace every supported entry with `target`, preserving unsupported entries.
    pub fn retarget(&mut self, target: DispatchTarget) {
        for slot in &mut self.entries {
            if slot.is_supported() {
                *slot = target;
            }
        }
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
    pub dispatch: Box<MajorFunctionTable>,
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
        Self::new_boxed(object_id, name, backend, Box::new(dispatch))
    }

    /// A newly-registered driver whose dispatch table was allocated directly in its final storage.
    pub fn new_boxed(
        object_id: ObjectId,
        name: NtPath,
        backend: DriverBackendId,
        dispatch: Box<MajorFunctionTable>,
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
