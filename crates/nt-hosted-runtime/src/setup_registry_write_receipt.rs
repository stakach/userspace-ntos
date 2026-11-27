//! Read-only evidence for a setup child's two completion markers.
//! A CM acknowledgement alone does not establish physical WAL durability.

use super::SetupOwnerIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupValueName {
    SystemSetupInProgress,
    SetupType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupWriteCandidate {
    owner: SetupOwnerIdentity,
    name: SetupValueName,
    value: u32,
}

impl SetupWriteCandidate {
    /// `selected` is the unique generation-checked direct child selected from Winlogon's live
    /// Process wait. Neither the path nor a numeric PID alone identifies the caller.
    pub fn capture(
        selected: SetupOwnerIdentity,
        caller: SetupOwnerIdentity,
        physical_path: &str,
        name: &str,
        value_type: u32,
        data: &[u8],
    ) -> Option<Self> {
        Self::capture_lazy(caller, physical_path, name, value_type, data, || Some(selected))
    }

    /// Exclude unrelated writes before reading Winlogon's live wait and process graph.
    pub fn capture_lazy(
        caller: SetupOwnerIdentity,
        physical_path: &str,
        name: &str,
        value_type: u32,
        data: &[u8],
        select: impl FnOnce() -> Option<SetupOwnerIdentity>,
    ) -> Option<Self> {
        if !physical_path.eq_ignore_ascii_case(r"\registry\machine\system\setup")
            || value_type != 4
        {
            return None;
        }
        let name = if name.eq_ignore_ascii_case("SystemSetupInProgress") {
            SetupValueName::SystemSetupInProgress
        } else if name.eq_ignore_ascii_case("SetupType") {
            SetupValueName::SetupType
        } else {
            return None;
        };
        let value = u32::from_le_bytes(data.try_into().ok()?);
        if select()? != caller { return None; }
        Some(Self { owner: caller, name, value })
    }

    pub const fn owner(self) -> SetupOwnerIdentity { self.owner }
    pub const fn name(self) -> SetupValueName { self.name }
    pub const fn value(self) -> u32 { self.value }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupWriteStorage {
    PerRow,
    Batch { epoch: u64, cm_mount: u64 },
}

/// The exact CM mutation has been acknowledged. For a batch, its marker and anchors are pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckedSetupWrite {
    candidate: SetupWriteCandidate,
    generation: u64,
    storage: SetupWriteStorage,
}

impl AckedSetupWrite {
    pub const fn new(candidate: SetupWriteCandidate, generation: u64, storage: SetupWriteStorage) -> Self {
        Self { candidate, generation, storage }
    }

    pub const fn candidate(self) -> SetupWriteCandidate { self.candidate }
    pub const fn generation(self) -> u64 { self.generation }
    pub const fn storage(self) -> SetupWriteStorage { self.storage }

    pub fn covered_by_batch(self, range: BatchDurableRange) -> bool {
        matches!(self.storage, SetupWriteStorage::Batch { epoch, cm_mount }
            if epoch == range.epoch && cm_mount == range.cm_mount
                && range.previous < self.generation && self.generation <= range.target)
    }
}

/// Published only after the matching physical marker, both anchors, release, and durable CAS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchDurableRange {
    pub epoch: u64,
    pub cm_mount: u64,
    pub previous: u64,
    pub target: u64,
}
