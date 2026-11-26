//! One exclusive owner for the mounted in-memory volume, independent of its journal or WAL work.

static GATE: nt_fs::VolumeOwnerGate = nt_fs::VolumeOwnerGate::new();

pub(crate) fn owns_volume() -> bool { GATE.is_owned() }

pub(super) fn claim() -> Result<nt_fs::VolumeOwner<'static>, u32> {
    match GATE.try_claim() {
        Ok(owner) => Ok(owner),
        Err(nt_fs::VolumeOwnerError::Busy) => Err(super::snapshot_storage::BUSY),
        Err(nt_fs::VolumeOwnerError::EpochExhausted) =>
            Err(nt_fs::STATUS_INSUFFICIENT_RESOURCES),
    }
}
