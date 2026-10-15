//! Exact-lease retirement of a fully folded SYSTEM WAL incarnation.

use alloc::vec::Vec;

use super::*;
use crate::{BoundedBlockRange, OwnedBoundedBlockRange, RegistryWal, RegistryWalState,
    RegistryWalVerifiedDevice};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Admitted,
    Resetting,
    Complete,
    Uncertain,
}

/// Retains the whole reserve while both slots change incarnation and the old WAL is erased.
#[must_use = "retain the exact reserve through paired RESETTING and READY headers"]
pub struct WalSnapshotEpochRollover<D: SnapshotBlockDevice> {
    device: Option<D>,
    store: SnapshotBlockStore,
    wal_start: u64,
    wal_sectors: u64,
    next_incarnation: u64,
    phase: Phase,
}

impl<D: SnapshotBlockDevice> Drop for WalSnapshotEpochRollover<D> {
    fn drop(&mut self) {
        if self.phase != Phase::Complete {
            if let Some(device) = self.device.take() {
                core::mem::forget(device);
            }
            panic!("dropping unresolved WAL epoch rollover");
        }
    }
}

impl<D: SnapshotBlockDevice> WalSnapshotEpochRollover<D> {
    /// Requires two complete snapshots with every old WAL record folded and no unanchored tail.
    /// Admission writes nothing and returns the verified physical owner on refusal.
    pub fn admit(
        store: SnapshotBlockStore,
        mut verified: RegistryWalVerifiedDevice<OwnedBoundedBlockRange<D>>,
        next_incarnation: u64,
    ) -> Result<Self, (SnapshotBlockStoreError, RegistryWalVerifiedDevice<OwnedBoundedBlockRange<D>>)> {
        let old = verified.anchor();
        let wal_start = verified.device_mut().start_lba();
        let wal_sectors = verified.device_mut().sector_count();
        let valid = (|| {
            let snapshot_end = store.start_lba.checked_add(store.sector_count)
                .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
            let wal_end = wal_start.checked_add(wal_sectors)
                .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
            if next_incarnation == 0 || next_incarnation == old.incarnation
                || old.serial == 0 || wal_sectors == 0
                || wal_start < snapshot_end && wal_end > store.start_lba
            {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            let plans = paired(&store, verified.device_mut().parent_device_mut())?;
            if plans.iter().any(|plan| plan.resetting || plan.wal.is_none_or(|wal| {
                wal.anchor() != old || wal.base_serial != old.serial
            })) {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            Ok(())
        })();
        if let Err(error) = valid {
            return Err((error, verified));
        }
        Ok(Self {
            device: Some(verified.into_full_device().into_device()), store, wal_start, wal_sectors,
            next_incarnation, phase: Phase::Admitted,
        })
    }

    /// Complete the first durable RESETTING header. The old WAL remains untouched.
    pub fn publish_resetting(&mut self) -> Result<(), SnapshotBlockStoreError> {
        if self.phase != Phase::Admitted {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let device = self.device.as_mut().expect("retained rollover device");
        let result = (|| {
            let plans = paired(&self.store, device)?;
            let older = if plans[0].generation < plans[1].generation { plans[0] } else { plans[1] };
            write_header(&self.store, device, older, self.next_incarnation, true)
        })();
        self.phase = if result.is_ok() { Phase::Resetting } else { Phase::Uncertain };
        result
    }

    /// Resume a durable mixed or paired RESETTING state after reboot, before normal mount.
    pub fn resume(
        store: SnapshotBlockStore,
        mut device: D,
        wal_start: u64,
        wal_sectors: u64,
    ) -> Result<Self, (SnapshotBlockStoreError, D)> {
        let result = (|| {
            let snapshot_end = store.start_lba.checked_add(store.sector_count)
                .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
            let wal_end = wal_start.checked_add(wal_sectors)
                .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
            if wal_sectors == 0 || wal_start < snapshot_end && wal_end > store.start_lba {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            let plans = paired(&store, &mut device)?;
            let resetting = plans.iter().find(|plan| plan.resetting).ok_or(SnapshotBlockStoreError::Corrupt)?;
            let next = resetting.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
            if next.base_serial != 0 || next.high_water_serial != 0 || next.high_water_end_lba != 0
                || wal_start.checked_add(wal_sectors).is_none_or(|end| end > device.sector_count())
            {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            for plan in plans {
                let wal = plan.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
                if plan.resetting {
                    if wal != next { return Err(SnapshotBlockStoreError::Corrupt); }
                } else if wal.incarnation != next.incarnation {
                    // Erasure has not begun while an old folded header survives.
                    if wal.base_serial != wal.high_water_serial || wal.high_water_serial == 0 {
                        return Err(SnapshotBlockStoreError::Corrupt);
                    }
                    let range = BoundedBlockRange::new(&mut device, wal_start, wal_sectors)
                        .map_err(|_| SnapshotBlockStoreError::InvalidGeometry)?;
                    let recovered = RegistryWal::recover(range, wal.incarnation)
                        .map_err(|_| SnapshotBlockStoreError::Corrupt)?;
                    if recovered.state() != RegistryWalState::Ready
                        || recovered.settled_anchor() != Some(wal.anchor())
                    {
                        core::mem::forget(recovered);
                        return Err(SnapshotBlockStoreError::Corrupt);
                    }
                } else if wal != next {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
            }
            Ok(next.incarnation)
        })();
        match result {
            Ok(next_incarnation) => Ok(Self {
                device: Some(device), store, wal_start, wal_sectors,
                next_incarnation, phase: Phase::Resetting,
            }),
            Err(error) => Err((error, device)),
        }
    }

    /// Make both RESETTING headers durable, erase old WAL, then publish both READY headers.
    pub fn finish(&mut self) -> Result<(), SnapshotBlockStoreError> {
        if self.phase != Phase::Resetting {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let device = self.device.as_mut().expect("retained rollover device");
        let result = (|| {
            let plans = paired(&self.store, device)?;
            for plan in plans {
                if !plan.resetting {
                    let wal = plan.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
                    if wal.incarnation != self.next_incarnation {
                        write_header(&self.store, device, plan, self.next_incarnation, true)?;
                    }
                }
            }
            let plans = paired(&self.store, device)?;
            let empty = WalSnapshotManifest {
                incarnation: self.next_incarnation, base_serial: 0,
                high_water_serial: 0, high_water_end_lba: 0,
            };
            if plans.iter().any(|plan| plan.wal != Some(empty)) {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            erase_old_wal(device, self.wal_start, self.wal_sectors)?;
            for plan in plans {
                if plan.resetting {
                    write_header(&self.store, device, plan, self.next_incarnation, false)?;
                }
            }
            Ok(())
        })();
        self.phase = if result.is_ok() { Phase::Complete } else { Phase::Uncertain };
        result
    }

    pub fn into_device(mut self) -> Result<D, Self> {
        if self.phase == Phase::Complete {
            Ok(self.device.take().expect("completed rollover device"))
        } else {
            Err(self)
        }
    }

    #[cfg(test)]
    pub(crate) fn device_mut_for_test(&mut self) -> &mut D {
        self.device.as_mut().expect("test rollover device")
    }

    #[cfg(test)]
    pub(crate) fn into_device_for_test(mut self) -> D {
        self.phase = Phase::Complete;
        self.device.take().expect("test rollover device")
    }
}

fn paired<D: SnapshotBlockDevice>(
    store: &SnapshotBlockStore,
    device: &mut D,
) -> Result<[SlotReadPlan; 2], SnapshotBlockStoreError> {
    let a = store.read_valid_slot_plan(device, 0)?.ok_or(SnapshotBlockStoreError::Corrupt)?;
    let b = store.read_valid_slot_plan(device, 1)?.ok_or(SnapshotBlockStoreError::Corrupt)?;
    if a.generation == b.generation {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    Ok([a, b])
}

fn write_header<D: SnapshotBlockDevice>(
    store: &SnapshotBlockStore,
    device: &mut D,
    plan: SlotReadPlan,
    next_incarnation: u64,
    resetting: bool,
) -> Result<(), SnapshotBlockStoreError> {
    let (size, slot_sectors) = store.geometry(device)?;
    if size < 84 { return Err(SnapshotBlockStoreError::InvalidGeometry); }
    let mut sector = Vec::new();
    sector.try_reserve_exact(size).map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
    sector.resize(size, 0);
    encode_header(&mut sector, SlotHeader {
        slot: plan.slot, generation: plan.generation, payload_len: plan.payload_len as u64,
        payload_crc: plan.payload_crc, payload_sectors: plan.payload_sectors,
        wal: Some(WalSnapshotManifest {
            incarnation: next_incarnation, base_serial: 0,
            high_water_serial: 0, high_water_end_lba: 0,
        }),
        resetting,
    });
    device.write_sector(store.slot_lba(slot_sectors, plan.slot)?, &sector)?;
    device.flush()
}

fn erase_old_wal<D: SnapshotBlockDevice>(
    device: &mut D,
    start: u64,
    sectors: u64,
) -> Result<(), SnapshotBlockStoreError> {
    let size = device.sector_size();
    let mut zero = Vec::new();
    zero.try_reserve_exact(size).map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
    zero.resize(size, 0);
    for offset in (1..sectors).rev() {
        device.write_sector(start + offset, &zero)?;
    }
    device.flush()?;
    device.write_sector(start, &zero)?;
    device.flush()
}
