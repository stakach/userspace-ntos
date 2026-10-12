//! Retained two-slot snapshot-header anchor advancement for the disjoint registry WAL.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Pending,
    Complete,
    Uncertain,
}

/// Owns the exact device across both header barriers. An uncertain effect cannot release it.
#[must_use = "retain the exact snapshot device until both WAL anchor barriers complete"]
pub struct WalSnapshotAnchorUpdate<D: SnapshotBlockDevice> {
    device: Option<D>,
    store: SnapshotBlockStore,
    headers: [SlotHeader; 2],
    phase: Phase,
}

impl<D: SnapshotBlockDevice> core::fmt::Debug for WalSnapshotAnchorUpdate<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalSnapshotAnchorUpdate")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl<D: SnapshotBlockDevice> Drop for WalSnapshotAnchorUpdate<D> {
    fn drop(&mut self) {
        if self.phase != Phase::Complete {
            if let Some(device) = self.device.take() {
                core::mem::forget(device);
            }
            panic!("dropping unresolved WAL snapshot anchor update");
        }
    }
}

impl<D: SnapshotBlockDevice> WalSnapshotAnchorUpdate<D> {
    /// Admission reads and validates both payloads before any write. Failure returns the
    /// unchanged device; WAL mode must first establish two valid v2 snapshot slots.
    pub fn admit(
        store: SnapshotBlockStore,
        device: D,
        next: WalSnapshotAnchor,
    ) -> Result<Self, (SnapshotBlockStoreError, D)> {
        Self::admit_checked(store, device, next, |current| {
            if current[0] != current[1]
                || next.incarnation != current[0].incarnation
                || current[0].serial.checked_add(1) != Some(next.serial)
                || next.end_lba <= current[0].end_lba
            {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            Ok(())
        })
    }

    /// Repair or advance both copies to a prefix proven by a parsed WAL after reboot.
    /// The caller must replay that prefix into registry state before publishing it.
    pub fn admit_verified_prefix<W: SnapshotBlockDevice>(
        store: SnapshotBlockStore,
        device: D,
        next: WalSnapshotAnchor,
        wal: &crate::RegistryWal<W>,
    ) -> Result<Self, (SnapshotBlockStoreError, D)> {
        Self::admit_checked(store, device, next, |current| {
            let Some((incarnation, recovered_serial, _)) = wal.verified_prefix() else {
                return Err(SnapshotBlockStoreError::Corrupt);
            };
            if incarnation != next.incarnation
                || recovered_serial < next.serial
                || wal.verified_record_end_lba(next.serial) != Some(next.end_lba)
                || current.iter().any(|anchor| {
                    anchor.incarnation != incarnation
                        || wal.verified_record_end_lba(anchor.serial) != Some(anchor.end_lba)
                        || anchor.serial > next.serial
                })
            {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            Ok(())
        })
    }

    fn admit_checked<F>(
        store: SnapshotBlockStore,
        mut device: D,
        next: WalSnapshotAnchor,
        check: F,
    ) -> Result<Self, (SnapshotBlockStoreError, D)>
    where
        F: FnOnce([WalSnapshotAnchor; 2]) -> Result<(), SnapshotBlockStoreError>,
    {
        let plans = (|| {
            let a = store
                .read_valid_slot_plan(&mut device, 0)?
                .ok_or(SnapshotBlockStoreError::Corrupt)?;
            let b = store
                .read_valid_slot_plan(&mut device, 1)?
                .ok_or(SnapshotBlockStoreError::Corrupt)?;
            let am = a.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
            let bm = b.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
            check([am.anchor(), bm.anchor()])?;
            Ok::<_, SnapshotBlockStoreError>([a, b])
        })();
        let plans = match plans {
            Ok(plans) => plans,
            Err(error) => return Err((error, device)),
        };
        let headers = plans.map(|plan| {
            let mut wal = plan.wal.unwrap();
            wal.high_water_serial = next.serial;
            wal.high_water_end_lba = next.end_lba;
            SlotHeader {
                slot: plan.slot,
                generation: plan.generation,
                payload_len: plan.payload_len as u64,
                payload_crc: plan.payload_crc,
                payload_sectors: plan.payload_sectors,
                wal: Some(wal),
            }
        });
        Ok(Self {
            device: Some(device),
            store,
            headers,
            phase: Phase::Pending,
        })
    }

    /// Write and flush each complete header in turn. No caller success is allowed before
    /// this returns Ok; on any error the exact device remains retained as uncertain.
    pub fn advance(&mut self) -> Result<(), SnapshotBlockStoreError> {
        if self.phase != Phase::Pending {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let result = (|| {
            let device = self.device.as_mut().expect("retained anchor device");
            let (sector_size, slot_sectors) = self.store.geometry(device)?;
            if sector_size < WAL_HEADER_LEN {
                return Err(SnapshotBlockStoreError::InvalidGeometry);
            }
            let mut sector = Vec::new();
            sector
                .try_reserve_exact(sector_size)
                .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
            sector.resize(sector_size, 0);
            for header in self.headers {
                sector.fill(0);
                encode_header(&mut sector, header);
                let lba = self.store.slot_lba(slot_sectors, header.slot)?;
                device.write_sector(lba, &sector)?;
                device.flush()?;
            }
            Ok(())
        })();
        self.phase = if result.is_ok() {
            Phase::Complete
        } else {
            Phase::Uncertain
        };
        result
    }

    pub fn into_device(mut self) -> Result<D, Self> {
        if self.phase == Phase::Complete {
            Ok(self.device.take().expect("retained anchor device"))
        } else {
            Err(self)
        }
    }

    #[cfg(test)]
    pub(super) fn into_device_for_test(mut self) -> D {
        self.phase = Phase::Complete;
        self.device.take().expect("retained anchor device")
    }
}
