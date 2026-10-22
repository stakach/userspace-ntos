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
    torn_companion_source: Option<SlotReadPlan>,
    continuation: Option<crate::RegistryWalContinuation>,
    paired_proof: Option<VerifiedPairedWalSnapshot>,
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
    pub(super) fn encode_async_header(&self, index: usize, out: &mut [u8]) {
        out.fill(0);
        encode_header(out, self.headers[index]);
    }

    pub(super) fn async_header_lba(&self, slot_sectors: u64, slot: u32)
        -> Result<u64, SnapshotBlockStoreError> {
        self.store.slot_lba(slot_sectors, slot)
    }

    pub(super) fn complete_async_headers(&mut self) { self.phase = Phase::Complete; }
    pub(super) fn fail_async_headers(&mut self) { self.phase = Phase::Uncertain; }

    #[cfg(test)]
    pub(super) fn device_for_test(&mut self) -> &mut D {
        self.device.as_mut().expect("retained anchor device")
    }
    /// Native admission consumes a header recheck minted under the same exclusive reserve.
    /// The WAL touched only its disjoint tail while the reserve remained held.
    pub(super) fn admit_rechecked_wal_pair(
        store: SnapshotBlockStore,
        verified: crate::RegistryWalVerifiedDevice<D>,
        rechecked: super::RecheckedPairedWalSnapshot,
    ) -> Result<Self, (SnapshotBlockStoreError, crate::RegistryWalVerifiedDevice<D>, super::RecheckedPairedWalSnapshot)> {
        let (device, prefix, record_end_lbas) = verified.into_parts();
        let next = prefix.anchor();
        let checked = (|| {
            if rechecked.store != store || rechecked.pair.store != store
                || rechecked.sector_size != device.sector_size()
                || rechecked.device_sectors != device.sector_count()
                || rechecked.sector_size < WAL_HEADER_LEN
            {
                return Err(SnapshotBlockStoreError::InvalidGeometry);
            }
            for plan in rechecked.pair.plans {
                let current = plan.wal.ok_or(SnapshotBlockStoreError::Corrupt)?.anchor();
                let exact_end = if current.serial == 0 { Some(0) } else {
                    usize::try_from(current.serial - 1).ok()
                        .and_then(|index| record_end_lbas.get(index).copied())
                };
                if current.incarnation != next.incarnation
                    || current.serial > next.serial || exact_end != Some(current.end_lba)
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err((error,
                crate::RegistryWalVerifiedDevice::from_parts(device, prefix, record_end_lbas),
                rechecked));
        }
        let pair = rechecked.pair;
        let mut update = Self::from_plans(store, device, next, pair.plans, None, Some(pair));
        update.continuation = Some(crate::RegistryWalContinuation::from_parts(
            prefix, record_end_lbas));
        Ok(update)
    }
    /// Admission reads and validates both payloads before any write. Failure returns the
    /// unchanged device; WAL mode must first establish two valid v2 snapshot slots.
    pub fn admit(
        store: SnapshotBlockStore,
        device: D,
        next: WalSnapshotAnchor,
    ) -> Result<Self, (SnapshotBlockStoreError, D)> {
        Self::admit_checked(store, device, next, false, |current| {
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

    /// Catch up or repair both snapshot headers using a parsed WAL prefix and the same
    /// physical device owner. Every existing header must name a frame boundary verified
    /// by this WAL; no separately supplied anchor or reconstructed lease is accepted.
    pub fn admit_verified_wal(
        store: SnapshotBlockStore,
        verified: crate::RegistryWalVerifiedDevice<D>,
    ) -> Result<Self, (SnapshotBlockStoreError, crate::RegistryWalVerifiedDevice<D>)> {
        let (device, prefix, record_end_lbas) = verified.into_parts();
        let next = prefix.anchor();
        let result = Self::admit_checked(store, device, next, true, |current| {
            for anchor in current {
                let exact_end = if anchor.serial == 0 {
                    Some(0)
                } else {
                    usize::try_from(anchor.serial - 1)
                        .ok()
                        .and_then(|index| record_end_lbas.get(index).copied())
                };
                if anchor.incarnation != next.incarnation
                    || anchor.serial > next.serial
                    || exact_end != Some(anchor.end_lba)
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
            }
            Ok(())
        });
        match result {
            Ok(mut update) => {
                update.continuation = Some(crate::RegistryWalContinuation::from_parts(
                    prefix, record_end_lbas,
                ));
                Ok(update)
            }
            Err((error, device)) => Err((
                error,
                crate::RegistryWalVerifiedDevice::from_parts(device, prefix, record_end_lbas),
            )),
        }
    }

    /// Steady-state admission using a payload proof carried with this exact reserve since
    /// boot or the last completed checkpoint. Exact headers are rechecked without rereading
    /// either payload. Failure returns both move-only proofs and the unchanged device.
    pub fn admit_verified_wal_pair(
        store: SnapshotBlockStore,
        verified: crate::RegistryWalVerifiedDevice<D>,
        paired: VerifiedPairedWalSnapshot,
    ) -> Result<Self, (SnapshotBlockStoreError, crate::RegistryWalVerifiedDevice<D>, VerifiedPairedWalSnapshot)> {
        let (mut device, prefix, record_end_lbas) = verified.into_parts();
        let next = prefix.anchor();
        let checked = (|| {
            store.recheck_verified_paired_wal_snapshot(&mut device, &paired)?;
            for plan in paired.plans {
                let current = plan.wal.ok_or(SnapshotBlockStoreError::Corrupt)?.anchor();
                let exact_end = if current.serial == 0 {
                    Some(0)
                } else {
                    usize::try_from(current.serial - 1)
                        .ok()
                        .and_then(|index| record_end_lbas.get(index).copied())
                };
                if current.incarnation != next.incarnation
                    || current.serial > next.serial
                    || exact_end != Some(current.end_lba)
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
            }
            Ok::<(), SnapshotBlockStoreError>(())
        })();
        if let Err(error) = checked {
            return Err((
                error,
                crate::RegistryWalVerifiedDevice::from_parts(device, prefix, record_end_lbas),
                paired,
            ));
        }
        let mut update = Self::from_plans(store, device, next, paired.plans, None, Some(paired));
        update.continuation = Some(crate::RegistryWalContinuation::from_parts(
            prefix, record_end_lbas,
        ));
        Ok(update)
    }

    /// Repair or advance both copies to a prefix proven by a parsed WAL after reboot.
    /// The caller must replay that prefix into registry state before publishing it.
    #[cfg(test)]
    pub fn admit_verified_prefix<W: SnapshotBlockDevice>(
        store: SnapshotBlockStore,
        device: D,
        next: WalSnapshotAnchor,
        wal: &crate::RegistryWal<W>,
    ) -> Result<Self, (SnapshotBlockStoreError, D)> {
        Self::admit_checked(store, device, next, true, |current| {
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
        allow_torn_companion: bool,
        check: F,
    ) -> Result<Self, (SnapshotBlockStoreError, D)>
    where
        F: FnOnce([WalSnapshotAnchor; 2]) -> Result<(), SnapshotBlockStoreError>,
    {
        let plans = (|| {
            let first = store.read_valid_slot_plan(&mut device, 0);
            let second = store.read_valid_slot_plan(&mut device, 1);
            let (plans, torn_companion_source) = match (first, second) {
                (Ok(Some(a)), Ok(Some(b))) => ([a, b], None),
                (Ok(Some(selected)), Err(SnapshotBlockStoreError::Corrupt))
                | (Err(SnapshotBlockStoreError::Corrupt), Ok(Some(selected))) => {
                    if !allow_torn_companion {
                        return Err(SnapshotBlockStoreError::Corrupt);
                    }
                    let companion_slot = 1 - selected.slot;
                    let companion = store.read_slot_plan(&mut device, companion_slot)?
                        .ok_or(SnapshotBlockStoreError::Corrupt)?;
                    let selected_wal = selected.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
                    let companion_wal = companion.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
                    same_anchor_wal_companion(
                        selected.generation, selected_wal,
                        companion.generation, companion_wal,
                    )?;
                    let repaired = SlotReadPlan {
                        slot: companion_slot,
                        generation: selected.generation.max(companion.generation)
                            .checked_add(1).ok_or(SnapshotBlockStoreError::OutOfSpace)?,
                        payload_len: selected.payload_len,
                        payload_crc: selected.payload_crc,
                        payload_sectors: selected.payload_sectors,
                        wal: Some(selected_wal),
                        resetting: false,
                    };
                    let plans = if selected.slot == 0 {
                        [selected, repaired]
                    } else {
                        [repaired, selected]
                    };
                    (plans, Some(selected))
                }
                (Err(error), _) | (_, Err(error)) => return Err(error),
                _ => return Err(SnapshotBlockStoreError::Corrupt),
            };
            let [a, b] = plans;
            if a.resetting || b.resetting {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            let am = a.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
            let bm = b.wal.ok_or(SnapshotBlockStoreError::Corrupt)?;
            check([am.anchor(), bm.anchor()])?;
            Ok::<_, SnapshotBlockStoreError>((plans, torn_companion_source))
        })();
        let (plans, torn_companion_source) = match plans {
            Ok(plans) => plans,
            Err(error) => return Err((error, device)),
        };
        Ok(Self::from_plans(store, device, next, plans, torn_companion_source, None))
    }

    fn from_plans(
        store: SnapshotBlockStore,
        device: D,
        next: WalSnapshotAnchor,
        plans: [SlotReadPlan; 2],
        torn_companion_source: Option<SlotReadPlan>,
        paired_proof: Option<VerifiedPairedWalSnapshot>,
    ) -> Self {
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
                resetting: false,
            }
        });
        Self {
            device: Some(device),
            store,
            headers,
            torn_companion_source,
            continuation: None,
            paired_proof,
            phase: Phase::Pending,
        }
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
            if let Some(source) = self.torn_companion_source {
                let target = 1 - source.slot;
                let source_lba = self.store.slot_lba(slot_sectors, source.slot)?;
                let target_lba = self.store.slot_lba(slot_sectors, target)?;
                for index in 0..source.payload_sectors {
                    device.read_sector(source_lba + 1 + u64::from(index), &mut sector)?;
                    device.write_sector(target_lba + 1 + u64::from(index), &sector)?;
                }
                device.flush()?;
                sector.fill(0);
                let repaired = self.headers[target as usize];
                let mut old_anchor = repaired;
                old_anchor.wal = source.wal;
                encode_header(&mut sector, old_anchor);
                device.write_sector(target_lba, &sector)?;
                device.flush()?;
            }
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
        if self.phase == Phase::Complete && self.paired_proof.is_none() {
            Ok(self.device.take().expect("retained anchor device"))
        } else {
            Err(self)
        }
    }

    /// Return the exact prefix only after both snapshot headers have crossed their
    /// durable barriers. Ordinary numeric-anchor admission cannot mint a continuation.
    pub fn into_continuation(mut self) -> Result<(D, crate::RegistryWalContinuation), Self> {
        if self.phase != Phase::Complete || self.continuation.is_none() || self.paired_proof.is_some() {
            return Err(self);
        }
        Ok((
            self.device.take().expect("retained anchor device"),
            self.continuation.take().expect("verified WAL prefix"),
        ))
    }

    /// Publish the refreshed paired proof only after both exact header barriers completed.
    pub fn into_continuation_and_pair(
        mut self,
    ) -> Result<(D, crate::RegistryWalContinuation, VerifiedPairedWalSnapshot), Self> {
        if self.phase != Phase::Complete || self.continuation.is_none() || self.paired_proof.is_none() {
            return Err(self);
        }
        let mut paired = self.paired_proof.take().expect("checked paired proof");
        for (plan, header) in paired.plans.iter_mut().zip(self.headers) {
            plan.generation = header.generation;
            plan.wal = header.wal;
        }
        paired.manifest = SnapshotBlockStore::paired_manifest(paired.plans)
            .expect("completed paired anchor retains valid manifests");
        Ok((
            self.device.take().expect("retained anchor device"),
            self.continuation.take().expect("verified WAL prefix"),
            paired,
        ))
    }

    #[cfg(test)]
    pub(super) fn into_device_for_test(mut self) -> D {
        self.phase = Phase::Complete;
        self.device.take().expect("retained anchor device")
    }
}
