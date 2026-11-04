//! Fail-closed eligibility for copied installed metadata on a native disk route.
//!
//! The Executive owns this fence in the same address space as its metadata cache. It must
//! authenticate the physical disk and classify the canonical SCSI request before invoking the
//! provider. A provider-local atomic would not protect Executive cache hits.

use core::sync::atomic::{AtomicBool, Ordering};

/// A nonempty, checked physical sector interval with an exclusive end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalSectorRange {
    start: u64,
    end: u64,
}

impl PhysicalSectorRange {
    pub fn new(start: u64, sectors: u64) -> Option<Self> {
        if sectors == 0 { return None; }
        Some(Self { start, end: start.checked_add(sectors)? })
    }

    fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Classification of an authenticated SRB after its full CDB and transfer range are checked.
/// Any unsupported opcode, malformed range, or command with an uncertain effect is mutating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PossibleScsiEffect {
    ProvenReadOnly,
    Write { lba: u64, sectors: u32 },
    PossiblyMutating,
}

impl PossibleScsiEffect {
    /// Classify proven read-only external disk controls from their canonical request shapes.
    /// The caller must first authenticate the physical disk stack; other controls may mutate
    /// media even when their access bits appear read-only.
    pub fn from_disk_device_control(ioctl_code: u32, input_len: u32, output_len: u32) -> Self {
        const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002d_1400;
        const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002d_1080;
        const IOCTL_SCSI_GET_ADDRESS: u32 = 0x0004_1018;
        const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x0007_0000;
        const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00a0;
        if (ioctl_code == IOCTL_STORAGE_QUERY_PROPERTY && input_len >= 12 && output_len >= 8)
            || (ioctl_code == IOCTL_STORAGE_GET_DEVICE_NUMBER && input_len == 0 && output_len >= 12)
            || (ioctl_code == IOCTL_SCSI_GET_ADDRESS && input_len == 0 && output_len >= 8)
            || (ioctl_code == IOCTL_DISK_GET_DRIVE_GEOMETRY && input_len == 0 && output_len >= 24)
            || (ioctl_code == IOCTL_DISK_GET_DRIVE_GEOMETRY_EX && input_len == 0 && output_len >= 40)
        {
            Self::ProvenReadOnly
        } else {
            Self::PossiblyMutating
        }
    }

    /// Classify only the pointer-free legacy SRB/CDB encodings used by the native block route.
    /// The Executive must first authenticate the route and validate the canonical transfer
    /// buffers. Any unfamiliar command or malformed scalar is a possible media mutation.
    pub fn from_legacy_srb(srb: &[u8]) -> Self {
        const LEGACY_BYTES: usize = 0x58;
        const DATA_IN: u32 = 0x40;
        if srb.len() != LEGACY_BYTES
            || u16::from_le_bytes([srb[0], srb[1]]) as usize != LEGACY_BYTES
        {
            return Self::PossiblyMutating;
        }
        if srb[2] == 1 { // SRB_FUNCTION_CLAIM_DEVICE
            let mut exact = [0; LEGACY_BYTES];
            exact[0..2].copy_from_slice(&(LEGACY_BYTES as u16).to_le_bytes());
            exact[2] = 1;
            return if srb == exact { Self::ProvenReadOnly }
                else { Self::PossiblyMutating };
        }
        if srb[2] != 0 { return Self::PossiblyMutating; } // SRB_FUNCTION_EXECUTE_SCSI
        let cdb_len = srb[0x0a];
        let flags = u32::from_le_bytes(srb[0x0c..0x10].try_into().unwrap());
        let data_len = u32::from_le_bytes(srb[0x10..0x14].try_into().unwrap());
        let cdb: &[u8; 16] = srb[0x48..0x58].try_into().unwrap();
        match cdb[0] {
            0x12 if cdb_len == 6 => {
                // INQUIRY only reports standard/VPD properties. LiberNT uses data-in plus
                // optional synchronous-transfer and queue-freeze policy flags; its receive
                // buffer may exceed the six-byte CDB allocation length.
                let inquiry_flags = DATA_IN | 0x08 | 0x100;
                if flags & DATA_IN != 0
                    && flags & !inquiry_flags == 0
                    && data_len != 0
                    && cdb[1] <= 1
                    && (cdb[1] == 1 || cdb[2] == 0)
                    && cdb[3] == 0
                    && cdb[4] != 0
                    && cdb[5..].iter().all(|byte| *byte == 0)
                { Self::ProvenReadOnly } else { Self::PossiblyMutating }
            }
            0x1a if cdb_len == 6 => {
                // MODE SENSE(6) returns mode-page data without changing media. The page
                // and subpage select reported data; the receive buffer must cover the
                // CDB allocation. Admit only DATA_IN and observed port policy bits.
                const MODE_SENSE_FLAGS: u32 = DATA_IN | 0x08 | 0x100 | 0x20_0000;
                if flags & DATA_IN != 0
                    && flags & !MODE_SENSE_FLAGS == 0
                    && cdb[1] & !0x08 == 0 // DBD; no reserved or LUN bits
                    && cdb[4] != 0
                    && data_len >= u32::from(cdb[4])
                    && cdb[5..].iter().all(|byte| *byte == 0)
                { Self::ProvenReadOnly } else { Self::PossiblyMutating }
            }
            0x28 | 0x2a if cdb_len == 10 => {
                let lba = u32::from_be_bytes(cdb[2..6].try_into().unwrap()) as u64;
                let sectors = u16::from_be_bytes(cdb[7..9].try_into().unwrap()) as u32;
                Self::checked_transfer(*cdb, flags, data_len, lba, sectors, false)
            }
            0x88 | 0x8a if cdb_len == 16 => {
                let lba = u64::from_be_bytes(cdb[2..10].try_into().unwrap());
                let sectors = u32::from_be_bytes(cdb[10..14].try_into().unwrap());
                Self::checked_transfer(*cdb, flags, data_len, lba, sectors, true)
            }
            0x25 if cdb_len == 10 && flags == 0x20_0148 && data_len == 8 => {
                // READ CAPACITY(10), with only LiberNT's observed receive and
                // port policy flags. PMI/LBA and control bytes must be zero.
                let mut expected = [0; 16];
                expected[0] = 0x25;
                if *cdb == expected { Self::ProvenReadOnly } else { Self::PossiblyMutating }
            }
            0x9e if cdb_len == 16 && flags == DATA_IN && data_len == 32 => {
                let mut expected = [0; 16];
                expected[0] = 0x9e;
                expected[1] = 0x10; // READ CAPACITY(16) service action
                expected[10..14].copy_from_slice(&32u32.to_be_bytes());
                if *cdb == expected { Self::ProvenReadOnly } else { Self::PossiblyMutating }
            }
            0x35 if cdb_len == 10 && flags == 0 && data_len == 0 => {
                let mut expected = [0; 16];
                expected[0] = 0x35; // SYNCHRONIZE CACHE(10)
                if *cdb == expected { Self::ProvenReadOnly } else { Self::PossiblyMutating }
            }
            _ => Self::PossiblyMutating,
        }
    }

    fn checked_transfer(
        cdb: [u8; 16], flags: u32, data_len: u32, lba: u64, sectors: u32,
        sixteen_byte: bool,
    ) -> Self {
        if sectors == 0
            || lba.checked_add(u64::from(sectors)).is_none()
            || u64::from(sectors).checked_mul(512) != Some(u64::from(data_len))
        {
            return Self::PossiblyMutating;
        }
        let write = matches!(cdb[0], 0x2a | 0x8a);
        // ClassPnP carries queue, adapter-cache and port-sense policy on
        // reads. These bits do not change the command's media effect; require
        // DATA_IN and reject every unknown or write-direction bit.
        const READ_POLICY_FLAGS: u32 = 0x20_0348;
        if (write && flags != 0x80)
            || (!write && (flags & 0x40 == 0 || flags & !READ_POLICY_FLAGS != 0))
        {
            return Self::PossiblyMutating;
        }
        let mut expected = [0; 16];
        expected[0] = cdb[0];
        if sixteen_byte {
            expected[2..10].copy_from_slice(&lba.to_be_bytes());
            expected[10..14].copy_from_slice(&sectors.to_be_bytes());
        } else {
            expected[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
            expected[7..9].copy_from_slice(&(sectors as u16).to_be_bytes());
        }
        if cdb != expected { return Self::PossiblyMutating; }
        if write { Self::Write { lba, sectors } } else { Self::ProvenReadOnly }
    }
}

/// One authoritative eligibility fence for an installed-volume metadata cache.
///
/// `D` is an authenticated physical disk identity; `R` includes mount and relation generation.
/// A same-disk possible mutation permanently disables read-through for this owner, even if its
/// provider later fails, times out, or retains an uncertain effect. The only write exception is
/// an exactly bounded request wholly inside a proven reserve disjoint from the installed range.
/// No method re-enables a poisoned owner; a new route needs a new cache and fence owner.
pub struct InstalledMetadataReadThroughFence<D: Eq, R: Eq> {
    disk: D,
    route: R,
    installed: PhysicalSectorRange,
    reserve: Option<PhysicalSectorRange>,
    poisoned: AtomicBool,
}

impl<D: Eq, R: Eq> InstalledMetadataReadThroughFence<D, R> {
    pub fn new(
        disk: D, route: R, installed: PhysicalSectorRange,
        reserve: Option<PhysicalSectorRange>,
    ) -> Option<Self> {
        if reserve.is_some_and(|reserve| reserve.overlaps(installed)) {
            return None;
        }
        Some(Self { disk, route, installed, reserve, poisoned: AtomicBool::new(false) })
    }

    /// Check the same authenticated disk and exact route generation before a cache hit.
    pub fn eligible(&self, disk: &D, route: &R) -> bool {
        disk == &self.disk && route == &self.route && !self.poisoned.load(Ordering::SeqCst)
    }

    pub fn poisoned(&self) -> bool {
        self.poisoned.load(Ordering::SeqCst)
    }

    /// Called in Executive memory before any provider entry, using a proven physical disk.
    /// The poison is irreversible across terminal failure, cancellation, or uncertain effects.
    pub fn before_effect(&self, disk: &D, effect: PossibleScsiEffect) {
        if disk != &self.disk { return; }
        let harmless = match effect {
            PossibleScsiEffect::ProvenReadOnly => true,
            PossibleScsiEffect::Write { lba, sectors } => {
                PhysicalSectorRange::new(lba, u64::from(sectors))
                    .is_some_and(|range| self.reserve.is_some_and(|reserve| reserve.contains(range))
                        && !range.overlaps(self.installed))
            }
            PossibleScsiEffect::PossiblyMutating => false,
        };
        if !harmless {
            self.poisoned.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PossibleScsiEffect;

    #[test]
    fn read_capacity_ten_with_native_policy_flags_preserves_metadata_read_through() {
        let mut srb = [0u8; 0x58];
        srb[0..2].copy_from_slice(&0x58u16.to_le_bytes());
        srb[0x0a] = 10;
        srb[0x0c..0x10].copy_from_slice(&0x20_0148u32.to_le_bytes());
        srb[0x10..0x14].copy_from_slice(&8u32.to_le_bytes());
        srb[0x48] = 0x25;
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&srb),
            PossibleScsiEffect::ProvenReadOnly);

        let mut malformed = srb;
        malformed[0x0a] = 9;
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&malformed),
            PossibleScsiEffect::PossiblyMutating);

        malformed = srb;
        malformed[0x0c..0x10].copy_from_slice(&0x20_0108u32.to_le_bytes()); // no DATA_IN
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&malformed),
            PossibleScsiEffect::PossiblyMutating);

        malformed = srb;
        malformed[0x0c..0x10].copy_from_slice(&0x20_0149u32.to_le_bytes()); // unknown bit
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&malformed),
            PossibleScsiEffect::PossiblyMutating);

        malformed = srb;
        malformed[0x10..0x14].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&malformed),
            PossibleScsiEffect::PossiblyMutating);

        malformed = srb;
        malformed[0x49] = 1;
        assert_eq!(PossibleScsiEffect::from_legacy_srb(&malformed),
            PossibleScsiEffect::PossiblyMutating);
    }
}
