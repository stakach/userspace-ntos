//! Bounded stall grace from an exact setup child File read that has completed and advanced.

const PENDING_READ_CAPACITY: usize = 16;

#[derive(Clone, Copy)]
struct PendingRead<Process, File> {
    owner: Process,
    file: File,
    irp: u64,
    offset: u64,
    length: u32,
}

/// Pending admission retains correlation only. The highwater advances after the exact terminal
/// read has been published and ACKed, and a finite grant requires a still-live exact owner.
pub struct SetupReadProgressDeferral<Process, File> {
    owner: Process,
    file: File,
    pending: [Option<PendingRead<Process, File>>; PENDING_READ_CAPACITY],
    highwater: Option<u64>,
    latest_completion_100ns: Option<u64>,
    granted_highwater: Option<u64>,
    grants: u8,
}

impl<Process: Copy + Eq, File: Copy + Eq> SetupReadProgressDeferral<Process, File> {
    // Eight additional 180-second windows plus the original window stay below one hour.
    pub const MAX_GRANTS: u8 = 8;

    pub fn new(owner: Process, file: File) -> Self {
        Self {
            owner,
            file,
            pending: [None; PENDING_READ_CAPACITY],
            highwater: None,
            latest_completion_100ns: None,
            granted_highwater: None,
            grants: 0,
        }
    }

    pub fn admit(&mut self, owner: Process, file: File, irp: u64, offset: u64, length: u32) -> bool {
        if owner != self.owner || file != self.file || irp == 0 || length == 0
            || offset.checked_add(u64::from(length)).is_none()
            || self.pending.iter().flatten().any(|entry| entry.irp == irp)
        {
            return false;
        }
        let Some(slot) = self.pending.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some(PendingRead { owner, file, irp, offset, length });
        true
    }

    pub fn complete(&mut self, owner: Process, file: File, irp: u64,
        status: u32, information: u64, now_100ns: u64) -> bool {
        if owner != self.owner || file != self.file {
            return false;
        }
        let Some(slot) = self.pending.iter_mut().find(|slot| {
            slot.is_some_and(|entry| entry.owner == owner && entry.file == file && entry.irp == irp)
        }) else {
            return false;
        };
        let pending = slot.take().expect("matched pending read disappeared");
        if status != 0 || information == 0 || information > u64::from(pending.length) {
            return false;
        }
        let Some(end) = pending.offset.checked_add(information) else { return false };
        if self.highwater.is_some_and(|highwater| {
            pending.offset > highwater || end <= highwater
        }) || self.latest_completion_100ns.is_some_and(|last| now_100ns < last) {
            return false;
        }
        self.highwater = Some(end);
        self.latest_completion_100ns = Some(now_100ns);
        true
    }

    pub fn grant(&mut self, live_owner: Option<Process>, now_100ns: u64,
        window_100ns: u64) -> bool {
        let (Some(highwater), Some(completed_at)) =
            (self.highwater, self.latest_completion_100ns) else { return false };
        if live_owner != Some(self.owner)
            || self.grants >= Self::MAX_GRANTS
            || now_100ns < completed_at
            || now_100ns - completed_at > window_100ns
            || self.granted_highwater.is_some_and(|granted| highwater <= granted)
        {
            return false;
        }
        self.granted_highwater = Some(highwater);
        self.grants += 1;
        true
    }

    pub const fn grants(&self) -> u8 { self.grants }
    pub const fn owner(&self) -> Process { self.owner }
    pub const fn file(&self) -> File { self.file }
    pub const fn highwater(&self) -> Option<u64> { self.highwater }
    pub fn pending_count(&self) -> usize { self.pending.iter().flatten().count() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: (u32, u64) = (408, 14);
    const FILE: (u64, u64) = (0x100, 0x800_0000_00ed);
    const WINDOW: u64 = 180 * 10_000_000;

    #[test]
    fn pending_admission_and_repeated_offset_do_not_extend_stall() {
        let mut progress = SetupReadProgressDeferral::new(OWNER, FILE);
        assert!(progress.admit(OWNER, FILE, 11, 0, 0x4000));
        assert!(!progress.grant(Some(OWNER), WINDOW, WINDOW));
        assert!(progress.complete(OWNER, FILE, 11, 0, 0x4000, 100));
        assert!(progress.grant(Some(OWNER), 100 + WINDOW, WINDOW));
        assert!(progress.admit(OWNER, FILE, 12, 0, 0x4000));
        assert!(!progress.complete(OWNER, FILE, 12, 0, 0x4000, 200));
        assert!(!progress.grant(Some(OWNER), 200, WINDOW));
    }

    #[test]
    fn only_exact_positive_terminal_read_advances_highwater() {
        let mut progress = SetupReadProgressDeferral::new(OWNER, FILE);
        assert!(progress.admit(OWNER, FILE, 11, 0, 0x4000));
        assert!(!progress.complete(OWNER, FILE, 12, 0, 0x4000, 100));
        assert!(!progress.complete(OWNER, FILE, 11, 0xc000_0001, 0, 100));
        assert!(progress.admit(OWNER, FILE, 13, 0, 0x4000));
        assert!(!progress.complete(OWNER, FILE, 13, 0, 0, 101));
        assert!(progress.admit(OWNER, FILE, 14, 0, 0x4000));
        assert!(!progress.complete(OWNER, FILE, 14, 0, 0x4001, 102));
        assert!(!progress.grant(Some(OWNER), 102, WINDOW));
        assert!(progress.admit(OWNER, FILE, 15, 0, 0x4000));
        assert!(!progress.complete((408, 15), FILE, 15, 0, 0x4000, 103));
        assert!(!progress.grant(Some(OWNER), 103, WINDOW));
    }

    #[test]
    fn pending_status_with_bytes_is_not_terminal_progress() {
        let mut progress = SetupReadProgressDeferral::new(OWNER, FILE);
        assert!(progress.admit(OWNER, FILE, 11, 0, 0x4000));
        assert!(!progress.complete(OWNER, FILE, 11, 0x103, 0x4000, 100));
        assert!(!progress.grant(Some(OWNER), 100, WINDOW));
    }

    #[test]
    fn full_pending_table_fails_closed_and_reclaims_exact_terminal_slot() {
        let mut progress = SetupReadProgressDeferral::new(OWNER, FILE);
        for irp in 1..=16 {
            assert!(progress.admit(OWNER, FILE, irp, (irp - 1) * 0x4000, 0x4000));
        }
        assert!(!progress.admit(OWNER, FILE, 17, 16 * 0x4000, 0x4000));
        assert!(!progress.grant(Some(OWNER), 100, WINDOW));
        assert!(!progress.complete(OWNER, FILE, 1, 0xc000_0001, 0, 100));
        assert!(progress.admit(OWNER, FILE, 17, 16 * 0x4000, 0x4000));
        assert!(!progress.grant(Some(OWNER), 100, WINDOW));
    }

    #[test]
    fn exact_file_contiguous_progress_and_recent_completion_required() {
        let mut progress = SetupReadProgressDeferral::new(OWNER, FILE);
        assert!(progress.admit(OWNER, FILE, 11, 0, 0x4000));
        assert!(progress.complete(OWNER, FILE, 11, 0, 0x4000, 100));
        assert!(!progress.grant(Some((408, 15)), 101, WINDOW));
        assert!(!progress.grant(Some(OWNER), 101 + WINDOW, WINDOW));
        assert!(!progress.admit(OWNER, (FILE.0, FILE.1 + 1), 12, 0x4000, 0x4000));
        assert!(progress.admit(OWNER, FILE, 13, 0x8000, 0x4000));
        assert!(!progress.complete(OWNER, FILE, 13, 0, 0x4000, 200 + WINDOW));
        assert!(progress.admit(OWNER, FILE, 14, 0x4000, 0x4000));
        assert!(progress.complete(OWNER, FILE, 14, 0, 0x4000, 201 + WINDOW));
        assert!(progress.grant(Some(OWNER), 201 + WINDOW, WINDOW));
    }

    #[test]
    fn grant_ceiling_is_finite_and_old_read_cannot_be_replayed() {
        let mut progress = SetupReadProgressDeferral::new(OWNER, FILE);
        for n in 0..SetupReadProgressDeferral::<(u32, u64), (u64, u64)>::MAX_GRANTS {
            let offset = u64::from(n) * 0x4000;
            let irp = u64::from(n) + 1;
            let now = u64::from(n) * WINDOW + 100;
            assert!(progress.admit(OWNER, FILE, irp, offset, 0x4000));
            assert!(progress.complete(OWNER, FILE, irp, 0, 0x4000, now));
            assert!(progress.grant(Some(OWNER), now, WINDOW));
            assert!(!progress.complete(OWNER, FILE, irp, 0, 0x4000, now + 1));
        }
        let next_offset = u64::from(progress.grants()) * 0x4000;
        assert!(progress.admit(OWNER, FILE, 100, next_offset, 0x4000));
        assert!(progress.complete(OWNER, FILE, 100, 0, 0x4000, 10 * WINDOW));
        assert!(!progress.grant(Some(OWNER), 10 * WINDOW, WINDOW));
    }
}
