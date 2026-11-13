//! Bounded native I/O observation policy; a pending return is not elapsed wait time.

use nt_syscall::NativeService;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeIoKind {
    Read,
    Write,
    RemoveCompletion,
}

impl NativeIoKind {
    pub const fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::RemoveCompletion => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeIoCall {
    pub kind: NativeIoKind,
    pub handle: u64,
    pub requested_bytes: Option<u64>,
    pub iosb_address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeIoOutcome {
    /// For Read/Write this is completed bytes; for RemoveCompletion it is packet Information.
    Completed(Option<u64>),
    PendingAsync,
    PendingPark,
    TimedOut,
    Failed,
}

/// Select powers of two among slow calls, retaining sparse evidence arbitrarily late in a run.
pub const fn sample_slow_ordinal(ordinal: u32) -> bool {
    ordinal != 0 && ordinal.is_power_of_two()
}

impl NativeIoCall {
    pub fn capture(service: NativeService, args: &[u64]) -> Option<Self> {
        match service {
            NativeService::NtReadFile | NativeService::NtWriteFile => Some(Self {
                kind: if service == NativeService::NtReadFile {
                    NativeIoKind::Read
                } else {
                    NativeIoKind::Write
                },
                handle: *args.first()?,
                requested_bytes: Some(*args.get(6)? & 0xffff_ffff),
                iosb_address: *args.get(4)?,
            }),
            NativeService::NtRemoveIoCompletion => Some(Self {
                kind: NativeIoKind::RemoveCompletion,
                handle: *args.first()?,
                requested_bytes: None,
                iosb_address: *args.get(3)?,
            }),
            _ => None,
        }
    }

    pub fn classify(self, status: u32, information: Option<u64>, parked: bool) -> NativeIoOutcome {
        if status == 0x103 {
            return if parked { NativeIoOutcome::PendingPark } else { NativeIoOutcome::PendingAsync };
        }
        if self.kind == NativeIoKind::RemoveCompletion && status == 0x102 {
            return NativeIoOutcome::TimedOut;
        }
        if status != 0 {
            return NativeIoOutcome::Failed;
        }
        let information = match self.kind {
            NativeIoKind::Read | NativeIoKind::Write =>
                information.filter(|bytes| self.requested_bytes.is_some_and(|requested| *bytes <= requested)),
            NativeIoKind::RemoveCompletion => information,
        };
        NativeIoOutcome::Completed(information)
    }
}
