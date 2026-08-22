//! State carried by a driver-owned IRP while completion crosses a hosted-driver boundary.
//!
//! The request graph remains the authoritative owner until the executive consumes this record.
//! Completing in place avoids transferring the only completion edge into a second bounded table.

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedIrpCompletion {
    sequence: u64,
    information: u64,
    source: u64,
    reclaim: u64,
    status: u32,
    length: u32,
    flags: u32,
    state: u8,
    _reserved: [u8; 3],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedCompletion {
    pub sequence: u64,
    pub status: u32,
    pub information: u64,
    pub source: u64,
    /// Driver-owned replacement buffer that must be released with the request graph.
    pub reclaim: u64,
    pub length: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedCompletionError {
    InvalidSequence,
    AlreadyCompleted,
}

impl RetainedIrpCompletion {
    const PENDING: u8 = 0;
    const COMPLETED: u8 = 1;

    pub const fn pending() -> Self {
        Self {
            sequence: 0,
            information: 0,
            source: 0,
            reclaim: 0,
            status: 0,
            length: 0,
            flags: 0,
            state: Self::PENDING,
            _reserved: [0; 3],
        }
    }

    pub fn complete(
        &mut self,
        sequence: u64,
        status: u32,
        information: u64,
        source: u64,
        reclaim: u64,
        length: u32,
        flags: u32,
    ) -> Result<(), RetainedCompletionError> {
        if sequence == 0 {
            return Err(RetainedCompletionError::InvalidSequence);
        }
        if self.state != Self::PENDING {
            return Err(RetainedCompletionError::AlreadyCompleted);
        }
        self.sequence = sequence;
        self.information = information;
        self.source = source;
        self.reclaim = reclaim;
        self.status = status;
        self.length = length;
        self.flags = flags;
        self.state = Self::COMPLETED;
        Ok(())
    }

    pub fn completed(&self) -> Option<RetainedCompletion> {
        if self.state != Self::COMPLETED {
            return None;
        }
        Some(RetainedCompletion {
            sequence: self.sequence,
            status: self.status,
            information: self.information,
            source: self.source,
            reclaim: self.reclaim,
            length: self.length,
            flags: self.flags,
        })
    }
}

impl Default for RetainedIrpCompletion {
    fn default() -> Self {
        Self::pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_stays_pending_until_durably_published() {
        let mut state = RetainedIrpCompletion::pending();
        assert_eq!(state.completed(), None);
        state
            .complete(7, 0x8000_0005, 16, 0x1000, 0x2000, 16, 0x70)
            .unwrap();
        assert_eq!(
            state.completed(),
            Some(RetainedCompletion {
                sequence: 7,
                status: 0x8000_0005,
                information: 16,
                source: 0x1000,
                reclaim: 0x2000,
                length: 16,
                flags: 0x70,
            })
        );
    }

    #[test]
    fn duplicate_completion_cannot_overwrite_the_first_result() {
        let mut state = RetainedIrpCompletion::pending();
        state.complete(1, 0, 4, 0x2000, 0, 4, 0).unwrap();
        assert_eq!(
            state.complete(2, 0xc000_0001, 0, 0, 0, 0, 0),
            Err(RetainedCompletionError::AlreadyCompleted)
        );
        assert_eq!(state.completed().unwrap().sequence, 1);
        assert_eq!(state.completed().unwrap().source, 0x2000);
    }

    #[test]
    fn zero_sequence_is_rejected_without_mutating_state() {
        let mut state = RetainedIrpCompletion::pending();
        assert_eq!(
            state.complete(0, 0, 0, 0, 0, 0, 0),
            Err(RetainedCompletionError::InvalidSequence)
        );
        assert_eq!(state.completed(), None);
    }

    #[test]
    fn retained_completion_abi_is_stable() {
        assert_eq!(core::mem::size_of::<RetainedIrpCompletion>(), 48);
        assert_eq!(core::mem::align_of::<RetainedIrpCompletion>(), 8);
    }
}
