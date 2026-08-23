//! Checked progress for a bounded transfer bank carrying an unbounded NT buffer.

use core::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BankedTransferError {
    EmptyBank,
    OutOfOrder,
    ChunkTooLarge,
    OutOfBounds,
    HostLengthOverflow,
}

/// Monotonic cursor for one direction of a banked transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BankedTransferCursor {
    total: u64,
    offset: u64,
}

impl BankedTransferCursor {
    pub const fn new(total: u64) -> Self {
        Self { total, offset: 0 }
    }

    pub const fn total(&self) -> u64 {
        self.total
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub const fn is_complete(&self) -> bool {
        self.offset == self.total
    }

    /// Claim the next exact chunk and return the corresponding host slice range.
    pub fn claim(
        &mut self,
        offset: u64,
        length: u64,
        bank_capacity: u64,
    ) -> Result<Range<usize>, BankedTransferError> {
        if bank_capacity == 0 {
            return Err(BankedTransferError::EmptyBank);
        }
        if offset != self.offset {
            return Err(BankedTransferError::OutOfOrder);
        }
        if length > bank_capacity {
            return Err(BankedTransferError::ChunkTooLarge);
        }
        let end = offset
            .checked_add(length)
            .ok_or(BankedTransferError::OutOfBounds)?;
        if end > self.total {
            return Err(BankedTransferError::OutOfBounds);
        }
        let start = usize::try_from(offset).map_err(|_| BankedTransferError::HostLengthOverflow)?;
        let end_host = usize::try_from(end).map_err(|_| BankedTransferError::HostLengthOverflow)?;
        self.offset = end;
        Ok(start..end_host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_a_buffer_larger_than_the_bank_in_exact_chunks() {
        let mut cursor = BankedTransferCursor::new(0x1_2345);
        assert_eq!(cursor.claim(0, 0x4000, 0x4000), Ok(0..0x4000));
        assert_eq!(cursor.claim(0x4000, 0x4000, 0x4000), Ok(0x4000..0x8000));
        assert_eq!(cursor.claim(0x8000, 0x4000, 0x4000), Ok(0x8000..0xc000));
        assert_eq!(cursor.claim(0xc000, 0x4000, 0x4000), Ok(0xc000..0x10000));
        assert_eq!(cursor.claim(0x10000, 0x2345, 0x4000), Ok(0x10000..0x12345));
        assert!(cursor.is_complete());
    }

    #[test]
    fn rejects_skips_replays_oversized_chunks_and_overflow() {
        let mut cursor = BankedTransferCursor::new(0x8001);
        assert_eq!(
            cursor.claim(1, 1, 0x4000),
            Err(BankedTransferError::OutOfOrder)
        );
        assert_eq!(
            cursor.claim(0, 0x4001, 0x4000),
            Err(BankedTransferError::ChunkTooLarge)
        );
        assert_eq!(cursor.claim(0, 0x4000, 0x4000), Ok(0..0x4000));
        assert_eq!(
            cursor.claim(0, 1, 0x4000),
            Err(BankedTransferError::OutOfOrder)
        );
        assert_eq!(cursor.claim(0x4000, 0x4000, 0x4000), Ok(0x4000..0x8000));
        assert_eq!(
            cursor.claim(0x8000, 2, 0x4000),
            Err(BankedTransferError::OutOfBounds)
        );
    }

    #[test]
    fn zero_length_transfer_completes_without_touching_the_bank() {
        let cursor = BankedTransferCursor::new(0);
        assert!(cursor.is_complete());
    }
}
