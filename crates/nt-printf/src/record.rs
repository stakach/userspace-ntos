//! Bounded capture and per-stream framing for narrow diagnostic output.

use crate::Output;

pub const TRUNCATION_MARKER: &[u8] = b"[record-truncated]";

/// Captures a prefix and formatted body without allocating or emitting fragments.
pub struct RecordBuffer<const N: usize> {
    storage: [u8; N],
    length: usize,
    overflowed: bool,
}

impl<const N: usize> RecordBuffer<N> {
    pub const fn new() -> Self {
        Self {
            storage: [0; N],
            length: 0,
            overflowed: false,
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> bool {
        let available = N - self.length;
        let count = bytes.len().min(available);
        self.storage[self.length..self.length + count].copy_from_slice(&bytes[..count]);
        self.length += count;
        self.overflowed |= count != bytes.len();
        count == bytes.len()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.storage[..self.length]
    }
    pub fn len(&self) -> usize {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }
}

impl<const N: usize> Default for RecordBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Output for RecordBuffer<N> {
    /// Narrow output follows the formatter's byte-output convention.
    fn write(&mut self, unit: u16) -> bool {
        self.push_bytes(&[unit as u8])
    }
}

impl<const N: usize> core::fmt::Write for RecordBuffer<N> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        if self.push_bytes(text.as_bytes()) {
            Ok(())
        } else {
            Err(core::fmt::Error)
        }
    }
}

/// One instance belongs to one stream; incomplete lines are never emitted.
pub struct LineBuffer<const N: usize> {
    storage: [u8; N],
    length: usize,
    overflowed: bool,
}

impl<const N: usize> LineBuffer<N> {
    pub const fn new() -> Self {
        assert!(N >= TRUNCATION_MARKER.len() + 1);
        Self {
            storage: [0; N],
            length: 0,
            overflowed: false,
        }
    }

    pub fn feed(&mut self, fragment: &[u8], mut emit: impl FnMut(&[u8])) {
        for &byte in fragment {
            if byte == b'\n' {
                if self.overflowed {
                    // Replace the tail rather than emitting a valid-looking truncated prefix.
                    self.length = self.length.min(N - TRUNCATION_MARKER.len() - 1);
                    let end = self.length + TRUNCATION_MARKER.len();
                    self.storage[self.length..end].copy_from_slice(TRUNCATION_MARKER);
                    self.length = end;
                }
                self.storage[self.length] = b'\n';
                self.length += 1;
                emit(&self.storage[..self.length]);
                self.length = 0;
                self.overflowed = false;
            } else if self.length < N - 1 {
                self.storage[self.length] = byte;
                self.length += 1;
            } else {
                self.overflowed = true;
            }
        }
    }
}

impl<const N: usize> Default for LineBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    #[test]
    fn core_formatter_captures_exact_fixed_width_hex_identities() {
        use core::fmt::Write;
        for (value, expected) in [
            (0u64, b"0x0000000000000000"),
            (0x000001000a123456, b"0x000001000a123456"),
            (u64::MAX, b"0xffffffffffffffff"),
        ] {
            let mut record = RecordBuffer::<18>::new();
            assert!(core::write!(&mut record, "0x{value:016x}").is_ok());
            assert_eq!(record.bytes(), expected);
            assert!(!record.overflowed());
        }
        let mut short = RecordBuffer::<17>::new();
        assert!(core::write!(&mut short, "0x{:016x}", u64::MAX).is_err());
        assert_eq!(short.len(), 17);
        assert!(short.overflowed());
    }

    #[test]
    fn fragments_emit_only_complete_records_once() {
        let mut buffer = LineBuffer::<64>::new();
        let mut records = Vec::new();
        buffer.feed(b"first ", |line| records.push(line.to_vec()));
        assert!(records.is_empty());
        buffer.feed(b"record\nsecond", |line| records.push(line.to_vec()));
        assert_eq!(records, [b"first record\n".to_vec()]);
        buffer.feed(b" record\n\nthird\n", |line| records.push(line.to_vec()));
        assert_eq!(
            records,
            [
                b"first record\n".to_vec(),
                b"second record\n".to_vec(),
                b"\n".to_vec(),
                b"third\n".to_vec()
            ]
        );
    }

    #[test]
    fn independently_interleaved_streams_keep_exact_records() {
        let mut first = LineBuffer::<64>::new();
        let mut second = LineBuffer::<64>::new();
        let mut records = Vec::new();
        first.feed(b"[first] body", |line| records.push(line.to_vec()));
        second.feed(b"[second] ", |line| records.push(line.to_vec()));
        first.feed(b" complete\n", |line| records.push(line.to_vec()));
        second.feed(b"complete\n", |line| records.push(line.to_vec()));
        assert_eq!(
            records,
            [
                b"[first] body complete\n".to_vec(),
                b"[second] complete\n".to_vec()
            ]
        );
    }

    #[test]
    fn overlong_line_is_marked_bounded_and_next_line_is_clean() {
        let mut buffer = LineBuffer::<32>::new();
        let mut records = Vec::new();
        buffer.feed(&[b'x'; 100], |line| records.push(line.to_vec()));
        assert!(records.is_empty());
        buffer.feed(b"ignored\nnext\n", |line| records.push(line.to_vec()));
        assert_eq!(records[0].len(), 32);
        assert!(records[0].ends_with(b"[record-truncated]\n"));
        assert_eq!(records[1], b"next\n");
    }

    #[test]
    fn exact_line_capacity_is_not_truncated() {
        let mut buffer = LineBuffer::<32>::new();
        let mut records = Vec::new();
        buffer.feed(&[b'x'; 31], |line| records.push(line.to_vec()));
        buffer.feed(b"\n", |line| records.push(line.to_vec()));
        assert_eq!(
            records[0],
            [b'x'; 31].into_iter().chain([b'\n']).collect::<Vec<_>>()
        );
    }

    #[test]
    fn prefix_and_formatted_body_share_one_512_byte_bound() {
        let mut record = RecordBuffer::<512>::new();
        assert!(record.is_empty());
        assert!(record.push_bytes(b"[driver] "));
        for _ in 0..503 {
            assert!(record.write(b'x' as u16));
        }
        assert_eq!(record.len(), 512);
        assert!(!record.overflowed());
        assert!(!record.write(b'y' as u16));
        assert!(record.overflowed());
        assert_eq!(&record.bytes()[..9], b"[driver] ");
        assert_eq!(record.bytes()[511], b'x');
    }

    #[test]
    fn record_prefix_overflow_and_zero_capacity_are_explicit() {
        let mut record = RecordBuffer::<3>::new();
        assert!(!record.push_bytes(b"prefix"));
        assert_eq!(record.bytes(), b"pre");
        assert!(record.overflowed());
        let mut empty = RecordBuffer::<0>::new();
        assert!(empty.push_bytes(b""));
        assert!(!empty.write(0x141));
        assert!(empty.is_empty());
        assert!(empty.overflowed());
    }
}
