//! Bounded exact reads of a retained routed image source.
//!
//! The native caller owns the Section reference and canonical File capture in `R`. It must
//! authenticate the provider completion against that capture before calling `terminal`, and
//! strictly acknowledge the provider IRP before calling `acknowledge`. An entered dispatch can
//! never be retried through this owner, even when the native result is uncertain.

use alloc::vec::Vec;

pub const MAX_IMAGE_READ_WINDOW: usize = 32 * 1024;
pub const STATUS_IO_DEVICE_ERROR: u32 = 0xc000_0185;
pub const STATUS_PENDING: u32 = 0x0000_0103;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageReadWindow {
    pub offset: u64,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase<K> {
    Ready,
    Entered(ImageReadWindow),
    Submitted(ImageReadWindow, K),
    Copying(ImageReadWindow, K, usize),
    AwaitAck(ImageReadWindow, K, Result<(), u32>),
    Complete,
    Failed(u32),
    Quarantined,
}

/// The retained source identity `S` is typically `(ImageAreaId, RoutedSectionLease)`.
/// Its non-cloneable owner `R` keeps the exact File and Section alive through provider ACK.
#[must_use = "retain through terminal read and backend acknowledgment"]
pub struct RoutedImageRead<S, K, R> {
    source: S,
    owner: R,
    bytes: Vec<u8>,
    base_offset: u64,
    next_offset: usize,
    window_limit: usize,
    phase: Phase<K>,
}

impl<S: Copy, K: Copy + Eq, R> RoutedImageRead<S, K, R> {
    /// Allocate the exact destination before any provider effect. Return `R` unchanged on
    /// admission failure so the caller can retire its captures deliberately.
    pub fn new(source: S, extent: u64, window_limit: usize, owner: R) -> Result<Self, R> {
        Self::new_at(source, 0, extent, window_limit, owner)
    }

    /// Read a bounded extent beginning at an absolute File offset. Page fillers may use this
    /// for a single PE section fragment without capturing unrelated bytes.
    pub fn new_at(
        source: S, base_offset: u64, extent: u64, window_limit: usize, owner: R,
    ) -> Result<Self, R> {
        let Ok(length) = usize::try_from(extent) else { return Err(owner) };
        if length == 0 || base_offset.checked_add(extent).is_none()
            || window_limit == 0 || window_limit > MAX_IMAGE_READ_WINDOW
        {
            return Err(owner);
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(length).is_err() { return Err(owner); }
        bytes.resize(length, 0);
        Ok(Self { source, owner, bytes, base_offset, next_offset: 0, window_limit, phase: Phase::Ready })
    }

    pub fn source(&self) -> S { self.source }

    pub fn owner(&self) -> &R { &self.owner }

    pub fn pending_key(&self) -> Option<K> {
        match self.phase {
            Phase::Submitted(_, key) | Phase::Copying(_, key, _)
                | Phase::AwaitAck(_, key, _) => Some(key),
            _ => None,
        }
    }

    /// Return the exact IRP key, next relative copy offset, and remaining bytes.
    pub fn copy_position(&self) -> Option<(K, usize, usize)> {
        match self.phase {
            Phase::Copying(window, key, copied) => Some((key, copied, window.length - copied)),
            _ => None,
        }
    }

    pub fn acknowledgment_key(&self) -> Option<K> {
        match self.phase {
            Phase::AwaitAck(_, key, _) => Some(key),
            _ => None,
        }
    }

    /// Enter one provider read. No second window is available until inline completion or
    /// exact pending completion and backend ACK have advanced this one.
    pub fn enter_window(&mut self) -> Option<ImageReadWindow> {
        if self.phase != Phase::Ready { return None; }
        let length = (self.bytes.len() - self.next_offset).min(self.window_limit);
        let window = ImageReadWindow {
            offset: self.base_offset + self.next_offset as u64,
            length,
        };
        self.phase = Phase::Entered(window);
        Some(window)
    }

    /// Use only when dispatch itself proves no provider operation entered. It never retries.
    pub fn reject_entry(&mut self, status: u32) -> bool {
        if !matches!(self.phase, Phase::Entered(_)) || status == 0 { return false; }
        self.phase = Phase::Failed(status);
        true
    }

    /// A result with uncertain provider effects must retain the whole owner for reconciliation.
    pub fn quarantine(&mut self) {
        self.phase = Phase::Quarantined;
    }

    pub fn complete_inline(&mut self, status: u32, information: u64, output: &[u8]) -> bool {
        let Phase::Entered(window) = self.phase else { return false; };
        if status == STATUS_PENDING { return false; }
        if status != 0 {
            self.phase = Phase::Failed(status);
        } else if information != window.length as u64 || output.len() < window.length {
            self.phase = Phase::Failed(STATUS_IO_DEVICE_ERROR);
        } else {
            let start = self.next_offset;
            self.bytes[start..start + window.length].copy_from_slice(&output[..window.length]);
            self.advance_success(window);
        }
        true
    }

    pub fn bind_pending(&mut self, key: K) -> bool {
        let Phase::Entered(window) = self.phase else { return false; };
        self.phase = Phase::Submitted(window, key);
        true
    }

    /// Caller first checks exact client, driver, File, device, requestor, and major identity.
    pub fn terminal(&mut self, key: K, status: u32, information: u64) -> bool {
        let Phase::Submitted(window, expected) = self.phase else { return false; };
        if expected != key || status == STATUS_PENDING { return false; }
        self.phase = if status != 0 {
            Phase::AwaitAck(window, key, Err(status))
        } else if information != window.length as u64 {
            Phase::AwaitAck(window, key, Err(STATUS_IO_DEVICE_ERROR))
        } else {
            Phase::Copying(window, key, 0)
        };
        true
    }

    /// `offset` is relative to this window; fragments must be contiguous and nonempty.
    pub fn copy_fragment(&mut self, key: K, offset: usize, fragment: &[u8]) -> bool {
        let Phase::Copying(window, expected, copied) = self.phase else { return false; };
        if expected != key || offset != copied || fragment.is_empty()
            || fragment.len() > window.length - copied
        { return false; }
        let start = self.next_offset + copied;
        self.bytes[start..start + fragment.len()].copy_from_slice(fragment);
        let next = copied + fragment.len();
        self.phase = if next == window.length {
            Phase::AwaitAck(window, key, Ok(()))
        } else {
            Phase::Copying(window, key, next)
        };
        true
    }

    pub fn fail_copy(&mut self, key: K, status: u32) -> bool {
        let Phase::Copying(window, expected, _) = self.phase else { return false; };
        if expected != key || status == 0 { return false; }
        self.phase = Phase::AwaitAck(window, key, Err(status));
        true
    }

    /// Call only after `acknowledge_completed_irp_strict` succeeds for this exact key.
    pub fn acknowledge(&mut self, key: K) -> bool {
        let Phase::AwaitAck(window, expected, outcome) = self.phase else { return false; };
        if expected != key { return false; }
        match outcome {
            Ok(()) => self.advance_success(window),
            Err(status) => self.phase = Phase::Failed(status),
        }
        true
    }

    fn advance_success(&mut self, window: ImageReadWindow) {
        self.next_offset += window.length;
        self.phase = if self.next_offset == self.bytes.len() {
            Phase::Complete
        } else {
            Phase::Ready
        };
    }

    pub fn terminal_result(&self) -> Option<Result<(), u32>> {
        match self.phase {
            Phase::Complete => Some(Ok(())),
            Phase::Failed(status) => Some(Err(status)),
            _ => None,
        }
    }

    /// Cancel before entering another provider operation. A pending or uncertain operation
    /// must complete and be acknowledged first.
    pub fn abort_ready(self) -> Result<R, Self> {
        if self.phase == Phase::Ready { Ok(self.owner) } else { Err(self) }
    }

    /// Transfer the captured owner and complete bytes only after all pending reads are ACKed.
    pub fn into_terminal(self) -> Result<(R, Result<Vec<u8>, u32>), Self> {
        match self.phase {
            Phase::Complete => Ok((self.owner, Ok(self.bytes))),
            Phase::Failed(status) => Ok((self.owner, Err(status))),
            _ => Err(self),
        }
    }
}

#[cfg(test)]
#[path = "routed_image_read_tests.rs"]
mod tests;
