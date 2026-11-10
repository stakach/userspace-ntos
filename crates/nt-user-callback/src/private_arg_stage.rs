//! Bounded private bytes for an ARG window shared with a provider only after admission.
//!
//! The caller owns this buffer. `provider_va` names the eventual provider mapping; writes
//! never touch that mapping. Dirty spans identify exactly which bytes may be copied after
//! the physical page authority has been promoted to the admitted dispatch.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgStageError {
    InvalidProviderRange,
    OutOfBounds,
    TooManyDirtySpans,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirtyArgSpan {
    pub offset: usize,
    pub len: usize,
}

impl DirtyArgSpan {
    const EMPTY: Self = Self { offset: 0, len: 0 };

    fn end(self) -> usize {
        self.offset + self.len
    }
}

/// Private staging for a fixed provider ARG region. The span limit is an explicit bound on
/// fragmented writes; a rejected write leaves both the bytes and dirty map unchanged.
pub struct PrivateArgStage<'a, const MAX_SPANS: usize> {
    provider_base: u64,
    bytes: &'a mut [u8],
    dirty: [DirtyArgSpan; MAX_SPANS],
    dirty_len: usize,
}

impl<'a, const MAX_SPANS: usize> PrivateArgStage<'a, MAX_SPANS> {
    pub fn new(provider_base: u64, bytes: &'a mut [u8]) -> Result<Self, ArgStageError> {
        let len = u64::try_from(bytes.len()).map_err(|_| ArgStageError::InvalidProviderRange)?;
        if bytes.is_empty() || provider_base.checked_add(len).is_none() {
            return Err(ArgStageError::InvalidProviderRange);
        }
        Ok(Self {
            provider_base,
            bytes,
            dirty: [DirtyArgSpan::EMPTY; MAX_SPANS],
            dirty_len: 0,
        })
    }

    pub fn provider_va(&self, offset: usize) -> Result<u64, ArgStageError> {
        if offset >= self.bytes.len() {
            return Err(ArgStageError::OutOfBounds);
        }
        Ok(self.provider_base + offset as u64)
    }

    pub fn write(&mut self, offset: usize, source: &[u8]) -> Result<(), ArgStageError> {
        let end = self.checked_end(offset, source.len())?;
        if source.is_empty() {
            return Ok(());
        }
        let (dirty, dirty_len) = self.merged_dirty(offset, end)?;
        self.bytes[offset..end].copy_from_slice(source);
        self.dirty = dirty;
        self.dirty_len = dirty_len;
        Ok(())
    }

    pub fn zero(&mut self, offset: usize, len: usize) -> Result<(), ArgStageError> {
        let end = self.checked_end(offset, len)?;
        if len == 0 {
            return Ok(());
        }
        let (dirty, dirty_len) = self.merged_dirty(offset, end)?;
        self.bytes[offset..end].fill(0);
        self.dirty = dirty;
        self.dirty_len = dirty_len;
        Ok(())
    }

    pub fn dirty_spans(&self) -> &[DirtyArgSpan] {
        &self.dirty[..self.dirty_len]
    }

    /// The caller must hold the promoted physical-page authority before copying these slices.
    pub fn for_each_dirty(&self, mut visit: impl FnMut(u64, &[u8])) {
        for span in self.dirty_spans() {
            visit(
                self.provider_base + span.offset as u64,
                &self.bytes[span.offset..span.end()],
            );
        }
    }

    fn checked_end(&self, offset: usize, len: usize) -> Result<usize, ArgStageError> {
        let end = offset.checked_add(len).ok_or(ArgStageError::OutOfBounds)?;
        if end > self.bytes.len() {
            return Err(ArgStageError::OutOfBounds);
        }
        Ok(end)
    }

    fn merged_dirty(
        &self,
        offset: usize,
        end: usize,
    ) -> Result<([DirtyArgSpan; MAX_SPANS], usize), ArgStageError> {
        let mut dirty = [DirtyArgSpan::EMPTY; MAX_SPANS];
        let mut count = 0;
        let mut merged = DirtyArgSpan {
            offset,
            len: end - offset,
        };
        let mut inserted = false;
        for span in self.dirty_spans() {
            if span.end() < merged.offset {
                Self::push(&mut dirty, &mut count, *span)?;
            } else if merged.end() < span.offset {
                if !inserted {
                    Self::push(&mut dirty, &mut count, merged)?;
                    inserted = true;
                }
                Self::push(&mut dirty, &mut count, *span)?;
            } else {
                let merged_end = merged.end().max(span.end());
                merged.offset = merged.offset.min(span.offset);
                merged.len = merged_end - merged.offset;
            }
        }
        if !inserted {
            Self::push(&mut dirty, &mut count, merged)?;
        }
        Ok((dirty, count))
    }

    fn push(
        dirty: &mut [DirtyArgSpan; MAX_SPANS],
        count: &mut usize,
        span: DirtyArgSpan,
    ) -> Result<(), ArgStageError> {
        let Some(slot) = dirty.get_mut(*count) else {
            return Err(ArgStageError::TooManyDirtySpans);
        };
        *slot = span;
        *count += 1;
        Ok(())
    }
}
