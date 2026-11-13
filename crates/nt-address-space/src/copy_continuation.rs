//! Exact ownership and byte progress for a syscall copy paused on page residency.

use super::CopyResult;
use crate::PAGE_SIZE;

const STATUS_PENDING: u32 = 0x0000_0103;
const COPY_CHUNK_SIZE: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase<Source, Irp> {
    Ready,
    Pending {
        offset: u64,
        source: Source,
        irp: Irp,
        acknowledged: bool,
    },
    OutputReady(CopyResult),
    OutputPublishing(CopyResult),
    ReplyReady(CopyResult),
    ReplyEntered,
}

/// Retains the original caller Reply, foreign address-space owner, count output and completed
/// prefix. Provider completion can only resume the exact page read entered by this copy.
pub struct VmCopyContinuation<Caller, Target, Source, Irp> {
    caller: Caller,
    target: Target,
    source_address: u64,
    destination_address: u64,
    length: u64,
    count_pointer: u64,
    transferred: u64,
    staged_offset: Option<u64>,
    staged_length: usize,
    staged_bytes: [u8; COPY_CHUNK_SIZE],
    probe_cursor: Option<u64>,
    probe_entered: bool,
    copy_write_entered: bool,
    output_offset: usize,
    output_entered: bool,
    output_bytes: [u8; 8],
    phase: Phase<Source, Irp>,
}

impl<Caller: Copy + Eq, Target: Copy + Eq, Source: Copy + Eq, Irp: Copy + Eq>
    VmCopyContinuation<Caller, Target, Source, Irp>
{
    pub fn new(
        caller: Caller,
        target: Target,
        source_address: u64,
        destination_address: u64,
        length: u64,
        count_pointer: u64,
    ) -> Self {
        Self {
            caller,
            target,
            source_address,
            destination_address,
            length,
            count_pointer,
            transferred: 0,
            staged_offset: None,
            staged_length: 0,
            staged_bytes: [0; COPY_CHUNK_SIZE],
            probe_cursor: (length != 0).then_some(destination_address),
            probe_entered: false,
            copy_write_entered: false,
            output_offset: 0,
            output_entered: false,
            output_bytes: [0; 8],
            phase: Phase::Ready,
        }
    }

    fn exact_owner(&self, caller: Caller, target: Target) -> bool {
        self.caller == caller && self.target == target
    }

    pub fn next_offset(&self, caller: Caller, target: Target) -> Option<u64> {
        (self.exact_owner(caller, target)
            && self.transferred < self.length
            && !self.copy_write_entered
            && matches!(self.phase, Phase::Ready))
        .then_some(self.transferred)
    }

    /// Native code must still choose a page-contained chunk and stage its source bytes first.
    pub fn next_addresses(&self, caller: Caller, target: Target) -> Option<(u64, u64, u64)> {
        let offset = self.next_offset(caller, target)?;
        Some((
            self.source_address.checked_add(offset)?,
            self.destination_address.checked_add(offset)?,
            self.length - offset,
        ))
    }

    /// Capture one page-contained source chunk before probing any destination page. The bytes
    /// remain stable if either page-in suspends this syscall.
    pub fn stage_source(
        &mut self,
        caller: Caller,
        target: Target,
        offset: u64,
        bytes: &[u8],
    ) -> bool {
        if self.next_offset(caller, target) != Some(offset)
            || self.staged_offset.is_some()
            || bytes.is_empty()
            || bytes.len() > COPY_CHUNK_SIZE
            || bytes.len() as u64 > self.length - offset
        {
            return false;
        }
        let Some(source) = self.source_address.checked_add(offset) else {
            return false;
        };
        let Some(destination) = self.destination_address.checked_add(offset) else {
            return false;
        };
        if bytes.len() as u64 > PAGE_SIZE - source % PAGE_SIZE
            || bytes.len() as u64 > PAGE_SIZE - destination % PAGE_SIZE
            || source.checked_add(bytes.len() as u64).is_none()
            || destination.checked_add(bytes.len() as u64).is_none()
        {
            return false;
        }
        self.staged_bytes[..bytes.len()].copy_from_slice(bytes);
        self.staged_offset = Some(offset);
        self.staged_length = bytes.len();
        true
    }

    pub fn staged_source(&self, caller: Caller, target: Target, offset: u64) -> Option<&[u8]> {
        (self.exact_owner(caller, target) && self.staged_offset == Some(offset))
            .then_some(&self.staged_bytes[..self.staged_length])
    }

    /// The complete first destination range is probed before writing any copied bytes.
    pub fn next_probe_address(&self, caller: Caller, target: Target) -> Option<u64> {
        (self.exact_owner(caller, target)
            && self.staged_offset == Some(self.transferred)
            && !self.probe_entered
            && matches!(self.phase, Phase::Ready))
        .then_some(self.probe_cursor)?
    }

    /// Record the self-write probe before it can change a COW or guard mapping. Until its
    /// outcome is known, the same effect cannot be entered a second time.
    pub fn enter_probe_page(&mut self, caller: Caller, target: Target, address: u64) -> bool {
        if self.next_probe_address(caller, target) != Some(address) {
            return false;
        }
        self.probe_entered = true;
        true
    }

    pub fn probe_page_completed(&mut self, caller: Caller, target: Target, address: u64) -> bool {
        if !self.exact_owner(caller, target)
            || !self.probe_entered
            || self.probe_cursor != Some(address)
            || !matches!(self.phase, Phase::Ready)
        {
            return false;
        }
        let Some(end) = self.destination_address.checked_add(self.length) else {
            return false;
        };
        if address >= end {
            return false;
        }
        let step = (PAGE_SIZE - address % PAGE_SIZE).min(end - address);
        let Some(next) = address.checked_add(step) else {
            return false;
        };
        self.probe_cursor = (next < end).then_some(next);
        self.probe_entered = false;
        true
    }

    /// Enter the staged destination write before physical effects. Its result must be proved
    /// before another chunk can be read or the same bytes can be written again.
    pub fn enter_copy_write(&mut self, caller: Caller, target: Target, offset: u64) -> bool {
        if self.next_offset(caller, target) != Some(offset)
            || self.staged_offset != Some(offset)
            || self.probe_cursor.is_some() || self.probe_entered
        {
            return false;
        }
        self.copy_write_entered = true;
        true
    }

    pub fn commit_copied(&mut self, caller: Caller, target: Target, offset: u64, bytes: u64) -> bool {
        if !self.exact_owner(caller, target) || self.transferred != offset
            || !matches!(self.phase, Phase::Ready) || !self.copy_write_entered
            || bytes == 0
            || bytes > self.length - offset
            || self.staged_offset != Some(offset)
            || bytes != self.staged_length as u64
            || self.probe_cursor.is_some()
            || self.source_address.checked_add(offset + bytes).is_none()
            || self.destination_address.checked_add(offset + bytes).is_none()
        {
            return false;
        }
        self.transferred = offset + bytes;
        self.staged_offset = None;
        self.staged_length = 0;
        self.copy_write_entered = false;
        true
    }

    /// Called before entering routed provider I/O; an entered read cannot be submitted again.
    pub fn begin_pending(
        &mut self,
        caller: Caller,
        target: Target,
        offset: u64,
        source: Source,
        irp: Irp,
    ) -> bool {
        if self.next_offset(caller, target) != Some(offset) || self.probe_entered {
            return false;
        }
        self.phase = Phase::Pending {
            offset,
            source,
            irp,
            acknowledged: false,
        };
        true
    }

    /// The provider's terminal data and acknowledgement must both belong to this operation.
    pub fn acknowledge_pending(
        &mut self,
        caller: Caller,
        target: Target,
        offset: u64,
        source: Source,
        irp: Irp,
    ) -> bool {
        if !self.exact_owner(caller, target) {
            return false;
        }
        let Phase::Pending {
            offset: expected_offset,
            source: expected_source,
            irp: expected_irp,
            acknowledged,
        } = &mut self.phase
        else {
            return false;
        };
        if *expected_offset != offset
            || *expected_source != source
            || *expected_irp != irp
            || *acknowledged
        {
            return false;
        }
        *acknowledged = true;
        true
    }

    pub fn resume_pending(
        &mut self,
        caller: Caller,
        target: Target,
        offset: u64,
        source: Source,
        irp: Irp,
    ) -> bool {
        if !self.exact_owner(caller, target)
            || !matches!(self.phase, Phase::Pending {
                offset: expected_offset,
                source: expected_source,
                irp: expected_irp,
                acknowledged: true,
            } if expected_offset == offset && expected_source == source && expected_irp == irp)
        {
            return false;
        }
        self.phase = Phase::Ready;
        true
    }

    pub fn fail_pending(
        &mut self,
        caller: Caller,
        target: Target,
        offset: u64,
        source: Source,
        irp: Irp,
        status: u32,
    ) -> bool {
        if status == 0 || status == STATUS_PENDING
            || !self.exact_owner(caller, target)
            || !matches!(self.phase, Phase::Pending {
                offset: expected_offset,
                source: expected_source,
                irp: expected_irp,
                acknowledged: true,
            } if expected_offset == offset && expected_source == source && expected_irp == irp)
        {
            return false;
        }
        self.phase = Phase::OutputReady(CopyResult {
            status,
            transferred: self.transferred,
        });
        self.output_bytes = self.transferred.to_le_bytes();
        true
    }

    /// A definitive inline read, probe, or write error ends the copy with its committed prefix.
    /// An entered probe with uncertain self-write cannot be converted into a clean failure.
    pub fn fail(&mut self, caller: Caller, target: Target, status: u32) -> bool {
        if status == 0 || status == STATUS_PENDING || !self.exact_owner(caller, target)
            || !matches!(self.phase, Phase::Ready) || self.probe_entered
            || self.copy_write_entered
        {
            return false;
        }
        self.phase = Phase::OutputReady(CopyResult {
            status,
            transferred: self.transferred,
        });
        self.output_bytes = self.transferred.to_le_bytes();
        true
    }

    pub fn finish(&mut self, caller: Caller, target: Target, status: u32) -> bool {
        if !self.exact_owner(caller, target)
            || !matches!(self.phase, Phase::Ready)
            || self.transferred != self.length
            || status != 0
        {
            return false;
        }
        self.phase = Phase::OutputReady(CopyResult {
            status,
            transferred: self.transferred,
        });
        self.output_bytes = self.transferred.to_le_bytes();
        true
    }

    pub fn output_to_publish(&self, caller: Caller, target: Target) -> Option<(u64, u64)> {
        if !self.exact_owner(caller, target) {
            return None;
        }
        let Phase::OutputReady(result) = self.phase else {
            return None;
        };
        Some((self.count_pointer, result.transferred))
    }

    pub fn next_output_chunk(&self, caller: Caller, target: Target) -> Option<(u64, &[u8])> {
        if !self.exact_owner(caller, target) || self.count_pointer == 0
            || self.output_entered || self.output_offset >= self.output_bytes.len()
            || !matches!(self.phase, Phase::OutputReady(_) | Phase::OutputPublishing(_))
        {
            return None;
        }
        let address = self.count_pointer.checked_add(self.output_offset as u64)?;
        let length = (self.output_bytes.len() - self.output_offset)
            .min((PAGE_SIZE - address % PAGE_SIZE) as usize);
        address.checked_add(length as u64)?;
        Some((address, &self.output_bytes[self.output_offset..self.output_offset + length]))
    }

    /// Enter a page-contained count write before the native effect. An uncertain write cannot
    /// be replayed, including when a SIZE_T output straddles two pages.
    pub fn enter_output_page(&mut self, caller: Caller, target: Target, address: u64) -> bool {
        if self.next_output_chunk(caller, target).map(|(next, _)| next) != Some(address) {
            return false;
        }
        if let Phase::OutputReady(result) = self.phase {
            self.phase = Phase::OutputPublishing(result);
        }
        self.output_entered = true;
        true
    }

    pub fn output_page_completed(&mut self, caller: Caller, target: Target, address: u64) -> bool {
        if !self.exact_owner(caller, target) || !self.output_entered
            || !matches!(self.phase, Phase::OutputPublishing(_))
        {
            return false;
        }
        let Some(expected) = self.count_pointer.checked_add(self.output_offset as u64) else {
            return false;
        };
        if expected != address {
            return false;
        }
        let length = (self.output_bytes.len() - self.output_offset)
            .min((PAGE_SIZE - address % PAGE_SIZE) as usize);
        self.output_offset += length;
        self.output_entered = false;
        true
    }

    pub fn output_published(&mut self, caller: Caller, target: Target) -> bool {
        if !self.exact_owner(caller, target) || self.count_pointer == 0
            || self.output_offset != self.output_bytes.len() || self.output_entered
        {
            return false;
        }
        let Phase::OutputPublishing(result) = self.phase else {
            return false;
        };
        self.phase = Phase::ReplyReady(result);
        true
    }

    /// The native count store may meet a definitive no-write failure after an earlier page was
    /// published. Preserve the copy result and enter the original Reply once; an entered write
    /// with uncertain effect must remain parked instead.
    pub fn output_failed(&mut self, caller: Caller, target: Target) -> bool {
        if !self.exact_owner(caller, target) || self.count_pointer == 0
            || self.output_entered || self.output_offset >= self.output_bytes.len()
        {
            return false;
        }
        let result = match self.phase {
            Phase::OutputReady(result) | Phase::OutputPublishing(result) => result,
            _ => return false,
        };
        self.phase = Phase::ReplyReady(result);
        true
    }

    pub fn skip_null_output(&mut self, caller: Caller, target: Target) -> bool {
        if !self.exact_owner(caller, target) || self.count_pointer != 0 {
            return false;
        }
        let Phase::OutputReady(result) = self.phase else {
            return false;
        };
        self.phase = Phase::ReplyReady(result);
        true
    }

    pub fn enter_reply(&mut self, caller: Caller, target: Target) -> Option<(Caller, CopyResult)> {
        if !self.exact_owner(caller, target) {
            return None;
        }
        let Phase::ReplyReady(result) = self.phase else {
            return None;
        };
        self.phase = Phase::ReplyEntered;
        Some((self.caller, result))
    }
}
