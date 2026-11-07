//! Select the current hosted driver's KPCR from its stack geometry.
//!
//! The KPCR holds a driver-visible value, never caller authority. The executive separately
//! authenticates every provider request against its retained physical route and dispatch.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedCurrentThreadKpcr {
    primary_stack: u64,
    primary_stack_bytes: u64,
    primary_kpcr: u64,
    worker_base: u64,
    worker_stride: u64,
    worker_stack_bytes: u64,
    worker_kpcr_offset: u64,
}

impl HostedCurrentThreadKpcr {
    pub const fn new(
        primary_stack: u64,
        primary_stack_bytes: u64,
        primary_kpcr: u64,
        worker_base: u64,
        worker_stride: u64,
        worker_stack_bytes: u64,
        worker_kpcr_offset: u64,
    ) -> Option<Self> {
        if primary_stack_bytes == 0
            || primary_kpcr == 0
            || worker_stride == 0
            || worker_stack_bytes == 0
            || worker_stack_bytes > worker_stride
            || primary_stack.checked_add(primary_stack_bytes).is_none()
            || worker_base.checked_add(worker_stride).is_none()
        {
            return None;
        }
        match worker_kpcr_offset.checked_add(0x1000) {
            Some(end) if end <= worker_stride => Some(Self {
                primary_stack,
                primary_stack_bytes,
                primary_kpcr,
                worker_base,
                worker_stride,
                worker_stack_bytes,
                worker_kpcr_offset,
            }),
            _ => None,
        }
    }

    /// Slot zero is the IRQ lane and uses a different GS layout. Worker slots start at one.
    pub const fn expected_kpcr(self, rsp: u64) -> Option<u64> {
        if rsp >= self.primary_stack && rsp < self.primary_stack + self.primary_stack_bytes {
            return Some(self.primary_kpcr);
        }
        let first_worker = self.worker_base + self.worker_stride;
        if rsp < first_worker {
            return None;
        }
        let relative = rsp - self.worker_base;
        let slot = relative / self.worker_stride;
        if relative % self.worker_stride >= self.worker_stack_bytes {
            return None;
        }
        let offset = match slot.checked_mul(self.worker_stride) {
            Some(offset) => offset,
            None => return None,
        };
        let base = match self.worker_base.checked_add(offset) {
            Some(base) => base,
            None => return None,
        };
        base.checked_add(self.worker_kpcr_offset)
    }

    /// A writable KPCR is sufficient for a driver-visible value, never for root authorization.
    pub const fn projected_thread(self, rsp: u64, gs_self: u64, gs_thread: u64) -> Option<u64> {
        match self.expected_kpcr(rsp) {
            Some(expected) if expected == gs_self && gs_thread != 0 => Some(gs_thread),
            _ => None,
        }
    }

    /// Keep the potentially unsafe GS reads behind stack and self-pointer checks. The caller
    /// supplies the architecture-specific read mechanism and falls back to its broker on `None`.
    #[inline(always)]
    pub fn read_projected_thread(
        self,
        rsp: u64,
        mut read_gs: impl FnMut(u64) -> u64,
    ) -> Option<u64> {
        let expected = self.expected_kpcr(rsp)?;
        let gs_self = read_gs(0x18);
        if gs_self != expected {
            return None;
        }
        self.projected_thread(rsp, gs_self, read_gs(0x188))
    }
}
