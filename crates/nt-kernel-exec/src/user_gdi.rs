//! Bounded mirrors for GDI objects that are session-global in ReactOS win32k.

/// ReactOS `NB_STOCK_OBJECTS`.
pub const NB_STOCK_OBJECTS: usize = 22;

/// The stock bitmap id used by zero-sized bitmap creation.
pub const DEFAULT_BITMAP: u32 = 21;

/// Handles returned from `NtGdiGetStockObject` are session-global stock handles. They are safe to
/// reuse in another process only after a real win32k call has returned that exact handle for the
/// requested stock-object id.
pub struct StockObjectMirror {
    handles: [u32; NB_STOCK_OBJECTS],
}

impl StockObjectMirror {
    pub const fn new() -> Self {
        Self {
            handles: [0; NB_STOCK_OBJECTS],
        }
    }

    pub fn clear(&mut self) {
        self.handles.fill(0);
    }

    pub fn observe(&mut self, object_id: u32, handle: u32) -> bool {
        let Some(slot) = self.handles.get_mut(object_id as usize) else {
            return false;
        };
        if handle == 0 {
            return false;
        }
        *slot = handle;
        true
    }

    pub fn lookup(&self, object_id: u32) -> Option<u32> {
        self.handles
            .get(object_id as usize)
            .copied()
            .filter(|handle| *handle != 0)
    }
}

impl Default for StockObjectMirror {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_only_observed_stock_handles() {
        let mut mirror = StockObjectMirror::new();
        assert_eq!(mirror.lookup(5), None);
        assert!(mirror.observe(5, 0x0090_1049));
        assert_eq!(mirror.lookup(5), Some(0x0090_1049));
    }

    #[test]
    fn rejects_zero_or_out_of_range_observations() {
        let mut mirror = StockObjectMirror::new();
        assert!(!mirror.observe(0, 0));
        assert!(!mirror.observe(NB_STOCK_OBJECTS as u32, 0x0010_0049));
        assert_eq!(mirror.lookup(0), None);
        assert_eq!(mirror.lookup(NB_STOCK_OBJECTS as u32), None);
    }

    #[test]
    fn replacement_updates_the_cached_handle() {
        let mut mirror = StockObjectMirror::new();
        assert!(mirror.observe(DEFAULT_BITMAP, 0x0085_0049));
        assert!(mirror.observe(DEFAULT_BITMAP, 0x0085_00dc));
        assert_eq!(mirror.lookup(DEFAULT_BITMAP), Some(0x0085_00dc));
    }
}
