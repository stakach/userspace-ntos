//! Exact mounted-device to data-section mount identity binding.

use alloc::vec::Vec;

use super::SectionMountId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionMountBindingError {
    Exhausted,
    Duplicate,
    WrongPhase,
}

#[derive(Clone, Copy)]
struct Binding<K> {
    mount: SectionMountId,
    device: Option<K>,
}

pub struct SectionMountBindings<K> {
    bindings: Vec<Binding<K>>,
}

impl<K: Copy + Eq> SectionMountBindings<K> {
    pub const fn new() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    /// Reserve all storage before the native device-create effect.
    pub fn reserve(&mut self, mount: SectionMountId) -> Result<(), SectionMountBindingError> {
        if self.bindings.iter().any(|binding| binding.mount == mount) {
            return Err(SectionMountBindingError::Duplicate);
        }
        self.bindings
            .try_reserve(1)
            .map_err(|_| SectionMountBindingError::Exhausted)?;
        self.bindings.push(Binding {
            mount,
            device: None,
        });
        Ok(())
    }

    pub fn publish(
        &mut self,
        mount: SectionMountId,
        device: K,
    ) -> Result<(), SectionMountBindingError> {
        if self
            .bindings
            .iter()
            .any(|binding| binding.device == Some(device))
        {
            return Err(SectionMountBindingError::Duplicate);
        }
        let binding = self
            .bindings
            .iter_mut()
            .find(|binding| binding.mount == mount)
            .ok_or(SectionMountBindingError::WrongPhase)?;
        if binding.device.is_some() {
            return Err(SectionMountBindingError::WrongPhase);
        }
        binding.device = Some(device);
        Ok(())
    }

    pub fn lookup(&self, device: K) -> Option<SectionMountId> {
        self.bindings
            .iter()
            .find(|binding| binding.device == Some(device))
            .map(|binding| binding.mount)
    }

    pub fn cancel(&mut self, mount: SectionMountId) -> Result<(), SectionMountBindingError> {
        let index = self
            .bindings
            .iter()
            .position(|binding| binding.mount == mount && binding.device.is_none())
            .ok_or(SectionMountBindingError::WrongPhase)?;
        self.bindings.remove(index);
        Ok(())
    }

    /// Call only after the I/O manager confirms exact device destruction.
    pub fn retire(&mut self, device: K) -> Option<SectionMountId> {
        let index = self
            .bindings
            .iter()
            .position(|binding| binding.device == Some(device))?;
        Some(self.bindings.remove(index).mount)
    }
}

impl<K: Copy + Eq> Default for SectionMountBindings<K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SectionMountIds;

    #[test]
    fn distinct_devices_cannot_share_one_mount_identity() {
        let mut ids = SectionMountIds::new();
        let first = ids.allocate().unwrap();
        let second = ids.allocate().unwrap();
        let mut bindings = SectionMountBindings::new();
        bindings.reserve(first).unwrap();
        bindings.reserve(second).unwrap();
        assert_eq!(bindings.lookup(0x1001u64), None);
        bindings.publish(first, 0x1001).unwrap();
        bindings.publish(second, 0x1002).unwrap();
        assert_eq!(bindings.lookup(0x1001), Some(first));
        assert_eq!(bindings.lookup(0x1002), Some(second));
        assert_eq!(
            bindings.publish(second, 0x1001),
            Err(SectionMountBindingError::Duplicate)
        );
        assert_eq!(bindings.lookup(0x1002), Some(second));
    }

    #[test]
    fn retired_generation_never_matches_replacement() {
        let mut ids = SectionMountIds::new();
        let first = ids.allocate().unwrap();
        let replacement = ids.allocate().unwrap();
        let mut bindings = SectionMountBindings::new();
        bindings.reserve(first).unwrap();
        bindings.publish(first, 0x0100_0000_0042u64).unwrap();
        assert_eq!(bindings.retire(0x0100_0000_0042), Some(first));
        bindings.reserve(replacement).unwrap();
        bindings.publish(replacement, 0x0200_0000_0042).unwrap();
        assert_eq!(bindings.lookup(0x0100_0000_0042), None);
        assert_eq!(bindings.lookup(0x0200_0000_0042), Some(replacement));
    }

    #[test]
    fn failed_create_cancels_only_the_prepared_binding() {
        let mut ids = SectionMountIds::new();
        let first = ids.allocate().unwrap();
        let second = ids.allocate().unwrap();
        let mut bindings = SectionMountBindings::new();
        bindings.reserve(first).unwrap();
        assert_eq!(
            bindings.reserve(first),
            Err(SectionMountBindingError::Duplicate)
        );
        assert_eq!(
            bindings.publish(second, 7u64),
            Err(SectionMountBindingError::WrongPhase)
        );
        bindings.cancel(first).unwrap();
        assert_eq!(
            bindings.cancel(first),
            Err(SectionMountBindingError::WrongPhase)
        );
        bindings.reserve(second).unwrap();
        bindings.publish(second, 7).unwrap();
        assert_eq!(
            bindings.cancel(second),
            Err(SectionMountBindingError::WrongPhase)
        );
        assert_eq!(bindings.lookup(7), Some(second));
    }
}
