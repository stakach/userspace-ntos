//! Pure ReactOS-compatible debug-filter mask selection and level conversion.

/// ReactOS `KdComponentTable` includes the `DPFLTR_ENDOFTABLE_ID` entry (155).
pub const COMPONENT_COUNT: usize = 156;
pub const SYSTEM_WIDE_COMPONENT: u32 = u32::MAX;
const DPFLTR_MASK: u32 = 0x8000_0000;

/// Convert a level index or raw `DPFLTR_MASK` value into mask bits.
pub const fn level_mask(level: u32) -> u32 {
    let bits = if level < 32 { 1u32 << level } else { level };
    bits & !DPFLTR_MASK
}

/// A system-wide bit enables the level regardless of the selected component.
pub const fn enabled(system_mask: u32, component_mask: u32, level: u32) -> bool {
    (system_mask | component_mask) & level_mask(level) != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetFilterError { AccessDenied }

/// Root-owned debug-print filter state. Unknown component IDs share the default mask.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugFilterMasks {
    system: u32,
    default: u32,
    components: [u32; COMPONENT_COUNT],
}

impl DebugFilterMasks {
    pub const fn new() -> Self {
        Self { system: 1, default: 0, components: [0; COMPONENT_COUNT] }
    }

    pub fn query(&self, component: u32, level: u32) -> bool {
        enabled(self.system, self.selected(component), level)
    }

    /// The caller must supply its checked `SeDebugPrivilege` decision.
    pub fn set(&mut self, component: u32, level: u32, state: bool,
        has_debug_privilege: bool) -> Result<(), SetFilterError> {
        if !has_debug_privilege { return Err(SetFilterError::AccessDenied); }
        let bits = level_mask(level);
        let target = self.selected_mut(component);
        if state { *target |= bits; } else { *target &= !bits; }
        Ok(())
    }

    pub fn system_mask(&self) -> u32 { self.system }
    pub fn default_mask(&self) -> u32 { self.default }
    pub fn component_masks(&self) -> &[u32; COMPONENT_COUNT] { &self.components }

    fn selected(&self, component: u32) -> u32 {
        if component == SYSTEM_WIDE_COMPONENT { self.system }
        else { self.components.get(component as usize).copied().unwrap_or(self.default) }
    }

    fn selected_mut(&mut self, component: u32) -> &mut u32 {
        if component == SYSTEM_WIDE_COMPONENT { &mut self.system }
        else { self.components.get_mut(component as usize).unwrap_or(&mut self.default) }
    }
}

impl Default for DebugFilterMasks {
    fn default() -> Self { Self::new() }
}
