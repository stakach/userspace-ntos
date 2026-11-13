//! Pure ReactOS-compatible debug-filter mask selection and level conversion.

/// ReactOS `KdComponentTable` includes the `DPFLTR_ENDOFTABLE_ID` entry (155).
pub const COMPONENT_COUNT: usize = 156;
pub const SYSTEM_WIDE_COMPONENT: u32 = u32::MAX;
const DPFLTR_MASK: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskSlot { System, Default, Component(usize) }

pub const fn mask_slot(component: u32) -> MaskSlot {
    if component == SYSTEM_WIDE_COMPONENT { MaskSlot::System }
    else if component < COMPONENT_COUNT as u32 { MaskSlot::Component(component as usize) }
    else { MaskSlot::Default }
}

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
pub enum SetFilterError { AccessDenied, IncompatiblePage }
