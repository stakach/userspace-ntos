//! Bounded length inference for RtlQueryRegistryValues direct string defaults.

/// ReactOS supplies a zero DefaultLength for NUL-terminated REG_SZ defaults.
/// The returned byte length includes the terminator, as RtlpQueryRegistryDirect expects.
pub(crate) fn direct_default_length(
    value_type: u32,
    supplied_length: u32,
    mut unit: impl FnMut(usize) -> Option<u16>,
) -> Option<usize> {
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const MAX_DEFAULT_BYTES: usize = 4096;
    if supplied_length != 0 {
        let length = supplied_length as usize;
        return (length <= MAX_DEFAULT_BYTES).then_some(length);
    }
    if !matches!(value_type, REG_SZ | REG_EXPAND_SZ) {
        return None;
    }
    for index in 0..MAX_DEFAULT_BYTES / 2 {
        if unit(index)? == 0 {
            return Some((index + 1) * 2);
        }
    }
    None
}
