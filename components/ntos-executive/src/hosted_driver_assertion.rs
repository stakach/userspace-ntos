//! Terminal kernel assertion export for isolated hosted drivers.

/// `RtlAssert` is a failure path, never a successful diagnostic no-op. The provider retains
/// its own strings; only the line number and assertion tag cross the physical bugcheck channel. The root
/// receiver records the source and suspends the provider domain before resource retirement.
pub(crate) extern "win64" fn rtl_assert(
    _assertion: u64,
    _file: u64,
    line: u32,
    _message: u64,
) -> ! {
    unsafe {
        crate::provider_bugcheck::report(
            0xc4,
            [0x5254_4c41, u64::from(line), 0, 0],
        )
    }
}
