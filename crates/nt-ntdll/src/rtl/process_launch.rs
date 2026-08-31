//! Pure process-launch policy shared by the live `RtlCreateUserProcess` implementation.

/// `RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB`.
pub const RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB: u32 = 0x20;
/// Native subsystem image type.
pub const IMAGE_SUBSYSTEM_NATIVE: u32 = 1;

/// `MEM_RESERVE`.
pub const MEM_RESERVE: u32 = 0x2000;
/// `PAGE_READWRITE`.
pub const PAGE_READWRITE: u32 = 0x04;

/// The low-memory reservation requested for native subsystem processes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LowMemoryReservation {
    pub base: u64,
    pub size: usize,
    pub allocation_type: u32,
    pub protection: u32,
}

/// Return the NT low 1 MiB request when a native image's process parameters require it.
pub const fn low_memory_reservation(
    subsystem_type: u32,
    flags: u32,
) -> Option<LowMemoryReservation> {
    if subsystem_type != IMAGE_SUBSYSTEM_NATIVE
        || flags & RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB == 0
    {
        return None;
    }
    Some(LowMemoryReservation {
        base: 4,
        size: 0x10_0000 - 0x100,
        allocation_type: MEM_RESERVE,
        protection: PAGE_READWRITE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_subsystem_flag_requests_the_nt_low_megabyte_shape() {
        assert_eq!(low_memory_reservation(IMAGE_SUBSYSTEM_NATIVE, 0x01), None);
        assert_eq!(low_memory_reservation(2, 0x21), None);
        assert_eq!(
            low_memory_reservation(IMAGE_SUBSYSTEM_NATIVE, 0x21),
            Some(LowMemoryReservation {
                base: 4,
                size: 0x0f_ff00,
                allocation_type: MEM_RESERVE,
                protection: PAGE_READWRITE,
            })
        );
    }
}
