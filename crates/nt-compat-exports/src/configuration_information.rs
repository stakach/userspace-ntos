//! Shared NT I/O configuration counters returned to kernel drivers.

/// `CONFIGURATION_INFORMATION` from the NT I/O manager ABI.
#[repr(C)]
pub struct ConfigurationInformation {
    pub disk_count: u32,
    pub floppy_count: u32,
    pub cd_rom_count: u32,
    pub tape_count: u32,
    pub scsi_port_count: u32,
    pub serial_count: u32,
    pub parallel_count: u32,
    pub at_disk_primary_address_claimed: u8,
    pub at_disk_secondary_address_claimed: u8,
    _padding: [u8; 2],
    pub version: u32,
    pub medium_changer_count: u32,
}

impl ConfigurationInformation {
    pub const fn new() -> Self {
        Self {
            disk_count: 0,
            floppy_count: 0,
            cd_rom_count: 0,
            tape_count: 0,
            scsi_port_count: 0,
            serial_count: 0,
            parallel_count: 0,
            at_disk_primary_address_claimed: 0,
            at_disk_secondary_address_claimed: 0,
            _padding: [0; 2],
            version: core::mem::size_of::<Self>() as u32,
            medium_changer_count: 0,
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<ConfigurationInformation>() == 40);
    assert!(core::mem::offset_of!(ConfigurationInformation, scsi_port_count) == 16);
    assert!(core::mem::offset_of!(ConfigurationInformation, at_disk_primary_address_claimed) == 28);
    assert!(core::mem::offset_of!(ConfigurationInformation, version) == 32);
    assert!(core::mem::offset_of!(ConfigurationInformation, medium_changer_count) == 36);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_configuration_is_versioned_and_mutable() {
        let mut config = ConfigurationInformation::new();
        assert_eq!(config.version, 40);
        assert_eq!(config.scsi_port_count, 0);
        config.scsi_port_count += 1;
        config.at_disk_primary_address_claimed = 1;
        assert_eq!(config.scsi_port_count, 1);
        assert_eq!(config.at_disk_primary_address_claimed, 1);
    }
}
