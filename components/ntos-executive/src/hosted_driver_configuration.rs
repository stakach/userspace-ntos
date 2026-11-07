//! Shared NT I/O configuration state visible to every hosted driver.

use super::*;

static mut CONFIGURATION_INFORMATION: nt_compat_exports::configuration_information::ConfigurationInformation =
    nt_compat_exports::configuration_information::ConfigurationInformation::new();

/// `PCONFIGURATION_INFORMATION IoGetConfigurationInformation(void)`.
extern "win64" fn io_get_configuration_information() -> u64 {
    core::ptr::addr_of_mut!(CONFIGURATION_INFORMATION) as u64
}

pub(crate) fn bind_configuration_export(reg: &mut nt_compat_exports::DriverExportRegistry) {
    reg.bind("IoGetConfigurationInformation", io_get_configuration_information as *const () as usize as u64);
}
