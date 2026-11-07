//! DEVPROPKEY query over the canonical hosted PDO property transfer.

use super::*;

// DEVPKEY_Device_Driver, fmtid a45c254e-df1c-4efd-8020-67d146a850e0, pid 11.
// The released ACPI driver uses this typed key for the same CM-backed value as
// DevicePropertyDriverKeyName. Unknown keys are explicitly unsupported.
const DEVPKEY_DEVICE_DRIVER: [u8; 20] = [
    0x4e, 0x25, 0x5c, 0xa4, 0x1c, 0xdf, 0xfd, 0x4e,
    0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0,
    11, 0, 0, 0,
];

/// NTSTATUS IoGetDevicePropertyData(PDO, DEVPROPKEY*, LCID, Flags, Size, Data,
///                                  RequiredSize*, DEVPROPTYPE*).
pub(super) extern "win64" fn s_io_get_device_property_data(
    pdo: u64,
    key: u64,
    lcid: u32,
    flags: u32,
    size: u32,
    data: u64,
    required_size: u64,
    property_type: u64,
) -> i32 {
    if pdo == 0 || key == 0 || required_size == 0 || property_type == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        write_unaligned(required_size as *mut u32, 0);
        write_unaligned(property_type as *mut u32, nt_config_manager::devprop_type::EMPTY);
        if hosted_current_irql() != 0 || lcid != 0 || flags != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let property_key = read_unaligned(key as *const [u8; 20]);
        if property_key != DEVPKEY_DEVICE_DRIVER {
            return STATUS_NOT_SUPPORTED;
        }
        let _reply_guard = component_device_reply_lock();
        // `device_property::query` authenticates the exact PDO in the root, obtains the
        // DRIVER_KEY_NAME CM snapshot, and copies the result only after a complete transfer.
        let status = device_property::query(
            &mut device_property::DriverPropertyClient,
            pdo,
            nt_config_manager::device_property::DRIVER_KEY_NAME,
            size,
            data,
            required_size,
        );
        if status == STATUS_SUCCESS || status == STATUS_BUFFER_TOO_SMALL {
            write_unaligned(property_type as *mut u32, nt_config_manager::devprop_type::STRING);
        }
        status
    }
}
