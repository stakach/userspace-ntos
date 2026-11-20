//! NT fast I/O device-control policy (`FAST_IO_DISPATCH.FastIoDeviceControl`).
//!
//! NtDeviceIoControlFile first offers a request to the target driver's FastIoDeviceControl
//! routine when its DRIVER_OBJECT publishes one; only a FALSE return builds an IRP. This module
//! validates the x64 dispatch table bytes and decides which output bytes a TRUE return makes
//! visible. It has no native effects.

/// `DRIVER_OBJECT.FastIoDispatch` in the x64 WDM layout.
pub const DRIVER_OBJECT_FAST_IO_DISPATCH_OFFSET: u64 = 0x50;
/// `FAST_IO_DISPATCH.FastIoDeviceControl`; the table starts with its ULONG size.
pub const FAST_IO_DEVICE_CONTROL_OFFSET: u64 = 0x50;
pub const FAST_IO_DEVICE_CONTROL_END: u32 = 0x58;

/// The FastIoDeviceControl routine a driver published, or `None` when its table is absent, too
/// small to contain the field, or leaves it NULL.
pub fn device_control_routine(size_of_fast_io_dispatch: u32, routine: u64) -> Option<u64> {
    (size_of_fast_io_dispatch >= FAST_IO_DEVICE_CONTROL_END && routine != 0).then_some(routine)
}

fn nt_error(status: u32) -> bool {
    status >> 30 == 3
}

/// Bytes of the driver-written output buffer to return to the caller after a TRUE return.
/// METHOD_BUFFERED output is bounded by IoStatus.Information, as the I/O manager copies it back;
/// direct and NEITHER buffers are written in place, so their whole extent is the driver's. An
/// error status returns no output.
pub fn output_copy_len(method: u32, status: u32, information: u64, output_len: u64) -> u64 {
    if nt_error(status) {
        0
    } else if method == nt_io_abi::ioctl::METHOD_BUFFERED {
        information.min(output_len)
    } else {
        output_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_io_abi::ioctl::{METHOD_BUFFERED, METHOD_NEITHER, METHOD_OUT_DIRECT};

    #[test]
    fn routine_requires_a_table_covering_the_field_and_a_nonnull_entry() {
        assert_eq!(device_control_routine(0xE0, 0x1_2e80), Some(0x1_2e80));
        assert_eq!(device_control_routine(0x58, 0x1_2e80), Some(0x1_2e80));
        assert_eq!(device_control_routine(0x50, 0x1_2e80), None);
        assert_eq!(device_control_routine(0xE0, 0), None);
    }

    #[test]
    fn output_visibility_follows_transfer_method_and_status() {
        assert_eq!(output_copy_len(METHOD_BUFFERED, 0, 12, 64), 12);
        assert_eq!(output_copy_len(METHOD_BUFFERED, 0, 99, 64), 64);
        assert_eq!(output_copy_len(METHOD_BUFFERED, 0x8000_0005, 64, 64), 64);
        assert_eq!(output_copy_len(METHOD_NEITHER, 0, 0, 64), 64);
        assert_eq!(output_copy_len(METHOD_OUT_DIRECT, 0, 3, 64), 64);
        assert_eq!(output_copy_len(METHOD_BUFFERED, 0xC000_0010, 12, 64), 0);
        assert_eq!(output_copy_len(METHOD_NEITHER, 0xC000_0023, 0, 64), 0);
    }
}
