//! Named-device lookup for hosted drivers' `IoGetDeviceObjectPointer` import.
//!
//! A successful lookup owns one FILE_OBJECT pointer reference after its temporary
//! open handle closes. `ObDereferenceObject(FileObject)` retires that reference.

use super::*;

const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033u32 as i32;

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    _padding: u32,
    root_directory: u64,
    object_name: u64,
    attributes: u32,
    _padding2: u32,
    security_descriptor: u64,
    security_qos: u64,
}

trait Lookup {
    fn open(&mut self) -> Result<u64, i32>;
    fn reference_file(&mut self, handle: u64) -> Result<u64, i32>;
    fn related_device(&mut self, file: u64) -> Result<u64, i32>;
    fn close(&mut self, handle: u64);
    fn dereference_file(&mut self, file: u64);
}

/// The temporary open handle is closed on every path. A successful File pointer
/// reference belongs to the caller and survives the close; an unsuccessful lookup
/// retires it before publishing either output pointer.
fn lookup<O: Lookup>(ops: &mut O) -> Result<(u64, u64), i32> {
    let handle = ops.open()?;
    let file = match ops.reference_file(handle) {
        Ok(file) => file,
        Err(status) => {
            ops.close(handle);
            return Err(status);
        }
    };
    let device = ops.related_device(file);
    ops.close(handle);
    match device {
        Ok(device) if device != 0 => Ok((file, device)),
        Ok(_) => {
            ops.dereference_file(file);
            Err(STATUS_INVALID_DEVICE_REQUEST)
        }
        Err(status) => {
            ops.dereference_file(file);
            Err(status)
        }
    }
}

struct HostedLookup {
    object_name: u64,
    desired_access: u32,
}

impl Lookup for HostedLookup {
    fn open(&mut self) -> Result<u64, i32> {
        let attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            _padding: 0,
            root_directory: 0,
            object_name: self.object_name,
            attributes: OBJ_KERNEL_HANDLE,
            _padding2: 0,
            security_descriptor: 0,
            security_qos: 0,
        };
        let mut handle = 0u64;
        let mut io_status = nt_kernel_abi::IoStatusBlock::default();
        let status = hosted_io_create_file_adapter::s_zw_open_file(
            &mut handle as *mut u64 as u64,
            self.desired_access,
            &attributes as *const ObjectAttributes as u64,
            &mut io_status as *mut nt_kernel_abi::IoStatusBlock as u64,
            0, // ReactOS IopGetDeviceObjectPointer opens with exclusive share access.
            FILE_NON_DIRECTORY_FILE,
        );
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        if handle == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(handle)
    }

    fn reference_file(&mut self, handle: u64) -> Result<u64, i32> {
        let mut file = 0u64;
        let status = s_ob_reference_object_by_handle(
            handle,
            0,
            FSD_DATA_IO_FILE_OBJECT_TYPE_BODY_VA,
            0, // KernelMode, matching the temporary Zw open.
            &mut file as *mut u64 as u64,
            0,
        );
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        if file == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(file)
    }

    fn related_device(&mut self, file: u64) -> Result<u64, i32> {
        let (words, status, device, reserved0, reserved1) = unsafe {
            call_on4_raw((FSD_SERVICE_FILE_LABEL << 12) | 4, 7, file, 0, 0)
        };
        if words != 4 || reserved0 != 0 || reserved1 != 0 {
            unsafe {
                crate::provider_bugcheck::report(
                    0xc4,
                    [FSD_SERVICE_FILE_LABEL, 7, words, status],
                );
            }
        }
        let status = status as u32 as i32;
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        if device == 0 || !unsafe { consumer_device_object_in_local_pool(device) } {
            unsafe {
                crate::provider_bugcheck::report(
                    0xc4,
                    [FSD_SERVICE_FILE_LABEL, 7, file, device],
                );
            }
        }
        Ok(device)
    }

    fn close(&mut self, handle: u64) {
        let status = s_zw_close(handle);
        if status != STATUS_SUCCESS {
            // The close may have entered the root-owned routed-File retirement lane.
            // Keep that owner and its File projection intact; no caller receives a
            // success result or retries the uncertain close.
            unsafe {
                crate::provider_bugcheck::report(
                    0xc4,
                    [FSD_SERVICE_FILE_LABEL, 7, handle, status as u32 as u64],
                );
            }
        }
    }

    fn dereference_file(&mut self, file: u64) {
        let _ = s_obf_dereference_object(file);
    }
}

/// `NTSTATUS IoGetDeviceObjectPointer(PUNICODE_STRING, ACCESS_MASK, PFILE_OBJECT*, PDEVICE_OBJECT*)`.
pub(super) extern "win64" fn s_io_get_device_object_pointer(
    object_name: u64,
    desired_access: u32,
    file_out: u64,
    device_out: u64,
) -> i32 {
    if object_name == 0 || file_out == 0 || device_out == 0 {
        return STATUS_ACCESS_VIOLATION;
    }
    unsafe {
        write_unaligned(file_out as *mut u64, 0);
        write_unaligned(device_out as *mut u64, 0);
        let length = read_unaligned(object_name as *const u16);
        let maximum = read_unaligned((object_name + 2) as *const u16);
        let buffer = read_unaligned((object_name + 8) as *const u64);
        if length == 0 || length & 1 != 0 || length > maximum || buffer == 0 {
            return STATUS_OBJECT_NAME_INVALID;
        }
        let mut ops = HostedLookup { object_name, desired_access };
        match lookup(&mut ops) {
            Ok((file, device)) => {
                write_unaligned(file_out as *mut u64, file);
                write_unaligned(device_out as *mut u64, device);
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        open_status: i32,
        reference_status: i32,
        related_status: i32,
        events: alloc::vec::Vec<&'static str>,
    }

    impl Lookup for Fake {
        fn open(&mut self) -> Result<u64, i32> {
            self.events.push("open");
            if self.open_status == 0 { Ok(11) } else { Err(self.open_status) }
        }
        fn reference_file(&mut self, handle: u64) -> Result<u64, i32> {
            assert_eq!(handle, 11);
            self.events.push("reference");
            if self.reference_status == 0 { Ok(22) } else { Err(self.reference_status) }
        }
        fn related_device(&mut self, file: u64) -> Result<u64, i32> {
            assert_eq!(file, 22);
            self.events.push("related");
            if self.related_status == 0 { Ok(33) } else { Err(self.related_status) }
        }
        fn close(&mut self, handle: u64) {
            assert_eq!(handle, 11);
            self.events.push("close");
        }
        fn dereference_file(&mut self, file: u64) {
            assert_eq!(file, 22);
            self.events.push("dereference");
        }
    }

    #[test]
    fn named_device_lookup_keeps_exact_file_reference_after_temporary_close() {
        let mut ops = Fake::default();
        assert_eq!(lookup(&mut ops), Ok((22, 33)));
        assert_eq!(ops.events, ["open", "reference", "related", "close"]);
    }

    #[test]
    fn failed_related_device_releases_reference_and_temporary_handle() {
        let mut ops = Fake { related_status: STATUS_INVALID_DEVICE_REQUEST, ..Fake::default() };
        assert_eq!(lookup(&mut ops), Err(STATUS_INVALID_DEVICE_REQUEST));
        assert_eq!(ops.events, ["open", "reference", "related", "close", "dereference"]);
    }

    #[test]
    fn failed_reference_closes_handle_without_publishing_file() {
        let mut ops = Fake { reference_status: STATUS_ACCESS_DENIED, ..Fake::default() };
        assert_eq!(lookup(&mut ops), Err(STATUS_ACCESS_DENIED));
        assert_eq!(ops.events, ["open", "reference", "close"]);
    }
}
