use super::*;
use crate::device_queue::{DeviceQueueSnapshot, DEVICE_QUEUE_SIZE, DEVICE_QUEUE_TYPE};

const DEVICE_ADDRESS: u64 = 0x7000_1000;
const DEVICE_QUEUE_OFFSET: usize = 0xa0;
const QUEUE_LIST_OFFSET: usize = 0x50;
const DEVICE_ALLOCATION_SIZE: usize =
    WDM_X64_DEVICE_OBJECT_SIZE + WDM_X64_DEVICE_OBJECT_EXTENSION_SIZE;

fn init(address: u64, device_type: u32) -> WdmDeviceObjectInit {
    WdmDeviceObjectInit {
        device_object_address: address,
        driver_object: 0x7000_0000,
        device_type,
        stack_size: 1,
        ..Default::default()
    }
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn allocation_planner_keeps_logical_size_separate_from_aligned_kernel_storage() {
    for driver_size in [
        0,
        1,
        15,
        16,
        17,
        u16::MAX as u32 - WDM_X64_DEVICE_OBJECT_SIZE as u32,
    ] {
        let layout = WdmDeviceObjectAllocationLayout::plan(driver_size).unwrap();
        let logical = WDM_X64_DEVICE_OBJECT_SIZE + driver_size as usize;
        let kernel = (logical + 15) & !15;
        assert_eq!(layout.size_field() as usize, logical);
        assert_eq!(layout.kernel_extension_offset(), kernel);
        assert_eq!(
            layout.allocation_size(),
            kernel + WDM_X64_DEVICE_OBJECT_EXTENSION_SIZE
        );
        assert_eq!(
            layout.driver_extension_offset(),
            (driver_size != 0).then_some(WDM_X64_DEVICE_OBJECT_SIZE)
        );
        assert_eq!(kernel % 16, 0);
        let mut bytes = alloc::vec![0xcc; layout.allocation_size()];
        let mut initialization = init(DEVICE_ADDRESS, 0x0b);
        initialization.driver_extension_size = driver_size;
        write_wdm_device_object(&mut bytes, initialization).unwrap();
        assert_eq!(u64_at(&bytes, 0x138), DEVICE_ADDRESS + kernel as u64);
        assert_eq!(u64_at(&bytes, kernel + 8), DEVICE_ADDRESS);
        assert!(bytes[WDM_X64_DEVICE_OBJECT_SIZE..kernel]
            .iter()
            .all(|byte| *byte == 0));
        assert_eq!(
            u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            layout.size_field()
        );
    }
}

#[test]
fn unrepresentable_logical_size_is_rejected_without_mutating_storage() {
    let maximum = u16::MAX as u32 - WDM_X64_DEVICE_OBJECT_SIZE as u32;
    for driver_size in [maximum + 1, u32::MAX] {
        assert_eq!(
            WdmDeviceObjectAllocationLayout::plan(driver_size),
            Err(WdmLayoutError::InvalidField)
        );
        let mut bytes = alloc::vec![0xcc; 0x10100];
        let original = bytes.clone();
        let mut initialization = init(DEVICE_ADDRESS, 0x0b);
        initialization.driver_extension_size = driver_size;
        assert_eq!(
            write_wdm_device_object(&mut bytes, initialization),
            Err(WdmLayoutError::InvalidField)
        );
        assert_eq!(bytes, original);
    }
}

#[test]
fn every_truncated_planned_allocation_is_rejected_before_any_write() {
    for driver_size in [0, 1, 17] {
        let layout = WdmDeviceObjectAllocationLayout::plan(driver_size).unwrap();
        for length in [
            0,
            WDM_X64_DEVICE_OBJECT_SIZE,
            layout.kernel_extension_offset(),
            layout.allocation_size() - 1,
        ] {
            let mut bytes = alloc::vec![0xcc; length];
            let original = bytes.clone();
            let mut initialization = init(DEVICE_ADDRESS, 0x0b);
            initialization.driver_extension_size = driver_size;
            assert_eq!(
                write_wdm_device_object(&mut bytes, initialization),
                Err(WdmLayoutError::BufferTooSmall)
            );
            assert_eq!(bytes, original);
        }
    }
}

#[test]
fn missing_kernel_extension_tail_leaves_entire_open_projection_unchanged() {
    let mut driver = [0xa5; WDM_X64_DRIVER_OBJECT_SIZE];
    let mut device = [0xb6; DEVICE_ALLOCATION_SIZE - 1];
    let mut file = [0xc7; WDM_X64_FILE_OBJECT_SIZE];
    assert_eq!(
        write_wdm_open_device_projection(
            &mut driver,
            &mut device,
            &mut file,
            WdmOpenDeviceProjectionInit {
                file_object_address: 0x7000_3000,
                driver_object: 0x7000_0000,
                device_object: DEVICE_ADDRESS,
                device_stack_size: 1,
                ..Default::default()
            },
        ),
        Err(WdmLayoutError::BufferTooSmall),
    );
    assert_eq!(driver, [0xa5; WDM_X64_DRIVER_OBJECT_SIZE]);
    assert_eq!(device, [0xb6; DEVICE_ALLOCATION_SIZE - 1]);
    assert_eq!(file, [0xc7; WDM_X64_FILE_OBJECT_SIZE]);
}

#[test]
fn mandatory_device_object_extension_is_owned_with_the_device_allocation() {
    // NT5 iosubs.c:4495-4517; io.h DEVOBJ_EXTENSION is 0x50 bytes on x64.
    const KERNEL_EXTENSION_SIZE: usize = 0x50;
    let mut bytes = [0xcc; WDM_X64_DEVICE_OBJECT_SIZE + KERNEL_EXTENSION_SIZE];
    write_wdm_device_object(&mut bytes, init(DEVICE_ADDRESS, 0x0b)).unwrap();
    let extension = u64_at(&bytes, 0x138);
    assert_ne!(extension, 0, "every device owns a kernel extension");
    assert_eq!(extension & 7, 0, "kernel extension must be pointer-aligned");
    let offset = usize::try_from(extension.checked_sub(DEVICE_ADDRESS).unwrap()).unwrap();
    assert!(offset >= WDM_X64_DEVICE_OBJECT_SIZE);
    assert!(offset.checked_add(KERNEL_EXTENSION_SIZE).unwrap() <= bytes.len());
    assert_eq!(
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()),
        0x0d
    );
    assert_eq!(
        u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()),
        0
    );
    assert_eq!(u64_at(&bytes, offset + 8), DEVICE_ADDRESS);
    assert_eq!(
        u64_at(&bytes, 0x40),
        0,
        "no driver-private extension requested"
    );
    assert_eq!(
        u64_at(&bytes, offset + 0x38),
        0,
        "StartIoCount and Key start empty"
    );
    assert_eq!(
        u32::from_le_bytes(bytes[offset + 0x40..offset + 0x44].try_into().unwrap()),
        0
    );
}

#[test]
fn mandatory_device_object_extension_is_separate_from_driver_bytes_and_size() {
    const DRIVER_BYTES: usize = 17;
    const KERNEL_EXTENSION_SIZE: usize = 0x50;
    // Enough for either NT5's 8-byte padding or ROS's x64 allocation alignment.
    let mut bytes = [0xcc; WDM_X64_DEVICE_OBJECT_SIZE + 32 + KERNEL_EXTENSION_SIZE];
    let mut initialization = init(DEVICE_ADDRESS, 0x0b);
    initialization.driver_extension_size = DRIVER_BYTES as u32;
    let driver_extension = DEVICE_ADDRESS + WDM_X64_DEVICE_OBJECT_SIZE as u64;
    write_wdm_device_object(&mut bytes, initialization).unwrap();
    let extension = u64_at(&bytes, 0x138);
    assert_ne!(
        extension, 0,
        "driver-private bytes do not replace the kernel extension"
    );
    assert_eq!(extension & 7, 0);
    let offset = usize::try_from(extension.checked_sub(DEVICE_ADDRESS).unwrap()).unwrap();
    assert!(offset >= WDM_X64_DEVICE_OBJECT_SIZE + DRIVER_BYTES);
    assert!(offset.checked_add(KERNEL_EXTENSION_SIZE).unwrap() <= bytes.len());
    assert_ne!(extension, driver_extension);
    assert_eq!(u64_at(&bytes, 0x40), driver_extension);
    assert_eq!(u64_at(&bytes, offset + 8), DEVICE_ADDRESS);
    assert_eq!(
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()),
        0x0d
    );
    assert_eq!(
        u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()),
        0
    );
    assert_eq!(
        u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        (WDM_X64_DEVICE_OBJECT_SIZE + DRIVER_BYTES) as u16
    );
}

#[test]
fn mandatory_device_object_extension_missing_storage_is_rejected_atomically() {
    let mut bytes = [0xcc; WDM_X64_DEVICE_OBJECT_SIZE];
    let original = bytes;
    assert_eq!(
        write_wdm_device_object(&mut bytes, init(DEVICE_ADDRESS, 0x0b)),
        Err(WdmLayoutError::BufferTooSmall),
        "a bare DEVICE_OBJECT allocation cannot own its mandatory extension"
    );
    assert_eq!(bytes, original);
}

#[test]
fn ordinary_device_queue_uses_final_device_address_not_output_alias() {
    // NT5 io.h DEVICE_OBJECT and iosubs.c IoCreateDevice; ROS device.c uses the same split.
    for device_type in [0x07, 0x0b, 0x0f, 0x22, 0x23] {
        let mut bytes = [0xcc; DEVICE_ALLOCATION_SIZE];
        assert_ne!(bytes.as_ptr() as u64, DEVICE_ADDRESS);
        write_wdm_device_object(&mut bytes, init(DEVICE_ADDRESS, device_type)).unwrap();
        let queue = DeviceQueueSnapshot::read(
            &bytes[DEVICE_QUEUE_OFFSET..DEVICE_QUEUE_OFFSET + DEVICE_QUEUE_SIZE],
        )
        .unwrap();
        let head = DEVICE_ADDRESS + DEVICE_QUEUE_OFFSET as u64 + 8;
        assert_eq!(queue.type_, DEVICE_QUEUE_TYPE);
        assert_eq!(queue.size, DEVICE_QUEUE_SIZE as u16);
        assert_eq!((queue.flink, queue.blink), (head, head));
        assert!(!queue.busy);
        assert_eq!(u64_at(&bytes, DEVICE_QUEUE_OFFSET + 24), 0);
        assert_eq!(u64_at(&bytes, 0x20), 0, "CurrentIrp starts empty");
        assert!(bytes[QUEUE_LIST_OFFSET..QUEUE_LIST_OFFSET + 16]
            .iter()
            .all(|byte| *byte == 0));
    }
}

#[test]
fn filesystem_device_initializes_queue_list_instead_of_device_queue() {
    // NT5 iosubs.c:4580-4602 explicitly selects these five filesystem device types.
    for device_type in [0x03, 0x08, 0x09, 0x14, 0x20] {
        let mut bytes = [0xcc; DEVICE_ALLOCATION_SIZE];
        write_wdm_device_object(&mut bytes, init(DEVICE_ADDRESS, device_type)).unwrap();
        let head = DEVICE_ADDRESS + QUEUE_LIST_OFFSET as u64;
        assert_eq!(u64_at(&bytes, QUEUE_LIST_OFFSET), head);
        assert_eq!(u64_at(&bytes, QUEUE_LIST_OFFSET + 8), head);
        assert!(
            bytes[DEVICE_QUEUE_OFFSET..DEVICE_QUEUE_OFFSET + DEVICE_QUEUE_SIZE]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(u64_at(&bytes, 0x20), 0);
    }
}

#[test]
fn invalid_device_addresses_are_rejected_before_mutation() {
    // DEVICE_OBJECT is DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT), 16 on x64.
    for address in [0, DEVICE_ADDRESS + 1, DEVICE_ADDRESS + 8, u64::MAX & !15] {
        let mut bytes = [0xcc; DEVICE_ALLOCATION_SIZE];
        let original = bytes;
        assert_eq!(
            write_wdm_device_object(&mut bytes, init(address, 0x0b)),
            Err(WdmLayoutError::InvalidField),
            "address={address:#x}"
        );
        assert_eq!(bytes, original);
    }
}

#[test]
fn open_device_projection_rejects_device_address_before_any_output_mutation() {
    for address in [0, DEVICE_ADDRESS + 8, u64::MAX & !15] {
        let mut driver = [0xa5; WDM_X64_DRIVER_OBJECT_SIZE];
        let mut device = [0xb6; DEVICE_ALLOCATION_SIZE];
        let mut file = [0xc7; WDM_X64_FILE_OBJECT_SIZE];
        let initialization = WdmOpenDeviceProjectionInit {
            file_object_address: 0x7000_3000,
            driver_object: 0x7000_0000,
            driver_extension: 0x7000_2000,
            device_object: address,
            device_type: 0x0b,
            device_stack_size: 1,
            ..Default::default()
        };
        assert_eq!(
            write_wdm_open_device_projection(&mut driver, &mut device, &mut file, initialization),
            Err(WdmLayoutError::InvalidField),
            "device_address={address:#x}"
        );
        assert_eq!(driver, [0xa5; WDM_X64_DRIVER_OBJECT_SIZE]);
        assert_eq!(device, [0xb6; DEVICE_ALLOCATION_SIZE]);
        assert_eq!(file, [0xc7; WDM_X64_FILE_OBJECT_SIZE]);
    }
}

#[test]
fn truncated_device_storage_leaves_all_outputs_untouched() {
    let mut device = [0xb6; WDM_X64_DEVICE_OBJECT_SIZE - 1];
    assert_eq!(
        write_wdm_device_object(&mut device, init(DEVICE_ADDRESS, 0x0b)),
        Err(WdmLayoutError::BufferTooSmall)
    );
    assert_eq!(device, [0xb6; WDM_X64_DEVICE_OBJECT_SIZE - 1]);
    let mut driver = [0xa5; WDM_X64_DRIVER_OBJECT_SIZE];
    let mut file = [0xc7; WDM_X64_FILE_OBJECT_SIZE];
    assert_eq!(
        write_wdm_open_device_projection(
            &mut driver,
            &mut device,
            &mut file,
            WdmOpenDeviceProjectionInit {
                file_object_address: 0x7000_3000,
                device_object: DEVICE_ADDRESS,
                device_stack_size: 1,
                ..Default::default()
            },
        ),
        Err(WdmLayoutError::BufferTooSmall)
    );
    assert_eq!(driver, [0xa5; WDM_X64_DRIVER_OBJECT_SIZE]);
    assert_eq!(device, [0xb6; WDM_X64_DEVICE_OBJECT_SIZE - 1]);
    assert_eq!(file, [0xc7; WDM_X64_FILE_OBJECT_SIZE]);
}

#[test]
fn device_extent_validation_includes_entire_zeroed_output_slice() {
    let address = u64::MAX - (DEVICE_ALLOCATION_SIZE as u64 + 15);
    assert!(address.checked_add(DEVICE_ALLOCATION_SIZE as u64).is_some());
    let mut device = [0xb6; DEVICE_ALLOCATION_SIZE + 0x20];
    assert!(address.checked_add(device.len() as u64).is_none());
    let original = device;
    assert_eq!(
        write_wdm_device_object(&mut device, init(address, 0x0b)),
        Err(WdmLayoutError::InvalidField)
    );
    assert_eq!(device, original);
    let mut driver = [0xa5; WDM_X64_DRIVER_OBJECT_SIZE];
    let mut file = [0xc7; WDM_X64_FILE_OBJECT_SIZE];
    assert_eq!(
        write_wdm_open_device_projection(
            &mut driver,
            &mut device,
            &mut file,
            WdmOpenDeviceProjectionInit {
                file_object_address: 0x7000_3000,
                device_object: address,
                device_stack_size: 1,
                ..Default::default()
            },
        ),
        Err(WdmLayoutError::InvalidField)
    );
    assert_eq!(driver, [0xa5; WDM_X64_DRIVER_OBJECT_SIZE]);
    assert_eq!(device, original);
    assert_eq!(file, [0xc7; WDM_X64_FILE_OBJECT_SIZE]);
}
