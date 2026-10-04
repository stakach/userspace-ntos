use super::*;
use crate::device_queue::{DeviceQueueSnapshot, DEVICE_QUEUE_SIZE, DEVICE_QUEUE_TYPE};

const DEVICE_ADDRESS: u64 = 0x7000_1000;
const DEVICE_QUEUE_OFFSET: usize = 0xa0;
const QUEUE_LIST_OFFSET: usize = 0x50;

fn init(address: u64, device_type: u32) -> WdmDeviceObjectInit {
    WdmDeviceObjectInit {
        device_object_address: address,
        size_field: WDM_X64_DEVICE_OBJECT_SIZE as u16,
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
fn ordinary_device_queue_uses_final_device_address_not_output_alias() {
    // NT5 io.h DEVICE_OBJECT and iosubs.c IoCreateDevice; ROS device.c uses the same split.
    for device_type in [0x07, 0x0b, 0x0f, 0x22, 0x23] {
        let mut bytes = [0xcc; WDM_X64_DEVICE_OBJECT_SIZE];
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
        let mut bytes = [0xcc; WDM_X64_DEVICE_OBJECT_SIZE];
        write_wdm_device_object(&mut bytes, init(DEVICE_ADDRESS, device_type)).unwrap();
        let head = DEVICE_ADDRESS + QUEUE_LIST_OFFSET as u64;
        assert_eq!(u64_at(&bytes, QUEUE_LIST_OFFSET), head);
        assert_eq!(u64_at(&bytes, QUEUE_LIST_OFFSET + 8), head);
        assert!(bytes[DEVICE_QUEUE_OFFSET..DEVICE_QUEUE_OFFSET + DEVICE_QUEUE_SIZE]
            .iter()
            .all(|byte| *byte == 0));
        assert_eq!(u64_at(&bytes, 0x20), 0);
    }
}

#[test]
fn invalid_device_addresses_are_rejected_before_mutation() {
    // DEVICE_OBJECT is DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT), 16 on x64.
    for address in [0, DEVICE_ADDRESS + 1, DEVICE_ADDRESS + 8, u64::MAX & !15] {
        let mut bytes = [0xcc; WDM_X64_DEVICE_OBJECT_SIZE];
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
        let mut device = [0xb6; WDM_X64_DEVICE_OBJECT_SIZE];
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
        assert_eq!(device, [0xb6; WDM_X64_DEVICE_OBJECT_SIZE]);
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
    let address = u64::MAX - 0x15f;
    assert!(address
        .checked_add(WDM_X64_DEVICE_OBJECT_SIZE as u64)
        .is_some());
    let mut device = [0xb6; WDM_X64_DEVICE_OBJECT_SIZE + 0x20];
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
