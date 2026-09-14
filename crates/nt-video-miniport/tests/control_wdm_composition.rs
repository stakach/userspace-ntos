//! Host byte-layout composition, not execution of native video-port globals or callbacks.

use nt_io_manager::{
    write_wdm_device_object, write_wdm_io_stack_location, write_wdm_irp, WdmDeviceObjectInit,
    WdmIoStackLocationInit, WdmIoStackParameters, WdmIrpInit, WDM_X64_DEVICE_OBJECT_SIZE,
    WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE,
};
use nt_video_miniport::{
    classify_start_io_status, VideoAdapterDiscoveryState, VideoHardwareInitializationState,
    VideoOpenAction, VideoPortDeviceState, VideoRequestPacketX64, VideoStatusBlockX64,
    FILE_DEVICE_VIDEO, IOCTL_VIDEO_QUERY_CURRENT_MODE, VIDEO_MODE_INFORMATION_SIZE,
    VIDEO_PORT_DEVICE_STATE_SIZE, VIDEO_REQUEST_PACKET_X64_SIZE,
};

const IO_STATUS_OFFSET: usize = 0x30;
const IO_STATUS_END: usize = 0x40;

struct ProjectedRequest {
    device: Box<[u8; WDM_X64_DEVICE_OBJECT_SIZE]>,
    extension: Box<[u8; 32]>,
    irp: Box<[u8]>,
    system: Box<[u8; VIDEO_MODE_INFORMATION_SIZE]>,
}

impl ProjectedRequest {
    fn new() -> Self {
        let mut device = Box::new([0xa5; WDM_X64_DEVICE_OBJECT_SIZE]);
        let extension = Box::new([0; 32]);
        write_wdm_device_object(
            device.as_mut_slice(),
            WdmDeviceObjectInit {
                size_field: WDM_X64_DEVICE_OBJECT_SIZE as u16,
                device_extension: extension.as_ptr() as u64,
                device_type: FILE_DEVICE_VIDEO,
                stack_size: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let mut system = Box::new([0; VIDEO_MODE_INFORMATION_SIZE]);
        system[..4].copy_from_slice(&0x1234u32.to_le_bytes());
        let mut irp =
            vec![0xa5; WDM_X64_IRP_SIZE + WDM_X64_IO_STACK_LOCATION_SIZE].into_boxed_slice();
        let stack_address = irp.as_ptr() as u64 + WDM_X64_IRP_SIZE as u64;
        let packet_size = irp.len() as u16;
        write_wdm_irp(
            &mut irp[..WDM_X64_IRP_SIZE],
            WdmIrpInit {
                packet_size,
                system_buffer: system.as_ptr() as u64,
                flags: 0x10,
                stack_count: 1,
                current_location: 1,
                current_stack_location: stack_address,
                ..Default::default()
            },
        )
        .unwrap();
        write_wdm_io_stack_location(
            &mut irp[WDM_X64_IRP_SIZE..],
            WdmIoStackLocationInit {
                major: 0x0e,
                minor: 0,
                flags: 0,
                control: 0,
                device_object: device.as_ptr() as u64,
                file_object: 0,
                parameters: WdmIoStackParameters::DeviceControl {
                    input_buffer_length: 4,
                    output_buffer_length: VIDEO_MODE_INFORMATION_SIZE as u32,
                    io_control_code: IOCTL_VIDEO_QUERY_CURRENT_MODE,
                    type3_input_buffer: 0,
                },
            },
        )
        .unwrap();
        Self {
            device,
            extension,
            irp,
            system,
        }
    }

    fn packet(&self) -> VideoRequestPacketX64 {
        VideoRequestPacketX64::buffered(
            IOCTL_VIDEO_QUERY_CURRENT_MODE,
            self.irp.as_ptr() as u64 + IO_STATUS_OFFSET as u64,
            self.system.as_ptr() as u64,
            4,
            VIDEO_MODE_INFORMATION_SIZE as u32,
        )
    }
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn transient_request_packet_points_to_persistent_irp_status_and_buffered_storage() {
    let mut request = ProjectedRequest::new();
    let original_irp = request.irp.to_vec();
    {
        let mut transient = [0xa5; VIDEO_REQUEST_PACKET_X64_SIZE];
        request.packet().write(&mut transient).unwrap();
        let packet = VideoRequestPacketX64::parse(&transient).unwrap();
        assert_eq!(
            packet.status_block,
            request.irp.as_ptr() as u64 + IO_STATUS_OFFSET as u64
        );
        assert_eq!(packet.input_buffer, packet.output_buffer);
        assert_eq!(packet.input_buffer, request.system.as_ptr() as u64);
        assert_eq!(packet.input_buffer, u64_at(&request.irp, 0x18));
        assert_eq!(packet.input_buffer_length, 4);
        assert_eq!(
            packet.output_buffer_length as usize,
            VIDEO_MODE_INFORMATION_SIZE
        );
        assert_eq!(
            u64_at(&request.irp[WDM_X64_IRP_SIZE..], 0x28),
            request.device.as_ptr() as u64
        );
        assert_eq!(
            u64_at(request.device.as_slice(), 0x40),
            request.extension.as_ptr() as u64
        );
        let offset = (packet.status_block - request.irp.as_ptr() as u64) as usize;
        VideoStatusBlockX64 {
            status: 234,
            information: 0x1_0000_0004,
        }
        .write(&mut request.irp[offset..offset + 16])
        .unwrap();
    }
    // The descriptor has expired; the driver's result remains in the original IRP allocation.
    assert_eq!(
        VideoStatusBlockX64::parse(&request.irp[IO_STATUS_OFFSET..IO_STATUS_END]).unwrap(),
        VideoStatusBlockX64 {
            status: 234,
            information: 0x1_0000_0004
        }
    );
    assert_eq!(
        &request.irp[..IO_STATUS_OFFSET],
        &original_irp[..IO_STATUS_OFFSET]
    );
    assert_eq!(
        &request.irp[IO_STATUS_END..],
        &original_irp[IO_STATUS_END..]
    );
}

#[test]
fn vp_completion_mapping_updates_only_original_irp_io_status_with_full_width_information() {
    for (vp_status, nt_status, preserves_information) in [
        (0, 0, true),
        (234, 0x8000_0005, true),
        (8, 0xc000_009a, false),
        (1, 0xc000_0002, false),
        (87, 0xc000_000d, false),
        (122, 0xc000_0023, false),
        (55, 0xc000_00c0, false),
    ] {
        for information in [0, 0x1_0000_0004, u64::MAX] {
            let mut request = ProjectedRequest::new();
            let original_irp = request.irp.to_vec();
            let original_device = *request.device;
            VideoStatusBlockX64 {
                status: vp_status as i32,
                information,
            }
            .write(&mut request.irp[IO_STATUS_OFFSET..IO_STATUS_END])
            .unwrap();
            let driver_status =
                VideoStatusBlockX64::parse(&request.irp[IO_STATUS_OFFSET..IO_STATUS_END]).unwrap();
            let completion =
                classify_start_io_status(driver_status.status as u32, driver_status.information)
                    .unwrap();
            VideoStatusBlockX64 {
                status: completion.nt_status as i32,
                information: completion.information,
            }
            .write(&mut request.irp[IO_STATUS_OFFSET..IO_STATUS_END])
            .unwrap();
            let mapped =
                VideoStatusBlockX64::parse(&request.irp[IO_STATUS_OFFSET..IO_STATUS_END]).unwrap();
            assert_eq!(mapped.status as u32, nt_status);
            assert_eq!(
                mapped.information,
                if preserves_information {
                    information
                } else {
                    0
                }
            );
            assert_eq!(u64_at(&request.irp, 0x38), mapped.information);
            assert_eq!(
                &request.irp[..IO_STATUS_OFFSET],
                &original_irp[..IO_STATUS_OFFSET]
            );
            assert_eq!(
                &request.irp[IO_STATUS_END..],
                &original_irp[IO_STATUS_END..]
            );
            assert_eq!(*request.device, original_device);
        }
    }
}

const HARDWARE_EXTENSION_SIZE: usize = 32;
const HARDWARE_EXTENSION_OFFSET: usize = WDM_X64_DEVICE_OBJECT_SIZE + VIDEO_PORT_DEVICE_STATE_SIZE;
const COMBINED_DEVICE_SIZE: usize = HARDWARE_EXTENSION_OFFSET + HARDWARE_EXTENSION_SIZE;

#[repr(align(16))]
struct CombinedDevice([u8; COMBINED_DEVICE_SIZE]);

impl CombinedDevice {
    fn new() -> Box<Self> {
        let mut device = Box::new(Self([0; COMBINED_DEVICE_SIZE]));
        let prefix_address = device.0.as_ptr() as u64 + WDM_X64_DEVICE_OBJECT_SIZE as u64;
        write_wdm_device_object(
            &mut device.0[..WDM_X64_DEVICE_OBJECT_SIZE],
            WdmDeviceObjectInit {
                size_field: COMBINED_DEVICE_SIZE as u16,
                device_extension: prefix_address,
                device_type: FILE_DEVICE_VIDEO,
                stack_size: 1,
                ..Default::default()
            },
        )
        .unwrap();
        device.store(VideoPortDeviceState::new());
        device
    }

    fn state(&self) -> VideoPortDeviceState {
        VideoPortDeviceState::parse(&self.0[WDM_X64_DEVICE_OBJECT_SIZE..HARDWARE_EXTENSION_OFFSET])
            .unwrap()
    }

    fn store(&mut self, state: VideoPortDeviceState) {
        assert_eq!(
            state.write(&mut self.0[WDM_X64_DEVICE_OBJECT_SIZE..HARDWARE_EXTENSION_OFFSET]),
            Ok(VIDEO_PORT_DEVICE_STATE_SIZE)
        );
    }

    fn assert_layout(&self) {
        assert_eq!(self.0.as_ptr() as usize % 16, 0);
        assert_eq!(
            (self.0.as_ptr() as usize + HARDWARE_EXTENSION_OFFSET) % 16,
            0
        );
        assert_eq!(
            u64_at(&self.0, 0x40),
            self.0.as_ptr() as u64 + WDM_X64_DEVICE_OBJECT_SIZE as u64
        );
        assert_eq!(
            u16::from_le_bytes(self.0[2..4].try_into().unwrap()) as usize,
            COMBINED_DEVICE_SIZE
        );
    }
}

#[test]
fn combined_devices_keep_discovery_and_initialization_state_independent_of_each_other_and_hw_bytes()
{
    let mut first = CombinedDevice::new();
    let mut second = CombinedDevice::new();
    first.assert_layout();
    second.assert_layout();
    assert_ne!(first.0.as_ptr(), second.0.as_ptr());
    assert_eq!(
        &first.0[HARDWARE_EXTENSION_OFFSET..],
        &[0; HARDWARE_EXTENSION_SIZE]
    );
    assert_eq!(
        &second.0[HARDWARE_EXTENSION_OFFSET..],
        &[0; HARDWARE_EXTENSION_SIZE]
    );
    let first_header = first.0[..WDM_X64_DEVICE_OBJECT_SIZE].to_vec();
    let second_header = second.0[..WDM_X64_DEVICE_OBJECT_SIZE].to_vec();
    // Miniport-owned contents must survive every subsequent port-state publication.
    first.0[HARDWARE_EXTENSION_OFFSET..].fill(0x31);
    second.0[HARDWARE_EXTENSION_OFFSET..].fill(0x72);
    let mut first_state = first.state();
    first_state.begin_find_adapter().unwrap();
    first.store(first_state);
    assert_eq!(
        second.state().discovery_state(),
        VideoAdapterDiscoveryState::NotCalled
    );
    let mut second_state = second.state();
    second_state.begin_find_adapter().unwrap();
    second.store(second_state);
    first_state.record_find_adapter(true).unwrap();
    first.store(first_state);
    second_state.record_find_adapter(true).unwrap();
    second.store(second_state);
    assert_eq!(
        first_state.begin_open(0, 0x8000_0000).unwrap(),
        VideoOpenAction::Initialize
    );
    first.store(first_state);
    assert_eq!(
        first.state().begin_open(0, 0x8000_0000).unwrap(),
        VideoOpenAction::Busy
    );
    assert_eq!(
        second_state.begin_open(0, 0x8000_0000).unwrap(),
        VideoOpenAction::Initialize
    );
    second.store(second_state);
    assert_eq!(first_state.finish_initialize(true).unwrap().status, 0);
    first.store(first_state);
    assert_eq!(
        second_state.finish_initialize(false).unwrap().status,
        0xc000_0182
    );
    second.store(second_state);
    assert_eq!(
        first.state().initialization_state(),
        VideoHardwareInitializationState::Succeeded
    );
    assert_eq!(
        second.state().initialization_state(),
        VideoHardwareInitializationState::Failed
    );
    assert_eq!(&first.0[..WDM_X64_DEVICE_OBJECT_SIZE], &first_header);
    assert_eq!(&second.0[..WDM_X64_DEVICE_OBJECT_SIZE], &second_header);
    assert_eq!(
        &first.0[HARDWARE_EXTENSION_OFFSET..],
        &[0x31; HARDWARE_EXTENSION_SIZE]
    );
    assert_eq!(
        &second.0[HARDWARE_EXTENSION_OFFSET..],
        &[0x72; HARDWARE_EXTENSION_SIZE]
    );
}

#[test]
fn repeated_opens_preserve_initialized_prefix_and_hardware_extension_contents() {
    let mut device = CombinedDevice::new();
    let mut state = device.state();
    state.begin_find_adapter().unwrap();
    device.store(state);
    state.record_find_adapter(true).unwrap();
    device.store(state);
    assert_eq!(
        state.begin_open(0, 0x8000_0000).unwrap(),
        VideoOpenAction::Initialize
    );
    device.store(state);
    // Model the initialized hardware context, without asserting a native allocator/cache policy.
    device.0[HARDWARE_EXTENSION_OFFSET..].fill(0x5c);
    state.finish_initialize(true).unwrap();
    device.store(state);
    let initialized = device.0;
    for (requestor_mode, desired_access, information) in
        [(0, 0x8000_0000, 1), (0, 0x80, 1), (1, 0x8000_0000, 0)]
    {
        let mut state = device.state();
        assert_eq!(
            state.begin_open(requestor_mode, desired_access).unwrap(),
            VideoOpenAction::Complete {
                status: 0,
                information
            }
        );
        device.store(state);
        assert_eq!(device.0, initialized);
        device.assert_layout();
    }
}
