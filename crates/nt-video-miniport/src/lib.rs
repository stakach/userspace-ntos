//! Minimal NT video-port/miniport contract for display adapters.
//!
//! The real ReactOS path is `videoprt.sys` handling port-owned IOCTLs and forwarding ordinary video
//! requests to a display miniport's `HwStartIO` callback. This crate keeps that split host-tested:
//! `VideoPort` owns the port controls consumed by win32k, while adapters implement
//! `VideoMiniportAdapter` for the mode/memory controls consumed by the display DLL.

#![no_std]

pub const FILE_DEVICE_VIDEO: u32 = 0x23;

pub const VIDEO_DRIVER_OBJECT_PATH_PREFIX: &str = "\\Driver\\";
pub const VIDEO_DEVICE_PATH_PREFIX: &str = "\\Device\\Video";
pub const VIDEO_DEVICE_MAP_KEY: &str = "\\Registry\\Machine\\Hardware\\DeviceMap\\Video";
pub const VIDEO_DEVICE_MAP_MAX_OBJECT_VALUE: &str = "MaxObjectNumber";

pub const IOCTL_VIDEO_QUERY_AVAIL_MODES: u32 = 0x0023_0400;
pub const IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES: u32 = 0x0023_0404;
pub const IOCTL_VIDEO_QUERY_CURRENT_MODE: u32 = 0x0023_0408;
pub const IOCTL_VIDEO_SET_CURRENT_MODE: u32 = 0x0023_040C;
pub const IOCTL_VIDEO_MAP_VIDEO_MEMORY: u32 = 0x0023_0458;
pub const IOCTL_VIDEO_INIT_WIN32K_CALLBACKS: u32 = 0x0023_001C;
pub const IOCTL_VIDEO_UNMAP_VIDEO_MEMORY: u32 = 0x0023_045C;

pub const VIDEO_NUM_MODES_SIZE: usize = 8;
pub const VIDEO_MODE_INFORMATION_SIZE: usize = 80;
pub const VIDEO_MEMORY_SIZE_X64: usize = 8;
pub const VIDEO_MEMORY_INFORMATION_SIZE_X64: usize = 32;
pub const VIDEO_WIN32K_CALLBACKS_SIZE_X64: usize = 40;
pub const VIDEO_HW_INITIALIZATION_DATA_NT4_X64_SIZE: usize = 64;
pub const VIDEO_HW_INITIALIZATION_DATA_W2K_X64_SIZE: usize = 140;
pub const VIDEO_HW_INITIALIZATION_DATA_X64_SIZE: usize = 144;
pub const VIDEO_ACCESS_RANGE_X64_SIZE: usize = 16;
pub const VIDEO_REQUEST_PACKET_X64_SIZE: usize = 48;
pub const VIDEO_STATUS_BLOCK_X64_SIZE: usize = 16;

pub const VIDEO_MODE_COLOR: u32 = 0x0001;
pub const VIDEO_MODE_GRAPHICS: u32 = 0x0002;
pub const VIDEO_MODE_LINEAR: u32 = 0x0100;
pub const VIDEO_MODE_MAP_MEM_LINEAR: u32 = 0x4000_0000;
pub const VIDEO_MODE_NO_ZERO_MEMORY: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoDeviceIdentityError {
    InvalidDriverName,
    InvalidServiceRegistryPath,
    BufferTooSmall { needed: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoHwInitializationDataError {
    BufferTooSmall { needed: usize },
    RevisionMismatch { declared: usize },
    UnsupportedSize { declared: usize },
    MissingRequiredCallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoHwInitializationDataVersion {
    Nt4,
    Windows2000,
    WindowsXpOrLater,
}

/// x64 `VIDEO_HW_INITIALIZATION_DATA` as supplied by a real video miniport to
/// `VideoPortInitialize`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoHwInitializationDataX64 {
    pub hw_init_data_size: u32,
    pub adapter_interface_type: u32,
    pub hw_find_adapter: u64,
    pub hw_initialize: u64,
    pub hw_interrupt: u64,
    pub hw_start_io: u64,
    pub hw_device_extension_size: u32,
    pub starting_device_number: u32,
    pub hw_reset_hw: u64,
    pub hw_timer: u64,
    pub hw_start_dma: u64,
    pub hw_set_power_state: u64,
    pub hw_get_power_state: u64,
    pub hw_get_video_child_descriptor: u64,
    pub hw_query_interface: u64,
    pub hw_child_device_extension_size: u32,
    pub hw_legacy_resource_list: u64,
    pub hw_legacy_resource_count: u32,
    pub hw_get_legacy_resources: u64,
    pub allow_early_enumeration: bool,
    pub reserved: u32,
}

impl VideoHwInitializationDataX64 {
    pub fn parse(input: &[u8]) -> Result<Self, VideoHwInitializationDataError> {
        require_video_hw_init_input(input, 4)?;
        let declared = read_u32_raw(input, 0) as usize;
        match declared {
            VIDEO_HW_INITIALIZATION_DATA_NT4_X64_SIZE
            | VIDEO_HW_INITIALIZATION_DATA_W2K_X64_SIZE
            | VIDEO_HW_INITIALIZATION_DATA_X64_SIZE => {}
            _ if declared > VIDEO_HW_INITIALIZATION_DATA_X64_SIZE => {
                return Err(VideoHwInitializationDataError::RevisionMismatch { declared });
            }
            _ => return Err(VideoHwInitializationDataError::UnsupportedSize { declared }),
        }
        require_video_hw_init_input(input, declared)?;

        let data = Self {
            hw_init_data_size: declared as u32,
            adapter_interface_type: read_u32_present(input, declared, 4),
            hw_find_adapter: read_u64_present(input, declared, 8),
            hw_initialize: read_u64_present(input, declared, 16),
            hw_interrupt: read_u64_present(input, declared, 24),
            hw_start_io: read_u64_present(input, declared, 32),
            hw_device_extension_size: read_u32_present(input, declared, 40),
            starting_device_number: read_u32_present(input, declared, 44),
            hw_reset_hw: read_u64_present(input, declared, 48),
            hw_timer: read_u64_present(input, declared, 56),
            hw_start_dma: read_u64_present(input, declared, 64),
            hw_set_power_state: read_u64_present(input, declared, 72),
            hw_get_power_state: read_u64_present(input, declared, 80),
            hw_get_video_child_descriptor: read_u64_present(input, declared, 88),
            hw_query_interface: read_u64_present(input, declared, 96),
            hw_child_device_extension_size: read_u32_present(input, declared, 104),
            hw_legacy_resource_list: read_u64_present(input, declared, 112),
            hw_legacy_resource_count: read_u32_present(input, declared, 120),
            hw_get_legacy_resources: read_u64_present(input, declared, 128),
            allow_early_enumeration: read_u8_present(input, declared, 136) != 0,
            reserved: read_u32_present(input, declared, 140),
        };
        if data.hw_find_adapter == 0 || data.hw_initialize == 0 || data.hw_start_io == 0 {
            return Err(VideoHwInitializationDataError::MissingRequiredCallback);
        }
        Ok(data)
    }

    pub fn version(&self) -> VideoHwInitializationDataVersion {
        match self.hw_init_data_size as usize {
            VIDEO_HW_INITIALIZATION_DATA_NT4_X64_SIZE => VideoHwInitializationDataVersion::Nt4,
            VIDEO_HW_INITIALIZATION_DATA_W2K_X64_SIZE => {
                VideoHwInitializationDataVersion::Windows2000
            }
            _ => VideoHwInitializationDataVersion::WindowsXpOrLater,
        }
    }

    pub fn is_pnp_miniport(&self) -> bool {
        (self.hw_init_data_size as usize) >= 96
            && self.hw_set_power_state != 0
            && self.hw_get_power_state != 0
            && self.hw_get_video_child_descriptor != 0
    }

    pub fn requires_legacy_detection(&self, hw_context: u64) -> bool {
        !self.is_pnp_miniport() || hw_context != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoRequestPacketError {
    BufferTooSmall { needed: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoAccessRangeError {
    BufferTooSmall { needed: usize },
}

/// x64 `VIDEO_ACCESS_RANGE` used by `VideoPortGetAccessRanges` and
/// `VideoPortVerifyAccessRanges`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoAccessRangeX64 {
    pub range_start: u64,
    pub range_length: u32,
    pub range_in_io_space: bool,
    pub range_visible: bool,
    pub range_shareable: bool,
    pub range_passive: u8,
}

impl VideoAccessRangeX64 {
    pub fn memory(range_start: u64, range_length: u32) -> Self {
        Self {
            range_start,
            range_length,
            range_in_io_space: false,
            range_visible: false,
            range_shareable: false,
            range_passive: 0,
        }
    }

    pub fn io(range_start: u64, range_length: u32) -> Self {
        Self {
            range_start,
            range_length,
            range_in_io_space: true,
            range_visible: false,
            range_shareable: false,
            range_passive: 0,
        }
    }

    pub fn parse(input: &[u8]) -> Result<Self, VideoAccessRangeError> {
        require_video_access_range_input(input, VIDEO_ACCESS_RANGE_X64_SIZE)?;
        Ok(Self {
            range_start: read_u64_raw(input, 0),
            range_length: read_u32_raw(input, 8),
            range_in_io_space: input[12] != 0,
            range_visible: input[13] != 0,
            range_shareable: input[14] != 0,
            range_passive: input[15],
        })
    }

    pub fn write(&self, output: &mut [u8]) -> Result<usize, VideoAccessRangeError> {
        require_video_access_range_input(output, VIDEO_ACCESS_RANGE_X64_SIZE)?;
        output[..VIDEO_ACCESS_RANGE_X64_SIZE].fill(0);
        write_u64(output, 0, self.range_start);
        write_u32(output, 8, self.range_length);
        output[12] = self.range_in_io_space as u8;
        output[13] = self.range_visible as u8;
        output[14] = self.range_shareable as u8;
        output[15] = self.range_passive;
        Ok(VIDEO_ACCESS_RANGE_X64_SIZE)
    }
}

/// x64 `VIDEO_REQUEST_PACKET` passed by videoprt to a miniport `HwStartIO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoRequestPacketX64 {
    pub io_control_code: u32,
    pub status_block: u64,
    pub input_buffer: u64,
    pub input_buffer_length: u32,
    pub output_buffer: u64,
    pub output_buffer_length: u32,
}

impl VideoRequestPacketX64 {
    pub fn buffered(
        io_control_code: u32,
        status_block: u64,
        system_buffer: u64,
        input_buffer_length: u32,
        output_buffer_length: u32,
    ) -> Self {
        Self {
            io_control_code,
            status_block,
            input_buffer: system_buffer,
            input_buffer_length,
            output_buffer: system_buffer,
            output_buffer_length,
        }
    }

    pub fn parse(input: &[u8]) -> Result<Self, VideoRequestPacketError> {
        require_video_request_input(input, VIDEO_REQUEST_PACKET_X64_SIZE)?;
        Ok(Self {
            io_control_code: read_u32_raw(input, 0),
            status_block: read_u64_raw(input, 8),
            input_buffer: read_u64_raw(input, 16),
            input_buffer_length: read_u32_raw(input, 24),
            output_buffer: read_u64_raw(input, 32),
            output_buffer_length: read_u32_raw(input, 40),
        })
    }

    pub fn write(&self, output: &mut [u8]) -> Result<usize, VideoRequestPacketError> {
        require_video_request_input(output, VIDEO_REQUEST_PACKET_X64_SIZE)?;
        output[..VIDEO_REQUEST_PACKET_X64_SIZE].fill(0);
        write_u32(output, 0, self.io_control_code);
        write_u64(output, 8, self.status_block);
        write_u64(output, 16, self.input_buffer);
        write_u32(output, 24, self.input_buffer_length);
        write_u64(output, 32, self.output_buffer);
        write_u32(output, 40, self.output_buffer_length);
        Ok(VIDEO_REQUEST_PACKET_X64_SIZE)
    }
}

pub fn write_video_status_block_x64(
    output: &mut [u8],
    status: i32,
    information: u64,
) -> Result<usize, VideoRequestPacketError> {
    require_video_request_input(output, VIDEO_STATUS_BLOCK_X64_SIZE)?;
    output[..VIDEO_STATUS_BLOCK_X64_SIZE].fill(0);
    write_u32(output, 0, status as u32);
    write_u64(output, 8, information);
    Ok(VIDEO_STATUS_BLOCK_X64_SIZE)
}

/// NT object/registry identity for a video miniport-created `\Device\Video<N>` route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoDeviceIdentity<'a> {
    object_number: u32,
    driver_name: &'a [u8],
    service_registry_path: &'a [u8],
}

impl<'a> VideoDeviceIdentity<'a> {
    pub fn new(
        object_number: u32,
        driver_name: &'a [u8],
        service_registry_path: &'a [u8],
    ) -> Result<Self, VideoDeviceIdentityError> {
        if !driver_name_component_is_safe(driver_name) {
            return Err(VideoDeviceIdentityError::InvalidDriverName);
        }
        if service_registry_path.is_empty()
            || !service_registry_path
                .iter()
                .copied()
                .all(|byte| byte.is_ascii())
        {
            return Err(VideoDeviceIdentityError::InvalidServiceRegistryPath);
        }
        Ok(Self {
            object_number,
            driver_name,
            service_registry_path,
        })
    }

    pub fn object_number(&self) -> u32 {
        self.object_number
    }

    pub fn max_object_number(&self) -> u32 {
        self.object_number
    }

    pub fn driver_name(&self) -> &'a [u8] {
        self.driver_name
    }

    pub fn service_registry_path(&self) -> &'a [u8] {
        self.service_registry_path
    }

    pub fn driver_object_path_len(&self) -> usize {
        VIDEO_DRIVER_OBJECT_PATH_PREFIX.len() + self.driver_name.len()
    }

    pub fn device_path_len(&self) -> usize {
        VIDEO_DEVICE_PATH_PREFIX.len() + decimal_u32_digits(self.object_number)
    }

    pub fn service_registry_path_utf16le_nul_len(&self) -> Option<usize> {
        self.service_registry_path
            .len()
            .checked_mul(2)?
            .checked_add(2)
    }

    pub fn write_driver_object_path_ascii(
        &self,
        out: &mut [u8],
    ) -> Result<usize, VideoDeviceIdentityError> {
        write_concat_ascii(
            out,
            VIDEO_DRIVER_OBJECT_PATH_PREFIX.as_bytes(),
            self.driver_name,
        )
    }

    pub fn write_device_path_ascii(
        &self,
        out: &mut [u8],
    ) -> Result<usize, VideoDeviceIdentityError> {
        let need = self.device_path_len();
        require_identity_output(out, need)?;
        let prefix = VIDEO_DEVICE_PATH_PREFIX.as_bytes();
        out[..prefix.len()].copy_from_slice(prefix);
        write_decimal_u32(self.object_number, &mut out[prefix.len()..need]);
        Ok(need)
    }

    pub fn write_service_registry_path_utf16le_nul(
        &self,
        out: &mut [u8],
    ) -> Result<usize, VideoDeviceIdentityError> {
        let need = self
            .service_registry_path_utf16le_nul_len()
            .ok_or(VideoDeviceIdentityError::InvalidServiceRegistryPath)?;
        require_identity_output(out, need)?;
        for (idx, &byte) in self.service_registry_path.iter().enumerate() {
            let unit = (byte as u16).to_le_bytes();
            out[idx * 2] = unit[0];
            out[idx * 2 + 1] = unit[1];
        }
        out[need - 2] = 0;
        out[need - 1] = 0;
        Ok(need)
    }

    pub fn device_path_eq_ascii_ignore_case(&self, candidate: &[u8]) -> bool {
        let need = self.device_path_len();
        if candidate.len() != need {
            return false;
        }
        let prefix = VIDEO_DEVICE_PATH_PREFIX.as_bytes();
        ascii_eq_ignore_case(&candidate[..prefix.len()], prefix)
            && decimal_u32_eq_ascii(self.object_number, &candidate[prefix.len()..need])
    }
}

const MODE_INDEX: u32 = 1;
const RGB_BITS: u32 = 8;
const RED_MASK_32BPP: u32 = 0x00FF_0000;
const GREEN_MASK_32BPP: u32 = 0x0000_FF00;
const BLUE_MASK_32BPP: u32 = 0x0000_00FF;
const DEFAULT_REFRESH_HZ: u32 = 60;
const DEFAULT_DPI: u32 = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoModeSpec {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bits_per_plane: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferMapping {
    pub virtual_address: u64,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootFramebufferMiniport {
    mapping: FramebufferMapping,
    mode: VideoModeSpec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoPort<A> {
    adapter: A,
    video_device_object: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoMiniportError {
    InvalidRegistration,
    UnsupportedMode,
    FramebufferTooLarge,
    BufferTooSmall { needed: usize },
    InvalidModeRequest,
    UnsupportedIoctl,
}

pub trait VideoMiniportAdapter {
    fn dispatch_io_control(
        &self,
        ioctl: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, VideoMiniportError>;

    fn dispatch_buffered_io_control(
        &self,
        ioctl: u32,
        system_buffer: &mut [u8],
        input_len: usize,
        output_len: usize,
    ) -> Result<usize, VideoMiniportError>;
}

impl<A> VideoPort<A> {
    pub fn new(adapter: A, video_device_object: u64) -> Self {
        Self {
            adapter,
            video_device_object,
        }
    }

    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    pub fn video_device_object(&self) -> u64 {
        self.video_device_object
    }
}

impl<A: VideoMiniportAdapter> VideoPort<A> {
    /// Dispatch a video I/O control as the video port driver would: handle port-owned controls and
    /// forward the remaining public `ntddvdeo.h` controls to the miniport adapter.
    pub fn dispatch_io_control(
        &self,
        ioctl: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, VideoMiniportError> {
        match ioctl {
            IOCTL_VIDEO_INIT_WIN32K_CALLBACKS => {
                write_win32k_callbacks(input, output, self.video_device_object)
            }
            IOCTL_VIDEO_UNMAP_VIDEO_MEMORY => Ok(0),
            _ => self.adapter.dispatch_io_control(ioctl, input, output),
        }
    }

    /// Dispatch the same port/miniport controls through a buffered I/O `SystemBuffer`.
    pub fn dispatch_buffered_io_control(
        &self,
        ioctl: u32,
        system_buffer: &mut [u8],
        input_len: usize,
        output_len: usize,
    ) -> Result<usize, VideoMiniportError> {
        if input_len > system_buffer.len() {
            return Err(VideoMiniportError::BufferTooSmall { needed: input_len });
        }
        if output_len > system_buffer.len() {
            return Err(VideoMiniportError::BufferTooSmall { needed: output_len });
        }
        match ioctl {
            IOCTL_VIDEO_INIT_WIN32K_CALLBACKS => {
                let input = &system_buffer[..input_len];
                let phys_disp = read_u64(input, 0)?;
                let callout = read_u64(input, 8)?;
                let output = &mut system_buffer[..output_len];
                write_win32k_callbacks_from_parts(
                    output,
                    phys_disp,
                    callout,
                    self.video_device_object,
                )
            }
            IOCTL_VIDEO_UNMAP_VIDEO_MEMORY => Ok(0),
            _ => self.adapter.dispatch_buffered_io_control(
                ioctl,
                system_buffer,
                input_len,
                output_len,
            ),
        }
    }
}

impl BootFramebufferMiniport {
    pub fn new(
        mapping: FramebufferMapping,
        mode: VideoModeSpec,
    ) -> Result<Self, VideoMiniportError> {
        validate_mapping(mapping, mode)?;
        Ok(Self { mapping, mode })
    }

    pub fn dispatch_io_control(
        &self,
        ioctl: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, VideoMiniportError> {
        match ioctl {
            IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES => self.query_num_available_modes(output),
            IOCTL_VIDEO_QUERY_AVAIL_MODES | IOCTL_VIDEO_QUERY_CURRENT_MODE => {
                self.query_mode(output)
            }
            IOCTL_VIDEO_SET_CURRENT_MODE => self.set_current_mode(input),
            IOCTL_VIDEO_MAP_VIDEO_MEMORY => self.map_video_memory(input, output),
            _ => Err(VideoMiniportError::UnsupportedIoctl),
        }
    }

    pub fn dispatch_buffered_io_control(
        &self,
        ioctl: u32,
        system_buffer: &mut [u8],
        input_len: usize,
        output_len: usize,
    ) -> Result<usize, VideoMiniportError> {
        if input_len > system_buffer.len() {
            return Err(VideoMiniportError::BufferTooSmall { needed: input_len });
        }
        if output_len > system_buffer.len() {
            return Err(VideoMiniportError::BufferTooSmall { needed: output_len });
        }
        match ioctl {
            IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES => {
                self.query_num_available_modes(&mut system_buffer[..output_len])
            }
            IOCTL_VIDEO_QUERY_AVAIL_MODES | IOCTL_VIDEO_QUERY_CURRENT_MODE => {
                self.query_mode(&mut system_buffer[..output_len])
            }
            IOCTL_VIDEO_SET_CURRENT_MODE => self.set_current_mode(&system_buffer[..input_len]),
            IOCTL_VIDEO_MAP_VIDEO_MEMORY => {
                require_input(&system_buffer[..input_len], VIDEO_MEMORY_SIZE_X64)?;
                self.write_video_memory_information(&mut system_buffer[..output_len])
            }
            _ => Err(VideoMiniportError::UnsupportedIoctl),
        }
    }

    pub fn mode(&self) -> VideoModeSpec {
        self.mode
    }

    pub fn mapping(&self) -> FramebufferMapping {
        self.mapping
    }

    fn query_num_available_modes(&self, output: &mut [u8]) -> Result<usize, VideoMiniportError> {
        require_output(output, VIDEO_NUM_MODES_SIZE)?;
        write_u32(output, 0, 1);
        write_u32(output, 4, VIDEO_MODE_INFORMATION_SIZE as u32);
        Ok(VIDEO_NUM_MODES_SIZE)
    }

    fn query_mode(&self, output: &mut [u8]) -> Result<usize, VideoMiniportError> {
        require_output(output, VIDEO_MODE_INFORMATION_SIZE)?;
        output[..VIDEO_MODE_INFORMATION_SIZE].fill(0);

        write_u32(output, 0, VIDEO_MODE_INFORMATION_SIZE as u32);
        write_u32(output, 4, MODE_INDEX);
        write_u32(output, 8, self.mode.width);
        write_u32(output, 12, self.mode.height);
        write_u32(output, 16, self.mode.stride);
        write_u32(output, 20, 1);
        write_u32(output, 24, self.mode.bits_per_plane);
        write_u32(output, 28, DEFAULT_REFRESH_HZ);
        write_u32(output, 32, millimeters_at_default_dpi(self.mode.width));
        write_u32(output, 36, millimeters_at_default_dpi(self.mode.height));
        write_u32(output, 40, RGB_BITS);
        write_u32(output, 44, RGB_BITS);
        write_u32(output, 48, RGB_BITS);
        write_u32(output, 52, RED_MASK_32BPP);
        write_u32(output, 56, GREEN_MASK_32BPP);
        write_u32(output, 60, BLUE_MASK_32BPP);
        write_u32(
            output,
            64,
            VIDEO_MODE_COLOR | VIDEO_MODE_GRAPHICS | VIDEO_MODE_LINEAR,
        );
        write_u32(output, 68, self.mode.width);
        write_u32(output, 72, self.mode.height);
        Ok(VIDEO_MODE_INFORMATION_SIZE)
    }

    fn set_current_mode(&self, input: &[u8]) -> Result<usize, VideoMiniportError> {
        require_input(input, 4)?;
        let requested = read_u32(input, 0);
        let allowed_flags = VIDEO_MODE_MAP_MEM_LINEAR | VIDEO_MODE_NO_ZERO_MEMORY;
        if requested & !allowed_flags != MODE_INDEX {
            return Err(VideoMiniportError::InvalidModeRequest);
        }
        Ok(0)
    }

    fn map_video_memory(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, VideoMiniportError> {
        require_input(input, VIDEO_MEMORY_SIZE_X64)?;
        self.write_video_memory_information(output)
    }

    fn write_video_memory_information(
        &self,
        output: &mut [u8],
    ) -> Result<usize, VideoMiniportError> {
        require_output(output, VIDEO_MEMORY_INFORMATION_SIZE_X64)?;
        if self.mapping.size_bytes > u32::MAX as u64 {
            return Err(VideoMiniportError::FramebufferTooLarge);
        }
        output[..VIDEO_MEMORY_INFORMATION_SIZE_X64].fill(0);
        write_u64(output, 0, self.mapping.virtual_address);
        write_u32(output, 8, self.mapping.size_bytes as u32);
        write_u64(output, 16, self.mapping.virtual_address);
        write_u32(output, 24, self.mapping.size_bytes as u32);
        Ok(VIDEO_MEMORY_INFORMATION_SIZE_X64)
    }
}

impl VideoMiniportAdapter for BootFramebufferMiniport {
    fn dispatch_io_control(
        &self,
        ioctl: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, VideoMiniportError> {
        BootFramebufferMiniport::dispatch_io_control(self, ioctl, input, output)
    }

    fn dispatch_buffered_io_control(
        &self,
        ioctl: u32,
        system_buffer: &mut [u8],
        input_len: usize,
        output_len: usize,
    ) -> Result<usize, VideoMiniportError> {
        BootFramebufferMiniport::dispatch_buffered_io_control(
            self,
            ioctl,
            system_buffer,
            input_len,
            output_len,
        )
    }
}

fn write_win32k_callbacks(
    input: &[u8],
    output: &mut [u8],
    video_device_object: u64,
) -> Result<usize, VideoMiniportError> {
    require_input(input, 16)?;
    let phys_disp = read_u64(input, 0)?;
    let callout = read_u64(input, 8)?;
    write_win32k_callbacks_from_parts(output, phys_disp, callout, video_device_object)
}

fn write_win32k_callbacks_from_parts(
    output: &mut [u8],
    phys_disp: u64,
    callout: u64,
    video_device_object: u64,
) -> Result<usize, VideoMiniportError> {
    require_output(output, VIDEO_WIN32K_CALLBACKS_SIZE_X64)?;
    output[..VIDEO_WIN32K_CALLBACKS_SIZE_X64].fill(0);
    write_u64(output, 0, phys_disp);
    write_u64(output, 8, callout);
    write_u32(output, 16, 0);
    write_u64(output, 24, video_device_object);
    write_u32(output, 32, 0);
    Ok(VIDEO_WIN32K_CALLBACKS_SIZE_X64)
}

fn validate_mapping(
    mapping: FramebufferMapping,
    mode: VideoModeSpec,
) -> Result<(), VideoMiniportError> {
    if mapping.virtual_address == 0
        || mapping.size_bytes == 0
        || mode.width == 0
        || mode.height == 0
        || mode.stride == 0
    {
        return Err(VideoMiniportError::InvalidRegistration);
    }
    if mode.bits_per_plane != 32 {
        return Err(VideoMiniportError::UnsupportedMode);
    }
    let minimum_stride = mode
        .width
        .checked_mul(mode.bits_per_plane / 8)
        .ok_or(VideoMiniportError::InvalidRegistration)?;
    if mode.stride < minimum_stride {
        return Err(VideoMiniportError::InvalidRegistration);
    }
    let minimum_size = (mode.stride as u64)
        .checked_mul(mode.height as u64)
        .ok_or(VideoMiniportError::InvalidRegistration)?;
    if mapping.size_bytes < minimum_size {
        return Err(VideoMiniportError::InvalidRegistration);
    }
    Ok(())
}

fn require_input(input: &[u8], needed: usize) -> Result<(), VideoMiniportError> {
    if input.len() < needed {
        Err(VideoMiniportError::BufferTooSmall { needed })
    } else {
        Ok(())
    }
}

fn require_output(output: &[u8], needed: usize) -> Result<(), VideoMiniportError> {
    if output.len() < needed {
        Err(VideoMiniportError::BufferTooSmall { needed })
    } else {
        Ok(())
    }
}

fn require_video_hw_init_input(
    input: &[u8],
    needed: usize,
) -> Result<(), VideoHwInitializationDataError> {
    if input.len() < needed {
        Err(VideoHwInitializationDataError::BufferTooSmall { needed })
    } else {
        Ok(())
    }
}

fn require_video_request_input(input: &[u8], needed: usize) -> Result<(), VideoRequestPacketError> {
    if input.len() < needed {
        Err(VideoRequestPacketError::BufferTooSmall { needed })
    } else {
        Ok(())
    }
}

fn require_video_access_range_input(
    input: &[u8],
    needed: usize,
) -> Result<(), VideoAccessRangeError> {
    if input.len() < needed {
        Err(VideoAccessRangeError::BufferTooSmall { needed })
    } else {
        Ok(())
    }
}

fn millimeters_at_default_dpi(pixels: u32) -> u32 {
    ((pixels as u64 * 254 + (DEFAULT_DPI as u64 * 5)) / (DEFAULT_DPI as u64 * 10)) as u32
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&input[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn read_u32_raw(input: &[u8], offset: usize) -> u32 {
    read_u32(input, offset)
}

fn read_u64_raw(input: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&input[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

fn read_u8_present(input: &[u8], declared: usize, offset: usize) -> u8 {
    if offset < declared {
        input[offset]
    } else {
        0
    }
}

fn read_u32_present(input: &[u8], declared: usize, offset: usize) -> u32 {
    if offset.checked_add(4).is_some_and(|end| end <= declared) {
        read_u32_raw(input, offset)
    } else {
        0
    }
}

fn read_u64_present(input: &[u8], declared: usize, offset: usize) -> u64 {
    if offset.checked_add(8).is_some_and(|end| end <= declared) {
        read_u64_raw(input, offset)
    } else {
        0
    }
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, VideoMiniportError> {
    require_input(input, offset + 8)?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&input[offset..offset + 8]);
    Ok(u64::from_le_bytes(bytes))
}

fn driver_name_component_is_safe(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .copied()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        && !name.windows(2).any(|w| w == b"..")
}

fn write_concat_ascii(
    out: &mut [u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<usize, VideoDeviceIdentityError> {
    let need = prefix
        .len()
        .checked_add(suffix.len())
        .ok_or(VideoDeviceIdentityError::BufferTooSmall { needed: usize::MAX })?;
    require_identity_output(out, need)?;
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()..need].copy_from_slice(suffix);
    Ok(need)
}

fn require_identity_output(out: &[u8], needed: usize) -> Result<(), VideoDeviceIdentityError> {
    if out.len() < needed {
        Err(VideoDeviceIdentityError::BufferTooSmall { needed })
    } else {
        Ok(())
    }
}

fn decimal_u32_digits(mut value: u32) -> usize {
    let mut digits = 1usize;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

fn write_decimal_u32(mut value: u32, out: &mut [u8]) {
    for idx in (0..out.len()).rev() {
        out[idx] = b'0' + (value % 10) as u8;
        value /= 10;
    }
}

fn decimal_u32_eq_ascii(value: u32, ascii: &[u8]) -> bool {
    if ascii.len() != decimal_u32_digits(value) {
        return false;
    }
    let mut rendered = [0u8; 10];
    let len = rendered.len();
    write_decimal_u32(value, &mut rendered[len - ascii.len()..]);
    &rendered[len - ascii.len()..] == ascii
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn miniport() -> BootFramebufferMiniport {
        BootFramebufferMiniport::new(
            FramebufferMapping {
                virtual_address: 0x0000_0100_0900_0000,
                size_bytes: 1280 * 800 * 4,
            },
            VideoModeSpec {
                width: 1280,
                height: 800,
                stride: 1280 * 4,
                bits_per_plane: 32,
            },
        )
        .unwrap()
    }

    fn video_port() -> VideoPort<BootFramebufferMiniport> {
        VideoPort::new(miniport(), 0x9999_AAAA_BBBB_CCCCu64)
    }

    fn u32_at(buf: &[u8], offset: usize) -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&buf[offset..offset + 4]);
        u32::from_le_bytes(bytes)
    }

    fn u64_at(buf: &[u8], offset: usize) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buf[offset..offset + 8]);
        u64::from_le_bytes(bytes)
    }

    fn valid_video_hw_init(size: usize) -> [u8; VIDEO_HW_INITIALIZATION_DATA_X64_SIZE] {
        let mut data = [0u8; VIDEO_HW_INITIALIZATION_DATA_X64_SIZE];
        write_u32(&mut data, 0, size as u32);
        write_u32(&mut data, 4, 5);
        write_u64(&mut data, 8, 0x1000_0000_0000_0001);
        write_u64(&mut data, 16, 0x1000_0000_0000_0002);
        write_u64(&mut data, 32, 0x1000_0000_0000_0004);
        write_u32(&mut data, 40, 0x120);
        write_u32(&mut data, 44, 7);
        write_u64(&mut data, 72, 0x1000_0000_0000_0005);
        write_u64(&mut data, 80, 0x1000_0000_0000_0006);
        write_u64(&mut data, 88, 0x1000_0000_0000_0007);
        write_u64(&mut data, 96, 0x1000_0000_0000_0008);
        write_u32(&mut data, 104, 0x40);
        write_u64(&mut data, 112, 0x2000_0000_0000_0000);
        write_u32(&mut data, 120, 3);
        write_u64(&mut data, 128, 0x1000_0000_0000_0009);
        data[136] = 1;
        write_u32(&mut data, 140, 0xAABB_CCDD);
        data
    }

    #[test]
    fn video_identity_materializes_nt_paths() {
        let identity = VideoDeviceIdentity::new(
            12,
            b"framebuf",
            b"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\framebuf",
        )
        .unwrap();

        let mut driver_path = [0u8; 32];
        let driver_len = identity
            .write_driver_object_path_ascii(&mut driver_path)
            .unwrap();
        assert_eq!(&driver_path[..driver_len], b"\\Driver\\framebuf");

        let mut device_path = [0u8; 32];
        let device_len = identity.write_device_path_ascii(&mut device_path).unwrap();
        assert_eq!(&device_path[..device_len], b"\\Device\\Video12");
        assert!(identity.device_path_eq_ascii_ignore_case(b"\\device\\video12"));
        assert!(!identity.device_path_eq_ascii_ignore_case(b"\\Device\\Video0"));
        assert_eq!(identity.max_object_number(), 12);
    }

    #[test]
    fn video_identity_writes_service_path_for_device_map() {
        let identity = VideoDeviceIdentity::new(
            0,
            b"framebuf",
            b"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\framebuf",
        )
        .unwrap();
        let expected_len = identity.service_registry_path().len() * 2 + 2;
        assert_eq!(
            identity.service_registry_path_utf16le_nul_len(),
            Some(expected_len)
        );

        let mut data = [0u8; 128];
        let written = identity
            .write_service_registry_path_utf16le_nul(&mut data)
            .unwrap();
        assert_eq!(written, expected_len);
        assert_eq!(data[written - 2], 0);
        assert_eq!(data[written - 1], 0);
        for (idx, &byte) in identity.service_registry_path().iter().enumerate() {
            assert_eq!(data[idx * 2], byte);
            assert_eq!(data[idx * 2 + 1], 0);
        }
    }

    #[test]
    fn video_identity_rejects_unstable_names_and_small_outputs() {
        assert_eq!(
            VideoDeviceIdentity::new(0, b"", b"\\Registry\\Machine\\System"),
            Err(VideoDeviceIdentityError::InvalidDriverName)
        );
        assert_eq!(
            VideoDeviceIdentity::new(0, b"..\\bad", b"\\Registry\\Machine\\System"),
            Err(VideoDeviceIdentityError::InvalidDriverName)
        );
        assert_eq!(
            VideoDeviceIdentity::new(0, b"framebuf", b""),
            Err(VideoDeviceIdentityError::InvalidServiceRegistryPath)
        );

        let identity =
            VideoDeviceIdentity::new(0, b"framebuf", b"\\Registry\\Machine\\System").unwrap();
        let mut out = [0u8; 4];
        assert_eq!(
            identity.write_device_path_ascii(&mut out),
            Err(VideoDeviceIdentityError::BufferTooSmall {
                needed: "\\Device\\Video0".len()
            })
        );
    }

    #[test]
    fn video_hw_initialization_data_parses_full_x64_layout() {
        let data = valid_video_hw_init(VIDEO_HW_INITIALIZATION_DATA_X64_SIZE);
        let parsed = VideoHwInitializationDataX64::parse(&data).unwrap();

        assert_eq!(
            parsed.version(),
            VideoHwInitializationDataVersion::WindowsXpOrLater
        );
        assert_eq!(parsed.adapter_interface_type, 5);
        assert_eq!(parsed.hw_find_adapter, 0x1000_0000_0000_0001);
        assert_eq!(parsed.hw_initialize, 0x1000_0000_0000_0002);
        assert_eq!(parsed.hw_interrupt, 0);
        assert_eq!(parsed.hw_start_io, 0x1000_0000_0000_0004);
        assert_eq!(parsed.hw_device_extension_size, 0x120);
        assert_eq!(parsed.starting_device_number, 7);
        assert_eq!(parsed.hw_set_power_state, 0x1000_0000_0000_0005);
        assert_eq!(parsed.hw_get_power_state, 0x1000_0000_0000_0006);
        assert_eq!(parsed.hw_get_video_child_descriptor, 0x1000_0000_0000_0007);
        assert_eq!(parsed.hw_query_interface, 0x1000_0000_0000_0008);
        assert_eq!(parsed.hw_child_device_extension_size, 0x40);
        assert_eq!(parsed.hw_legacy_resource_list, 0x2000_0000_0000_0000);
        assert_eq!(parsed.hw_legacy_resource_count, 3);
        assert_eq!(parsed.hw_get_legacy_resources, 0x1000_0000_0000_0009);
        assert!(parsed.allow_early_enumeration);
        assert_eq!(parsed.reserved, 0xAABB_CCDD);
        assert!(parsed.is_pnp_miniport());
        assert!(!parsed.requires_legacy_detection(0));
        assert!(parsed.requires_legacy_detection(0xCAFE));
    }

    #[test]
    fn video_hw_initialization_data_preserves_legacy_versions() {
        let nt4 = valid_video_hw_init(VIDEO_HW_INITIALIZATION_DATA_NT4_X64_SIZE);
        let parsed =
            VideoHwInitializationDataX64::parse(&nt4[..VIDEO_HW_INITIALIZATION_DATA_NT4_X64_SIZE])
                .unwrap();
        assert_eq!(parsed.version(), VideoHwInitializationDataVersion::Nt4);
        assert_eq!(parsed.hw_timer, 0);
        assert_eq!(parsed.hw_start_dma, 0);
        assert_eq!(parsed.hw_set_power_state, 0);
        assert!(!parsed.is_pnp_miniport());
        assert!(parsed.requires_legacy_detection(0));

        let w2k = valid_video_hw_init(VIDEO_HW_INITIALIZATION_DATA_W2K_X64_SIZE);
        let parsed =
            VideoHwInitializationDataX64::parse(&w2k[..VIDEO_HW_INITIALIZATION_DATA_W2K_X64_SIZE])
                .unwrap();
        assert_eq!(
            parsed.version(),
            VideoHwInitializationDataVersion::Windows2000
        );
        assert_eq!(parsed.reserved, 0);
        assert!(parsed.allow_early_enumeration);
    }

    #[test]
    fn video_hw_initialization_data_rejects_invalid_inputs() {
        assert_eq!(
            VideoHwInitializationDataX64::parse(&[0; 3]),
            Err(VideoHwInitializationDataError::BufferTooSmall { needed: 4 })
        );

        let mut data = valid_video_hw_init(VIDEO_HW_INITIALIZATION_DATA_X64_SIZE);
        write_u32(
            &mut data,
            0,
            (VIDEO_HW_INITIALIZATION_DATA_X64_SIZE + 1) as u32,
        );
        assert_eq!(
            VideoHwInitializationDataX64::parse(&data),
            Err(VideoHwInitializationDataError::RevisionMismatch {
                declared: VIDEO_HW_INITIALIZATION_DATA_X64_SIZE + 1
            })
        );

        write_u32(&mut data, 0, 96);
        assert_eq!(
            VideoHwInitializationDataX64::parse(&data[..96]),
            Err(VideoHwInitializationDataError::UnsupportedSize { declared: 96 })
        );

        data = valid_video_hw_init(VIDEO_HW_INITIALIZATION_DATA_NT4_X64_SIZE);
        write_u64(&mut data, 16, 0);
        assert_eq!(
            VideoHwInitializationDataX64::parse(&data[..VIDEO_HW_INITIALIZATION_DATA_NT4_X64_SIZE]),
            Err(VideoHwInitializationDataError::MissingRequiredCallback)
        );
    }

    #[test]
    fn video_access_range_uses_x64_layout() {
        let range = VideoAccessRangeX64 {
            range_start: 0x0000_0000_F000_0000,
            range_length: 0x1000,
            range_in_io_space: true,
            range_visible: false,
            range_shareable: true,
            range_passive: 2,
        };
        let mut raw = [0xCCu8; VIDEO_ACCESS_RANGE_X64_SIZE];
        assert_eq!(range.write(&mut raw).unwrap(), VIDEO_ACCESS_RANGE_X64_SIZE);

        assert_eq!(u64_at(&raw, 0), 0x0000_0000_F000_0000);
        assert_eq!(u32_at(&raw, 8), 0x1000);
        assert_eq!(raw[12], 1);
        assert_eq!(raw[13], 0);
        assert_eq!(raw[14], 1);
        assert_eq!(raw[15], 2);
        assert_eq!(VideoAccessRangeX64::parse(&raw).unwrap(), range);
    }

    #[test]
    fn video_access_range_rejects_small_buffers() {
        let mut raw = [0u8; VIDEO_ACCESS_RANGE_X64_SIZE - 1];
        assert_eq!(
            VideoAccessRangeX64::memory(0xE000_0000, 0x1000).write(&mut raw),
            Err(VideoAccessRangeError::BufferTooSmall {
                needed: VIDEO_ACCESS_RANGE_X64_SIZE
            })
        );
        assert_eq!(
            VideoAccessRangeX64::parse(&raw),
            Err(VideoAccessRangeError::BufferTooSmall {
                needed: VIDEO_ACCESS_RANGE_X64_SIZE
            })
        );
    }

    #[test]
    fn video_request_packet_uses_x64_vrp_layout() {
        let packet = VideoRequestPacketX64::buffered(
            IOCTL_VIDEO_QUERY_CURRENT_MODE,
            0x1000_0000_0000_0100,
            0x1000_0000_0000_2000,
            4,
            VIDEO_MODE_INFORMATION_SIZE as u32,
        );
        let mut raw = [0xCCu8; VIDEO_REQUEST_PACKET_X64_SIZE];
        assert_eq!(
            packet.write(&mut raw).unwrap(),
            VIDEO_REQUEST_PACKET_X64_SIZE
        );

        assert_eq!(u32_at(&raw, 0), IOCTL_VIDEO_QUERY_CURRENT_MODE);
        assert_eq!(&raw[4..8], &[0, 0, 0, 0]);
        assert_eq!(u64_at(&raw, 8), 0x1000_0000_0000_0100);
        assert_eq!(u64_at(&raw, 16), 0x1000_0000_0000_2000);
        assert_eq!(u32_at(&raw, 24), 4);
        assert_eq!(&raw[28..32], &[0, 0, 0, 0]);
        assert_eq!(u64_at(&raw, 32), 0x1000_0000_0000_2000);
        assert_eq!(u32_at(&raw, 40), VIDEO_MODE_INFORMATION_SIZE as u32);
        assert_eq!(&raw[44..48], &[0, 0, 0, 0]);
        assert_eq!(VideoRequestPacketX64::parse(&raw).unwrap(), packet);
    }

    #[test]
    fn video_status_block_uses_x64_status_block_layout() {
        let mut raw = [0xCCu8; VIDEO_STATUS_BLOCK_X64_SIZE];
        assert_eq!(
            write_video_status_block_x64(&mut raw, 0xC000_000Du32 as i32, 0x1234).unwrap(),
            VIDEO_STATUS_BLOCK_X64_SIZE
        );
        assert_eq!(u32_at(&raw, 0), 0xC000_000D);
        assert_eq!(&raw[4..8], &[0, 0, 0, 0]);
        assert_eq!(u64_at(&raw, 8), 0x1234);
    }

    #[test]
    fn rejects_invalid_registration() {
        assert_eq!(
            BootFramebufferMiniport::new(
                FramebufferMapping {
                    virtual_address: 0,
                    size_bytes: 1
                },
                VideoModeSpec {
                    width: 1,
                    height: 1,
                    stride: 4,
                    bits_per_plane: 32,
                },
            ),
            Err(VideoMiniportError::InvalidRegistration)
        );
        assert_eq!(
            BootFramebufferMiniport::new(
                FramebufferMapping {
                    virtual_address: 0x1000,
                    size_bytes: 4
                },
                VideoModeSpec {
                    width: 1,
                    height: 1,
                    stride: 4,
                    bits_per_plane: 24,
                },
            ),
            Err(VideoMiniportError::UnsupportedMode)
        );
        assert_eq!(
            BootFramebufferMiniport::new(
                FramebufferMapping {
                    virtual_address: 0x1000,
                    size_bytes: 12
                },
                VideoModeSpec {
                    width: 2,
                    height: 2,
                    stride: 8,
                    bits_per_plane: 32,
                },
            ),
            Err(VideoMiniportError::InvalidRegistration)
        );
    }

    #[test]
    fn query_num_available_modes_uses_ntddvdeo_layout() {
        let mut out = [0u8; VIDEO_NUM_MODES_SIZE];
        let written = miniport()
            .dispatch_io_control(IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES, &[], &mut out)
            .unwrap();
        assert_eq!(written, VIDEO_NUM_MODES_SIZE);
        assert_eq!(u32_at(&out, 0), 1);
        assert_eq!(u32_at(&out, 4), VIDEO_MODE_INFORMATION_SIZE as u32);
    }

    #[test]
    fn query_mode_uses_registered_boot_framebuffer_mode() {
        let mut out = [0xCCu8; VIDEO_MODE_INFORMATION_SIZE];
        let written = miniport()
            .dispatch_io_control(IOCTL_VIDEO_QUERY_CURRENT_MODE, &[], &mut out)
            .unwrap();
        assert_eq!(written, VIDEO_MODE_INFORMATION_SIZE);
        assert_eq!(u32_at(&out, 0), VIDEO_MODE_INFORMATION_SIZE as u32);
        assert_eq!(u32_at(&out, 4), MODE_INDEX);
        assert_eq!(u32_at(&out, 8), 1280);
        assert_eq!(u32_at(&out, 12), 800);
        assert_eq!(u32_at(&out, 16), 5120);
        assert_eq!(u32_at(&out, 20), 1);
        assert_eq!(u32_at(&out, 24), 32);
        assert_eq!(u32_at(&out, 52), RED_MASK_32BPP);
        assert_eq!(u32_at(&out, 56), GREEN_MASK_32BPP);
        assert_eq!(u32_at(&out, 60), BLUE_MASK_32BPP);
        assert_eq!(
            u32_at(&out, 64),
            VIDEO_MODE_COLOR | VIDEO_MODE_GRAPHICS | VIDEO_MODE_LINEAR
        );
        assert_eq!(u32_at(&out, 68), 1280);
        assert_eq!(u32_at(&out, 72), 800);
    }

    #[test]
    fn set_current_mode_requires_the_advertised_mode() {
        let mut mode = MODE_INDEX.to_le_bytes();
        assert_eq!(
            miniport()
                .dispatch_io_control(IOCTL_VIDEO_SET_CURRENT_MODE, &mode, &mut [])
                .unwrap(),
            0
        );
        mode = (MODE_INDEX | VIDEO_MODE_MAP_MEM_LINEAR).to_le_bytes();
        assert_eq!(
            miniport()
                .dispatch_io_control(IOCTL_VIDEO_SET_CURRENT_MODE, &mode, &mut [])
                .unwrap(),
            0
        );
        assert_eq!(
            miniport().dispatch_io_control(
                IOCTL_VIDEO_SET_CURRENT_MODE,
                &2u32.to_le_bytes(),
                &mut []
            ),
            Err(VideoMiniportError::InvalidModeRequest)
        );
    }

    #[test]
    fn map_video_memory_returns_the_registered_win32k_mapping() {
        let input = 0u64.to_le_bytes();
        let mut out = [0xCCu8; VIDEO_MEMORY_INFORMATION_SIZE_X64];
        let written = miniport()
            .dispatch_io_control(IOCTL_VIDEO_MAP_VIDEO_MEMORY, &input, &mut out)
            .unwrap();
        assert_eq!(written, VIDEO_MEMORY_INFORMATION_SIZE_X64);
        assert_eq!(u64_at(&out, 0), 0x0000_0100_0900_0000);
        assert_eq!(u32_at(&out, 8), 1280 * 800 * 4);
        assert_eq!(u64_at(&out, 16), 0x0000_0100_0900_0000);
        assert_eq!(u32_at(&out, 24), 1280 * 800 * 4);
    }

    #[test]
    fn buffered_ioctl_dispatch_uses_one_system_buffer() {
        let input = 0u64.to_le_bytes();
        let mut sys = [0u8; VIDEO_MEMORY_INFORMATION_SIZE_X64];
        sys[..input.len()].copy_from_slice(&input);
        let written = miniport()
            .dispatch_buffered_io_control(
                IOCTL_VIDEO_MAP_VIDEO_MEMORY,
                &mut sys,
                VIDEO_MEMORY_SIZE_X64,
                VIDEO_MEMORY_INFORMATION_SIZE_X64,
            )
            .unwrap();
        assert_eq!(written, VIDEO_MEMORY_INFORMATION_SIZE_X64);
        assert_eq!(u64_at(&sys, 16), 0x0000_0100_0900_0000);
    }

    #[test]
    fn video_port_control_initializes_win32k_callbacks() {
        let mut input = [0u8; 16];
        input[..8].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        input[8..16].copy_from_slice(&0x5555_6666_7777_8888u64.to_le_bytes());
        let mut out = [0xCCu8; VIDEO_WIN32K_CALLBACKS_SIZE_X64];
        let written = video_port()
            .dispatch_io_control(IOCTL_VIDEO_INIT_WIN32K_CALLBACKS, &input, &mut out)
            .unwrap();
        assert_eq!(written, VIDEO_WIN32K_CALLBACKS_SIZE_X64);
        assert_eq!(u64_at(&out, 0), 0x1111_2222_3333_4444);
        assert_eq!(u64_at(&out, 8), 0x5555_6666_7777_8888);
        assert_eq!(u32_at(&out, 16), 0);
        assert_eq!(u64_at(&out, 24), 0x9999_AAAA_BBBB_CCCC);
        assert_eq!(u32_at(&out, 32), 0);
        assert_eq!(u32_at(&out, 36), 0);
    }

    #[test]
    fn buffered_video_port_control_uses_system_buffer_for_callbacks() {
        let mut sys = [0u8; VIDEO_WIN32K_CALLBACKS_SIZE_X64];
        sys[..8].copy_from_slice(&0x1010_2020_3030_4040u64.to_le_bytes());
        sys[8..16].copy_from_slice(&0x5050_6060_7070_8080u64.to_le_bytes());
        let written = VideoPort::new(miniport(), 0x9090_A0A0_B0B0_C0C0u64)
            .dispatch_buffered_io_control(
                IOCTL_VIDEO_INIT_WIN32K_CALLBACKS,
                &mut sys,
                16,
                VIDEO_WIN32K_CALLBACKS_SIZE_X64,
            )
            .unwrap();
        assert_eq!(written, VIDEO_WIN32K_CALLBACKS_SIZE_X64);
        assert_eq!(u64_at(&sys, 0), 0x1010_2020_3030_4040);
        assert_eq!(u64_at(&sys, 8), 0x5050_6060_7070_8080);
        assert_eq!(u64_at(&sys, 24), 0x9090_A0A0_B0B0_C0C0);
    }

    #[test]
    fn video_port_control_unmap_is_a_visible_success_noop() {
        let mut out = [0xCCu8; 8];
        assert_eq!(
            VideoPort::new(miniport(), 0x1234).dispatch_io_control(
                IOCTL_VIDEO_UNMAP_VIDEO_MEMORY,
                &[],
                &mut out,
            ),
            Ok(0)
        );
        assert_eq!(out, [0xCCu8; 8]);
    }

    #[test]
    fn undersized_buffers_fail_visibly() {
        let mut out = [0u8; VIDEO_NUM_MODES_SIZE - 1];
        assert_eq!(
            miniport().dispatch_io_control(IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES, &[], &mut out),
            Err(VideoMiniportError::BufferTooSmall {
                needed: VIDEO_NUM_MODES_SIZE
            })
        );
        assert_eq!(
            miniport().dispatch_io_control(IOCTL_VIDEO_MAP_VIDEO_MEMORY, &[], &mut []),
            Err(VideoMiniportError::BufferTooSmall {
                needed: VIDEO_MEMORY_SIZE_X64
            })
        );
    }
}
