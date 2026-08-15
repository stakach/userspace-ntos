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
