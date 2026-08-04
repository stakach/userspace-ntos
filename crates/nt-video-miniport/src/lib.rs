//! Minimal NT video miniport contract for a boot framebuffer-backed adapter.
//!
//! The real ReactOS path is videoprt.sys dispatching video IOCTLs to a display miniport. This crate
//! models the miniport-facing contract for the one boot framebuffer mode we can currently expose,
//! with tested encoders for the public `ntddvdeo.h` structures consumed by the framebuf display DLL.

#![no_std]

pub const FILE_DEVICE_VIDEO: u32 = 0x23;

pub const IOCTL_VIDEO_QUERY_AVAIL_MODES: u32 = 0x0023_0400;
pub const IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES: u32 = 0x0023_0404;
pub const IOCTL_VIDEO_QUERY_CURRENT_MODE: u32 = 0x0023_0408;
pub const IOCTL_VIDEO_SET_CURRENT_MODE: u32 = 0x0023_040C;
pub const IOCTL_VIDEO_MAP_VIDEO_MEMORY: u32 = 0x0023_0458;

pub const VIDEO_NUM_MODES_SIZE: usize = 8;
pub const VIDEO_MODE_INFORMATION_SIZE: usize = 80;
pub const VIDEO_MEMORY_SIZE_X64: usize = 8;
pub const VIDEO_MEMORY_INFORMATION_SIZE_X64: usize = 32;

pub const VIDEO_MODE_COLOR: u32 = 0x0001;
pub const VIDEO_MODE_GRAPHICS: u32 = 0x0002;
pub const VIDEO_MODE_LINEAR: u32 = 0x0100;
pub const VIDEO_MODE_MAP_MEM_LINEAR: u32 = 0x4000_0000;
pub const VIDEO_MODE_NO_ZERO_MEMORY: u32 = 0x8000_0000;

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
pub enum VideoMiniportError {
    InvalidRegistration,
    UnsupportedMode,
    FramebufferTooLarge,
    BufferTooSmall { needed: usize },
    InvalidModeRequest,
    UnsupportedIoctl,
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
