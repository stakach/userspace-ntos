//! # `nt-cm-resources` — `CM_RESOURCE_LIST` encoding for PnP `START_DEVICE`
//!
//! Encodes the WDK `CM_RESOURCE_LIST` variable-length layout (spec: NT PnP Manager,
//! Milestone 12, §7.1, §13.3) that a function driver reads from
//! `Parameters.StartDevice.AllocatedResourcesTranslated` during `IRP_MN_START_DEVICE`.
//! The layout is `#pragma pack(4)` — a `CM_PARTIAL_RESOURCE_DESCRIPTOR` is 20 bytes.
//! `no_std`, no allocation, no raw pointers in the encoded bytes; the caller copies
//! the result into driver-visible memory.
//!
//! Byte layout for one memory + one interrupt descriptor (total 60 bytes):
//!
//! ```text
//! CM_RESOURCE_LIST          Count:u32                                @0
//! CM_FULL_RESOURCE_DESC     InterfaceType:i32 @4  BusNumber:u32 @8
//!   CM_PARTIAL_RESOURCE_LIST Version:u16 @12  Revision:u16 @14  Count:u32 @16
//!     [0] Memory     Type:u8 @20 Share @21 Flags:u16 @22  Start:u64 @24  Length:u32 @32
//!     [1] Interrupt  Type:u8 @40 Share @41 Flags:u16 @42  Level:u32 @44 Vector:u32 @48 Affinity:u64 @52
//! ```
//!
//! A PCI device with both MMIO and port-space BARs uses the same header with three descriptors
//! (total 80 bytes): Memory @20, Port @40, Interrupt @60. I/O-only PCI devices omit the memory
//! descriptor and keep the same 20-byte descriptor stride.

#![no_std]

/// `CM_PARTIAL_RESOURCE_DESCRIPTOR.Type` values.
pub const CM_RESOURCE_TYPE_NULL: u8 = 0;
pub const CM_RESOURCE_TYPE_PORT: u8 = 1;
pub const CM_RESOURCE_TYPE_INTERRUPT: u8 = 2;
pub const CM_RESOURCE_TYPE_MEMORY: u8 = 3;
pub const CM_RESOURCE_TYPE_DMA: u8 = 4;
pub const CM_RESOURCE_TYPE_DEVICE_SPECIFIC: u8 = 5;
pub const CM_RESOURCE_TYPE_BUS_NUMBER: u8 = 6;

/// Interrupt `Flags` bits.
pub const CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE: u16 = 0;
pub const CM_RESOURCE_INTERRUPT_LATCHED: u16 = 1;

/// Memory `Flags` bits.
pub const CM_RESOURCE_MEMORY_READ_WRITE: u16 = 0;

/// Port `Flags` bits.
pub const CM_RESOURCE_PORT_MEMORY: u16 = 0;
pub const CM_RESOURCE_PORT_IO: u16 = 1;
pub const CM_RESOURCE_PORT_BAR: u16 = 0x0100;

/// `ShareDisposition` values.
pub const CM_RESOURCE_SHARE_UNDETERMINED: u8 = 0;
pub const CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE: u8 = 1;
pub const CM_RESOURCE_SHARE_DRIVER_EXCLUSIVE: u8 = 2;
pub const CM_RESOURCE_SHARE_SHARED: u8 = 3;

/// `InterfaceType` values used by the hosted buses.
pub const INTERFACE_TYPE_INTERNAL: i32 = 0;
pub const INTERFACE_TYPE_PCI_BUS: i32 = 5;
pub const INTERFACE_TYPE_PNP_BUS: i32 = 16;

/// Size of one `CM_PARTIAL_RESOURCE_DESCRIPTOR` (WDK `#pragma pack(4)`).
pub const PARTIAL_DESCRIPTOR_SIZE: usize = 20;
/// Total encoded size of a one-memory `CM_RESOURCE_LIST`.
pub const MEMORY_LIST_SIZE: usize = 40;
/// Total encoded size of a one-memory + one-port `CM_RESOURCE_LIST`.
pub const MEMORY_PORT_LIST_SIZE: usize = 60;
/// Total encoded size of a one-memory + one-interrupt `CM_RESOURCE_LIST`.
pub const MEMORY_INTERRUPT_LIST_SIZE: usize = 60;
/// Total encoded size of a one-memory + one-port + one-interrupt `CM_RESOURCE_LIST`.
pub const MEMORY_PORT_INTERRUPT_LIST_SIZE: usize = 80;
/// Total encoded size of a one-port `CM_RESOURCE_LIST`.
pub const PORT_LIST_SIZE: usize = 40;
/// Total encoded size of a one-port + one-interrupt `CM_RESOURCE_LIST`.
pub const PORT_INTERRUPT_LIST_SIZE: usize = 60;

fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// The parameters for a memory descriptor.
#[derive(Copy, Clone, Debug)]
pub struct MemoryDescriptor {
    pub start: u64,
    pub length: u32,
    pub flags: u16,
    pub share: u8,
}

/// The parameters for an I/O port descriptor.
#[derive(Copy, Clone, Debug)]
pub struct PortDescriptor {
    pub start: u64,
    pub length: u32,
    pub flags: u16,
    pub share: u8,
}

/// The parameters for an interrupt descriptor (translated form).
#[derive(Copy, Clone, Debug)]
pub struct InterruptDescriptor {
    pub level: u32,
    pub vector: u32,
    pub affinity: u64,
    pub flags: u16,
    pub share: u8,
}

fn build_list_header(
    buf: &mut [u8],
    total_size: usize,
    interface_type: i32,
    bus_number: u32,
    count: u32,
) -> Option<()> {
    if buf.len() < total_size {
        return None;
    }
    for b in buf.iter_mut().take(total_size) {
        *b = 0;
    }
    w32(buf, 0, 1);
    w32(buf, 4, interface_type as u32);
    w32(buf, 8, bus_number);
    w16(buf, 12, 1);
    w16(buf, 14, 1);
    w32(buf, 16, count);
    Some(())
}

fn write_memory_descriptor(buf: &mut [u8], offset: usize, mem: MemoryDescriptor) {
    buf[offset] = CM_RESOURCE_TYPE_MEMORY;
    buf[offset + 1] = mem.share;
    w16(buf, offset + 2, mem.flags);
    w64(buf, offset + 4, mem.start);
    w32(buf, offset + 12, mem.length);
}

fn write_port_descriptor(buf: &mut [u8], offset: usize, port: PortDescriptor) {
    buf[offset] = CM_RESOURCE_TYPE_PORT;
    buf[offset + 1] = port.share;
    w16(buf, offset + 2, port.flags);
    w64(buf, offset + 4, port.start);
    w32(buf, offset + 12, port.length);
}

fn write_interrupt_descriptor(buf: &mut [u8], offset: usize, int: InterruptDescriptor) {
    buf[offset] = CM_RESOURCE_TYPE_INTERRUPT;
    buf[offset + 1] = int.share;
    w16(buf, offset + 2, int.flags);
    w32(buf, offset + 4, int.level);
    w32(buf, offset + 8, int.vector);
    w64(buf, offset + 12, int.affinity);
}

/// Encode a `CM_RESOURCE_LIST` with a single memory descriptor into `buf`.
pub fn build_memory_list(
    buf: &mut [u8],
    interface_type: i32,
    bus_number: u32,
    mem: MemoryDescriptor,
) -> Option<usize> {
    build_list_header(buf, MEMORY_LIST_SIZE, interface_type, bus_number, 1)?;
    write_memory_descriptor(buf, 20, mem);
    Some(MEMORY_LIST_SIZE)
}

/// Encode a `CM_RESOURCE_LIST` with memory + port descriptors into `buf`.
pub fn build_memory_port_list(
    buf: &mut [u8],
    interface_type: i32,
    bus_number: u32,
    mem: MemoryDescriptor,
    port: PortDescriptor,
) -> Option<usize> {
    build_list_header(buf, MEMORY_PORT_LIST_SIZE, interface_type, bus_number, 2)?;
    write_memory_descriptor(buf, 20, mem);
    write_port_descriptor(buf, 40, port);
    Some(MEMORY_PORT_LIST_SIZE)
}

/// Encode a `CM_RESOURCE_LIST` with a single memory + single interrupt descriptor
/// into `buf` (which must be at least [`MEMORY_INTERRUPT_LIST_SIZE`] bytes). Returns
/// the number of bytes written, or `None` if the buffer is too small.
pub fn build_memory_interrupt_list(
    buf: &mut [u8],
    interface_type: i32,
    bus_number: u32,
    mem: MemoryDescriptor,
    int: InterruptDescriptor,
) -> Option<usize> {
    build_list_header(
        buf,
        MEMORY_INTERRUPT_LIST_SIZE,
        interface_type,
        bus_number,
        2,
    )?;
    write_memory_descriptor(buf, 20, mem);
    write_interrupt_descriptor(buf, 40, int);
    Some(MEMORY_INTERRUPT_LIST_SIZE)
}

/// Encode a `CM_RESOURCE_LIST` with memory + port + interrupt descriptors into
/// `buf` (which must be at least [`MEMORY_PORT_INTERRUPT_LIST_SIZE`] bytes).
pub fn build_memory_port_interrupt_list(
    buf: &mut [u8],
    interface_type: i32,
    bus_number: u32,
    mem: MemoryDescriptor,
    port: PortDescriptor,
    int: InterruptDescriptor,
) -> Option<usize> {
    build_list_header(
        buf,
        MEMORY_PORT_INTERRUPT_LIST_SIZE,
        interface_type,
        bus_number,
        3,
    )?;
    write_memory_descriptor(buf, 20, mem);
    write_port_descriptor(buf, 40, port);
    write_interrupt_descriptor(buf, 60, int);
    Some(MEMORY_PORT_INTERRUPT_LIST_SIZE)
}

/// Encode a `CM_RESOURCE_LIST` with a single I/O-port descriptor into `buf`.
pub fn build_port_list(
    buf: &mut [u8],
    interface_type: i32,
    bus_number: u32,
    port: PortDescriptor,
) -> Option<usize> {
    build_list_header(buf, PORT_LIST_SIZE, interface_type, bus_number, 1)?;
    write_port_descriptor(buf, 20, port);
    Some(PORT_LIST_SIZE)
}

/// Encode a `CM_RESOURCE_LIST` with port + interrupt descriptors into `buf`.
pub fn build_port_interrupt_list(
    buf: &mut [u8],
    interface_type: i32,
    bus_number: u32,
    port: PortDescriptor,
    int: InterruptDescriptor,
) -> Option<usize> {
    build_list_header(buf, PORT_INTERRUPT_LIST_SIZE, interface_type, bus_number, 2)?;
    write_port_descriptor(buf, 20, port);
    write_interrupt_descriptor(buf, 40, int);
    Some(PORT_INTERRUPT_LIST_SIZE)
}

/// Decode `(memory, interrupt)` from an encoded list — the same field reads a
/// WDK-compiled driver performs. Returns `None` if the layout is malformed or the
/// expected descriptors are missing.
pub fn decode_memory_interrupt_list(buf: &[u8]) -> Option<(MemoryDescriptor, InterruptDescriptor)> {
    if buf.len() < MEMORY_INTERRUPT_LIST_SIZE {
        return None;
    }
    let r32 = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
    let r16 = |o: usize| u16::from_le_bytes(buf[o..o + 2].try_into().unwrap());
    let r64 = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    if r32(0) != 1 || r32(16) != 2 {
        return None;
    }
    let mut mem = None;
    let mut int = None;
    for k in 0..2 {
        let d = 20 + k * PARTIAL_DESCRIPTOR_SIZE;
        match buf[d] {
            CM_RESOURCE_TYPE_MEMORY => {
                mem = Some(MemoryDescriptor {
                    start: r64(d + 4),
                    length: r32(d + 12),
                    flags: r16(d + 2),
                    share: buf[d + 1],
                })
            }
            CM_RESOURCE_TYPE_INTERRUPT => {
                int = Some(InterruptDescriptor {
                    level: r32(d + 4),
                    vector: r32(d + 8),
                    affinity: r64(d + 12),
                    flags: r16(d + 2),
                    share: buf[d + 1],
                })
            }
            _ => {}
        }
    }
    Some((mem?, int?))
}

/// Decode `(memory, port, interrupt)` from an encoded list. Returns `None` if
/// the layout is malformed or any expected descriptor is absent.
pub fn decode_memory_port_interrupt_list(
    buf: &[u8],
) -> Option<(MemoryDescriptor, PortDescriptor, InterruptDescriptor)> {
    if buf.len() < MEMORY_PORT_INTERRUPT_LIST_SIZE {
        return None;
    }
    let r32 = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
    let r16 = |o: usize| u16::from_le_bytes(buf[o..o + 2].try_into().unwrap());
    let r64 = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    if r32(0) != 1 || r32(16) != 3 {
        return None;
    }
    let mut mem = None;
    let mut port = None;
    let mut int = None;
    for k in 0..3 {
        let d = 20 + k * PARTIAL_DESCRIPTOR_SIZE;
        match buf[d] {
            CM_RESOURCE_TYPE_MEMORY => {
                mem = Some(MemoryDescriptor {
                    start: r64(d + 4),
                    length: r32(d + 12),
                    flags: r16(d + 2),
                    share: buf[d + 1],
                })
            }
            CM_RESOURCE_TYPE_PORT => {
                port = Some(PortDescriptor {
                    start: r64(d + 4),
                    length: r32(d + 12),
                    flags: r16(d + 2),
                    share: buf[d + 1],
                })
            }
            CM_RESOURCE_TYPE_INTERRUPT => {
                int = Some(InterruptDescriptor {
                    level: r32(d + 4),
                    vector: r32(d + 8),
                    affinity: r64(d + 12),
                    flags: r16(d + 2),
                    share: buf[d + 1],
                })
            }
            _ => {}
        }
    }
    Some((mem?, port?, int?))
}

/// Decode `(port, interrupt)` from an encoded list. Returns `None` if the layout is malformed or
/// either descriptor is absent.
pub fn decode_port_interrupt_list(buf: &[u8]) -> Option<(PortDescriptor, InterruptDescriptor)> {
    if buf.len() < PORT_INTERRUPT_LIST_SIZE {
        return None;
    }
    let r32 = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
    let r16 = |o: usize| u16::from_le_bytes(buf[o..o + 2].try_into().unwrap());
    let r64 = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    if r32(0) != 1 || r32(16) != 2 {
        return None;
    }
    let mut port = None;
    let mut int = None;
    for k in 0..2 {
        let d = 20 + k * PARTIAL_DESCRIPTOR_SIZE;
        match buf[d] {
            CM_RESOURCE_TYPE_PORT => {
                port = Some(PortDescriptor {
                    start: r64(d + 4),
                    length: r32(d + 12),
                    flags: r16(d + 2),
                    share: buf[d + 1],
                })
            }
            CM_RESOURCE_TYPE_INTERRUPT => {
                int = Some(InterruptDescriptor {
                    level: r32(d + 4),
                    vector: r32(d + 8),
                    affinity: r64(d + 12),
                    flags: r16(d + 2),
                    share: buf[d + 1],
                })
            }
            _ => {}
        }
    }
    Some((port?, int?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_round_trips() {
        let mut buf = [0u8; 64];
        let n = build_memory_interrupt_list(
            &mut buf,
            INTERFACE_TYPE_INTERNAL,
            0,
            MemoryDescriptor {
                start: 0x1000_0000,
                length: 0x1000,
                flags: CM_RESOURCE_MEMORY_READ_WRITE,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
            InterruptDescriptor {
                level: 5,
                vector: 5,
                affinity: 1,
                flags: CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
        )
        .unwrap();
        assert_eq!(n, 60);

        let (mem, int) = decode_memory_interrupt_list(&buf).unwrap();
        assert_eq!(mem.start, 0x1000_0000);
        assert_eq!(mem.length, 0x1000);
        assert_eq!(int.vector, 5);
        assert_eq!(int.level, 5);
        assert_eq!(int.affinity, 1);
    }

    #[test]
    fn encodes_memory_only_list() {
        let mut buf = [0xCCu8; MEMORY_LIST_SIZE];
        let n = build_memory_list(
            &mut buf,
            INTERFACE_TYPE_INTERNAL,
            2,
            MemoryDescriptor {
                start: 0xE000_0000,
                length: 0x1000,
                flags: CM_RESOURCE_MEMORY_READ_WRITE,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
        )
        .unwrap();
        assert_eq!(n, MEMORY_LIST_SIZE);
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 1);
        assert_eq!(buf[20], CM_RESOURCE_TYPE_MEMORY);
        assert_eq!(
            u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            0xE000_0000
        );
        assert_eq!(u32::from_le_bytes(buf[32..36].try_into().unwrap()), 0x1000);
    }

    #[test]
    fn encodes_memory_port_without_interrupt() {
        let mut buf = [0xCCu8; MEMORY_PORT_LIST_SIZE];
        let n = build_memory_port_list(
            &mut buf,
            INTERFACE_TYPE_INTERNAL,
            0,
            MemoryDescriptor {
                start: 0xE000_0000,
                length: 0x1000,
                flags: CM_RESOURCE_MEMORY_READ_WRITE,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
            PortDescriptor {
                start: 0x1CE,
                length: 2,
                flags: CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_BAR,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
        )
        .unwrap();
        assert_eq!(n, MEMORY_PORT_LIST_SIZE);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 2);
        assert_eq!(buf[20], CM_RESOURCE_TYPE_MEMORY);
        assert_eq!(buf[40], CM_RESOURCE_TYPE_PORT);
        assert_eq!(u64::from_le_bytes(buf[44..52].try_into().unwrap()), 0x1CE);
        assert_eq!(u32::from_le_bytes(buf[52..56].try_into().unwrap()), 2);
    }

    #[test]
    fn encodes_memory_port_interrupt_and_round_trips() {
        let mut buf = [0u8; MEMORY_PORT_INTERRUPT_LIST_SIZE];
        let n = build_memory_port_interrupt_list(
            &mut buf,
            INTERFACE_TYPE_INTERNAL,
            0,
            MemoryDescriptor {
                start: 0xFEBC_0000,
                length: 0x2_0000,
                flags: CM_RESOURCE_MEMORY_READ_WRITE,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
            PortDescriptor {
                start: 0xC000,
                length: 0x40,
                flags: CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_BAR,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
            InterruptDescriptor {
                level: 11,
                vector: 11,
                affinity: 1,
                flags: CM_RESOURCE_INTERRUPT_LATCHED,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
        )
        .unwrap();
        assert_eq!(n, MEMORY_PORT_INTERRUPT_LIST_SIZE);

        let (mem, port, int) = decode_memory_port_interrupt_list(&buf).unwrap();
        assert_eq!(mem.start, 0xFEBC_0000);
        assert_eq!(mem.length, 0x2_0000);
        assert_eq!(port.start, 0xC000);
        assert_eq!(port.length, 0x40);
        assert_eq!(port.flags, CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_BAR);
        assert_eq!(int.vector, 11);
        assert_eq!(int.flags, CM_RESOURCE_INTERRUPT_LATCHED);
    }

    #[test]
    fn encodes_port_interrupt_without_memory() {
        let mut buf = [0u8; PORT_INTERRUPT_LIST_SIZE];
        let n = build_port_interrupt_list(
            &mut buf,
            INTERFACE_TYPE_INTERNAL,
            0,
            PortDescriptor {
                start: 0x6000,
                length: 0x80,
                flags: CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_BAR,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
            InterruptDescriptor {
                level: 10,
                vector: 10,
                affinity: 1,
                flags: CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
        )
        .unwrap();
        assert_eq!(n, PORT_INTERRUPT_LIST_SIZE);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 2);
        assert_eq!(buf[20], CM_RESOURCE_TYPE_PORT);
        assert_eq!(buf[40], CM_RESOURCE_TYPE_INTERRUPT);

        let (port, int) = decode_port_interrupt_list(&buf).unwrap();
        assert_eq!(port.start, 0x6000);
        assert_eq!(port.length, 0x80);
        assert_eq!(port.flags, CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_BAR);
        assert_eq!(int.vector, 10);
        assert_eq!(int.flags, CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE);
    }

    #[test]
    fn field_offsets_match_wdk() {
        let mut buf = [0u8; 60];
        build_memory_interrupt_list(
            &mut buf,
            INTERFACE_TYPE_INTERNAL,
            7,
            MemoryDescriptor {
                start: 0xDEAD_BEEF,
                length: 0x2000,
                flags: 0,
                share: 1,
            },
            InterruptDescriptor {
                level: 9,
                vector: 0x30,
                affinity: 0xF,
                flags: CM_RESOURCE_INTERRUPT_LATCHED,
                share: 1,
            },
        )
        .unwrap();
        // CM_RESOURCE_LIST.Count @0, PartialResourceList.Count @16.
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 7); // BusNumber
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 2);
        // Memory descriptor @20.
        assert_eq!(buf[20], CM_RESOURCE_TYPE_MEMORY);
        assert_eq!(
            u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            0xDEAD_BEEF
        );
        assert_eq!(u32::from_le_bytes(buf[32..36].try_into().unwrap()), 0x2000);
        // Interrupt descriptor @40 (20-byte stride).
        assert_eq!(buf[40], CM_RESOURCE_TYPE_INTERRUPT);
        assert_eq!(
            u16::from_le_bytes(buf[42..44].try_into().unwrap()),
            CM_RESOURCE_INTERRUPT_LATCHED
        );
        assert_eq!(u32::from_le_bytes(buf[44..48].try_into().unwrap()), 9); // Level
        assert_eq!(u32::from_le_bytes(buf[48..52].try_into().unwrap()), 0x30); // Vector
        assert_eq!(u64::from_le_bytes(buf[52..60].try_into().unwrap()), 0xF); // Affinity
    }

    #[test]
    fn rejects_small_buffer() {
        let mut small = [0u8; 32];
        assert!(build_memory_interrupt_list(
            &mut small,
            INTERFACE_TYPE_INTERNAL,
            0,
            MemoryDescriptor {
                start: 0,
                length: 0,
                flags: 0,
                share: 0
            },
            InterruptDescriptor {
                level: 0,
                vector: 0,
                affinity: 0,
                flags: 0,
                share: 0
            },
        )
        .is_none());
        assert!(decode_memory_interrupt_list(&small).is_none());
        assert!(build_memory_port_interrupt_list(
            &mut small,
            INTERFACE_TYPE_INTERNAL,
            0,
            MemoryDescriptor {
                start: 0,
                length: 0,
                flags: 0,
                share: 0
            },
            PortDescriptor {
                start: 0,
                length: 0,
                flags: 0,
                share: 0
            },
            InterruptDescriptor {
                level: 0,
                vector: 0,
                affinity: 0,
                flags: 0,
                share: 0
            },
        )
        .is_none());
        assert!(decode_memory_port_interrupt_list(&small).is_none());
        assert!(build_port_interrupt_list(
            &mut small,
            INTERFACE_TYPE_INTERNAL,
            0,
            PortDescriptor {
                start: 0,
                length: 0,
                flags: 0,
                share: 0
            },
            InterruptDescriptor {
                level: 0,
                vector: 0,
                affinity: 0,
                flags: 0,
                share: 0
            },
        )
        .is_none());
        assert!(decode_port_interrupt_list(&small).is_none());
    }
}
