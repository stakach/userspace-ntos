//! ReactOS VideoPort monitor PDO `IRP_MN_QUERY_ID` values.
//!
//! Each successful result is UTF-16 including its required terminator. Multi-string
//! ID types have a second trailing NUL. The caller owns the destination buffer.

const MAX_CHILD_ID_UNITS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorChildIdResult {
    Written { units: usize },
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorChildIdError {
    DescriptorTooShort,
    InstanceIdTooLarge,
    BufferTooSmall { needed: usize },
}

/// Write a monitor child ID using the already validated EDID decision from the
/// VideoPort child owner. The descriptor is read only for valid-EDID ID types.
pub fn write_monitor_child_id(
    id_type: u32,
    child_id: u32,
    edid_valid: bool,
    descriptor: &[u8],
    output: &mut [u16],
) -> Result<MonitorChildIdResult, MonitorChildIdError> {
    let mut units = [0u16; MAX_CHILD_ID_UNITS];
    let mut len = 0usize;
    match id_type {
        nt_pnp_abi::BUS_QUERY_DEVICE_ID | nt_pnp_abi::BUS_QUERY_HARDWARE_IDS => {
            let multi = id_type == nt_pnp_abi::BUS_QUERY_HARDWARE_IDS;
            append_ascii(
                &mut units,
                &mut len,
                if multi { b"MONITOR\\" } else { b"DISPLAY\\" },
            );
            if edid_valid {
                let id = monitor_id(descriptor)?;
                units[len..len + id.len()].copy_from_slice(&id);
                len += id.len();
            } else {
                append_ascii(&mut units, &mut len, b"Default_Monitor");
            }
            len += 1; // Single-string terminator; the array is zero-initialized.
            if multi {
                len += 1;
            }
        }
        nt_pnp_abi::BUS_QUERY_INSTANCE_ID => {
            // ReactOS allocates five WCHARs but sets MaximumLength to four,
            // leaving room for at most three hex digits and a NUL.
            if child_id > 0xfff {
                return Err(MonitorChildIdError::InstanceIdTooLarge);
            }
            let digits = if child_id >= 0x100 {
                3
            } else if child_id >= 0x10 {
                2
            } else {
                1
            };
            for index in (0..digits).rev() {
                let digit = ((child_id >> (index * 4)) & 0xf) as u8;
                units[len] = if digit < 10 {
                    u16::from(b'0' + digit)
                } else {
                    u16::from(b'A' + digit - 10)
                };
                len += 1;
            }
            len += 1;
        }
        nt_pnp_abi::BUS_QUERY_COMPATIBLE_IDS if edid_valid => {
            append_ascii(&mut units, &mut len, b"*PNP09FF");
            len += 2;
        }
        _ => return Ok(MonitorChildIdResult::Unsupported),
    }
    if output.len() < len {
        return Err(MonitorChildIdError::BufferTooSmall { needed: len });
    }
    output[..len].copy_from_slice(&units[..len]);
    Ok(MonitorChildIdResult::Written { units: len })
}

fn append_ascii(units: &mut [u16; MAX_CHILD_ID_UNITS], len: &mut usize, ascii: &[u8]) {
    for &byte in ascii {
        units[*len] = u16::from(byte);
        *len += 1;
    }
}

fn monitor_id(descriptor: &[u8]) -> Result<[u16; 7], MonitorChildIdError> {
    let bytes = descriptor
        .get(8..12)
        .ok_or(MonitorChildIdError::DescriptorTooShort)?;
    let manufacturer = u16::from_be_bytes([bytes[0], bytes[1]]);
    let model = u16::from_le_bytes([bytes[2], bytes[3]]);
    let mut id = [0u16; 7];
    for (index, shift) in [10, 5, 0].into_iter().enumerate() {
        id[index] = ((manufacturer >> shift & 0x1f) + u16::from(b'A' - 1)) as u16;
    }
    for (index, shift) in [12, 8, 4, 0].into_iter().enumerate() {
        let digit = ((model >> shift) & 0xf) as u8;
        id[3 + index] = u16::from(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edid() -> [u8; 256] {
        let mut descriptor = [0u8; 256];
        descriptor[8..12].copy_from_slice(&[0x04, 0x43, 0x34, 0x12]); // ABC1234
        descriptor
    }

    fn output(id_type: u32, child_id: u32, valid: bool) -> Option<([u16; 32], usize)> {
        let mut buffer = [0xaaaa; 32];
        match write_monitor_child_id(id_type, child_id, valid, &edid(), &mut buffer).unwrap() {
            MonitorChildIdResult::Written { units } => Some((buffer, units)),
            MonitorChildIdResult::Unsupported => None,
        }
    }

    #[test]
    fn valid_edid_device_and_hardware_ids_use_manufacturer_and_model() {
        let (device, len) = output(nt_pnp_abi::BUS_QUERY_DEVICE_ID, 1, true).unwrap();
        assert!(device[..len].iter().copied().eq("DISPLAY\\ABC1234\0".encode_utf16()));
        let (hardware, len) = output(nt_pnp_abi::BUS_QUERY_HARDWARE_IDS, 1, true).unwrap();
        assert!(hardware[..len].iter().copied().eq("MONITOR\\ABC1234\0\0".encode_utf16()));
    }

    #[test]
    fn invalid_edid_uses_default_id_and_has_no_compatible_ids() {
        let (device, len) = output(nt_pnp_abi::BUS_QUERY_DEVICE_ID, 1, false).unwrap();
        assert!(device[..len].iter().copied().eq("DISPLAY\\Default_Monitor\0".encode_utf16()));
        let (hardware, len) = output(nt_pnp_abi::BUS_QUERY_HARDWARE_IDS, 1, false).unwrap();
        assert!(hardware[..len].iter().copied().eq("MONITOR\\Default_Monitor\0\0".encode_utf16()));
        assert!(output(nt_pnp_abi::BUS_QUERY_COMPATIBLE_IDS, 1, false).is_none());
    }

    #[test]
    fn instance_and_compatible_ids_have_reactos_terminators() {
        let (instance, len) = output(nt_pnp_abi::BUS_QUERY_INSTANCE_ID, 0x2a, false).unwrap();
        assert!(instance[..len].iter().copied().eq("2A\0".encode_utf16()));
        let (compatible, len) = output(nt_pnp_abi::BUS_QUERY_COMPATIBLE_IDS, 1, true).unwrap();
        assert!(compatible[..len].iter().copied().eq("*PNP09FF\0\0".encode_utf16()));
    }

    #[test]
    fn errors_and_unsupported_ids_leave_caller_buffer_unchanged() {
        let mut buffer = [0xaaaa; 8];
        assert_eq!(
            write_monitor_child_id(nt_pnp_abi::BUS_QUERY_DEVICE_ID, 1, true, &edid(), &mut buffer),
            Err(MonitorChildIdError::BufferTooSmall { needed: 16 })
        );
        assert_eq!(
            write_monitor_child_id(nt_pnp_abi::BUS_QUERY_INSTANCE_ID, 0x1000, true, &edid(), &mut buffer),
            Err(MonitorChildIdError::InstanceIdTooLarge)
        );
        assert_eq!(
            write_monitor_child_id(99, 1, true, &edid(), &mut buffer),
            Ok(MonitorChildIdResult::Unsupported)
        );
        assert_eq!(
            write_monitor_child_id(
                nt_pnp_abi::BUS_QUERY_DEVICE_ID,
                1,
                true,
                &[0; 11],
                &mut buffer,
            ),
            Err(MonitorChildIdError::DescriptorTooShort)
        );
        assert!(buffer.iter().all(|unit| *unit == 0xaaaa));
    }
}
