//! Small decoder for the privileged x86 port-I/O instructions reflected by a hosted-driver #GP.
//!
//! This deliberately recognizes only the architecturally relevant `IN`/`OUT` forms. It is not a
//! general x86 decoder.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortIoDirection {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortIoPort {
    Dx,
    Immediate(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortIoInstruction {
    pub direction: PortIoDirection,
    pub port: PortIoPort,
    pub width_bits: u8,
    pub len: u8,
}

impl PortIoInstruction {
    pub const fn width_bytes(self) -> u8 {
        self.width_bits / 8
    }
}

/// Decode one x86-64 `IN` or `OUT` instruction, including the operand-size override used by the
/// 16-bit forms. A REX prefix is accepted because it is semantically inert for these accumulator
/// and `DX` operands, but it must appear in the architecturally valid position after legacy
/// prefixes.
pub fn decode_port_io_instruction(bytes: &[u8]) -> Option<PortIoInstruction> {
    let mut index = 0usize;
    let mut operand_16 = false;
    if bytes.get(index) == Some(&0x66) {
        operand_16 = true;
        index += 1;
    }
    if bytes
        .get(index)
        .is_some_and(|byte| (0x40..=0x4f).contains(byte))
    {
        index += 1;
    }

    let opcode = *bytes.get(index)?;
    index += 1;
    let (direction, port, width_bits) = match opcode {
        0xec => (PortIoDirection::Read, PortIoPort::Dx, 8),
        0xed => (
            PortIoDirection::Read,
            PortIoPort::Dx,
            if operand_16 { 16 } else { 32 },
        ),
        0xee => (PortIoDirection::Write, PortIoPort::Dx, 8),
        0xef => (
            PortIoDirection::Write,
            PortIoPort::Dx,
            if operand_16 { 16 } else { 32 },
        ),
        0xe4 => (
            PortIoDirection::Read,
            PortIoPort::Immediate(*bytes.get(index)?),
            8,
        ),
        0xe5 => (
            PortIoDirection::Read,
            PortIoPort::Immediate(*bytes.get(index)?),
            if operand_16 { 16 } else { 32 },
        ),
        0xe6 => (
            PortIoDirection::Write,
            PortIoPort::Immediate(*bytes.get(index)?),
            8,
        ),
        0xe7 => (
            PortIoDirection::Write,
            PortIoPort::Immediate(*bytes.get(index)?),
            if operand_16 { 16 } else { 32 },
        ),
        _ => return None,
    };
    if matches!(port, PortIoPort::Immediate(_)) {
        index += 1;
    }
    Some(PortIoInstruction {
        direction,
        port,
        width_bits,
        len: index as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_dx_byte_word_and_dword_forms() {
        assert_eq!(
            decode_port_io_instruction(&[0xec]),
            Some(PortIoInstruction {
                direction: PortIoDirection::Read,
                port: PortIoPort::Dx,
                width_bits: 8,
                len: 1,
            })
        );
        assert_eq!(
            decode_port_io_instruction(&[0x66, 0xef]),
            Some(PortIoInstruction {
                direction: PortIoDirection::Write,
                port: PortIoPort::Dx,
                width_bits: 16,
                len: 2,
            })
        );
        assert_eq!(
            decode_port_io_instruction(&[0xed]),
            Some(PortIoInstruction {
                direction: PortIoDirection::Read,
                port: PortIoPort::Dx,
                width_bits: 32,
                len: 1,
            })
        );
    }

    #[test]
    fn decodes_immediate_port_and_rex_forms() {
        assert_eq!(
            decode_port_io_instruction(&[0xe6, 0x71]),
            Some(PortIoInstruction {
                direction: PortIoDirection::Write,
                port: PortIoPort::Immediate(0x71),
                width_bits: 8,
                len: 2,
            })
        );
        assert_eq!(
            decode_port_io_instruction(&[0x66, 0x40, 0xe5, 0xcf]),
            Some(PortIoInstruction {
                direction: PortIoDirection::Read,
                port: PortIoPort::Immediate(0xcf),
                width_bits: 16,
                len: 4,
            })
        );
    }

    #[test]
    fn rejects_truncated_and_unrelated_instructions() {
        assert_eq!(decode_port_io_instruction(&[]), None);
        assert_eq!(decode_port_io_instruction(&[0x66]), None);
        assert_eq!(decode_port_io_instruction(&[0xe4]), None);
        assert_eq!(decode_port_io_instruction(&[0x90]), None);
        assert_eq!(decode_port_io_instruction(&[0xf3, 0xec]), None);
    }
}
