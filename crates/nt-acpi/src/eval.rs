//! Checked buffers for the standard ACPI PDO method-evaluation IOCTL.

pub const IOCTL_ACPI_EVAL_METHOD: u32 = 0x0032_c004;
pub const IOCTL_ACPI_EVAL_METHOD_EX: u32 = 0x0032_c018;
pub const ACPI_EVAL_INPUT_BUFFER_LEN: usize = 8;
pub const ACPI_EVAL_INPUT_BUFFER_EX_LEN: usize = 260;
/// Native `sizeof(ACPI_EVAL_OUTPUT_BUFFER)` for the shipped amd64 provider.
pub const ACPI_EVAL_OUTPUT_PROBE_LEN: usize = 20;

const EVAL_INPUT_SIGNATURE: u32 = u32::from_be_bytes(*b"BieA");
const EVAL_INPUT_EX_SIGNATURE: u32 = u32::from_be_bytes(*b"AieA");
const EVAL_OUTPUT_SIGNATURE: u32 = u32::from_be_bytes(*b"BoeA");
const EVAL_OUTPUT_HEADER_LEN: usize = 12;
const METHOD_ARGUMENT_STORAGE_LEN: usize = 8;
const METHOD_ARGUMENT_INTEGER: u16 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiEvalError {
    Truncated,
    InvalidMethodName,
    InvalidOutput,
    InvalidRequiredLength,
    InvalidIntegerResult,
}

/// Build an argument-free `ACPI_EVAL_INPUT_BUFFER` for one exact ACPI NameSeg.
pub fn eval_method_input(
    method: [u8; 4],
) -> Result<[u8; ACPI_EVAL_INPUT_BUFFER_LEN], AcpiEvalError> {
    if !valid_name_seg(method) {
        return Err(AcpiEvalError::InvalidMethodName);
    }
    let mut input = [0u8; ACPI_EVAL_INPUT_BUFFER_LEN];
    input[..4].copy_from_slice(&EVAL_INPUT_SIGNATURE.to_le_bytes());
    input[4..].copy_from_slice(&method);
    Ok(input)
}

/// Build a no-argument full-path `ACPI_EVAL_INPUT_BUFFER_EX`.
pub fn eval_method_input_ex(
    method_path: &str,
) -> Result<[u8; ACPI_EVAL_INPUT_BUFFER_EX_LEN], AcpiEvalError> {
    if method_path.len() >= ACPI_EVAL_INPUT_BUFFER_EX_LEN - 4
        || crate::namespace::validate_absolute_path(method_path.as_bytes()).is_err()
    {
        return Err(AcpiEvalError::InvalidMethodName);
    }
    let mut input = [0u8; ACPI_EVAL_INPUT_BUFFER_EX_LEN];
    input[..4].copy_from_slice(&EVAL_INPUT_EX_SIGNATURE.to_le_bytes());
    input[4..4 + method_path.len()].copy_from_slice(method_path.as_bytes());
    Ok(input)
}

/// Validate an overflow probe and return the provider's exact retry size.
///
/// The ReactOS provider writes `Signature`, `Length`, and `Count`, then reports the same required
/// length through `IoStatus.Information`. The executive validates both values independently.
pub fn eval_output_required_len(probe: &[u8], maximum: usize) -> Result<usize, AcpiEvalError> {
    if probe.len() < EVAL_OUTPUT_HEADER_LEN {
        return Err(AcpiEvalError::Truncated);
    }
    if read_u32(probe, 0)? != EVAL_OUTPUT_SIGNATURE {
        return Err(AcpiEvalError::InvalidOutput);
    }
    let required = read_u32(probe, 4)? as usize;
    let count = read_u32(probe, 8)? as usize;
    let minimum = count
        .checked_mul(METHOD_ARGUMENT_STORAGE_LEN)
        .and_then(|bytes| EVAL_OUTPUT_HEADER_LEN.checked_add(bytes))
        .ok_or(AcpiEvalError::InvalidRequiredLength)?;
    if count == 0
        || required <= ACPI_EVAL_OUTPUT_PROBE_LEN
        || required < minimum
        || required > maximum
    {
        return Err(AcpiEvalError::InvalidRequiredLength);
    }
    Ok(required)
}

/// Decode one exact integer result, as used for `_SEG` and `_BBN`.
pub fn parse_integer_evaluation(bytes: &[u8]) -> Result<u32, AcpiEvalError> {
    if bytes.len() < EVAL_OUTPUT_HEADER_LEN {
        return Err(AcpiEvalError::Truncated);
    }
    let declared = read_u32(bytes, 4)? as usize;
    if read_u32(bytes, 0)? != EVAL_OUTPUT_SIGNATURE
        || declared != bytes.len()
        || declared != ACPI_EVAL_OUTPUT_PROBE_LEN
        || read_u32(bytes, 8)? != 1
        || read_u16(bytes, 12)? != METHOD_ARGUMENT_INTEGER
        || read_u16(bytes, 14)? != 4
    {
        return Err(AcpiEvalError::InvalidIntegerResult);
    }
    read_u32(bytes, 16).map_err(|_| AcpiEvalError::InvalidIntegerResult)
}

fn valid_name_seg(method: [u8; 4]) -> bool {
    matches!(method[0], b'A'..=b'Z' | b'_')
        && method[1..]
            .iter()
            .all(|byte| matches!(*byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AcpiEvalError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(AcpiEvalError::Truncated)?;
    Ok(u16::from_le_bytes(value.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AcpiEvalError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(AcpiEvalError::Truncated)?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output_header(length: u32, count: u32) -> [u8; ACPI_EVAL_OUTPUT_PROBE_LEN] {
        let mut bytes = [0u8; ACPI_EVAL_OUTPUT_PROBE_LEN];
        bytes[..4].copy_from_slice(&EVAL_OUTPUT_SIGNATURE.to_le_bytes());
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[8..12].copy_from_slice(&count.to_le_bytes());
        bytes
    }

    #[test]
    fn simple_input_matches_frozen_provider_abi() {
        assert_eq!(
            eval_method_input(*b"_PRT").unwrap(),
            [0x41, 0x65, 0x69, 0x42, b'_', b'P', b'R', b'T']
        );
        assert_eq!(
            eval_method_input(*b"1PRT"),
            Err(AcpiEvalError::InvalidMethodName)
        );
        assert_eq!(
            eval_method_input(*b"_prT"),
            Err(AcpiEvalError::InvalidMethodName)
        );
    }

    #[test]
    fn extended_input_is_exact_bounded_canonical_full_path() {
        let input = eval_method_input_ex("\\_SB_.PCI0.BRG0._PRT").unwrap();
        assert_eq!(&input[..4], &[0x41, 0x65, 0x69, 0x41]);
        assert_eq!(&input[4..24], b"\\_SB_.PCI0.BRG0._PRT");
        assert_eq!(input[24], 0);
        assert!(input[25..].iter().all(|byte| *byte == 0));
        assert_eq!(
            eval_method_input_ex("_SB_.PCI0._PRT"),
            Err(AcpiEvalError::InvalidMethodName)
        );
        assert_eq!(
            eval_method_input_ex("\\_SB_.pci0._PRT"),
            Err(AcpiEvalError::InvalidMethodName)
        );
    }

    #[test]
    fn overflow_probe_requires_exact_larger_bounded_retry() {
        assert_eq!(
            eval_output_required_len(&output_header(84, 4), 4096),
            Ok(84)
        );
        assert_eq!(
            eval_output_required_len(&output_header(20, 1), 4096),
            Err(AcpiEvalError::InvalidRequiredLength)
        );
        assert_eq!(
            eval_output_required_len(&output_header(35, 3), 4096),
            Err(AcpiEvalError::InvalidRequiredLength)
        );
        assert_eq!(
            eval_output_required_len(&output_header(4097, 1), 4096),
            Err(AcpiEvalError::InvalidRequiredLength)
        );
        assert_eq!(
            eval_output_required_len(&[0; ACPI_EVAL_OUTPUT_PROBE_LEN], 4096),
            Err(AcpiEvalError::InvalidOutput)
        );
    }

    #[test]
    fn integer_result_requires_exact_single_argument() {
        let mut bytes = output_header(ACPI_EVAL_OUTPUT_PROBE_LEN as u32, 1);
        bytes[12..14].copy_from_slice(&METHOD_ARGUMENT_INTEGER.to_le_bytes());
        bytes[14..16].copy_from_slice(&4u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        assert_eq!(parse_integer_evaluation(&bytes), Ok(0x1234_5678));

        let mut wrong_count = bytes;
        wrong_count[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            parse_integer_evaluation(&wrong_count),
            Err(AcpiEvalError::InvalidIntegerResult)
        );
        assert_eq!(
            parse_integer_evaluation(&bytes[..19]),
            Err(AcpiEvalError::InvalidIntegerResult)
        );
    }
}
