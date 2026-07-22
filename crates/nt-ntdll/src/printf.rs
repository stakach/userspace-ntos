//! Allocation-free NT CRT printf formatting core.

/// ABI type the formatter needs from the variadic argument source.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArgumentKind {
    Int,
    UInt,
    I64,
    U64,
    Pointer,
    Double,
}

/// Source of promoted C variadic arguments.
pub trait Arguments {
    /// Return the next argument as raw bits using the requested ABI type.
    ///
    /// # Safety
    /// The caller's format string must describe the actual variadic argument list.
    unsafe fn next(&mut self, kind: ArgumentKind) -> u64;
}

/// Output destination. Returning `false` reports a full bounded buffer.
pub trait Output {
    fn write(&mut self, unit: u16) -> bool;
}

#[derive(Copy, Clone, Default)]
struct Flags {
    left: bool,
    plus: bool,
    space: bool,
    alternate: bool,
    zero: bool,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Length {
    Default,
    Hh,
    H,
    L,
    Ll,
    W,
    I,
    I32,
    I64,
    Z,
}

trait FormatInput {
    unsafe fn unit(&self, index: usize) -> u16;
}

struct NarrowFormat(*const u8);
struct WideFormat(*const u16);

impl FormatInput for NarrowFormat {
    unsafe fn unit(&self, index: usize) -> u16 {
        unsafe { *self.0.add(index) as u16 }
    }
}

impl FormatInput for WideFormat {
    unsafe fn unit(&self, index: usize) -> u16 {
        unsafe { *self.0.add(index) }
    }
}

/// Format a NUL-terminated narrow format string.
///
/// # Safety
/// `format` and every pointer described by it must satisfy the C printf contract.
pub unsafe fn format_narrow<A: Arguments, O: Output>(
    format: *const u8,
    args: &mut A,
    output: &mut O,
) -> Result<usize, ()> {
    if format.is_null() {
        return Err(());
    }
    unsafe { format_impl(NarrowFormat(format), false, args, output) }
}

/// Format a NUL-terminated UTF-16 format string.
///
/// # Safety
/// `format` and every pointer described by it must satisfy the C printf contract.
pub unsafe fn format_wide<A: Arguments, O: Output>(
    format: *const u16,
    args: &mut A,
    output: &mut O,
) -> Result<usize, ()> {
    if format.is_null() {
        return Err(());
    }
    unsafe { format_impl(WideFormat(format), true, args, output) }
}

unsafe fn format_impl<F: FormatInput, A: Arguments, O: Output>(
    format: F,
    wide_output: bool,
    args: &mut A,
    output: &mut O,
) -> Result<usize, ()> {
    let mut position = 0usize;
    let mut index = 0usize;
    loop {
        let unit = unsafe { format.unit(index) };
        if unit == 0 {
            return Ok(position);
        }
        if unit != b'%' as u16 {
            emit(output, &mut position, unit)?;
            index += 1;
            continue;
        }
        index += 1;
        if unsafe { format.unit(index) } == b'%' as u16 {
            emit(output, &mut position, b'%' as u16)?;
            index += 1;
            continue;
        }

        let mut flags = Flags::default();
        loop {
            match unsafe { format.unit(index) } as u8 {
                b'-' => flags.left = true,
                b'+' => flags.plus = true,
                b' ' => flags.space = true,
                b'#' => flags.alternate = true,
                b'0' => flags.zero = true,
                _ => break,
            }
            index += 1;
        }

        let mut width = 0usize;
        if unsafe { format.unit(index) } == b'*' as u16 {
            let raw = unsafe { args.next(ArgumentKind::Int) } as u32 as i32;
            if raw < 0 {
                flags.left = true;
                width = raw.unsigned_abs() as usize;
            } else {
                width = raw as usize;
            }
            index += 1;
        } else {
            while let digit @ b'0'..=b'9' = unsafe { format.unit(index) } as u8 {
                width = width.saturating_mul(10).saturating_add((digit - b'0') as usize);
                index += 1;
            }
        }

        let mut precision = None;
        if unsafe { format.unit(index) } == b'.' as u16 {
            index += 1;
            if unsafe { format.unit(index) } == b'*' as u16 {
                let raw = unsafe { args.next(ArgumentKind::Int) } as u32 as i32;
                if raw >= 0 {
                    precision = Some(raw as usize);
                }
                index += 1;
            } else {
                let mut value = 0usize;
                while let digit @ b'0'..=b'9' = unsafe { format.unit(index) } as u8 {
                    value = value
                        .saturating_mul(10)
                        .saturating_add((digit - b'0') as usize);
                    index += 1;
                }
                precision = Some(value);
            }
        }

        let (length, consumed) = unsafe { parse_length(&format, index) };
        index += consumed;
        let spec = unsafe { format.unit(index) } as u8;
        if spec == 0 {
            return Ok(position);
        }
        index += 1;

        match spec {
            b'd' | b'i' => {
                let signed = unsafe { next_signed(args, length) };
                let negative = signed < 0;
                let magnitude = if negative {
                    signed.wrapping_neg() as u64
                } else {
                    signed as u64
                };
                emit_integer(
                    output,
                    &mut position,
                    magnitude,
                    10,
                    false,
                    negative,
                    flags,
                    width,
                    precision,
                    false,
                )?;
            }
            b'u' | b'o' | b'x' | b'X' => {
                let value = unsafe { next_unsigned(args, length) };
                let base = if spec == b'o' { 8 } else if spec == b'u' { 10 } else { 16 };
                emit_integer(
                    output,
                    &mut position,
                    value,
                    base,
                    spec == b'X',
                    false,
                    flags,
                    width,
                    precision,
                    false,
                )?;
            }
            b'p' => {
                let value = unsafe { args.next(ArgumentKind::Pointer) };
                if width == 0 {
                    width = core::mem::size_of::<usize>() * 2;
                    flags.zero = true;
                }
                emit_integer(
                    output,
                    &mut position,
                    value,
                    16,
                    false,
                    false,
                    flags,
                    width,
                    precision,
                    true,
                )?;
            }
            b'c' | b'C' => {
                let wide = string_is_wide(wide_output, spec == b'C', length);
                let unit = unsafe { args.next(ArgumentKind::Int) } as u16;
                let unit = if wide { unit } else { unit as u8 as u16 };
                emit_padded_units(output, &mut position, 1, width, flags.left, |out, pos| {
                    emit(out, pos, unit)
                })?;
            }
            b's' | b'S' => {
                let pointer = unsafe { args.next(ArgumentKind::Pointer) } as usize;
                let wide = string_is_wide(wide_output, spec == b'S', length);
                unsafe {
                    emit_string(
                        output,
                        &mut position,
                        pointer,
                        wide,
                        None,
                        width,
                        precision,
                        flags.left,
                    )
                }?;
            }
            b'Z' => {
                let descriptor = unsafe { args.next(ArgumentKind::Pointer) } as usize;
                let wide = length == Length::W || length == Length::L || wide_output;
                let (pointer, units) = unsafe { read_counted_string(descriptor, wide) };
                unsafe {
                    emit_string(
                        output,
                        &mut position,
                        pointer,
                        wide,
                        Some(units),
                        width,
                        precision,
                        flags.left,
                    )
                }?;
            }
            b'n' => {
                let pointer = unsafe { args.next(ArgumentKind::Pointer) } as usize;
                unsafe { write_count(pointer, length, position) };
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                // Consume the correctly promoted argument, but fail explicitly until the float
                // renderer lands. Callers must never receive a plausible partial string.
                let _ = unsafe { args.next(ArgumentKind::Double) };
                return Err(());
            }
            other => {
                emit(output, &mut position, b'%' as u16)?;
                emit(output, &mut position, other as u16)?;
            }
        }
    }
}

unsafe fn parse_length<F: FormatInput>(format: &F, index: usize) -> (Length, usize) {
    let first = unsafe { format.unit(index) } as u8;
    match first {
        b'h' => {
            if unsafe { format.unit(index + 1) } == b'h' as u16 {
                (Length::Hh, 2)
            } else {
                (Length::H, 1)
            }
        }
        b'l' => {
            if unsafe { format.unit(index + 1) } == b'l' as u16 {
                (Length::Ll, 2)
            } else {
                (Length::L, 1)
            }
        }
        b'L' => (Length::L, 1),
        b'w' => (Length::W, 1),
        b'I' => {
            let second = unsafe { format.unit(index + 1) };
            if second == b'3' as u16 && unsafe { format.unit(index + 2) } == b'2' as u16 {
                (Length::I32, 3)
            } else if second == b'6' as u16 && unsafe { format.unit(index + 2) } == b'4' as u16 {
                (Length::I64, 3)
            } else {
                (Length::I, 1)
            }
        }
        b'z' => (Length::Z, 1),
        _ => (Length::Default, 0),
    }
}

unsafe fn next_signed<A: Arguments>(args: &mut A, length: Length) -> i64 {
    match length {
        Length::Ll | Length::I64 => (unsafe { args.next(ArgumentKind::I64) }) as i64,
        Length::I | Length::Z => (unsafe { args.next(ArgumentKind::I64) }) as isize as i64,
        Length::Hh => (unsafe { args.next(ArgumentKind::Int) }) as u32 as i8 as i64,
        Length::H => (unsafe { args.next(ArgumentKind::Int) }) as u32 as i16 as i64,
        _ => (unsafe { args.next(ArgumentKind::Int) }) as u32 as i32 as i64,
    }
}

unsafe fn next_unsigned<A: Arguments>(args: &mut A, length: Length) -> u64 {
    match length {
        Length::Ll | Length::I64 => unsafe { args.next(ArgumentKind::U64) },
        Length::I | Length::Z => (unsafe { args.next(ArgumentKind::U64) }) as usize as u64,
        Length::Hh => (unsafe { args.next(ArgumentKind::UInt) }) as u8 as u64,
        Length::H => (unsafe { args.next(ArgumentKind::UInt) }) as u16 as u64,
        _ => (unsafe { args.next(ArgumentKind::UInt) }) as u32 as u64,
    }
}

fn string_is_wide(wide_output: bool, upper: bool, length: Length) -> bool {
    match length {
        Length::H | Length::Hh => false,
        Length::L | Length::Ll | Length::W => true,
        _ => wide_output ^ upper,
    }
}

unsafe fn read_counted_string(descriptor: usize, wide: bool) -> (usize, usize) {
    if descriptor == 0 {
        return (0, 0);
    }
    let length = unsafe { core::ptr::read_unaligned(descriptor as *const u16) } as usize;
    let pointer = unsafe { core::ptr::read_unaligned((descriptor + 8) as *const usize) };
    (pointer, if wide { length / 2 } else { length })
}

unsafe fn write_count(pointer: usize, length: Length, value: usize) {
    if pointer == 0 {
        return;
    }
    match length {
        Length::Hh => unsafe { core::ptr::write_unaligned(pointer as *mut i8, value as i8) },
        Length::H => unsafe { core::ptr::write_unaligned(pointer as *mut i16, value as i16) },
        Length::Ll | Length::I64 => {
            unsafe { core::ptr::write_unaligned(pointer as *mut i64, value as i64) }
        }
        Length::I | Length::Z => {
            unsafe { core::ptr::write_unaligned(pointer as *mut isize, value as isize) }
        }
        _ => unsafe { core::ptr::write_unaligned(pointer as *mut i32, value as i32) },
    }
}

unsafe fn string_length(pointer: usize, wide: bool, bounded: Option<usize>) -> usize {
    if pointer == 0 {
        return 6;
    }
    if let Some(length) = bounded {
        return length;
    }
    let mut length = 0usize;
    loop {
        let unit = if wide {
            unsafe { core::ptr::read_unaligned((pointer as *const u16).add(length)) }
        } else {
            unsafe { core::ptr::read((pointer as *const u8).add(length)) as u16 }
        };
        if unit == 0 {
            return length;
        }
        length += 1;
    }
}

unsafe fn emit_string<O: Output>(
    output: &mut O,
    position: &mut usize,
    pointer: usize,
    wide: bool,
    bounded: Option<usize>,
    width: usize,
    precision: Option<usize>,
    left: bool,
) -> Result<(), ()> {
    let mut length = unsafe { string_length(pointer, wide, bounded) };
    if let Some(limit) = precision {
        length = length.min(limit);
    }
    emit_padded_units(output, position, length, width, left, |out, pos| {
        for index in 0..length {
            let unit = if pointer == 0 {
                b"(null)"[index] as u16
            } else if wide {
                unsafe { core::ptr::read_unaligned((pointer as *const u16).add(index)) }
            } else {
                unsafe { core::ptr::read((pointer as *const u8).add(index)) as u16 }
            };
            emit(out, pos, unit)?;
        }
        Ok(())
    })
}

#[allow(clippy::too_many_arguments)]
fn emit_integer<O: Output>(
    output: &mut O,
    position: &mut usize,
    value: u64,
    base: u64,
    upper: bool,
    negative: bool,
    flags: Flags,
    width: usize,
    precision: Option<usize>,
    pointer: bool,
) -> Result<(), ()> {
    let mut digits = [0u16; 64];
    let mut digit_count = 0usize;
    if value != 0 || precision != Some(0) || pointer {
        let mut remaining = value;
        loop {
            let digit = (remaining % base) as u8;
            digits[digit_count] = if digit < 10 {
                (b'0' + digit) as u16
            } else if upper {
                (b'A' + digit - 10) as u16
            } else {
                (b'a' + digit - 10) as u16
            };
            digit_count += 1;
            remaining /= base;
            if remaining == 0 {
                break;
            }
        }
    }
    let sign = if negative {
        Some(b'-' as u16)
    } else if flags.plus {
        Some(b'+' as u16)
    } else if flags.space {
        Some(b' ' as u16)
    } else {
        None
    };
    let prefix = if flags.alternate && base == 16 && value != 0 {
        if upper { b'X' } else { b'x' }
    } else {
        0
    };
    let octal_prefix = flags.alternate
        && base == 8
        && (digit_count == 0 || digits[digit_count.saturating_sub(1)] != b'0' as u16);
    let precision_zeroes = precision.unwrap_or(0).saturating_sub(digit_count);
    let content = sign.is_some() as usize
        + if prefix != 0 { 2 } else { 0 }
        + octal_prefix as usize
        + precision_zeroes
        + digit_count;
    let pad = width.saturating_sub(content);
    let zero_pad = flags.zero && !flags.left && precision.is_none();
    if !flags.left && !zero_pad {
        emit_repeat(output, position, b' ' as u16, pad)?;
    }
    if let Some(sign) = sign {
        emit(output, position, sign)?;
    }
    if prefix != 0 {
        emit(output, position, b'0' as u16)?;
        emit(output, position, prefix as u16)?;
    }
    if octal_prefix {
        emit(output, position, b'0' as u16)?;
    }
    emit_repeat(
        output,
        position,
        b'0' as u16,
        precision_zeroes + if zero_pad { pad } else { 0 },
    )?;
    for digit in digits[..digit_count].iter().rev() {
        emit(output, position, *digit)?;
    }
    if flags.left {
        emit_repeat(output, position, b' ' as u16, pad)?;
    }
    Ok(())
}

fn emit_padded_units<O: Output, F: FnOnce(&mut O, &mut usize) -> Result<(), ()>>(
    output: &mut O,
    position: &mut usize,
    length: usize,
    width: usize,
    left: bool,
    body: F,
) -> Result<(), ()> {
    let padding = width.saturating_sub(length);
    if !left {
        emit_repeat(output, position, b' ' as u16, padding)?;
    }
    body(output, position)?;
    if left {
        emit_repeat(output, position, b' ' as u16, padding)?;
    }
    Ok(())
}

fn emit_repeat<O: Output>(
    output: &mut O,
    position: &mut usize,
    unit: u16,
    count: usize,
) -> Result<(), ()> {
    for _ in 0..count {
        emit(output, position, unit)?;
    }
    Ok(())
}

fn emit<O: Output>(output: &mut O, position: &mut usize, unit: u16) -> Result<(), ()> {
    if !output.write(unit) {
        return Err(());
    }
    *position = position.saturating_add(1);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::*;

    struct TestArgs<'a> {
        values: &'a [u64],
        index: usize,
    }

    impl Arguments for TestArgs<'_> {
        unsafe fn next(&mut self, _kind: ArgumentKind) -> u64 {
            let value = self.values[self.index];
            self.index += 1;
            value
        }
    }

    #[derive(Default)]
    struct TestOutput {
        units: Vec<u16>,
        capacity: usize,
    }

    impl Output for TestOutput {
        fn write(&mut self, unit: u16) -> bool {
            if self.units.len() == self.capacity {
                return false;
            }
            self.units.push(unit);
            true
        }
    }

    fn render(format: &[u8], values: &[u64]) -> Result<Vec<u8>, ()> {
        let mut args = TestArgs { values, index: 0 };
        let mut output = TestOutput {
            units: Vec::new(),
            capacity: usize::MAX,
        };
        unsafe { format_narrow(format.as_ptr(), &mut args, &mut output)? };
        Ok(output.units.into_iter().map(|unit| unit as u8).collect())
    }

    #[test]
    fn integers_flags_width_precision_and_lengths() {
        assert_eq!(
            render(
                b"%+06d %#08X %-5u %.4x %I64d\0",
                &[42, 0x2a, 7, 0x2a, (-9i64) as u64]
            ),
            Ok(b"+00042 0X00002A 7     002a -9".to_vec())
        );
        assert_eq!(render(b"%hhd %hu %p\0", &[0xff, 0x1_0001, 0x123]), Ok(b"-1 1 0000000000000123".to_vec()));
    }

    #[test]
    fn narrow_wide_and_counted_strings() {
        #[repr(C)]
        struct Counted {
            length: u16,
            maximum: u16,
            padding: u32,
            buffer: *const u16,
        }
        let narrow = b"smss\0";
        let wide = [b'W' as u16, b'i' as u16, b'n' as u16, 0];
        let counted = Counted {
            length: 6,
            maximum: 8,
            padding: 0,
            buffer: wide.as_ptr(),
        };
        assert_eq!(
            render(
                b"%-6s %.2ws %wZ\0",
                &[
                    narrow.as_ptr() as u64,
                    wide.as_ptr() as u64,
                    &counted as *const Counted as u64,
                ]
            ),
            Ok(b"smss   Wi Win".to_vec())
        );
    }

    #[test]
    fn bounded_output_distinguishes_exact_fit_and_overflow() {
        let mut args = TestArgs { values: &[], index: 0 };
        let mut exact = TestOutput {
            units: Vec::new(),
            capacity: 4,
        };
        assert_eq!(unsafe { format_narrow(b"test\0".as_ptr(), &mut args, &mut exact) }, Ok(4));
        assert_eq!(exact.units, b"test".iter().map(|byte| *byte as u16).collect::<Vec<_>>());

        let mut args = TestArgs { values: &[], index: 0 };
        let mut short = TestOutput {
            units: Vec::new(),
            capacity: 3,
        };
        assert_eq!(unsafe { format_narrow(b"test\0".as_ptr(), &mut args, &mut short) }, Err(()));
        assert_eq!(short.units, b"tes".iter().map(|byte| *byte as u16).collect::<Vec<_>>());
    }

    #[test]
    fn percent_n_records_units_written() {
        let mut count = 0i32;
        assert_eq!(
            render(b"abc%n!\0", &[&mut count as *mut i32 as u64]),
            Ok(b"abc!".to_vec())
        );
        assert_eq!(count, 3);
    }
}
