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
    unsafe { format_impl(NarrowFormat(format), false, true, args, output) }
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
    unsafe { format_impl(WideFormat(format), true, true, args, output) }
}

/// Format an `RtlFormatMessage` insertion fragment.
///
/// Message insertion fragments use the wide printf grammar, but unknown conversions omit the
/// leading percent sign. `arguments_are_ansi` reverses the default `%s`/`%S` and `%c`/`%C`
/// interpretation in the same way as the native routine.
///
/// # Safety
/// `format` and every pointer described by it must satisfy the C printf contract.
pub unsafe fn format_wide_message<A: Arguments, O: Output>(
    format: *const u16,
    arguments_are_ansi: bool,
    args: &mut A,
    output: &mut O,
) -> Result<usize, ()> {
    if format.is_null() {
        return Err(());
    }
    unsafe { format_impl(WideFormat(format), !arguments_are_ansi, false, args, output) }
}

unsafe fn format_impl<F: FormatInput, A: Arguments, O: Output>(
    format: F,
    wide_output: bool,
    unknown_with_percent: bool,
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
                width = width
                    .saturating_mul(10)
                    .saturating_add((digit - b'0') as usize);
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
                let base = if spec == b'o' {
                    8
                } else if spec == b'u' {
                    10
                } else {
                    16
                };
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
            b'f' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                let value = f64::from_bits(unsafe { args.next(ArgumentKind::Double) });
                emit_float(output, &mut position, value, spec, flags, width, precision)?;
            }
            other => {
                if unknown_with_percent {
                    emit(output, &mut position, b'%' as u16)?;
                }
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
        b'F' => (Length::L, 1),
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
        Length::Ll | Length::I64 => unsafe {
            core::ptr::write_unaligned(pointer as *mut i64, value as i64)
        },
        Length::I | Length::Z => unsafe {
            core::ptr::write_unaligned(pointer as *mut isize, value as isize)
        },
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

struct FloatText {
    bytes: [u8; 512],
    length: usize,
}

impl FloatText {
    fn new() -> Self {
        Self {
            bytes: [0; 512],
            length: 0,
        }
    }

    fn push(&mut self, byte: u8) -> Result<(), ()> {
        let slot = self.bytes.get_mut(self.length).ok_or(())?;
        *slot = byte;
        self.length += 1;
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), ()> {
        for byte in bytes {
            self.push(*byte)?;
        }
        Ok(())
    }

    fn remove(&mut self, index: usize) {
        if index >= self.length {
            return;
        }
        self.bytes.copy_within(index + 1..self.length, index);
        self.length -= 1;
    }

    fn exponent_index(&self) -> Option<usize> {
        self.bytes[..self.length]
            .iter()
            .position(|byte| *byte == b'e' || *byte == b'E')
    }

    fn strip_fraction_zeroes(&mut self, keep_point: bool) {
        let mut end = self.exponent_index().unwrap_or(self.length);
        if !self.bytes[..end].contains(&b'.') {
            return;
        }
        while end > 0 && self.bytes[end - 1] == b'0' {
            self.remove(end - 1);
            end -= 1;
        }
        if end > 0 && self.bytes[end - 1] == b'.' && !keep_point {
            self.remove(end - 1);
        }
    }
}

impl core::fmt::Write for FloatText {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        self.extend(value.as_bytes()).map_err(|_| core::fmt::Error)
    }
}

fn pow10(exponent: usize) -> f64 {
    let mut value = 1.0;
    for _ in 0..exponent {
        value *= 10.0;
    }
    value
}

fn decimal_exponent(mut value: f64) -> i32 {
    if value == 0.0 {
        return 0;
    }
    let mut exponent = 0i32;
    while value >= 10.0 {
        value /= 10.0;
        exponent += 1;
    }
    while value < 1.0 {
        value *= 10.0;
        exponent -= 1;
    }
    exponent
}

fn push_decimal_u64(text: &mut FloatText, value: u64, minimum_digits: usize) -> Result<(), ()> {
    let mut reversed = [0u8; 32];
    let mut count = 0usize;
    let mut remaining = value;
    loop {
        reversed[count] = b'0' + (remaining % 10) as u8;
        count += 1;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    for _ in count..minimum_digits {
        text.push(b'0')?;
    }
    for digit in reversed[..count].iter().rev() {
        text.push(*digit)?;
    }
    Ok(())
}

fn fixed_scaled(value: u64, fraction: usize, extra_zeroes: usize) -> Result<FloatText, ()> {
    let mut digits = FloatText::new();
    push_decimal_u64(&mut digits, value, fraction + 1)?;
    if fraction == 0 {
        for _ in 0..extra_zeroes {
            digits.push(b'0')?;
        }
        return Ok(digits);
    }
    let point = digits.length - fraction;
    if digits.length == digits.bytes.len() {
        return Err(());
    }
    digits.bytes.copy_within(point..digits.length, point + 1);
    digits.bytes[point] = b'.';
    digits.length += 1;
    for _ in 0..extra_zeroes {
        digits.push(b'0')?;
    }
    Ok(digits)
}

fn render_fixed(value: f64, precision: usize) -> Result<FloatText, ()> {
    let computed = precision.min(17);
    let extra = precision.saturating_sub(computed);
    let scale = pow10(computed);
    let scaled = value * scale;
    if scaled.is_finite() && scaled <= u64::MAX as f64 - 1.0 {
        return fixed_scaled((scaled + 0.5) as u64, computed, extra);
    }

    // Large fixed values cannot pass through the u64-scaled ReactOS algorithm. Core's
    // allocation-free Dragon fallback keeps the output correct and bounded for all finite f64s.
    let mut text = FloatText::new();
    use core::fmt::Write;
    core::write!(&mut text, "{value:.computed$}").map_err(|_| ())?;
    for _ in 0..extra {
        text.push(b'0')?;
    }
    Ok(text)
}

fn render_scientific(value: f64, precision: usize, upper: bool) -> Result<(FloatText, i32), ()> {
    let computed = precision.min(17);
    let extra = precision.saturating_sub(computed);
    let mut exponent = decimal_exponent(value);
    let normalized = if value == 0.0 {
        0.0
    } else if exponent >= 0 {
        value / pow10(exponent as usize)
    } else {
        value * pow10((-exponent) as usize)
    };
    let scale = pow10(computed);
    let mut scaled = (normalized * scale + 0.5) as u64;
    let carry = pow10(computed + 1) as u64;
    if scaled >= carry {
        exponent += 1;
        scaled /= 10;
    }
    let mut text = fixed_scaled(scaled, computed, extra)?;
    text.push(if upper { b'E' } else { b'e' })?;
    text.push(if exponent < 0 { b'-' } else { b'+' })?;
    let magnitude = exponent.unsigned_abs() as u64;
    push_decimal_u64(&mut text, magnitude, 3)?;
    Ok((text, exponent))
}

fn ensure_decimal_point(text: &mut FloatText) -> Result<(), ()> {
    let end = text.exponent_index().unwrap_or(text.length);
    if text.bytes[..end].contains(&b'.') {
        return Ok(());
    }
    if text.length == text.bytes.len() {
        return Err(());
    }
    text.bytes.copy_within(end..text.length, end + 1);
    text.bytes[end] = b'.';
    text.length += 1;
    Ok(())
}

fn render_float_magnitude(
    value: f64,
    spec: u8,
    precision: Option<usize>,
    alternate: bool,
) -> Result<FloatText, ()> {
    let requested = precision.unwrap_or(6);
    if value.is_nan() || value.is_infinite() {
        let mut text = FloatText::new();
        text.push(b'1')?;
        if requested != 0 || alternate {
            text.push(b'.')?;
        }
        text.extend(if value.is_nan() { b"#QNAN" } else { b"#INF" })?;
        return Ok(text);
    }

    match spec {
        b'e' | b'E' => {
            let (mut text, _) = render_scientific(value, requested, spec == b'E')?;
            if alternate && requested == 0 {
                ensure_decimal_point(&mut text)?;
            }
            Ok(text)
        }
        b'g' | b'G' => {
            let significant = if requested == 0 { 1 } else { requested };
            let fractional = significant.saturating_sub(1);
            let exponent = decimal_exponent(value);
            if exponent < -4 || exponent >= fractional as i32 {
                let (mut text, _) = render_scientific(value, fractional, spec == b'G')?;
                if alternate {
                    ensure_decimal_point(&mut text)?;
                }
                Ok(text)
            } else {
                let decimals = if exponent >= 0 {
                    fractional.saturating_sub(exponent as usize)
                } else {
                    fractional.saturating_add((-exponent) as usize)
                };
                let mut text = render_fixed(value, decimals)?;
                text.strip_fraction_zeroes(alternate);
                if alternate {
                    ensure_decimal_point(&mut text)?;
                }
                Ok(text)
            }
        }
        // ReactOS NT5 has hexadecimal a/A marked TODO and deliberately falls through to decimal f.
        b'f' | b'a' | b'A' => {
            let mut text = render_fixed(value, requested)?;
            if alternate && requested == 0 {
                ensure_decimal_point(&mut text)?;
            }
            Ok(text)
        }
        _ => Err(()),
    }
}

fn emit_float<O: Output>(
    output: &mut O,
    position: &mut usize,
    value: f64,
    spec: u8,
    flags: Flags,
    width: usize,
    precision: Option<usize>,
) -> Result<(), ()> {
    let negative = value < 0.0;
    let magnitude = if negative { -value } else { value };
    let text = render_float_magnitude(magnitude, spec, precision, flags.alternate)?;
    let sign = if negative {
        Some(b'-' as u16)
    } else if flags.plus {
        Some(b'+' as u16)
    } else if flags.space {
        Some(b' ' as u16)
    } else {
        None
    };
    let content = text.length + sign.is_some() as usize;
    let padding = width.saturating_sub(content);
    let zero_pad = flags.zero && !flags.left;
    if !flags.left && !zero_pad {
        emit_repeat(output, position, b' ' as u16, padding)?;
    }
    if let Some(sign) = sign {
        emit(output, position, sign)?;
    }
    if zero_pad {
        emit_repeat(output, position, b'0' as u16, padding)?;
    }
    for byte in &text.bytes[..text.length] {
        emit(output, position, *byte as u16)?;
    }
    if flags.left {
        emit_repeat(output, position, b' ' as u16, padding)?;
    }
    Ok(())
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
        if upper {
            b'X'
        } else {
            b'x'
        }
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
        assert_eq!(
            render(b"%hhd %hu %p\0", &[0xff, 0x1_0001, 0x123]),
            Ok(b"-1 1 0000000000000123".to_vec())
        );
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
        let mut args = TestArgs {
            values: &[],
            index: 0,
        };
        let mut exact = TestOutput {
            units: Vec::new(),
            capacity: 4,
        };
        assert_eq!(
            unsafe { format_narrow(b"test\0".as_ptr(), &mut args, &mut exact) },
            Ok(4)
        );
        assert_eq!(
            exact.units,
            b"test".iter().map(|byte| *byte as u16).collect::<Vec<_>>()
        );

        let mut args = TestArgs {
            values: &[],
            index: 0,
        };
        let mut short = TestOutput {
            units: Vec::new(),
            capacity: 3,
        };
        assert_eq!(
            unsafe { format_narrow(b"test\0".as_ptr(), &mut args, &mut short) },
            Err(())
        );
        assert_eq!(
            short.units,
            b"tes".iter().map(|byte| *byte as u16).collect::<Vec<_>>()
        );
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

    #[test]
    fn float_fixed_rounding_specials_and_legacy_hex_fallthrough() {
        assert_eq!(
            render(b"%f\0", &[3.14159265359f64.to_bits()]),
            Ok(b"3.141593".to_vec())
        );
        assert_eq!(render(b"%.0f\0", &[0.5f64.to_bits()]), Ok(b"1".to_vec()));
        assert_eq!(
            render(b"%.0f\0", &[(-0.5f64).to_bits()]),
            Ok(b"-1".to_vec())
        );
        assert_eq!(
            render(b"%f\0", &[(-0.0f64).to_bits()]),
            Ok(b"0.000000".to_vec())
        );
        assert_eq!(render(b"%#.0f\0", &[0.6f64.to_bits()]), Ok(b"1.".to_vec()));
        assert_eq!(
            render(b"%.20f\0", &[1.0f64.to_bits()]),
            Ok(b"1.00000000000000000000".to_vec())
        );
        assert_eq!(
            render(b"%a %A\0", &[8.6f64.to_bits(), 8.6f64.to_bits()]),
            Ok(b"8.600000 8.600000".to_vec())
        );
        assert_eq!(
            render(b"%f\0", &[f64::NAN.to_bits()]),
            Ok(b"1.#QNAN".to_vec())
        );
        assert_eq!(
            render(b"%f\0", &[f64::INFINITY.to_bits()]),
            Ok(b"1.#INF".to_vec())
        );
        assert_eq!(
            render(b"%f\0", &[f64::NEG_INFINITY.to_bits()]),
            Ok(b"-1.#INF".to_vec())
        );
    }

    #[test]
    fn float_scientific_general_and_width_match_nt5() {
        assert_eq!(
            render(b"% 014.4e\0", &[8.6f64.to_bits()]),
            Ok(b" 008.6000e+000".to_vec())
        );
        assert_eq!(
            render(b"%.1e\0", &[9.96f64.to_bits()]),
            Ok(b"1.0e+001".to_vec())
        );
        assert_eq!(
            render(b"%.2E\0", &[0.0125f64.to_bits()]),
            Ok(b"1.25E-002".to_vec())
        );
        assert_eq!(render(b"%g\0", &[8.6f64.to_bits()]), Ok(b"8.6".to_vec()));
        assert_eq!(
            render(b"%g\0", &[0.0005f64.to_bits()]),
            Ok(b"0.0005".to_vec())
        );
        assert_eq!(
            render(b"%g\0", &[0.00005f64.to_bits()]),
            Ok(b"5.00000e-005".to_vec())
        );
        assert_eq!(
            render(b"%g\0", &[100000.0f64.to_bits()]),
            Ok(b"1.00000e+005".to_vec())
        );
        assert_eq!(
            render(b"%#1.1g\0", &[789456123.0f64.to_bits()]),
            Ok(b"8.e+008".to_vec())
        );
        assert_eq!(
            render(b"%G\0", &[0.00005f64.to_bits()]),
            Ok(b"5.00000E-005".to_vec())
        );
    }

    #[test]
    fn legacy_upper_f_is_a_modifier_and_does_not_consume_an_argument() {
        assert_eq!(render(b"%F\0", &[8.6f64.to_bits()]), Ok(Vec::new()));
    }
}
