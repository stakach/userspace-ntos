//! Message-table resource helpers for `RtlFindMessage`.
//!
//! ReactOS stores message strings in an `RT_MESSAGETABLE` resource whose payload starts with a
//! `MESSAGE_RESOURCE_DATA`: a block count, an array of `(LowId, HighId, OffsetToEntries)` records,
//! then a run of variable-length `MESSAGE_RESOURCE_ENTRY` records. The DLL export locates the
//! resource with `LdrFindResource_U`/`LdrAccessResource`; this module performs the pure table walk.

/// `STATUS_SUCCESS`.
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_MESSAGE_NOT_FOUND`.
pub const STATUS_MESSAGE_NOT_FOUND: u32 = 0xC000_0109;
/// `STATUS_RESOURCE_DATA_NOT_FOUND`.
pub const STATUS_RESOURCE_DATA_NOT_FOUND: u32 = 0xC000_0089;
/// `STATUS_INVALID_PARAMETER`.
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// `STATUS_BUFFER_OVERFLOW`.
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

const MESSAGE_RESOURCE_DATA_HEADER: usize = 4;
const MESSAGE_RESOURCE_BLOCK_SIZE: usize = 12;
const MESSAGE_RESOURCE_ENTRY_HEADER: usize = 4;
const MAX_INSERTS: usize = 200;
const INSERT_FORMAT_UNITS: usize = 32;

/// Source of pointer-sized `RtlFormatMessage` argument slots.
pub trait MessageArguments {
    fn next_slot(&mut self) -> Option<u64>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FormatMessageOptions {
    pub maximum_width: u32,
    pub ignore_inserts: bool,
    pub arguments_are_ansi: bool,
    pub arguments_are_an_array: bool,
}

/// Format a NUL-free message into a UTF-16 output buffer.
///
/// The successful length is returned in bytes and includes the terminating NUL, matching the
/// native `ReturnLength` contract. Errors preserve whatever partial output native formatting would
/// have produced and do not return a length.
pub fn format_message(
    message: &[u16],
    options: FormatMessageOptions,
    mut arguments: Option<&mut dyn MessageArguments>,
    output: &mut [u16],
) -> Result<usize, u32> {
    let mut cache = [0u64; MAX_INSERTS];
    let mut cached = 0usize;
    let mut source = 0usize;
    let mut position = 0usize;
    let mut column = 0usize;
    let mut last_space = None;

    while source < message.len() {
        if message[source] == b'%' as u16 {
            let sequence_start = source;
            source += 1;
            let token_start = position;
            let mut reset_column = false;
            let Some(&control) = message.get(source) else {
                return Err(STATUS_INVALID_PARAMETER);
            };
            if (b'1' as u16..=b'9' as u16).contains(&control) {
                let mut insert = 0usize;
                let mut digits = 0usize;
                while let Some(&unit) = message.get(source) {
                    if !(b'0' as u16..=b'9' as u16).contains(&unit) {
                        break;
                    }
                    if digits == 3 {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    insert = insert
                        .checked_mul(10)
                        .and_then(|value| value.checked_add((unit - b'0' as u16) as usize))
                        .ok_or(STATUS_INVALID_PARAMETER)?;
                    digits += 1;
                    source += 1;
                }
                let insert = insert.checked_sub(1).ok_or(STATUS_INVALID_PARAMETER)?;
                let mut format = [0u16; INSERT_FORMAT_UNITS];
                format[0] = b'%' as u16;
                let mut format_len = 1usize;
                let mut stars = 0usize;
                if message.get(source) == Some(&(b'!' as u16)) {
                    source += 1;
                    loop {
                        let Some(&unit) = message.get(source) else {
                            return Err(STATUS_INVALID_PARAMETER);
                        };
                        if unit == b'!' as u16 {
                            source += 1;
                            break;
                        }
                        if format_len == INSERT_FORMAT_UNITS - 1 {
                            return Err(STATUS_INVALID_PARAMETER);
                        }
                        if unit == b'*' as u16 {
                            stars += 1;
                            if stars > 2 {
                                return Err(STATUS_INVALID_PARAMETER);
                            }
                        }
                        format[format_len] = unit;
                        format_len += 1;
                        source += 1;
                    }
                } else {
                    format[1] = b's' as u16;
                    format_len = 2;
                }
                format[format_len] = 0;

                if options.ignore_inserts {
                    write_insert_literal(output, &mut position, &message[sequence_start..source])?;
                } else {
                    let arguments = arguments.as_deref_mut().ok_or(STATUS_INVALID_PARAMETER)?;
                    if insert
                        .checked_add(stars)
                        .is_none_or(|last| last >= MAX_INSERTS)
                    {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    while insert >= cached {
                        cache[cached] = arguments.next_slot().ok_or(STATUS_INVALID_PARAMETER)?;
                        cached += 1;
                    }
                    let mut values = [cache[insert], 0, 0];
                    for star in 0..stars {
                        let value = arguments.next_slot().ok_or(STATUS_INVALID_PARAMETER)?;
                        values[star + 1] = value;
                        if options.arguments_are_an_array || star == 1 {
                            cache[cached] = value;
                            cached += 1;
                        }
                    }
                    write_formatted_insert(
                        output,
                        &mut position,
                        &format,
                        options.arguments_are_ansi,
                        values,
                    )?;
                }
            } else {
                source += 1;
                match control {
                    value if value == b'0' as u16 => break,
                    value if value == b'r' as u16 => {
                        write_reserved(output, &mut position, &[b'\r' as u16])?;
                        reset_column = true;
                    }
                    value if value == b'n' as u16 => {
                        write_reserved(output, &mut position, &[b'\r' as u16, b'\n' as u16])?;
                        reset_column = true;
                    }
                    value if value == b't' as u16 => {
                        column = if column % 8 == 0 {
                            column + 8
                        } else {
                            (column + 7) & !7
                        };
                        last_space = Some(position);
                        write_reserved(output, &mut position, &[b'\t' as u16])?;
                    }
                    value if value == b'b' as u16 => {
                        last_space = Some(position);
                        write_reserved(output, &mut position, &[b' ' as u16])?;
                    }
                    value if options.ignore_inserts => {
                        write_reserved(output, &mut position, &[b'%' as u16, value])?;
                    }
                    value => write_reserved(output, &mut position, &[value])?,
                }
            }
            if reset_column {
                last_space = None;
                column = 0;
            } else {
                column = column.saturating_add(position - token_start);
            }
        } else {
            let mut unit = message[source];
            source += 1;
            if unit == b'\r' as u16 || unit == b'\n' as u16 {
                if message.get(source).is_some_and(|next| {
                    (*next == b'\r' as u16 || *next == b'\n' as u16) && *next != unit
                }) {
                    source += 1;
                }
                if options.maximum_width == 0 {
                    write_reserved(output, &mut position, &[b'\r' as u16, b'\n' as u16])?;
                    last_space = None;
                    column = 0;
                    continue;
                }
                unit = b' ' as u16;
                last_space = Some(position);
            } else if unit == b' ' as u16 {
                last_space = Some(position);
            }
            write_literal(output, &mut position, unit)?;
            column = column.saturating_add(1);
        }

        if options.maximum_width != 0
            && options.maximum_width != u32::MAX
            && column >= options.maximum_width as usize
        {
            apply_wrap(output, &mut position, &mut column, &mut last_space)?;
        }
    }

    if position == output.len() {
        return Err(STATUS_BUFFER_OVERFLOW);
    }
    output[position] = 0;
    position
        .checked_add(1)
        .and_then(|units| units.checked_mul(2))
        .ok_or(STATUS_BUFFER_OVERFLOW)
}

fn write_literal(output: &mut [u16], position: &mut usize, unit: u16) -> Result<(), u32> {
    let Some(slot) = output.get_mut(*position) else {
        return Err(STATUS_BUFFER_OVERFLOW);
    };
    *slot = unit;
    *position += 1;
    Ok(())
}

fn write_reserved(output: &mut [u16], position: &mut usize, units: &[u16]) -> Result<(), u32> {
    let end = position
        .checked_add(units.len())
        .ok_or(STATUS_BUFFER_OVERFLOW)?;
    if end >= output.len() {
        return Err(STATUS_BUFFER_OVERFLOW);
    }
    output[*position..end].copy_from_slice(units);
    *position = end;
    Ok(())
}

fn write_insert_literal(
    output: &mut [u16],
    position: &mut usize,
    units: &[u16],
) -> Result<(), u32> {
    for &unit in units {
        if *position + 1 >= output.len() {
            if let Some(slot) = output.get_mut(*position) {
                *slot = 0;
            }
            return Err(STATUS_BUFFER_OVERFLOW);
        }
        output[*position] = unit;
        *position += 1;
    }
    output[*position] = 0;
    Ok(())
}

struct FixedArguments {
    values: [u64; 3],
    position: usize,
}

impl crate::printf::Arguments for FixedArguments {
    unsafe fn next(&mut self, _kind: crate::printf::ArgumentKind) -> u64 {
        let value = self.values.get(self.position).copied().unwrap_or(0);
        self.position += 1;
        value
    }
}

struct InsertOutput<'a> {
    output: &'a mut [u16],
    start: usize,
    written: usize,
}

impl crate::printf::Output for InsertOutput<'_> {
    fn write(&mut self, unit: u16) -> bool {
        let position = self.start + self.written;
        if position + 1 >= self.output.len() {
            return false;
        }
        self.output[position] = unit;
        self.written += 1;
        true
    }
}

fn write_formatted_insert(
    output: &mut [u16],
    position: &mut usize,
    format: &[u16; INSERT_FORMAT_UNITS],
    arguments_are_ansi: bool,
    values: [u64; 3],
) -> Result<(), u32> {
    let mut arguments = FixedArguments {
        values,
        position: 0,
    };
    let mut destination = InsertOutput {
        output,
        start: *position,
        written: 0,
    };
    let result = unsafe {
        crate::printf::format_wide_message(
            format.as_ptr(),
            arguments_are_ansi,
            &mut arguments,
            &mut destination,
        )
    };
    let written = destination.written;
    if let Some(terminator) = destination.output.get_mut(*position + written) {
        *terminator = 0;
    }
    if result.is_err() {
        return Err(STATUS_BUFFER_OVERFLOW);
    }
    *position += written;
    Ok(())
}

fn apply_wrap(
    output: &mut [u16],
    position: &mut usize,
    column: &mut usize,
    last_space: &mut Option<usize>,
) -> Result<(), u32> {
    if let Some(space) = *last_space {
        let mut suffix = space;
        while suffix < *position && is_message_space(output[suffix]) {
            suffix += 1;
        }
        let mut line_end = space;
        while line_end > 0 && is_message_space(output[line_end - 1]) {
            line_end -= 1;
        }
        let suffix_len = *position - suffix;
        let new_position = line_end
            .checked_add(2)
            .and_then(|value| value.checked_add(suffix_len))
            .ok_or(STATUS_BUFFER_OVERFLOW)?;
        if new_position >= output.len() {
            return Err(STATUS_BUFFER_OVERFLOW);
        }
        output.copy_within(suffix..*position, line_end + 2);
        output[line_end] = b'\r' as u16;
        output[line_end + 1] = b'\n' as u16;
        *position = new_position;
        *column = suffix_len;
        *last_space = None;
    } else {
        write_reserved(output, position, &[b'\r' as u16, b'\n' as u16])?;
        *column = 0;
    }
    Ok(())
}

fn is_message_space(unit: u16) -> bool {
    unit == b' ' as u16 || unit == b'\t' as u16
}

#[inline]
fn rd_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Locate `message_id` in a `MESSAGE_RESOURCE_DATA` buffer.
///
/// Returns the byte offset of the matched `MESSAGE_RESOURCE_ENTRY` within `table`.
pub fn find_message_entry(table: &[u8], message_id: u32) -> Result<usize, u32> {
    let block_count = rd_u32(table, 0).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)? as usize;
    let blocks_end = MESSAGE_RESOURCE_DATA_HEADER
        .checked_add(
            block_count
                .checked_mul(MESSAGE_RESOURCE_BLOCK_SIZE)
                .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?,
        )
        .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
    if blocks_end > table.len() {
        return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
    }

    for i in 0..block_count {
        let block = MESSAGE_RESOURCE_DATA_HEADER + i * MESSAGE_RESOURCE_BLOCK_SIZE;
        let low = rd_u32(table, block).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
        let high = rd_u32(table, block + 4).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
        let entries = rd_u32(table, block + 8).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)? as usize;

        if message_id < low {
            return Err(STATUS_MESSAGE_NOT_FOUND);
        }
        if message_id > high {
            continue;
        }
        if entries < blocks_end || entries >= table.len() {
            return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
        }

        let mut entry = entries;
        for _ in 0..(message_id - low) {
            let length = rd_u16(table, entry).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)? as usize;
            if length < MESSAGE_RESOURCE_ENTRY_HEADER {
                return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
            }
            entry = entry
                .checked_add(length)
                .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
            if entry >= table.len() {
                return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
            }
        }

        let length = rd_u16(table, entry).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)? as usize;
        if length < MESSAGE_RESOURCE_ENTRY_HEADER {
            return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
        }
        let end = entry
            .checked_add(length)
            .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
        if end > table.len() {
            return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
        }
        return Ok(entry);
    }

    Err(STATUS_MESSAGE_NOT_FOUND)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::{vec, vec::Vec};

    fn push_u16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_entry(buf: &mut Vec<u8>, flags: u16, text: &[u8]) -> usize {
        let off = buf.len();
        push_u16(buf, (MESSAGE_RESOURCE_ENTRY_HEADER + text.len()) as u16);
        push_u16(buf, flags);
        buf.extend_from_slice(text);
        off
    }

    #[test]
    fn finds_entry_by_message_id() {
        let mut table = Vec::new();
        push_u32(&mut table, 1); // NumberOfBlocks
        push_u32(&mut table, 100); // LowId
        push_u32(&mut table, 102); // HighId
        push_u32(&mut table, 16); // OffsetToEntries
        let first = push_entry(&mut table, 0, b"one");
        let second = push_entry(&mut table, 0, b"two");
        let third = push_entry(&mut table, 0, b"three");

        assert_eq!(first, 16);
        assert_eq!(find_message_entry(&table, 100), Ok(first));
        assert_eq!(find_message_entry(&table, 101), Ok(second));
        assert_eq!(find_message_entry(&table, 102), Ok(third));
    }

    #[test]
    fn missing_ids_return_message_not_found() {
        let mut table = Vec::new();
        push_u32(&mut table, 1);
        push_u32(&mut table, 10);
        push_u32(&mut table, 10);
        push_u32(&mut table, 16);
        push_entry(&mut table, 0, b"x");

        assert_eq!(find_message_entry(&table, 9), Err(STATUS_MESSAGE_NOT_FOUND));
        assert_eq!(
            find_message_entry(&table, 11),
            Err(STATUS_MESSAGE_NOT_FOUND)
        );
    }

    #[test]
    fn malformed_tables_return_resource_data_not_found() {
        assert_eq!(
            find_message_entry(&[], 1),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND)
        );

        let mut table = Vec::new();
        push_u32(&mut table, 1);
        push_u32(&mut table, 1);
        push_u32(&mut table, 1);
        push_u32(&mut table, 2); // Offset points into the header.
        assert_eq!(
            find_message_entry(&table, 1),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND)
        );

        let mut table = Vec::new();
        push_u32(&mut table, 1);
        push_u32(&mut table, 1);
        push_u32(&mut table, 1);
        push_u32(&mut table, 16);
        push_u16(&mut table, 3); // Entry length smaller than header.
        push_u16(&mut table, 0);
        assert_eq!(
            find_message_entry(&table, 1),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND)
        );
    }

    struct Slots {
        values: Vec<u64>,
        position: usize,
    }

    impl MessageArguments for Slots {
        fn next_slot(&mut self) -> Option<u64> {
            let value = self.values.get(self.position).copied();
            self.position += usize::from(value.is_some());
            value
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn wide_z(value: &str) -> Vec<u16> {
        let mut value = wide(value);
        value.push(0);
        value
    }

    fn format(
        message: &str,
        options: FormatMessageOptions,
        arguments: Option<&mut dyn MessageArguments>,
    ) -> (Vec<u16>, usize) {
        let mut output = vec![0xcccc; 256];
        let bytes = format_message(&wide(message), options, arguments, &mut output).unwrap();
        let end = output.iter().position(|unit| *unit == 0).unwrap();
        (output[..end].to_vec(), bytes)
    }

    #[test]
    fn formats_controls_and_indexed_wide_or_ansi_strings() {
        let wide_value = wide_z("test");
        let ansi_value = b"ansi\0";
        let mut arguments = Slots {
            values: vec![
                wide_value.as_ptr() as u64,
                ansi_value.as_ptr() as u64,
                0xbeef,
            ],
            position: 0,
        };
        let (output, bytes) = format(
            "%1 %2!S! %3!04X! %.%%%Z%n%t%r%!% ",
            FormatMessageOptions::default(),
            Some(&mut arguments),
        );
        assert_eq!(output, wide("test ansi BEEF .%Z\r\n\t\r! "));
        assert_eq!(bytes, (output.len() + 1) * 2);

        let mut ansi_arguments = Slots {
            values: vec![ansi_value.as_ptr() as u64, wide_value.as_ptr() as u64],
            position: 0,
        };
        let (output, _) = format(
            "%1!s! %2!S!",
            FormatMessageOptions {
                arguments_are_ansi: true,
                ..FormatMessageOptions::default()
            },
            Some(&mut ansi_arguments),
        );
        assert_eq!(output, wide("ansi test"));
    }

    #[test]
    fn caches_sequential_and_array_arguments_like_native() {
        let message = "%2!*.*I64x! %1!u! %4!u! %2!u!";
        let mut sequential = Slots {
            values: vec![19, 17, 15, 13, 11, 9],
            position: 0,
        };
        let (output, _) = format(
            message,
            FormatMessageOptions::default(),
            Some(&mut sequential),
        );
        assert_eq!(output, wide("  00000000000000d 19 11 17"));

        let mut array = Slots {
            values: vec![19, 17, 15, 13, 11, 9, 7],
            position: 0,
        };
        let (output, _) = format(
            message,
            FormatMessageOptions {
                arguments_are_an_array: true,
                ..FormatMessageOptions::default()
            },
            Some(&mut array),
        );
        assert_eq!(output, wide("  00000000000000d 19 13 17"));

        let mut repeated = Slots {
            values: vec![6, 4, 2, 5, 3, 1],
            position: 0,
        };
        let (output, _) = format(
            "%1!*.*u!,%1!*.*u!",
            FormatMessageOptions {
                arguments_are_an_array: true,
                ..FormatMessageOptions::default()
            },
            Some(&mut repeated),
        );
        assert_eq!(output, wide("  0002, 00003"));
    }

    #[test]
    fn normalizes_newlines_wraps_and_flattens_at_maximum_width() {
        let (output, _) = format(
            "te st\nabc d\nfoo",
            FormatMessageOptions {
                maximum_width: 6,
                ..FormatMessageOptions::default()
            },
            None,
        );
        assert_eq!(output, wide("te st\r\nabc d\r\nfoo"));

        let (output, _) = format(
            "a\r\nb\rc\r\rd\r\r\ne",
            FormatMessageOptions::default(),
            None,
        );
        assert_eq!(output, wide("a\r\nb\r\nc\r\n\r\nd\r\n\r\ne"));

        let (output, _) = format(
            "te st\r\nabc d\n\nfoo\rbar",
            FormatMessageOptions {
                maximum_width: 0xff,
                ..FormatMessageOptions::default()
            },
            None,
        );
        assert_eq!(output, wide("te st abc d  foo bar"));
    }

    #[test]
    fn preserves_ignore_insert_syntax_and_stops_at_percent_zero() {
        let (output, _) = format(
            "%1!x!%r%%%n%t",
            FormatMessageOptions {
                ignore_inserts: true,
                ..FormatMessageOptions::default()
            },
            None,
        );
        assert_eq!(output, wide("%1!x!\r%%\r\n\t"));
        let (output, _) = format(
            "ab%0cd",
            FormatMessageOptions {
                ignore_inserts: true,
                ..FormatMessageOptions::default()
            },
            None,
        );
        assert_eq!(output, wide("ab"));
    }

    #[test]
    fn matches_literal_insert_and_control_overflow_shapes() {
        let mut literal = vec![0xcccc; 4];
        assert_eq!(
            format_message(
                &wide("testing"),
                FormatMessageOptions::default(),
                None,
                &mut literal,
            ),
            Err(STATUS_BUFFER_OVERFLOW)
        );
        assert_eq!(literal, wide("test"));

        let value = wide_z("test");
        let mut arguments = Slots {
            values: vec![value.as_ptr() as u64],
            position: 0,
        };
        let mut insert = vec![0xcccc; 4];
        assert_eq!(
            format_message(
                &wide("%1"),
                FormatMessageOptions::default(),
                Some(&mut arguments),
                &mut insert,
            ),
            Err(STATUS_BUFFER_OVERFLOW)
        );
        assert_eq!(insert, vec![b't' as u16, b'e' as u16, b's' as u16, 0]);

        let mut control = vec![0xcccc; 3];
        assert_eq!(
            format_message(
                &wide("ab%n"),
                FormatMessageOptions::default(),
                None,
                &mut control,
            ),
            Err(STATUS_BUFFER_OVERFLOW)
        );
        assert_eq!(control, vec![b'a' as u16, b'b' as u16, 0xcccc]);
    }

    #[test]
    fn rejects_invalid_formats_and_uses_message_unknown_conversion_rules() {
        for message in ["abc%", "%1!unterminated", "aa%1!***u!"] {
            let mut output = [0xcccc; 64];
            let mut arguments = Slots {
                values: vec![34],
                position: 0,
            };
            assert_eq!(
                format_message(
                    &wide(message),
                    FormatMessageOptions::default(),
                    Some(&mut arguments),
                    &mut output,
                ),
                Err(STATUS_INVALID_PARAMETER)
            );
        }

        let mut arguments = Slots {
            values: vec![34, 0, 0, 0, 0],
            position: 0,
        };
        let (output, _) = format(
            "%1!**u! %1!0.3+*u! %1!QQ!",
            FormatMessageOptions::default(),
            Some(&mut arguments),
        );
        assert_eq!(output, wide("*u +*u QQ"));
    }
}
