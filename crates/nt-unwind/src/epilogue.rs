use crate::{Context, ImageReader, StackReader};

struct Code<'a> {
    image: &'a dyn ImageReader,
    base: u64,
    end: u32,
}

impl Code<'_> {
    fn byte(&self, rva: u32) -> Option<u8> {
        if rva >= self.end {
            return None;
        }
        self.image.read_u8(self.base, rva)
    }

    fn word(&self, rva: u32) -> Option<u16> {
        if rva.checked_add(2)? > self.end {
            return None;
        }
        self.image.read_u16(self.base, rva)
    }

    fn dword(&self, rva: u32) -> Option<u32> {
        if rva.checked_add(4)? > self.end {
            return None;
        }
        self.image.read_u32(self.base, rva)
    }

    fn pop(&self, rva: u32) -> Option<Option<(usize, u32)>> {
        let first = self.byte(rva)?;
        let (rex, opcode, len) = if first & 0xf0 == 0x40 {
            (first, self.byte(rva.checked_add(1)?)?, 2)
        } else {
            (0, first, 1)
        };
        Some(
            (opcode & 0xf8 == 0x58)
                .then_some(((opcode & 7) as usize + ((rex & 1) as usize * 8), len)),
        )
    }
}

enum Adjustment {
    None,
    Add(i64),
    Frame { register: usize, displacement: i64 },
}

struct Plan {
    adjustment: Adjustment,
    pops_begin: u32,
    pops_end: u32,
    return_adjustment: u16,
}

/// Decode without reading the stack. None is an unreadable/truncated instruction, while Some(None)
/// is ordinary body code and permits metadata interpretation. Tail jumps need separate function
/// identity checks and are not classified as return epilogues here.
fn decode(code: &Code<'_>, start: u32, frame_register: u8) -> Option<Option<Plan>> {
    let mut cursor = start;
    let mut adjustment = Adjustment::None;
    let rex = code.byte(cursor)?;
    if rex & 0xf8 == 0x48 {
        let opcode = code.byte(cursor.checked_add(1)?)?;
        match opcode {
            0x81 | 0x83 => {
                if rex != 0x48 || code.byte(cursor.checked_add(2)?)? != 0xc4 {
                    return Some(None);
                }
                let (immediate, len) = if opcode == 0x83 {
                    (code.byte(cursor.checked_add(3)?)? as i8 as i64, 4)
                } else {
                    (code.dword(cursor.checked_add(3)?)? as i32 as i64, 7)
                };
                adjustment = Adjustment::Add(immediate);
                cursor = cursor.checked_add(len)?;
            }
            0x8d => {
                let modrm = code.byte(cursor.checked_add(2)?)?;
                let register = (modrm & 7) + (rex & 1) * 8;
                if rex & 6 != 0
                    || modrm & 0x38 != 0x20
                    || modrm & 7 == 4
                    || frame_register == 0
                    || register != frame_register
                {
                    return Some(None);
                }
                let (displacement, len) = match modrm >> 6 {
                    1 => (code.byte(cursor.checked_add(3)?)? as i8 as i64, 4),
                    2 => (code.dword(cursor.checked_add(3)?)? as i32 as i64, 7),
                    _ => return Some(None),
                };
                adjustment = Adjustment::Frame {
                    register: register as usize,
                    displacement,
                };
                cursor = cursor.checked_add(len)?;
            }
            _ => {}
        }
    }

    let pops_begin = cursor;
    while let Some((_, len)) = code.pop(cursor)? {
        cursor = cursor.checked_add(len)?;
    }
    let pops_end = cursor;
    let mut opcode = code.byte(cursor)?;
    if opcode & 0xf0 == 0x40 {
        cursor = cursor.checked_add(1)?;
        opcode = code.byte(cursor)?;
    }
    let return_adjustment = match opcode {
        0xc3 => 0,
        0xc2 => code.word(cursor.checked_add(1)?)?,
        0xf3 if code.byte(cursor.checked_add(1)?)? == 0xc3 => 0,
        _ => return Some(None),
    };
    Some(Some(Plan {
        adjustment,
        pops_begin,
        pops_end,
        return_adjustment,
    }))
}

/// Recognize a canonical return epilogue anywhere in the covering function and execute it only
/// after full decoding. Failed reads/arithmetic never select a different unwind path or publish a
/// partially restored context. Pop opcodes are replayed without allocating on the exception path.
/// The image owner must keep instruction bytes stable for the duration of this call.
pub(crate) fn unwind_return(
    image_base: u64,
    control_rva: u32,
    function_end: u32,
    frame_register: u8,
    context: &mut Context,
    image: &dyn ImageReader,
    stack: &dyn StackReader,
) -> Option<bool> {
    let code = Code {
        image,
        base: image_base,
        end: function_end,
    };
    let Some(plan) = decode(&code, control_rva, frame_register)? else {
        return Some(false);
    };
    let mut next = *context;
    match plan.adjustment {
        Adjustment::None => {}
        Adjustment::Add(value) => next.set_rsp(next.rsp().checked_add_signed(value)?),
        Adjustment::Frame {
            register,
            displacement,
        } => {
            next.set_rsp(next.gpr[register].checked_add_signed(displacement)?);
        }
    }
    let mut cursor = plan.pops_begin;
    while cursor < plan.pops_end {
        let (register, len) = code.pop(cursor)??;
        cursor = cursor.checked_add(len)?;
        if cursor > plan.pops_end {
            return None;
        }
        let rsp = next.rsp();
        let value = stack.read_u64(rsp)?;
        next.set_rsp(rsp.checked_add(8)?);
        next.gpr[register] = value;
    }
    next.rip = stack.read_u64(next.rsp())?;
    next.set_rsp(
        next.rsp()
            .checked_add(8 + u64::from(plan.return_adjustment))?,
    );
    *context = next;
    Some(true)
}
