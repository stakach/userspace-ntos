//! Conservative static AML I/O authority from checksum-validated firmware.
//!
//! Only literal `_CRS` buffers and SystemIO operation regions in the same Device can authorize
//! ports. Method bodies are opaque and cannot create boot-time authority.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticIoResource {
    pub namespace_path: String,
    pub hardware_id: String,
    pub region_name: [u8; 4],
    pub start: u16,
    pub length: u16,
    pub table_address: u64,
    pub table_length: u32,
    pub table_signature: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticIoResourceError {
    InvalidChecksum,
    InvalidTable,
    MalformedAml,
    UnsupportedAml { offset: usize, opcode: u8 },
    Allocation,
}

type Result<T> = core::result::Result<T, StaticIoResourceError>;

#[derive(Clone, Default, PartialEq, Eq)]
struct Scope(Vec<[u8; 4]>);

impl Scope {
    fn display(&self) -> Result<String> {
        let mut out = String::from("\\");
        out.try_reserve(self.0.len() * 5)
            .map_err(|_| StaticIoResourceError::Allocation)?;
        for (index, part) in self.0.iter().enumerate() {
            if index != 0 {
                out.push('.');
            }
            out.push_str(
                core::str::from_utf8(part).map_err(|_| StaticIoResourceError::MalformedAml)?,
            );
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Port {
    start: u16,
    length: u16,
}

#[derive(Default)]
struct Device {
    hid: Option<String>,
    hid_declared: bool,
    crs: Vec<Port>,
    crs_declared: bool,
    region_names: Vec<[u8; 4]>,
    regions: Vec<([u8; 4], Port)>,
}

struct Aml<'a> {
    data: &'a [u8],
    table_address: u64,
    declared: Vec<Scope>,
    found: Vec<StaticIoResource>,
}

impl Aml<'_> {
    fn declare(&mut self, name: Scope) -> Result<()> {
        if self.declared.contains(&name) {
            return Err(StaticIoResourceError::MalformedAml);
        }
        self.declared
            .try_reserve(1)
            .map_err(|_| StaticIoResourceError::Allocation)?;
        self.declared.push(name);
        Ok(())
    }

    fn direct_child(name: &Scope, parent: &Scope) -> bool {
        name.0.len() == parent.0.len() + 1 && name.0[..parent.0.len()] == parent.0[..]
    }

    fn byte(&self, at: usize, end: usize) -> Result<u8> {
        self.data
            .get(at)
            .copied()
            .filter(|_| at < end)
            .ok_or(StaticIoResourceError::MalformedAml)
    }

    fn pkg(&self, at: usize, end: usize) -> Result<(usize, usize)> {
        let (size, body) = self.pkg_length(at, end)?;
        let limit = at
            .checked_add(size)
            .filter(|limit| *limit >= body && *limit <= end)
            .ok_or(StaticIoResourceError::MalformedAml)?;
        Ok((body, limit))
    }

    fn pkg_length(&self, at: usize, end: usize) -> Result<(usize, usize)> {
        let lead = self.byte(at, end)?;
        let more = (lead >> 6) as usize;
        let mut size = if more == 0 {
            (lead & 0x3f) as usize
        } else {
            (lead & 0xf) as usize
        };
        for n in 0..more {
            size |= (self.byte(at + 1 + n, end)? as usize) << (4 + 8 * n);
        }
        let body = at + 1 + more;
        Ok((size, body))
    }

    fn field_list(&mut self, mut at: usize, end: usize, scope: &Scope) -> Result<()> {
        while at < end {
            match self.byte(at, end)? {
                0 => at = self.pkg_length(at + 1, end)?.1,
                1 => at = at + 3,
                2 => {
                    at = if self.byte(at + 1, end)? == 0x11 {
                        self.pkg(at + 2, end)?.1
                    } else {
                        self.name(at + 1, end, scope)?.1
                    };
                }
                3 => at = at + 4,
                _ => {
                    let (name, next) = self.name(at, end, scope)?;
                    if next != at + 4 {
                        return Err(StaticIoResourceError::MalformedAml);
                    }
                    self.declare(name)?;
                    at = self.pkg_length(next, end)?.1;
                }
            }
            if at > end {
                return Err(StaticIoResourceError::MalformedAml);
            }
        }
        Ok(())
    }

    fn name(&self, at: usize, end: usize, parent: &Scope) -> Result<(Scope, usize)> {
        let mut at = at;
        let mut scope = parent.clone();
        if self.byte(at, end)? == b'\\' {
            scope = Scope::default();
            at += 1;
        }
        while self.byte(at, end)? == b'^' {
            scope.0.pop().ok_or(StaticIoResourceError::MalformedAml)?;
            at += 1;
        }
        let count = match self.byte(at, end)? {
            0 => return Ok((scope, at + 1)),
            0x2e => {
                at += 1;
                2
            }
            0x2f => {
                at += 1;
                let n = self.byte(at, end)? as usize;
                at += 1;
                n
            }
            _ => 1,
        };
        if count == 0 || count > 32 {
            return Err(StaticIoResourceError::MalformedAml);
        }
        scope
            .0
            .try_reserve(count)
            .map_err(|_| StaticIoResourceError::Allocation)?;
        for _ in 0..count {
            let next = at
                .checked_add(4)
                .filter(|next| *next <= end)
                .ok_or(StaticIoResourceError::MalformedAml)?;
            let part: [u8; 4] = self.data[at..next].try_into().unwrap();
            if !(part[0].is_ascii_uppercase() || part[0] == b'_')
                || !part[1..]
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
            {
                return Err(StaticIoResourceError::MalformedAml);
            }
            scope.0.push(part);
            at = next;
        }
        Ok((scope, at))
    }

    fn integer(&self, at: usize, end: usize) -> Result<Option<(u64, usize)>> {
        let (value, size) = match self.byte(at, end)? {
            0 => (0, 1),
            1 => (1, 1),
            0xff => (u64::MAX, 1),
            0x0a => (self.byte(at + 1, end)? as u64, 2),
            0x0b => (
                u16::from_le_bytes(
                    self.data
                        .get(at + 1..at + 3)
                        .filter(|_| at + 3 <= end)
                        .ok_or(StaticIoResourceError::MalformedAml)?
                        .try_into()
                        .unwrap(),
                ) as u64,
                3,
            ),
            0x0c => (
                u32::from_le_bytes(
                    self.data
                        .get(at + 1..at + 5)
                        .filter(|_| at + 5 <= end)
                        .ok_or(StaticIoResourceError::MalformedAml)?
                        .try_into()
                        .unwrap(),
                ) as u64,
                5,
            ),
            0x0e => (
                u64::from_le_bytes(
                    self.data
                        .get(at + 1..at + 9)
                        .filter(|_| at + 9 <= end)
                        .ok_or(StaticIoResourceError::MalformedAml)?
                        .try_into()
                        .unwrap(),
                ),
                9,
            ),
            _ => return Ok(None),
        };
        Ok(Some((value, at + size)))
    }

    fn data_end(&self, at: usize, end: usize) -> Result<usize> {
        if let Some((_, next)) = self.integer(at, end)? {
            return Ok(next);
        }
        match self.byte(at, end)? {
            0x0d => Ok(at
                + 2
                + self.data[at + 1..end]
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or(StaticIoResourceError::MalformedAml)?),
            0x11 | 0x12 | 0x13 => Ok(self.pkg(at + 1, end)?.1),
            _ => Ok(self.name(at, end, &Scope::default())?.1),
        }
    }

    fn hid(&self, at: usize, end: usize) -> Result<Option<String>> {
        if self.byte(at, end)? == 0x0d {
            let next = self.data_end(at, end)?;
            return Ok(Some(
                core::str::from_utf8(&self.data[at + 1..next - 1])
                    .map_err(|_| StaticIoResourceError::MalformedAml)?
                    .to_string(),
            ));
        }
        let Some((encoded, _)) = self.integer(at, end)? else {
            return Ok(None);
        };
        let encoded = (encoded as u32).swap_bytes();
        let mut out = String::new();
        out.try_reserve(7)
            .map_err(|_| StaticIoResourceError::Allocation)?;
        for shift in [26, 21, 16] {
            let letter = ((encoded >> shift) & 0x1f) as u8;
            if !(1..=26).contains(&letter) {
                return Ok(None);
            }
            out.push((b'A' + letter - 1) as char);
        }
        for shift in [12, 8, 4, 0] {
            let nibble = ((encoded >> shift) & 0xf) as u8;
            out.push(if nibble < 10 {
                (b'0' + nibble) as char
            } else {
                (b'A' + nibble - 10) as char
            });
        }
        Ok(Some(out))
    }

    fn crs(&self, at: usize, end: usize) -> Result<Vec<Port>> {
        let mut ports = Vec::new();
        if self.byte(at, end)? != 0x11 {
            return Ok(ports);
        }
        let (body, limit) = self.pkg(at + 1, end)?;
        let Some((length, mut cursor)) = self.integer(body, limit)? else {
            return Ok(ports);
        };
        if cursor.checked_add(length as usize) != Some(limit) {
            return Err(StaticIoResourceError::MalformedAml);
        }
        let resource_start = cursor;
        let mut end_tag = false;
        while cursor < limit {
            let head = self.byte(cursor, limit)?;
            let (kind, data, next) = if head & 0x80 == 0 {
                let next = cursor + 1 + (head & 7) as usize;
                ((head >> 3) & 0xf, cursor + 1, next)
            } else {
                let size = u16::from_le_bytes(
                    self.data
                        .get(cursor + 1..cursor + 3)
                        .filter(|_| cursor + 3 <= limit)
                        .ok_or(StaticIoResourceError::MalformedAml)?
                        .try_into()
                        .unwrap(),
                ) as usize;
                (0, cursor + 3, cursor + 3 + size)
            };
            if next > limit {
                return Err(StaticIoResourceError::MalformedAml);
            }
            if head & 0x80 == 0 && kind == 0xf {
                if next != limit || next - data != 1 {
                    return Err(StaticIoResourceError::MalformedAml);
                }
                let checksum = self.data[data];
                if checksum != 0
                    && self.data[resource_start..limit]
                        .iter()
                        .copied()
                        .fold(0u8, u8::wrapping_add)
                        != 0
                {
                    return Err(StaticIoResourceError::MalformedAml);
                }
                end_tag = true;
                break;
            }
            if head & 0x80 == 0 && kind == 8 && next - data == 7 {
                let p = &self.data[data..next];
                let start = u16::from_le_bytes([p[1], p[2]]);
                let maximum = u16::from_le_bytes([p[3], p[4]]);
                let length = p[6] as u16;
                if p[0] & !1 == 0
                    && p[5] == 1
                    && start == maximum
                    && length != 0
                    && (start as u32 + length as u32) <= 0x1_0000
                {
                    ports
                        .try_reserve(1)
                        .map_err(|_| StaticIoResourceError::Allocation)?;
                    ports.push(Port { start, length });
                }
            }
            cursor = next;
        }
        if !end_tag {
            return Err(StaticIoResourceError::MalformedAml);
        }
        Ok(ports)
    }

    fn walk(
        &mut self,
        mut at: usize,
        end: usize,
        scope: &Scope,
        mut device: Option<&mut Device>,
        depth: usize,
    ) -> Result<()> {
        if depth > 32 {
            return Err(StaticIoResourceError::MalformedAml);
        }
        while at < end {
            match self.byte(at, end)? {
                0x10 => {
                    let (body, next) = self.pkg(at + 1, end)?;
                    let (name, terms) = self.name(body, next, scope)?;
                    self.walk(terms, next, &name, None, depth + 1)?;
                    at = next;
                }
                0x5b if self.byte(at + 1, end)? == 0x82 => {
                    let (body, next) = self.pkg(at + 2, end)?;
                    let (name, terms) = self.name(body, next, scope)?;
                    self.declare(name.clone())?;
                    let mut child = Device::default();
                    self.walk(terms, next, &name, Some(&mut child), depth + 1)?;
                    if let Some(hid) = child.hid {
                        for (region_name, range) in child.regions {
                            if child.crs.contains(&range) {
                                self.found
                                    .try_reserve(1)
                                    .map_err(|_| StaticIoResourceError::Allocation)?;
                                self.found.push(StaticIoResource {
                                    namespace_path: name.display()?,
                                    hardware_id: hid.clone(),
                                    region_name,
                                    start: range.start,
                                    length: range.length,
                                    table_address: self.table_address,
                                    table_length: self.data.len() as u32,
                                    table_signature: self.data[..4].try_into().unwrap(),
                                });
                            }
                        }
                    }
                    at = next;
                }
                0x08 => {
                    let (name, value) = self.name(at + 1, end, scope)?;
                    self.declare(name.clone())?;
                    if let Some(device) = device.as_deref_mut() {
                        if Self::direct_child(&name, scope) && name.0.last() == Some(b"_HID") {
                            if device.hid_declared {
                                return Err(StaticIoResourceError::MalformedAml);
                            }
                            device.hid_declared = true;
                            device.hid = self.hid(value, end)?;
                        }
                        if Self::direct_child(&name, scope) && name.0.last() == Some(b"_CRS") {
                            if device.crs_declared {
                                return Err(StaticIoResourceError::MalformedAml);
                            }
                            device.crs_declared = true;
                            device.crs = self.crs(value, end)?;
                        }
                    }
                    at = self.data_end(value, end)?;
                }
                0x5b if self.byte(at + 1, end)? == 0x80 => {
                    let (name, space) = self.name(at + 2, end, scope)?;
                    self.declare(name.clone())?;
                    if Self::direct_child(&name, scope) {
                        if let (Some(device), Some(region_name)) =
                            (device.as_deref_mut(), name.0.last())
                        {
                            if device.region_names.contains(region_name) {
                                return Err(StaticIoResourceError::MalformedAml);
                            }
                            device
                                .region_names
                                .try_reserve(1)
                                .map_err(|_| StaticIoResourceError::Allocation)?;
                            device.region_names.push(*region_name);
                        }
                    }
                    let Some((address, next)) = self.integer(space + 1, end)? else {
                        return Err(StaticIoResourceError::MalformedAml);
                    };
                    let Some((length, next)) = self.integer(next, end)? else {
                        return Err(StaticIoResourceError::MalformedAml);
                    };
                    if self.byte(space, end)? == 1 {
                        if let (Ok(start), Ok(length)) =
                            (u16::try_from(address), u16::try_from(length))
                        {
                            if length != 0 && (start as u32 + length as u32) <= 0x1_0000 {
                                if let (Some(device), Some(region_name)) =
                                    (device.as_deref_mut(), name.0.last())
                                {
                                    if Self::direct_child(&name, scope) {
                                        device
                                            .regions
                                            .try_reserve(1)
                                            .map_err(|_| StaticIoResourceError::Allocation)?;
                                        device.regions.push((*region_name, Port { start, length }));
                                    }
                                }
                            }
                        }
                    }
                    at = next;
                }
                0x14 => {
                    let (body, next) = self.pkg(at + 1, end)?;
                    let (name, _) = self.name(body, next, scope)?;
                    self.declare(name)?;
                    at = next;
                }
                0xa0 | 0xa1 | 0xa2 => at = self.pkg(at + 1, end)?.1,
                0x5b if matches!(self.byte(at + 1, end)?, 0x81 | 0x86 | 0x87) => {
                    let opcode = self.byte(at + 1, end)?;
                    let (body, next) = self.pkg(at + 2, end)?;
                    let (_, mut fields) = self.name(body, next, scope)?;
                    if opcode != 0x81 {
                        fields = self.name(fields, next, scope)?.1;
                    }
                    if opcode == 0x87 {
                        fields = self
                            .integer(fields, next)?
                            .ok_or(StaticIoResourceError::MalformedAml)?
                            .1;
                    }
                    self.byte(fields, next)?; // FieldFlags
                    self.field_list(fields + 1, next, scope)?;
                    at = next;
                }
                0x5b if matches!(self.byte(at + 1, end)?, 0x83 | 0x84 | 0x85) => {
                    let opcode = self.byte(at + 1, end)?;
                    let (body, next) = self.pkg(at + 2, end)?;
                    let (name, terms) = self.name(body, next, scope)?;
                    self.declare(name.clone())?;
                    let fixed = match opcode {
                        0x83 => 6, // Processor ID, PBlock address, PBlock length.
                        0x84 => 3, // System level and resource order.
                        _ => 0,
                    };
                    let terms = terms
                        .checked_add(fixed)
                        .filter(|terms| *terms <= next)
                        .ok_or(StaticIoResourceError::MalformedAml)?;
                    self.walk(terms, next, &name, None, depth + 1)?;
                    at = next;
                }
                0x5b if self.byte(at + 1, end)? == 0x01 => {
                    let (name, next) = self.name(at + 2, end, scope)?;
                    self.declare(name)?;
                    at = next + 1;
                }
                0x06 => {
                    let (_, next) = self.name(at + 1, end, scope)?;
                    let (name, next) = self.name(next, end, scope)?;
                    self.declare(name)?;
                    at = next;
                }
                other => {
                    return Err(StaticIoResourceError::UnsupportedAml {
                        offset: at,
                        opcode: other,
                    })
                }
            }
        }
        Ok(())
    }
}

pub fn parse_static_system_io_resources(
    table: &[u8],
    table_address: u64,
) -> Result<Vec<StaticIoResource>> {
    if table_address == 0
        || table.len() < 36
        || !matches!(&table[..4], b"DSDT" | b"SSDT")
        || u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize != table.len()
    {
        return Err(StaticIoResourceError::InvalidTable);
    }
    if table.iter().copied().fold(0u8, u8::wrapping_add) != 0 {
        return Err(StaticIoResourceError::InvalidChecksum);
    }
    let mut aml = Aml {
        data: table,
        table_address,
        declared: Vec::new(),
        found: Vec::new(),
    };
    aml.walk(36, table.len(), &Scope::default(), None, 0)?;
    Ok(aml.found)
}
