//! Checked decoding of the ACPI bus driver's `_PRT` and interrupt-link results.
//!
//! The executive does not evaluate AML. A dynamically selected ACPI bus provider evaluates `_PRT`
//! and, when necessary, `_CRS` on a PCI interrupt-link PDO through `IOCTL_ACPI_EVAL_METHOD`. This
//! module validates those standard WDM buffers and resolves them into physical interrupt routes.

use alloc::string::String;
use alloc::vec::Vec;

const EVAL_OUTPUT_SIGNATURE: u32 = u32::from_be_bytes(*b"BoeA");
const EVAL_OUTPUT_HEADER_LEN: usize = 12;
const METHOD_ARGUMENT_HEADER_LEN: usize = 4;
const METHOD_ARGUMENT_INTEGER: u16 = 0;
const METHOD_ARGUMENT_STRING: u16 = 1;
const METHOD_ARGUMENT_BUFFER: u16 = 2;
const METHOD_ARGUMENT_PACKAGE: u16 = 3;
const PCI_ROUTING_ENTRY_STORAGE_LEN: usize = 36;
const MAX_PCI_ROUTING_ENTRIES: usize = 32 * 4;

const SMALL_RESOURCE_IRQ: u8 = 0x04;
const SMALL_RESOURCE_END_TAG: u8 = 0x0f;
const LARGE_RESOURCE_EXTENDED_IRQ: u8 = 0x09;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciRoutingError {
    Truncated,
    InvalidEvaluationBuffer,
    InvalidMethodArgument,
    InvalidRoutingEntry,
    DuplicateRoutingEntry,
    InvalidResourceTemplate,
    DuplicateInterruptResource,
    MissingInterruptLink,
    DuplicateInterruptLink,
    AmbiguousInterruptLink,
    DuplicateLegacyIrqOverride,
    UnsupportedResourceSource,
    Allocation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PciRouteSource {
    GlobalSystemInterrupt(u32),
    InterruptLink { name: String, resource_index: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciRoutingEntry {
    pub device: u8,
    pub function: Option<u8>,
    /// ACPI `_PRT` pin numbering: INTA=0 through INTD=3.
    pub pin: u8,
    pub source: PciRouteSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciRoutingTable {
    pub segment: u16,
    pub bus: u8,
    pub entries: Vec<PciRoutingEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptResource {
    /// Descriptor position in the `_CRS` resource template, excluding the end tag.
    pub descriptor_index: u32,
    pub interrupt: InterruptSource,
    pub level_sensitive: bool,
    pub active_low: bool,
    pub shared: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptSource {
    /// A PIC-compatible IRQ that still requires MADT interrupt-source-override translation.
    LegacyIrq(u8),
    GlobalSystemInterrupt(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciInterruptLink {
    /// Route-specific binding produced after the ACPI provider resolves `name` in `_PRT` scope.
    pub device: u8,
    pub pin: u8,
    pub name: String,
    pub resources: Vec<InterruptResource>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyIrqOverride {
    pub irq: u8,
    pub gsi: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedPciRoute {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: Option<u8>,
    pub pin: u8,
    pub gsi: u32,
    pub level_sensitive: bool,
    pub active_low: bool,
    pub shared: bool,
}

#[derive(Clone, Copy)]
struct MethodArgument<'a> {
    kind: u16,
    data: &'a [u8],
}

/// Decode the output of `IOCTL_ACPI_EVAL_METHOD(_PRT)` on one PCI-root/bridge ACPI PDO.
///
/// `segment` and `bus` are provider-owned scope, not values embedded in `_PRT`. Integer results
/// use the ReactOS/Windows `ACPI_METHOD_ARGUMENT` ABI and therefore carry a 32-bit value.
pub fn parse_pci_routing_table(
    segment: u16,
    bus: u8,
    bytes: &[u8],
) -> Result<PciRoutingTable, PciRoutingError> {
    let declared_len = read_u32(bytes, 4)? as usize;
    let count = read_u32(bytes, 8)? as usize;
    if read_u32(bytes, 0)? != EVAL_OUTPUT_SIGNATURE
        || declared_len < EVAL_OUTPUT_HEADER_LEN
        || declared_len > bytes.len()
        || count == 0
        || count > MAX_PCI_ROUTING_ENTRIES
        || count > (declared_len - EVAL_OUTPUT_HEADER_LEN) / PCI_ROUTING_ENTRY_STORAGE_LEN
    {
        return Err(PciRoutingError::InvalidEvaluationBuffer);
    }

    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| PciRoutingError::Allocation)?;
    let mut cursor = EVAL_OUTPUT_HEADER_LEN;
    for _ in 0..count {
        let (argument, next) = parse_argument(&bytes[..declared_len], cursor)?;
        if argument.kind != METHOD_ARGUMENT_PACKAGE {
            return Err(PciRoutingError::InvalidRoutingEntry);
        }
        let entry = parse_routing_entry(argument.data)?;
        if entries.iter().any(|existing: &PciRoutingEntry| {
            existing.device == entry.device && existing.pin == entry.pin
        }) {
            return Err(PciRoutingError::DuplicateRoutingEntry);
        }
        entries.push(entry);
        cursor = next;
    }
    if cursor != declared_len {
        return Err(PciRoutingError::InvalidEvaluationBuffer);
    }
    Ok(PciRoutingTable {
        segment,
        bus,
        entries,
    })
}

fn parse_routing_entry(bytes: &[u8]) -> Result<PciRoutingEntry, PciRoutingError> {
    let mut arguments = [None; 4];
    let mut cursor = 0usize;
    for slot in &mut arguments {
        let (argument, next) = parse_argument(bytes, cursor)?;
        *slot = Some(argument);
        cursor = next;
    }
    if cursor != bytes.len() {
        return Err(PciRoutingError::InvalidRoutingEntry);
    }
    let address = integer_argument(arguments[0].unwrap())?;
    let device = u8::try_from(address >> 16)
        .ok()
        .filter(|device| *device < 32)
        .ok_or(PciRoutingError::InvalidRoutingEntry)?;
    if address & 0xffff != 0xffff {
        return Err(PciRoutingError::InvalidRoutingEntry);
    }
    let function = None;
    let pin = u8::try_from(integer_argument(arguments[1].unwrap())?)
        .ok()
        .filter(|pin| *pin < 4)
        .ok_or(PciRoutingError::InvalidRoutingEntry)?;
    let source_argument = arguments[2].unwrap();
    let source_index = integer_argument(arguments[3].unwrap())?;
    let source = match source_argument.kind {
        METHOD_ARGUMENT_INTEGER if integer_argument(source_argument)? == 0 => {
            PciRouteSource::GlobalSystemInterrupt(source_index)
        }
        METHOD_ARGUMENT_STRING => PciRouteSource::InterruptLink {
            name: nonempty_string_argument(source_argument)?,
            resource_index: source_index,
        },
        _ => return Err(PciRoutingError::InvalidRoutingEntry),
    };
    Ok(PciRoutingEntry {
        device,
        function,
        pin,
        source,
    })
}

/// Decode the byte buffer returned by `IOCTL_ACPI_EVAL_METHOD(_CRS)` for an interrupt-link PDO.
pub fn parse_interrupt_resource_template(
    bytes: &[u8],
) -> Result<Vec<InterruptResource>, PciRoutingError> {
    let declared_len = read_u32(bytes, 4)? as usize;
    let count = read_u32(bytes, 8)? as usize;
    if read_u32(bytes, 0)? != EVAL_OUTPUT_SIGNATURE
        || declared_len < EVAL_OUTPUT_HEADER_LEN
        || declared_len > bytes.len()
        || count != 1
    {
        return Err(PciRoutingError::InvalidEvaluationBuffer);
    }
    let (argument, next) = parse_argument(&bytes[..declared_len], EVAL_OUTPUT_HEADER_LEN)?;
    if next != declared_len || argument.kind != METHOD_ARGUMENT_BUFFER {
        return Err(PciRoutingError::InvalidEvaluationBuffer);
    }
    parse_resource_template(argument.data)
}

fn parse_resource_template(bytes: &[u8]) -> Result<Vec<InterruptResource>, PciRoutingError> {
    let mut resources = Vec::new();
    let mut cursor = 0usize;
    let mut descriptor_index = 0u32;
    let mut found_end_tag = false;
    while cursor < bytes.len() {
        let header = bytes[cursor];
        if header & 0x80 == 0 {
            let kind = (header >> 3) & 0x0f;
            let length = (header & 0x07) as usize;
            let payload_start = cursor
                .checked_add(1)
                .ok_or(PciRoutingError::InvalidResourceTemplate)?;
            let end = payload_start
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or(PciRoutingError::Truncated)?;
            if kind == SMALL_RESOURCE_END_TAG {
                if length != 1 || end != bytes.len() {
                    return Err(PciRoutingError::InvalidResourceTemplate);
                }
                let checksum = bytes[payload_start];
                if checksum != 0 && bytes.iter().copied().fold(0u8, u8::wrapping_add) != 0 {
                    return Err(PciRoutingError::InvalidResourceTemplate);
                }
                found_end_tag = true;
                break;
            }
            if kind == SMALL_RESOURCE_IRQ {
                parse_small_irq(&bytes[payload_start..end], descriptor_index, &mut resources)?;
            }
            cursor = end;
        } else {
            let kind = header & 0x7f;
            let length = read_u16(bytes, cursor + 1)? as usize;
            let payload_start = cursor
                .checked_add(3)
                .ok_or(PciRoutingError::InvalidResourceTemplate)?;
            let end = payload_start
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or(PciRoutingError::Truncated)?;
            if kind == LARGE_RESOURCE_EXTENDED_IRQ {
                parse_extended_irq(&bytes[payload_start..end], descriptor_index, &mut resources)?;
            }
            cursor = end;
        }
        descriptor_index = descriptor_index
            .checked_add(1)
            .ok_or(PciRoutingError::InvalidResourceTemplate)?;
    }
    if !found_end_tag || resources.is_empty() {
        return Err(PciRoutingError::InvalidResourceTemplate);
    }
    Ok(resources)
}

fn parse_small_irq(
    payload: &[u8],
    descriptor_index: u32,
    resources: &mut Vec<InterruptResource>,
) -> Result<(), PciRoutingError> {
    if !matches!(payload.len(), 2 | 3) {
        return Err(PciRoutingError::InvalidResourceTemplate);
    }
    let mask = u16::from_le_bytes(payload[..2].try_into().unwrap());
    if mask == 0 {
        return Err(PciRoutingError::InvalidResourceTemplate);
    }
    let flags = payload.get(2).copied().unwrap_or(0x01);
    if flags & 0xc0 != 0 {
        return Err(PciRoutingError::InvalidResourceTemplate);
    }
    let level_sensitive = flags & 0x01 == 0;
    let active_low = flags & 0x08 != 0;
    if level_sensitive != active_low {
        return Err(PciRoutingError::InvalidResourceTemplate);
    }
    for irq in 0..16u8 {
        if mask & (1u16 << irq) == 0 {
            continue;
        }
        push_interrupt_resource(
            resources,
            InterruptResource {
                descriptor_index,
                interrupt: InterruptSource::LegacyIrq(irq),
                level_sensitive,
                active_low,
                shared: flags & 0x10 != 0,
            },
        )?;
    }
    Ok(())
}

fn parse_extended_irq(
    payload: &[u8],
    descriptor_index: u32,
    resources: &mut Vec<InterruptResource>,
) -> Result<(), PciRoutingError> {
    let flags = *payload.first().ok_or(PciRoutingError::Truncated)?;
    let count = *payload.get(1).ok_or(PciRoutingError::Truncated)? as usize;
    if flags & 0xe0 != 0 || flags & 0x01 != 0 || count != 1 {
        return Err(PciRoutingError::InvalidResourceTemplate);
    }
    let interrupt_bytes = count
        .checked_mul(4)
        .and_then(|length| length.checked_add(2))
        .filter(|length| *length <= payload.len())
        .ok_or(PciRoutingError::Truncated)?;
    if validate_optional_resource_source(&payload[interrupt_bytes..])? {
        return Err(PciRoutingError::UnsupportedResourceSource);
    }
    for index in 0..count {
        let offset = 2 + index * 4;
        let gsi = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        push_interrupt_resource(
            resources,
            InterruptResource {
                descriptor_index,
                interrupt: InterruptSource::GlobalSystemInterrupt(gsi),
                level_sensitive: flags & 0x02 == 0,
                active_low: flags & 0x04 != 0,
                shared: flags & 0x08 != 0,
            },
        )?;
    }
    Ok(())
}

fn validate_optional_resource_source(bytes: &[u8]) -> Result<bool, PciRoutingError> {
    if bytes.is_empty() {
        return Ok(false);
    }
    if bytes.len() < 2 || bytes.last() != Some(&0) || bytes[1..bytes.len() - 1].contains(&0) {
        return Err(PciRoutingError::InvalidResourceTemplate);
    }
    Ok(true)
}

fn push_interrupt_resource(
    resources: &mut Vec<InterruptResource>,
    resource: InterruptResource,
) -> Result<(), PciRoutingError> {
    if resources
        .iter()
        .any(|existing| existing.interrupt == resource.interrupt)
    {
        return Err(PciRoutingError::DuplicateInterruptResource);
    }
    resources
        .try_reserve(1)
        .map_err(|_| PciRoutingError::Allocation)?;
    resources.push(resource);
    Ok(())
}

/// Resolve direct `_PRT` GSIs and link-device references into generation-independent route facts.
///
/// Direct PCI routes have the ACPI-defined PCI INTx attributes (level, active-low, shared). A link
/// reference must select exactly one interrupt from the referenced `_CRS` descriptor index.
pub fn resolve_pci_routing_table(
    table: &PciRoutingTable,
    links: &[PciInterruptLink],
    legacy_irq_overrides: &[LegacyIrqOverride],
) -> Result<Vec<ResolvedPciRoute>, PciRoutingError> {
    for (index, route) in legacy_irq_overrides.iter().enumerate() {
        if route.irq >= 16
            || legacy_irq_overrides[index + 1..]
                .iter()
                .any(|other| other.irq == route.irq)
        {
            return Err(PciRoutingError::DuplicateLegacyIrqOverride);
        }
    }
    let mut routes = Vec::new();
    routes
        .try_reserve_exact(table.entries.len())
        .map_err(|_| PciRoutingError::Allocation)?;
    for entry in &table.entries {
        let interrupt = match &entry.source {
            PciRouteSource::GlobalSystemInterrupt(gsi) => InterruptResource {
                descriptor_index: 0,
                interrupt: InterruptSource::GlobalSystemInterrupt(*gsi),
                level_sensitive: true,
                active_low: true,
                shared: true,
            },
            PciRouteSource::InterruptLink {
                name,
                resource_index,
            } => {
                let mut matches = links.iter().filter(|link| {
                    link.device == entry.device
                        && link.pin == entry.pin
                        && link.name.eq_ignore_ascii_case(name)
                });
                let link = matches
                    .next()
                    .ok_or(PciRoutingError::MissingInterruptLink)?;
                if matches.next().is_some() {
                    return Err(PciRoutingError::DuplicateInterruptLink);
                }
                let mut matches = link
                    .resources
                    .iter()
                    .filter(|resource| resource.descriptor_index == *resource_index);
                let selected = *matches
                    .next()
                    .ok_or(PciRoutingError::MissingInterruptLink)?;
                if matches.next().is_some() {
                    return Err(PciRoutingError::AmbiguousInterruptLink);
                }
                selected
            }
        };
        let gsi = match interrupt.interrupt {
            InterruptSource::GlobalSystemInterrupt(gsi) => gsi,
            InterruptSource::LegacyIrq(irq) => legacy_irq_overrides
                .iter()
                .find(|route| route.irq == irq)
                .map(|route| route.gsi)
                .unwrap_or(irq as u32),
        };
        routes.push(ResolvedPciRoute {
            segment: table.segment,
            bus: table.bus,
            device: entry.device,
            function: entry.function,
            pin: entry.pin,
            gsi,
            level_sensitive: interrupt.level_sensitive,
            active_low: interrupt.active_low,
            shared: interrupt.shared,
        });
    }
    Ok(routes)
}

fn parse_argument(
    bytes: &[u8],
    offset: usize,
) -> Result<(MethodArgument<'_>, usize), PciRoutingError> {
    let kind = read_u16(bytes, offset)?;
    let data_len = read_u16(bytes, offset + 2)? as usize;
    let storage_len = data_len.max(4);
    let data_start = offset
        .checked_add(METHOD_ARGUMENT_HEADER_LEN)
        .ok_or(PciRoutingError::InvalidMethodArgument)?;
    let next = data_start
        .checked_add(storage_len)
        .filter(|next| *next <= bytes.len())
        .ok_or(PciRoutingError::Truncated)?;
    let data_end = data_start
        .checked_add(data_len)
        .filter(|end| *end <= next)
        .ok_or(PciRoutingError::Truncated)?;
    if !matches!(
        kind,
        METHOD_ARGUMENT_INTEGER
            | METHOD_ARGUMENT_STRING
            | METHOD_ARGUMENT_BUFFER
            | METHOD_ARGUMENT_PACKAGE
    ) {
        return Err(PciRoutingError::InvalidMethodArgument);
    }
    Ok((
        MethodArgument {
            kind,
            data: &bytes[data_start..data_end],
        },
        next,
    ))
}

fn integer_argument(argument: MethodArgument<'_>) -> Result<u32, PciRoutingError> {
    if argument.kind != METHOD_ARGUMENT_INTEGER || argument.data.len() != 4 {
        return Err(PciRoutingError::InvalidRoutingEntry);
    }
    Ok(u32::from_le_bytes(argument.data.try_into().unwrap()))
}

fn nonempty_string_argument(argument: MethodArgument<'_>) -> Result<String, PciRoutingError> {
    if argument.kind != METHOD_ARGUMENT_STRING
        || argument.data.len() < 2
        || argument.data.last() != Some(&0)
        || argument.data[..argument.data.len() - 1].contains(&0)
        || !argument.data[..argument.data.len() - 1]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'\\' | b'.' | b'^'))
    {
        return Err(PciRoutingError::InvalidRoutingEntry);
    }
    let bytes = &argument.data[..argument.data.len() - 1];
    let mut name = String::new();
    name.try_reserve_exact(bytes.len())
        .map_err(|_| PciRoutingError::Allocation)?;
    for byte in bytes {
        name.push(*byte as char);
    }
    name.make_ascii_uppercase();
    Ok(name)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PciRoutingError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(PciRoutingError::Truncated)?;
    Ok(u16::from_le_bytes(value.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PciRoutingError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(PciRoutingError::Truncated)?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn argument(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
        bytes.extend_from_slice(data);
        bytes.resize(METHOD_ARGUMENT_HEADER_LEN + data.len().max(4), 0);
        bytes
    }

    fn integer(value: u32) -> Vec<u8> {
        argument(METHOD_ARGUMENT_INTEGER, &value.to_le_bytes())
    }

    fn string(value: &[u8]) -> Vec<u8> {
        let mut data = value.to_vec();
        data.push(0);
        argument(METHOD_ARGUMENT_STRING, &data)
    }

    fn package(arguments: &[Vec<u8>]) -> Vec<u8> {
        let data = arguments.concat();
        argument(METHOD_ARGUMENT_PACKAGE, &data)
    }

    fn eval_output(arguments: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&EVAL_OUTPUT_SIGNATURE.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(arguments.len() as u32).to_le_bytes());
        bytes.extend(arguments.concat());
        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    fn prt_entry(address: u32, pin: u32, source: Option<&[u8]>, index: u32) -> Vec<u8> {
        package(&[
            integer(address),
            integer(pin),
            source.map(string).unwrap_or_else(|| integer(0)),
            integer(index),
        ])
    }

    #[test]
    fn direct_prt_routes_decode_with_pci_intx_attributes() {
        let bytes = eval_output(&[
            prt_entry(3 << 16 | 0xffff, 0, None, 16),
            prt_entry(3 << 16 | 0xffff, 1, None, 17),
        ]);
        let table = parse_pci_routing_table(0, 0, &bytes).unwrap();
        assert_eq!(table.entries[0].device, 3);
        assert_eq!(table.entries[0].function, None);
        assert_eq!(
            resolve_pci_routing_table(&table, &[], &[]).unwrap()[0],
            ResolvedPciRoute {
                segment: 0,
                bus: 0,
                device: 3,
                function: None,
                pin: 0,
                gsi: 16,
                level_sensitive: true,
                active_low: true,
                shared: true,
            }
        );
    }

    #[test]
    fn frozen_eval_output_abi_fixture_decodes_without_test_encoder() {
        let bytes = [
            0x41, 0x65, 0x6f, 0x42, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x10, 0x00, 0x00, 0x00,
        ];
        let table = parse_pci_routing_table(0, 0, &bytes).unwrap();
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries[0].device, 3);
        assert_eq!(table.entries[0].pin, 0);
        assert_eq!(
            table.entries[0].source,
            PciRouteSource::GlobalSystemInterrupt(16)
        );
    }

    #[test]
    fn interrupt_link_prt_route_uses_checked_extended_irq_crs() {
        let prt = eval_output(&[prt_entry(5 << 16 | 0xffff, 3, Some(b"lnka"), 1)]);
        let table = parse_pci_routing_table(0, 2, &prt).unwrap();

        let mut template = vec![0x22, 0x00, 0x02];
        template.extend_from_slice(&[0x89, 0x06, 0x00, 0x0c, 0x01]);
        template.extend_from_slice(&19u32.to_le_bytes());
        template.extend_from_slice(&[0x79, 0]);
        let crs = eval_output(&[argument(METHOD_ARGUMENT_BUFFER, &template)]);
        let links = [PciInterruptLink {
            device: 5,
            pin: 3,
            name: String::from("LNKA"),
            resources: parse_interrupt_resource_template(&crs).unwrap(),
        }];
        assert_eq!(
            resolve_pci_routing_table(&table, &links, &[]).unwrap(),
            vec![ResolvedPciRoute {
                segment: 0,
                bus: 2,
                device: 5,
                function: None,
                pin: 3,
                gsi: 19,
                level_sensitive: true,
                active_low: true,
                shared: true,
            }]
        );
    }

    #[test]
    fn small_irq_resources_use_madt_override_and_preserve_descriptor_attributes() {
        let template = [0x23, 0x20, 0x00, 0x18, 0x79, 0];
        let crs = eval_output(&[argument(METHOD_ARGUMENT_BUFFER, &template)]);
        let resources = parse_interrupt_resource_template(&crs).unwrap();
        assert_eq!(
            resources,
            vec![InterruptResource {
                descriptor_index: 0,
                interrupt: InterruptSource::LegacyIrq(5),
                level_sensitive: true,
                active_low: true,
                shared: true,
            }]
        );

        let prt = eval_output(&[prt_entry(7 << 16 | 0xffff, 1, Some(b"LNKB"), 0)]);
        let table = parse_pci_routing_table(0, 0, &prt).unwrap();
        let links = [PciInterruptLink {
            device: 7,
            pin: 1,
            name: String::from("LNKB"),
            resources,
        }];
        let routes =
            resolve_pci_routing_table(&table, &links, &[LegacyIrqOverride { irq: 5, gsi: 21 }])
                .unwrap();
        assert_eq!(routes[0].gsi, 21);
        assert!(routes[0].level_sensitive);
        assert!(routes[0].active_low);
        assert!(routes[0].shared);
    }

    #[test]
    fn malformed_and_overlapping_routes_fail_closed() {
        let duplicate = eval_output(&[
            prt_entry(3 << 16 | 0xffff, 0, None, 16),
            prt_entry(3 << 16 | 0xffff, 0, None, 17),
        ]);
        assert_eq!(
            parse_pci_routing_table(0, 0, &duplicate),
            Err(PciRoutingError::DuplicateRoutingEntry)
        );

        let mut truncated = eval_output(&[prt_entry(3 << 16 | 0xffff, 0, None, 16)]);
        truncated.pop();
        assert_eq!(
            parse_pci_routing_table(0, 0, &truncated),
            Err(PciRoutingError::InvalidEvaluationBuffer)
        );

        let malformed_template = eval_output(&[argument(
            METHOD_ARGUMENT_BUFFER,
            &[
                0x89, 0x06, 0x00, 0x0c, 0x02, 0x10, 0x00, 0x00, 0x00, 0x79, 0,
            ],
        )]);
        assert_eq!(
            parse_interrupt_resource_template(&malformed_template),
            Err(PciRoutingError::InvalidResourceTemplate)
        );
    }

    #[test]
    fn unsupported_or_ambiguous_interrupt_authority_fails_closed() {
        let invalid_pic_pair = eval_output(&[argument(
            METHOD_ARGUMENT_BUFFER,
            &[0x23, 0x20, 0x00, 0x19, 0x79, 0],
        )]);
        assert_eq!(
            parse_interrupt_resource_template(&invalid_pic_pair),
            Err(PciRoutingError::InvalidResourceTemplate)
        );

        let sourced_extended = eval_output(&[argument(
            METHOD_ARGUMENT_BUFFER,
            &[
                0x89, 0x0b, 0x00, 0x0c, 0x01, 19, 0, 0, 0, 0, b'G', b'S', b'I', 0, 0x79, 0,
            ],
        )]);
        assert_eq!(
            parse_interrupt_resource_template(&sourced_extended),
            Err(PciRoutingError::UnsupportedResourceSource)
        );

        let consumer_extended = eval_output(&[argument(
            METHOD_ARGUMENT_BUFFER,
            &[0x89, 0x06, 0x00, 0x0d, 0x01, 19, 0, 0, 0, 0x79, 0],
        )]);
        assert_eq!(
            parse_interrupt_resource_template(&consumer_extended),
            Err(PciRoutingError::InvalidResourceTemplate)
        );

        let function_specific = eval_output(&[prt_entry(5 << 16 | 2, 0, None, 16)]);
        assert_eq!(
            parse_pci_routing_table(0, 0, &function_specific),
            Err(PciRoutingError::InvalidRoutingEntry)
        );

        let prt = eval_output(&[prt_entry(5 << 16 | 0xffff, 2, Some(b"LNKA"), 0)]);
        let table = parse_pci_routing_table(0, 0, &prt).unwrap();
        let link = PciInterruptLink {
            device: 5,
            pin: 2,
            name: String::from("LNKA"),
            resources: vec![InterruptResource {
                descriptor_index: 0,
                interrupt: InterruptSource::GlobalSystemInterrupt(19),
                level_sensitive: true,
                active_low: true,
                shared: true,
            }],
        };
        assert_eq!(
            resolve_pci_routing_table(&table, &[link.clone(), link], &[]),
            Err(PciRoutingError::DuplicateInterruptLink)
        );
    }
}
