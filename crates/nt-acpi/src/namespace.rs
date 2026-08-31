//! Standard ACPI PDO namespace enumeration and scoped reference resolution.

use alloc::string::String;
use alloc::vec::Vec;

pub const IOCTL_ACPI_ENUM_CHILDREN: u32 = 0x0032_c020;
pub const ACPI_ENUM_CHILDREN_INPUT_LEN: usize = 16;
pub const ACPI_ENUM_CHILDREN_FILTER_INPUT_LEN: usize = 17;

const ENUM_INPUT_SIGNATURE: u32 = u32::from_be_bytes(*b"HieA");
const ENUM_OUTPUT_SIGNATURE: u32 = u32::from_be_bytes(*b"GieA");
const ENUM_CHILDREN_IMMEDIATE_ONLY: u32 = 1;
const ENUM_CHILDREN_MULTILEVEL: u32 = 2;
const ENUM_CHILDREN_NAME_IS_FILTER: u32 = 4;
const ENUM_OUTPUT_HEADER_LEN: usize = 8;
const ENUM_CHILD_HEADER_LEN: usize = 8;
const ACPI_OBJECT_HAS_CHILDREN: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiNamespaceError {
    Truncated,
    InvalidInput,
    InvalidOutput,
    InvalidRequiredLength,
    InvalidPath,
    DuplicatePath,
    InvalidReference,
    MissingReference,
    AmbiguousReference,
    LimitExceeded,
    Allocation,
}

/// Canonical fully qualified ACPI namespace path, such as `\_SB_.PCI0.LNKA`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiNamespacePath(String);

impl AcpiNamespacePath {
    pub fn parse(path: &str) -> Result<Self, AcpiNamespaceError> {
        validate_absolute_path(path.as_bytes())?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(path.len())
            .map_err(|_| AcpiNamespaceError::Allocation)?;
        owned.push_str(path);
        Ok(Self(owned))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn try_clone(&self) -> Result<Self, AcpiNamespaceError> {
        let mut owned = String::new();
        owned
            .try_reserve_exact(self.0.len())
            .map_err(|_| AcpiNamespaceError::Allocation)?;
        owned.push_str(&self.0);
        Ok(Self(owned))
    }

    pub fn name_seg(&self) -> Option<&str> {
        (self.0 != "\\").then(|| self.0.rsplit('.').next().unwrap_or(&self.0[1..]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiNamespaceChild {
    pub path: AcpiNamespacePath,
    pub has_children: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiNamespaceChildren {
    children: Vec<AcpiNamespaceChild>,
}

impl AcpiNamespaceChildren {
    pub fn self_path(&self) -> &AcpiNamespacePath {
        &self.children[0].path
    }

    pub fn children(&self) -> &[AcpiNamespaceChild] {
        &self.children
    }
}

/// Exact full paths returned by a multilevel NameSeg filter. Unlike immediate enumeration, a
/// filtered result does not include the queried PDO itself and may legitimately be empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiNamespaceMatches {
    objects: Vec<AcpiNamespaceChild>,
}

impl AcpiNamespaceMatches {
    pub fn objects(&self) -> &[AcpiNamespaceChild] {
        &self.objects
    }
}

/// Build the C-sized immediate-only input buffer. The trailing four bytes represent the
/// `ANYSIZE_ARRAY` element plus native structure padding and remain zero when no filter is used.
pub fn immediate_namespace_children_input() -> [u8; ACPI_ENUM_CHILDREN_INPUT_LEN] {
    let mut input = [0u8; ACPI_ENUM_CHILDREN_INPUT_LEN];
    input[0..4].copy_from_slice(&ENUM_INPUT_SIGNATURE.to_le_bytes());
    input[4..8].copy_from_slice(&ENUM_CHILDREN_IMMEDIATE_ONLY.to_le_bytes());
    input
}

/// Build the exact variable-sized input for a multilevel NameSeg-filtered namespace walk.
pub fn multilevel_namespace_filter_input(
    name: [u8; 4],
) -> Result<[u8; ACPI_ENUM_CHILDREN_FILTER_INPUT_LEN], AcpiNamespaceError> {
    validate_relative_path(&name).map_err(|_| AcpiNamespaceError::InvalidInput)?;
    let mut input = [0u8; ACPI_ENUM_CHILDREN_FILTER_INPUT_LEN];
    input[0..4].copy_from_slice(&ENUM_INPUT_SIGNATURE.to_le_bytes());
    input[4..8]
        .copy_from_slice(&(ENUM_CHILDREN_MULTILEVEL | ENUM_CHILDREN_NAME_IS_FILTER).to_le_bytes());
    input[8..12].copy_from_slice(&5u32.to_le_bytes());
    input[12..16].copy_from_slice(&name);
    Ok(input)
}

/// Validate the standard overflow header, where `NumberOfChildren` carries the exact required
/// byte length rather than a child count.
pub fn namespace_children_required_len(
    header: &[u8],
    maximum: usize,
) -> Result<usize, AcpiNamespaceError> {
    if header.len() < ENUM_OUTPUT_HEADER_LEN {
        return Err(AcpiNamespaceError::Truncated);
    }
    if read_u32(header, 0)? != ENUM_OUTPUT_SIGNATURE {
        return Err(AcpiNamespaceError::InvalidOutput);
    }
    let required = read_u32(header, 4)? as usize;
    if required < ENUM_OUTPUT_HEADER_LEN || required > maximum {
        return Err(AcpiNamespaceError::InvalidRequiredLength);
    }
    Ok(required)
}

/// Decode one exact successful `IOCTL_ACPI_ENUM_CHILDREN` result. The provider returns the queried
/// PDO itself as record zero, followed by the requested namespace descendants.
pub fn parse_namespace_children(
    bytes: &[u8],
    maximum_children: usize,
) -> Result<AcpiNamespaceChildren, AcpiNamespaceError> {
    let children = parse_namespace_records(bytes, maximum_children)?;
    if children.is_empty() {
        return Err(AcpiNamespaceError::LimitExceeded);
    }
    Ok(AcpiNamespaceChildren { children })
}

/// Decode an exact successful multilevel NameSeg-filtered enumeration result.
pub fn parse_namespace_matches(
    bytes: &[u8],
    maximum_objects: usize,
) -> Result<AcpiNamespaceMatches, AcpiNamespaceError> {
    parse_namespace_records(bytes, maximum_objects).map(|objects| AcpiNamespaceMatches { objects })
}

fn parse_namespace_records(
    bytes: &[u8],
    maximum_records: usize,
) -> Result<Vec<AcpiNamespaceChild>, AcpiNamespaceError> {
    if bytes.len() < ENUM_OUTPUT_HEADER_LEN {
        return Err(AcpiNamespaceError::Truncated);
    }
    if read_u32(bytes, 0)? != ENUM_OUTPUT_SIGNATURE {
        return Err(AcpiNamespaceError::InvalidOutput);
    }
    let count = read_u32(bytes, 4)? as usize;
    if count > maximum_records {
        return Err(AcpiNamespaceError::LimitExceeded);
    }
    if count > (bytes.len() - ENUM_OUTPUT_HEADER_LEN) / (ENUM_CHILD_HEADER_LEN + 2) {
        return Err(AcpiNamespaceError::InvalidOutput);
    }
    let mut children = Vec::new();
    children
        .try_reserve_exact(count)
        .map_err(|_| AcpiNamespaceError::Allocation)?;
    let mut cursor = ENUM_OUTPUT_HEADER_LEN;
    for _ in 0..count {
        let flags = read_u32(bytes, cursor)?;
        let name_len = read_u32(bytes, cursor + 4)? as usize;
        if flags & !ACPI_OBJECT_HAS_CHILDREN != 0 || name_len < 2 {
            return Err(AcpiNamespaceError::InvalidOutput);
        }
        let name_start = cursor
            .checked_add(ENUM_CHILD_HEADER_LEN)
            .ok_or(AcpiNamespaceError::InvalidOutput)?;
        let end = name_start
            .checked_add(name_len)
            .filter(|end| *end <= bytes.len())
            .ok_or(AcpiNamespaceError::Truncated)?;
        let name = &bytes[name_start..end];
        if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
            return Err(AcpiNamespaceError::InvalidPath);
        }
        let path = core::str::from_utf8(&name[..name.len() - 1])
            .map_err(|_| AcpiNamespaceError::InvalidPath)
            .and_then(AcpiNamespacePath::parse)?;
        if children
            .iter()
            .any(|child: &AcpiNamespaceChild| child.path == path)
        {
            return Err(AcpiNamespaceError::DuplicatePath);
        }
        children.push(AcpiNamespaceChild {
            path,
            has_children: flags & ACPI_OBJECT_HAS_CHILDREN != 0,
        });
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(AcpiNamespaceError::InvalidOutput);
    }
    Ok(children)
}

/// Resolve an absolute or relative `_PRT` reference against exact provider-published PDO paths.
/// Relative names use ACPI scope up-search. No global NameSeg/tail fallback is permitted.
pub fn resolve_namespace_reference(
    scope: &AcpiNamespacePath,
    reference: &str,
    candidates: &[AcpiNamespacePath],
) -> Result<usize, AcpiNamespaceError> {
    if reference.starts_with('\\') {
        validate_absolute_path(reference.as_bytes())?;
        return unique_path_index(reference, candidates);
    }
    validate_relative_path(reference.as_bytes())?;

    let mut scope_len = scope.as_str().len();
    loop {
        let current = &scope.as_str()[..scope_len];
        let mut match_index = None;
        for (index, candidate) in candidates.iter().enumerate() {
            if joined_path_eq(candidate.as_str(), current, reference) {
                if match_index.is_some() {
                    return Err(AcpiNamespaceError::AmbiguousReference);
                }
                match_index = Some(index);
            }
        }
        if let Some(index) = match_index {
            return Ok(index);
        }
        if current == "\\" {
            break;
        }
        scope_len = current.rfind('.').unwrap_or(0).max(1);
    }
    Err(AcpiNamespaceError::MissingReference)
}

fn unique_path_index(
    expected: &str,
    candidates: &[AcpiNamespacePath],
) -> Result<usize, AcpiNamespaceError> {
    let mut found = None;
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.as_str() == expected {
            if found.is_some() {
                return Err(AcpiNamespaceError::AmbiguousReference);
            }
            found = Some(index);
        }
    }
    found.ok_or(AcpiNamespaceError::MissingReference)
}

fn joined_path_eq(candidate: &str, scope: &str, relative: &str) -> bool {
    let separator_len = usize::from(scope != "\\");
    if candidate.len() != scope.len() + separator_len + relative.len()
        || !candidate.starts_with(scope)
    {
        return false;
    }
    let suffix = &candidate[scope.len()..];
    if separator_len == 0 {
        suffix == relative
    } else {
        suffix.as_bytes().first() == Some(&b'.') && &suffix[1..] == relative
    }
}

pub(crate) fn validate_absolute_path(path: &[u8]) -> Result<(), AcpiNamespaceError> {
    if path == b"\\" {
        return Ok(());
    }
    if path.first() != Some(&b'\\') {
        return Err(AcpiNamespaceError::InvalidPath);
    }
    validate_relative_path(&path[1..]).map_err(|_| AcpiNamespaceError::InvalidPath)
}

fn validate_relative_path(path: &[u8]) -> Result<(), AcpiNamespaceError> {
    if path.is_empty() {
        return Err(AcpiNamespaceError::InvalidReference);
    }
    for segment in path.split(|byte| *byte == b'.') {
        if segment.len() != 4
            || !matches!(segment[0], b'A'..=b'Z' | b'_')
            || !segment[1..]
                .iter()
                .all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
        {
            return Err(AcpiNamespaceError::InvalidReference);
        }
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AcpiNamespaceError> {
    let end = offset
        .checked_add(4)
        .filter(|end| *end <= bytes.len())
        .ok_or(AcpiNamespaceError::Truncated)?;
    Ok(u32::from_le_bytes(bytes[offset..end].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn output(records: &[(u32, &str)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ENUM_OUTPUT_SIGNATURE.to_le_bytes());
        bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for (flags, name) in records {
            bytes.extend_from_slice(&flags.to_le_bytes());
            bytes.extend_from_slice(&((name.len() + 1) as u32).to_le_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn immediate_input_is_the_exact_zero_filter_c_layout() {
        let input = immediate_namespace_children_input();
        assert_eq!(&input[0..4], &ENUM_INPUT_SIGNATURE.to_le_bytes());
        assert_eq!(u32::from_le_bytes(input[4..8].try_into().unwrap()), 1);
        assert_eq!(&input[8..], &[0; 8]);
    }

    #[test]
    fn multilevel_filter_has_distinct_exact_input_and_zero_result_contract() {
        assert_eq!(
            multilevel_namespace_filter_input(*b"_PRT").unwrap(),
            [0x41, 0x65, 0x69, 0x48, 6, 0, 0, 0, 5, 0, 0, 0, b'_', b'P', b'R', b'T', 0,]
        );
        assert_eq!(
            multilevel_namespace_filter_input(*b"_prT"),
            Err(AcpiNamespaceError::InvalidInput)
        );

        let empty = output(&[]);
        assert_eq!(parse_namespace_matches(&empty, 8).unwrap().objects(), &[]);
        assert_eq!(
            parse_namespace_children(&empty, 8),
            Err(AcpiNamespaceError::LimitExceeded)
        );
    }

    #[test]
    fn filtered_paths_are_exact_canonical_and_unique_without_self_assumption() {
        let bytes = output(&[(0, "\\_SB_.PCI0._PRT"), (0, "\\_SB_.PCI0.BRG0._PRT")]);
        let matches = parse_namespace_matches(&bytes, 2).unwrap();
        assert_eq!(matches.objects().len(), 2);
        assert_eq!(matches.objects()[0].path.as_str(), "\\_SB_.PCI0._PRT");

        let duplicate = output(&[(0, "\\_SB_.PCI0._PRT"), (0, "\\_SB_.PCI0._PRT")]);
        assert_eq!(
            parse_namespace_matches(&duplicate, 2),
            Err(AcpiNamespaceError::DuplicatePath)
        );
    }

    #[test]
    fn overflow_header_yields_only_a_bounded_exact_size() {
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&ENUM_OUTPUT_SIGNATURE.to_le_bytes());
        header[4..].copy_from_slice(&1234u32.to_le_bytes());
        assert_eq!(namespace_children_required_len(&header, 4096), Ok(1234));
        assert_eq!(
            namespace_children_required_len(&header, 1024),
            Err(AcpiNamespaceError::InvalidRequiredLength)
        );
        header[4..].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            namespace_children_required_len(&header, 4096),
            Err(AcpiNamespaceError::InvalidRequiredLength)
        );
    }

    #[test]
    fn self_first_full_paths_and_flags_decode_exactly() {
        let bytes = output(&[
            (1, "\\_SB_.PCI0"),
            (1, "\\_SB_.PCI0.BRG0"),
            (0, "\\_SB_.PCI0.LNKA"),
        ]);
        let decoded = parse_namespace_children(&bytes, 3).unwrap();
        assert_eq!(decoded.self_path().as_str(), "\\_SB_.PCI0");
        assert_eq!(decoded.children().len(), 3);
        assert!(decoded.children()[1].has_children);
        assert_eq!(decoded.children()[2].path.name_seg(), Some("LNKA"));
    }

    #[test]
    fn malformed_records_paths_duplicates_and_trailing_bytes_fail() {
        let duplicate = output(&[(0, "\\_SB_.PCI0"), (0, "\\_SB_.PCI0")]);
        assert_eq!(
            parse_namespace_children(&duplicate, 2),
            Err(AcpiNamespaceError::DuplicatePath)
        );
        let lowercase = output(&[(0, "\\_SB_.pci0")]);
        assert_eq!(
            parse_namespace_children(&lowercase, 1),
            Err(AcpiNamespaceError::InvalidPath)
        );
        let mut trailing = output(&[(0, "\\_SB_.PCI0")]);
        trailing.push(0);
        assert_eq!(
            parse_namespace_children(&trailing, 1),
            Err(AcpiNamespaceError::InvalidOutput)
        );
        let invalid_flags = output(&[(2, "\\_SB_.PCI0")]);
        assert_eq!(
            parse_namespace_children(&invalid_flags, 1),
            Err(AcpiNamespaceError::InvalidOutput)
        );
    }

    #[test]
    fn relative_reference_uses_nearest_acpi_scope_only() {
        let scope = AcpiNamespacePath::parse("\\_SB_.PCI0.BRG0").unwrap();
        let candidates = vec![
            AcpiNamespacePath::parse("\\_SB_.LNKA").unwrap(),
            AcpiNamespacePath::parse("\\_SB_.PCI0.LNKA").unwrap(),
            AcpiNamespacePath::parse("\\_SB_.PCI0.BRG0.LNKB").unwrap(),
        ];
        assert_eq!(
            resolve_namespace_reference(&scope, "LNKA", &candidates),
            Ok(1)
        );
        assert_eq!(
            resolve_namespace_reference(&scope, "LNKB", &candidates),
            Ok(2)
        );
        assert_eq!(
            resolve_namespace_reference(&scope, "\\_SB_.LNKA", &candidates),
            Ok(0)
        );
    }

    #[test]
    fn reference_resolution_has_no_global_tail_fallback() {
        let scope = AcpiNamespacePath::parse("\\_SB_.PCI0").unwrap();
        let candidates = vec![AcpiNamespacePath::parse("\\_SB_.ISA_.LNKA").unwrap()];
        assert_eq!(
            resolve_namespace_reference(&scope, "LNKA", &candidates),
            Err(AcpiNamespaceError::MissingReference)
        );
        let duplicate = vec![
            AcpiNamespacePath::parse("\\_SB_.PCI0.LNKA").unwrap(),
            AcpiNamespacePath::parse("\\_SB_.PCI0.LNKA").unwrap(),
        ];
        assert_eq!(
            resolve_namespace_reference(&scope, "LNKA", &duplicate),
            Err(AcpiNamespaceError::AmbiguousReference)
        );
    }
}
