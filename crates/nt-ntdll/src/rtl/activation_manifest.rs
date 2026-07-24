//! Bounded parsing for the activation-context manifest subset used by DLL redirection.

use alloc::vec::Vec;
use core::ops::Range;

use crate::NtStatus;

use super::activation::{
    CompatibilityElement, DllRedirect, COMPATIBILITY_ELEMENT_TYPE_MAX_VERSION_TESTED,
    COMPATIBILITY_ELEMENT_TYPE_OS, RUN_LEVEL_AS_INVOKER, RUN_LEVEL_HIGHEST_AVAILABLE,
    RUN_LEVEL_REQUIRE_ADMIN, RUN_LEVEL_UNSPECIFIED, STATUS_SXS_CANT_GEN_ACTCTX,
};
use super::guid::Guid;

const STATUS_NO_MEMORY: NtStatus = 0xC000_0017;
const STATUS_SXS_INVALID_ACTCTXDATA_FORMAT: NtStatus = 0xC015_0003;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedManifest {
    pub dll_redirects: Vec<DllRedirect>,
    pub assembly_identity: AssemblyIdentity,
    pub compatibility: Vec<CompatibilityElement>,
    pub run_level: u32,
    pub ui_access: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedManifestDetails {
    pub root: ParsedManifest,
    pub root_language: Option<Vec<u16>>,
    pub dependencies: Vec<ManifestDependency>,
    pub window_classes: Vec<ManifestWindowClass>,
    pub com_interfaces: Vec<ManifestComInterface>,
    pub clr_surrogates: Vec<ManifestClrSurrogate>,
    pub application_settings: Vec<ManifestApplicationSetting>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestDependency {
    pub identity: AssemblyIdentity,
    pub language: Option<Vec<u16>>,
    pub optional: bool,
    pub delayed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestWindowClass {
    /// Index of the owning file in `ParsedManifest::dll_redirects`.
    pub file_index: usize,
    pub name: Vec<u16>,
    pub versioned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestComInterface {
    /// `Some` identifies a file-scoped proxy stub; `None` is an assembly-level external proxy stub.
    pub file_index: Option<usize>,
    /// The interface identifier used as the GUID-section lookup key.
    pub iid: Guid,
    pub name: Option<Vec<u16>>,
    pub proxy_stub_clsid32: Option<Guid>,
    pub type_library: Option<Guid>,
    pub base_interface: Option<Guid>,
    /// `Some(0)` preserves an explicitly empty or zero `numMethods` attribute and its mask bit.
    pub num_methods: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestClrSurrogate {
    pub clsid: Guid,
    pub name: Vec<u16>,
    /// `Some(empty)` preserves an explicitly empty `runtimeVersion` attribute.
    pub runtime_version: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestApplicationSetting {
    pub namespace: Vec<u16>,
    pub name: Vec<u16>,
    pub value: Vec<u16>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssemblyIdentity {
    pub name: Option<Vec<u16>>,
    pub processor_architecture: Option<Vec<u16>>,
    pub public_key_token: Option<Vec<u16>>,
    pub kind: Option<Vec<u16>>,
    pub version: [u16; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

#[derive(Clone, Copy, Debug)]
struct Tag {
    name_start: usize,
    name_end: usize,
    attrs_start: usize,
    attrs_end: usize,
    self_closing: bool,
}

impl Tag {
    fn name(self) -> Range<usize> {
        self.name_start..self.name_end
    }
}

#[derive(Clone, Copy, Debug)]
struct Attribute {
    name_start: usize,
    name_end: usize,
    value_start: usize,
    value_end: usize,
}

impl Attribute {
    fn name(self) -> Range<usize> {
        self.name_start..self.name_end
    }

    fn value(self) -> Range<usize> {
        self.value_start..self.value_end
    }
}

pub fn parse_manifest(bytes: &[u8]) -> Result<ParsedManifest, NtStatus> {
    let details = parse_manifest_details(bytes)?;
    if !details.dependencies.is_empty() {
        return Err(STATUS_SXS_CANT_GEN_ACTCTX);
    }
    Ok(details.root)
}

pub fn parse_manifest_details(bytes: &[u8]) -> Result<ParsedManifestDetails, NtStatus> {
    let input = decode_manifest(bytes)?;
    Parser::new(&input).parse()
}

pub fn encode_assembly_identity(identity: &AssemblyIdentity) -> Result<Vec<u16>, NtStatus> {
    let mut output = Vec::new();
    output.try_reserve(128).map_err(|_| STATUS_NO_MEMORY)?;
    if let Some(name) = &identity.name {
        output.extend_from_slice(name);
    }
    append_identity_attribute(
        &mut output,
        ",processorArchitecture=\"",
        identity.processor_architecture.as_deref(),
    )?;
    append_identity_attribute(
        &mut output,
        ",publicKeyToken=\"",
        identity.public_key_token.as_deref(),
    )?;
    append_identity_attribute(&mut output, ",type=\"", identity.kind.as_deref())?;
    extend_ascii(&mut output, ",version=\"")?;
    for (index, component) in identity.version.iter().copied().enumerate() {
        if index != 0 {
            output.push(b'.' as u16);
        }
        push_decimal_u16(&mut output, component)?;
    }
    output.push(b'"' as u16);
    Ok(output)
}

fn append_identity_attribute(
    output: &mut Vec<u16>,
    prefix: &str,
    value: Option<&[u16]>,
) -> Result<(), NtStatus> {
    let Some(value) = value else {
        return Ok(());
    };
    extend_ascii(output, prefix)?;
    output
        .try_reserve(value.len() + 1)
        .map_err(|_| STATUS_NO_MEMORY)?;
    output.extend_from_slice(value);
    output.push(b'"' as u16);
    Ok(())
}

fn extend_ascii(output: &mut Vec<u16>, value: &str) -> Result<(), NtStatus> {
    output
        .try_reserve(value.len())
        .map_err(|_| STATUS_NO_MEMORY)?;
    output.extend(value.bytes().map(u16::from));
    Ok(())
}

fn push_decimal_u16(output: &mut Vec<u16>, value: u16) -> Result<(), NtStatus> {
    let mut digits = [0u16; 5];
    let mut remaining = value;
    let mut count = 0usize;
    loop {
        digits[count] = b'0' as u16 + remaining % 10;
        count += 1;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    output.try_reserve(count).map_err(|_| STATUS_NO_MEMORY)?;
    output.extend(digits[..count].iter().rev().copied());
    Ok(())
}

fn parse_assembly_version(input: &[u16]) -> Result<[u16; 4], NtStatus> {
    if input.is_empty() {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    let mut result = [0u16; 4];
    let mut start = 0usize;
    let mut index = 0usize;
    loop {
        if index == result.len() {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let end = input[start..]
            .iter()
            .position(|unit| *unit == b'.' as u16)
            .map_or(input.len(), |offset| start + offset);
        if start == end {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let mut value = 0u16;
        for unit in &input[start..end] {
            if !(b'0' as u16..=b'9' as u16).contains(unit) {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(*unit - b'0' as u16))
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        }
        result[index] = value;
        index += 1;
        if end == input.len() {
            break;
        }
        start = end + 1;
    }
    Ok(result)
}

fn parse_u32_decimal(input: &[u16]) -> Result<u32, NtStatus> {
    let mut value = 0u32;
    for unit in input {
        if !(b'0' as u16..=b'9' as u16).contains(unit) {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u32::from(*unit - b'0' as u16)))
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    }
    Ok(value)
}

fn decode_manifest(bytes: &[u8]) -> Result<Vec<u16>, NtStatus> {
    let (encoding, offset) = if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        (Encoding::Utf8, 3)
    } else if bytes.starts_with(&[0xff, 0xfe]) {
        (Encoding::Utf16Le, 2)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        (Encoding::Utf16Be, 2)
    } else if bytes.len() >= 2 && bytes[0] == 0 && bytes[1] != 0 {
        (Encoding::Utf16Be, 0)
    } else if bytes.len() >= 2 && bytes[0] != 0 && bytes[1] == 0 {
        (Encoding::Utf16Le, 0)
    } else {
        (Encoding::Utf8, 0)
    };

    let payload = &bytes[offset..];
    let mut output = Vec::new();
    match encoding {
        Encoding::Utf8 => {
            let text =
                core::str::from_utf8(payload).map_err(|_| STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
            output
                .try_reserve(text.len())
                .map_err(|_| STATUS_NO_MEMORY)?;
            output.extend(text.encode_utf16());
        }
        Encoding::Utf16Le | Encoding::Utf16Be => {
            if payload.len() % 2 != 0 {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            output
                .try_reserve(payload.len() / 2)
                .map_err(|_| STATUS_NO_MEMORY)?;
            for pair in payload.chunks_exact(2) {
                output.push(match encoding {
                    Encoding::Utf16Le => u16::from_le_bytes([pair[0], pair[1]]),
                    Encoding::Utf16Be => u16::from_be_bytes([pair[0], pair[1]]),
                    Encoding::Utf8 => unreachable!(),
                });
            }
        }
    }
    validate_xml_characters(&output)?;
    Ok(output)
}

fn validate_xml_characters(input: &[u16]) -> Result<(), NtStatus> {
    let mut index = 0;
    while index < input.len() {
        let unit = input[index];
        let scalar = if (0xd800..=0xdbff).contains(&unit) {
            let Some(&low) = input.get(index + 1) else {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            };
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            index += 2;
            0x1_0000 + (((unit as u32 - 0xd800) << 10) | (low as u32 - 0xdc00))
        } else if (0xdc00..=0xdfff).contains(&unit) {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        } else {
            index += 1;
            unit as u32
        };
        if !is_xml_character(scalar) {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
    }
    Ok(())
}

fn is_xml_character(value: u32) -> bool {
    matches!(value, 0x09 | 0x0a | 0x0d)
        || (0x20..=0xd7ff).contains(&value)
        || (0xe000..=0xfffd).contains(&value)
        || (0x1_0000..=0x10_ffff).contains(&value)
}

struct Parser<'a> {
    input: &'a [u16],
    position: usize,
    redirects: Vec<DllRedirect>,
    identity: Option<AssemblyIdentity>,
    root_language: Option<Vec<u16>>,
    dependencies: Vec<ManifestDependency>,
    window_classes: Vec<ManifestWindowClass>,
    com_interfaces: Vec<ManifestComInterface>,
    clr_surrogates: Vec<ManifestClrSurrogate>,
    application_settings: Vec<ManifestApplicationSetting>,
    selected_settings_application: Option<usize>,
    next_application_id: usize,
    compatibility: Vec<CompatibilityElement>,
    run_level: u32,
    ui_access: u32,
}

struct Frame {
    tag: Tag,
    kind: FrameKind,
}

enum FrameKind {
    Assembly,
    File {
        file_index: usize,
    },
    Dependency {
        optional: bool,
    },
    DependentAssembly {
        optional: bool,
        delayed: bool,
        saw_identity: bool,
    },
    WindowClass {
        file_index: usize,
        versioned: bool,
        text: Vec<u16>,
    },
    Application {
        application_id: usize,
    },
    WindowsSettings {
        application_id: usize,
    },
    ApplicationSetting {
        namespace: Vec<u16>,
        name: Vec<u16>,
        value: Vec<u16>,
    },
    EmptyKnown,
    Other,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u16]) -> Self {
        Self {
            input,
            position: 0,
            redirects: Vec::new(),
            identity: None,
            root_language: None,
            dependencies: Vec::new(),
            window_classes: Vec::new(),
            com_interfaces: Vec::new(),
            clr_surrogates: Vec::new(),
            application_settings: Vec::new(),
            selected_settings_application: None,
            next_application_id: 0,
            compatibility: Vec::new(),
            run_level: RUN_LEVEL_UNSPECIFIED,
            ui_access: 0,
        }
    }

    fn parse(mut self) -> Result<ParsedManifestDetails, NtStatus> {
        self.skip_document_misc()?;
        let root = self.parse_start_tag()?;
        if !local_eq(self.input, root.name(), "assembly") || !self.root_has_version(root)? {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }

        if !root.self_closing {
            let mut stack = Vec::new();
            stack.try_reserve(1).map_err(|_| STATUS_NO_MEMORY)?;
            stack.push(Frame {
                tag: root,
                kind: FrameKind::Assembly,
            });

            while !stack.is_empty() {
                let text_start = self.position;
                while self.position < self.input.len() && self.input[self.position] != b'<' as u16 {
                    self.position += 1;
                }
                let text = &self.input[text_start..self.position];
                validate_escaped_text(text)?;
                if let Some(frame) = stack.last_mut() {
                    if matches!(&frame.kind, FrameKind::EmptyKnown)
                        && text.iter().copied().any(|unit| !is_whitespace(unit))
                    {
                        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                    }
                    let output = match &mut frame.kind {
                        FrameKind::WindowClass { text, .. }
                        | FrameKind::ApplicationSetting { value: text, .. } => Some(text),
                        _ => None,
                    };
                    if let Some(output) = output {
                        let decoded = decode_attribute_value(text)?;
                        output
                            .try_reserve(decoded.len())
                            .map_err(|_| STATUS_NO_MEMORY)?;
                        output.extend_from_slice(&decoded);
                    }
                }
                if self.position == self.input.len() {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                }

                if self.starts_with("<!--") {
                    self.skip_comment()?;
                } else if self.starts_with("<![CDATA[") {
                    let content_start = self.position + 9;
                    let content_end = find_ascii(self.input, content_start, "]]>")
                        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
                    if let Some(frame) = stack.last_mut() {
                        if matches!(&frame.kind, FrameKind::EmptyKnown) {
                            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                        }
                        let output = match &mut frame.kind {
                            FrameKind::WindowClass { text, .. }
                            | FrameKind::ApplicationSetting { value: text, .. } => Some(text),
                            _ => None,
                        };
                        if let Some(output) = output {
                            output
                                .try_reserve(content_end - content_start)
                                .map_err(|_| STATUS_NO_MEMORY)?;
                            output.extend_from_slice(&self.input[content_start..content_end]);
                        }
                    }
                    self.position = content_end + 3;
                } else if self.starts_with("<?") {
                    self.skip_processing_instruction()?;
                } else if self.starts_with("</") {
                    let closing = self.parse_end_tag()?;
                    let Some(frame) = stack.pop() else {
                        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                    };
                    if self.input[frame.tag.name()] != self.input[closing] {
                        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                    }
                    self.finish_frame(frame.kind)?;
                } else if self.starts_with("<!") {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                } else {
                    let tag = self.parse_start_tag()?;
                    if stack.last().is_some_and(|frame| {
                        matches!(
                            &frame.kind,
                            FrameKind::WindowClass { .. }
                                | FrameKind::ApplicationSetting { .. }
                                | FrameKind::EmptyKnown
                        )
                    }) {
                        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                    }
                    let namespace = resolve_element_namespace(self.input, tag, &stack)?;
                    let parent_is_assembly = stack
                        .last()
                        .is_some_and(|frame| matches!(&frame.kind, FrameKind::Assembly));
                    let parent_dependency_optional =
                        stack.last().and_then(|frame| match &frame.kind {
                            FrameKind::Dependency { optional } => Some(*optional),
                            _ => None,
                        });
                    let parent_dependent = stack.last().and_then(|frame| match &frame.kind {
                        FrameKind::DependentAssembly {
                            optional,
                            delayed,
                            saw_identity,
                        } => Some((*optional, *delayed, *saw_identity)),
                        _ => None,
                    });
                    let parent_file_index = stack.last().and_then(|frame| match &frame.kind {
                        FrameKind::File { file_index } => Some(*file_index),
                        _ => None,
                    });
                    let parent_application_id = stack.last().and_then(|frame| match &frame.kind {
                        FrameKind::Application { application_id } => Some(*application_id),
                        _ => None,
                    });
                    let parent_settings_application_id =
                        stack.last().and_then(|frame| match &frame.kind {
                            FrameKind::WindowsSettings { application_id } => Some(*application_id),
                            _ => None,
                        });

                    let kind = if parent_is_assembly && local_eq(self.input, tag.name(), "file") {
                        FrameKind::File {
                            file_index: self.add_file_redirect(tag)?,
                        }
                    } else if parent_is_assembly && local_eq(self.input, tag.name(), "dependency") {
                        FrameKind::Dependency {
                            optional: self.dependency_is_optional(tag)?,
                        }
                    } else if parent_is_assembly
                        && local_eq(self.input, tag.name(), "assemblyIdentity")
                    {
                        self.set_assembly_identity(tag)?;
                        FrameKind::Other
                    } else if parent_is_assembly && local_eq(self.input, tag.name(), "clrSurrogate")
                    {
                        self.add_clr_surrogate(tag)?;
                        FrameKind::Other
                    } else if parent_is_assembly
                        && local_eq(self.input, tag.name(), "comInterfaceExternalProxyStub")
                        && is_assembly_v1_namespace(&namespace)
                    {
                        self.add_com_interface(tag, None)?;
                        FrameKind::EmptyKnown
                    } else if parent_dependency_optional.is_some()
                        && local_eq(self.input, tag.name(), "dependentAssembly")
                    {
                        FrameKind::DependentAssembly {
                            optional: parent_dependency_optional.unwrap(),
                            delayed: self.dependent_is_delayed(tag)?,
                            saw_identity: false,
                        }
                    } else if parent_dependent.is_some()
                        && local_eq(self.input, tag.name(), "assemblyIdentity")
                    {
                        let (optional, delayed, saw_identity) = parent_dependent.unwrap();
                        if saw_identity {
                            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                        }
                        self.add_dependency_identity(tag, optional, delayed)?;
                        if let Some(Frame {
                            kind: FrameKind::DependentAssembly { saw_identity, .. },
                            ..
                        }) = stack.last_mut()
                        {
                            *saw_identity = true;
                        }
                        FrameKind::Other
                    } else if parent_file_index.is_some()
                        && local_eq(self.input, tag.name(), "windowClass")
                    {
                        FrameKind::WindowClass {
                            file_index: parent_file_index.unwrap(),
                            versioned: self.window_class_is_versioned(tag)?,
                            text: Vec::new(),
                        }
                    } else if let Some(file_index) = parent_file_index.filter(|_| {
                        local_eq(self.input, tag.name(), "comInterfaceProxyStub")
                            && is_assembly_v1_namespace(&namespace)
                    }) {
                        self.add_com_interface(tag, Some(file_index))?;
                        FrameKind::EmptyKnown
                    } else if parent_is_assembly
                        && local_eq(self.input, tag.name(), "application")
                        && is_assembly_namespace(&namespace)
                    {
                        let application_id = self.next_application_id;
                        self.next_application_id = self
                            .next_application_id
                            .checked_add(1)
                            .ok_or(STATUS_NO_MEMORY)?;
                        FrameKind::Application { application_id }
                    } else if parent_application_id.is_some()
                        && local_eq(self.input, tag.name(), "windowsSettings")
                        && is_assembly_namespace(&namespace)
                    {
                        FrameKind::WindowsSettings {
                            application_id: parent_application_id.unwrap(),
                        }
                    } else if let Some(application_id) = parent_settings_application_id {
                        let name = local_name(self.input, tag.name());
                        if !tag.self_closing
                            && is_application_setting(&namespace, name)
                            && self
                                .selected_settings_application
                                .is_none_or(|selected| selected == application_id)
                        {
                            self.selected_settings_application = Some(application_id);
                            FrameKind::ApplicationSetting {
                                namespace,
                                name: name.to_vec(),
                                value: Vec::new(),
                            }
                        } else {
                            FrameKind::Other
                        }
                    } else {
                        FrameKind::Other
                    };
                    if local_eq(self.input, tag.name(), "supportedOS")
                        && local_frame_suffix(self.input, &stack, &["compatibility", "application"])
                    {
                        self.add_supported_os(tag)?;
                    }
                    if local_eq(self.input, tag.name(), "maxversiontested")
                        && local_frame_suffix(self.input, &stack, &["compatibility", "application"])
                    {
                        self.add_max_version_tested(tag)?;
                    }
                    if local_eq(self.input, tag.name(), "requestedExecutionLevel")
                        && local_frame_suffix(
                            self.input,
                            &stack,
                            &["trustInfo", "security", "requestedPrivileges"],
                        )
                    {
                        self.set_requested_execution_level(tag)?;
                    }
                    if !tag.self_closing {
                        stack.try_reserve(1).map_err(|_| STATUS_NO_MEMORY)?;
                        stack.push(Frame { tag, kind });
                    }
                }
            }
        }

        self.skip_document_misc()?;
        if self.position != self.input.len() {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        Ok(ParsedManifestDetails {
            root: ParsedManifest {
                dll_redirects: self.redirects,
                assembly_identity: self.identity.unwrap_or_default(),
                compatibility: self.compatibility,
                run_level: self.run_level,
                ui_access: self.ui_access,
            },
            root_language: self.root_language,
            dependencies: self.dependencies,
            window_classes: self.window_classes,
            com_interfaces: self.com_interfaces,
            clr_surrogates: self.clr_surrogates,
            application_settings: self.application_settings,
        })
    }

    fn root_has_version(&self, tag: Tag) -> Result<bool, NtStatus> {
        let mut position = tag.attrs_start;
        let mut found = false;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            if local_eq(self.input, attribute.name(), "manifestVersion") {
                if found {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                }
                let value = decode_attribute_value(&self.input[attribute.value()])?;
                found = value.as_slice() == [b'1' as u16, b'.' as u16, b'0' as u16];
                if !found {
                    return Ok(false);
                }
            }
        }
        Ok(found)
    }

    fn add_file_redirect(&mut self, tag: Tag) -> Result<usize, NtStatus> {
        let mut position = tag.attrs_start;
        let mut name = None;
        let mut load_from = None;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            if local_eq(self.input, attribute.name(), "name") {
                if name.is_some() {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                }
                name = Some(decode_attribute_value(&self.input[attribute.value()])?);
            } else if local_eq(self.input, attribute.name(), "loadFrom") {
                if load_from.is_some() {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                }
                load_from = Some(decode_attribute_value(&self.input[attribute.value()])?);
            }
        }
        let Some(name) = name else {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        };
        if name.is_empty() {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        self.redirects
            .try_reserve(1)
            .map_err(|_| STATUS_NO_MEMORY)?;
        let file_index = self.redirects.len();
        self.redirects.push(DllRedirect { name, load_from });
        Ok(file_index)
    }

    fn set_assembly_identity(&mut self, tag: Tag) -> Result<(), NtStatus> {
        if self.identity.is_some() {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let (identity, language) = self.parse_assembly_identity(tag)?;
        self.identity = Some(identity);
        self.root_language = language;
        Ok(())
    }

    fn add_dependency_identity(
        &mut self,
        tag: Tag,
        optional: bool,
        delayed: bool,
    ) -> Result<(), NtStatus> {
        let (identity, language) = self.parse_assembly_identity(tag)?;
        self.dependencies
            .try_reserve(1)
            .map_err(|_| STATUS_NO_MEMORY)?;
        self.dependencies.push(ManifestDependency {
            identity,
            language,
            optional,
            delayed,
        });
        Ok(())
    }

    fn parse_assembly_identity(
        &self,
        tag: Tag,
    ) -> Result<(AssemblyIdentity, Option<Vec<u16>>), NtStatus> {
        let mut identity = AssemblyIdentity::default();
        let mut language = None;
        let mut position = tag.attrs_start;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            let value = || decode_attribute_value(&self.input[attribute.value()]);
            if attribute_eq(self.input, attribute, "name") {
                identity.name = Some(value()?);
            } else if attribute_eq(self.input, attribute, "processorArchitecture") {
                identity.processor_architecture = Some(value()?);
            } else if attribute_eq(self.input, attribute, "publicKeyToken") {
                identity.public_key_token = Some(value()?);
            } else if attribute_eq(self.input, attribute, "type") {
                identity.kind = Some(value()?);
            } else if attribute_eq(self.input, attribute, "version") {
                identity.version = parse_assembly_version(&value()?)?;
            } else if attribute_eq(self.input, attribute, "language") {
                language = Some(value()?);
            }
        }
        Ok((identity, language))
    }

    fn dependency_is_optional(&self, tag: Tag) -> Result<bool, NtStatus> {
        let mut optional = false;
        let mut position = tag.attrs_start;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            if attribute_eq(self.input, attribute, "optional") {
                optional = ascii_slice_eq_ci(
                    &decode_attribute_value(&self.input[attribute.value()])?,
                    "yes",
                );
            }
        }
        Ok(optional)
    }

    fn dependent_is_delayed(&self, tag: Tag) -> Result<bool, NtStatus> {
        let mut delayed = false;
        let mut position = tag.attrs_start;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            if attribute_eq(self.input, attribute, "allowDelayedBinding") {
                delayed = ascii_slice_eq(
                    &decode_attribute_value(&self.input[attribute.value()])?,
                    "true",
                );
            }
        }
        Ok(delayed)
    }

    fn window_class_is_versioned(&self, tag: Tag) -> Result<bool, NtStatus> {
        let mut versioned = true;
        let mut position = tag.attrs_start;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            if attribute_eq(self.input, attribute, "versioned") {
                let value = decode_attribute_value(&self.input[attribute.value()])?;
                if ascii_slice_eq_ci(&value, "yes") {
                    versioned = true;
                } else if ascii_slice_eq_ci(&value, "no") {
                    versioned = false;
                } else {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                }
            }
        }
        Ok(versioned)
    }

    fn add_com_interface(&mut self, tag: Tag, file_index: Option<usize>) -> Result<(), NtStatus> {
        let mut iid = None;
        let mut name = None;
        let mut proxy_stub_clsid32 = None;
        let mut type_library = None;
        let mut base_interface = None;
        let mut num_methods = None;
        let mut position = tag.attrs_start;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            let value = || decode_attribute_value(&self.input[attribute.value()]);
            if attribute_eq(self.input, attribute, "iid") {
                iid = Some(
                    super::guid::guid_from_string(&value()?)
                        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
                );
            } else if attribute_eq(self.input, attribute, "name") {
                name = Some(value()?);
            } else if attribute_eq(self.input, attribute, "proxyStubClsid32") {
                proxy_stub_clsid32 = Some(
                    super::guid::guid_from_string(&value()?)
                        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
                );
            } else if attribute_eq(self.input, attribute, "tlbid") {
                type_library = Some(
                    super::guid::guid_from_string(&value()?)
                        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
                );
            } else if attribute_eq(self.input, attribute, "baseInterface") {
                base_interface = Some(
                    super::guid::guid_from_string(&value()?)
                        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?,
                );
            } else if attribute_eq(self.input, attribute, "numMethods") {
                num_methods = Some(parse_u32_decimal(&value()?)?);
            }
        }
        let iid = iid.ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        if name
            .as_ref()
            .is_some_and(|name| name.is_empty() || name.contains(&0))
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        self.com_interfaces
            .try_reserve(1)
            .map_err(|_| STATUS_NO_MEMORY)?;
        self.com_interfaces.push(ManifestComInterface {
            file_index,
            iid,
            name,
            proxy_stub_clsid32,
            type_library,
            base_interface,
            num_methods,
        });
        Ok(())
    }

    fn add_clr_surrogate(&mut self, tag: Tag) -> Result<(), NtStatus> {
        let mut clsid = None;
        let mut name = None;
        let mut runtime_version = None;
        let mut position = tag.attrs_start;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            let value = || decode_attribute_value(&self.input[attribute.value()]);
            if attribute_eq(self.input, attribute, "clsid") {
                clsid = super::guid::guid_from_string(&value()?);
                if clsid.is_none() {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                }
            } else if attribute_eq(self.input, attribute, "name") {
                name = Some(value()?);
            } else if attribute_eq(self.input, attribute, "runtimeVersion") {
                runtime_version = Some(value()?);
            }
        }
        let (Some(clsid), Some(name)) = (clsid, name) else {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        };
        if name.is_empty()
            || name.contains(&0)
            || runtime_version
                .as_ref()
                .is_some_and(|version| version.contains(&0))
        {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        self.clr_surrogates
            .try_reserve(1)
            .map_err(|_| STATUS_NO_MEMORY)?;
        self.clr_surrogates.push(ManifestClrSurrogate {
            clsid,
            name,
            runtime_version,
        });
        Ok(())
    }

    fn finish_frame(&mut self, kind: FrameKind) -> Result<(), NtStatus> {
        match kind {
            FrameKind::WindowClass {
                file_index,
                versioned,
                text,
            } => {
                if text.is_empty() || text.contains(&0) {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                }
                self.window_classes
                    .try_reserve(1)
                    .map_err(|_| STATUS_NO_MEMORY)?;
                self.window_classes.push(ManifestWindowClass {
                    file_index,
                    name: text,
                    versioned,
                });
            }
            FrameKind::ApplicationSetting {
                namespace,
                name,
                value,
            } => {
                if value.contains(&0) {
                    return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                }
                self.application_settings
                    .try_reserve(1)
                    .map_err(|_| STATUS_NO_MEMORY)?;
                self.application_settings.push(ManifestApplicationSetting {
                    namespace,
                    name,
                    value,
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn add_supported_os(&mut self, tag: Tag) -> Result<(), NtStatus> {
        let mut position = tag.attrs_start;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            if local_eq(self.input, attribute.name(), "Id") {
                let value = decode_attribute_value(&self.input[attribute.value()])?;
                if let Some(id) = super::guid::guid_from_string(&value) {
                    self.compatibility
                        .try_reserve(1)
                        .map_err(|_| STATUS_NO_MEMORY)?;
                    self.compatibility.push(CompatibilityElement {
                        id,
                        kind: COMPATIBILITY_ELEMENT_TYPE_OS,
                        max_version_tested: 0,
                    });
                }
            }
        }
        Ok(())
    }

    fn add_max_version_tested(&mut self, tag: Tag) -> Result<(), NtStatus> {
        let mut position = tag.attrs_start;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            if local_eq(self.input, attribute.name(), "Id") {
                let value = decode_attribute_value(&self.input[attribute.value()])?;
                let [major, minor, build, revision] = parse_assembly_version(&value)?;
                self.compatibility
                    .try_reserve(1)
                    .map_err(|_| STATUS_NO_MEMORY)?;
                self.compatibility.push(CompatibilityElement {
                    id: super::guid::Guid::default(),
                    kind: COMPATIBILITY_ELEMENT_TYPE_MAX_VERSION_TESTED,
                    max_version_tested: (u64::from(major) << 48)
                        | (u64::from(minor) << 32)
                        | (u64::from(build) << 16)
                        | u64::from(revision),
                });
            }
        }
        Ok(())
    }

    fn set_requested_execution_level(&mut self, tag: Tag) -> Result<(), NtStatus> {
        if self.run_level != RUN_LEVEL_UNSPECIFIED {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let mut position = tag.attrs_start;
        while let Some(attribute) = next_attribute(self.input, &mut position, tag.attrs_end)? {
            let value = decode_attribute_value(&self.input[attribute.value()])?;
            if local_eq(self.input, attribute.name(), "level") {
                self.run_level = if ascii_slice_eq_ci(&value, "asInvoker") {
                    RUN_LEVEL_AS_INVOKER
                } else if ascii_slice_eq_ci(&value, "highestAvailable") {
                    RUN_LEVEL_HIGHEST_AVAILABLE
                } else if ascii_slice_eq_ci(&value, "requireAdministrator") {
                    RUN_LEVEL_REQUIRE_ADMIN
                } else {
                    RUN_LEVEL_UNSPECIFIED
                };
            } else if local_eq(self.input, attribute.name(), "uiAccess") {
                if ascii_slice_eq_ci(&value, "true") {
                    self.ui_access = 1;
                } else if ascii_slice_eq_ci(&value, "false") {
                    self.ui_access = 0;
                }
            }
        }
        Ok(())
    }

    fn parse_start_tag(&mut self) -> Result<Tag, NtStatus> {
        if self.input.get(self.position) != Some(&(b'<' as u16)) {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        self.position += 1;
        let name_start = self.position;
        self.parse_name()?;
        let name_end = self.position;
        let attrs_start = self.position;

        loop {
            let before_whitespace = self.position;
            skip_whitespace(self.input, &mut self.position);
            let had_whitespace = self.position != before_whitespace;
            match self.input.get(self.position).copied() {
                Some(value) if value == b'>' as u16 => {
                    let attrs_end = self.position;
                    ensure_unique_attributes(self.input, attrs_start, attrs_end)?;
                    self.position += 1;
                    return Ok(Tag {
                        name_start,
                        name_end,
                        attrs_start,
                        attrs_end,
                        self_closing: false,
                    });
                }
                Some(value) if value == b'/' as u16 => {
                    let attrs_end = self.position;
                    ensure_unique_attributes(self.input, attrs_start, attrs_end)?;
                    self.position += 1;
                    if self.input.get(self.position) != Some(&(b'>' as u16)) {
                        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
                    }
                    self.position += 1;
                    return Ok(Tag {
                        name_start,
                        name_end,
                        attrs_start,
                        attrs_end,
                        self_closing: true,
                    });
                }
                Some(_) if had_whitespace => self.validate_one_attribute()?,
                Some(_) => return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT),
                None => return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT),
            }
        }
    }

    fn validate_one_attribute(&mut self) -> Result<(), NtStatus> {
        self.parse_name()?;
        skip_whitespace(self.input, &mut self.position);
        if self.input.get(self.position) != Some(&(b'=' as u16)) {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        self.position += 1;
        skip_whitespace(self.input, &mut self.position);
        let quote = self
            .input
            .get(self.position)
            .copied()
            .filter(|value| *value == b'\'' as u16 || *value == b'"' as u16)
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        self.position += 1;
        let value_start = self.position;
        while self.position < self.input.len() && self.input[self.position] != quote {
            if self.input[self.position] == b'<' as u16 {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
            self.position += 1;
        }
        if self.position == self.input.len() {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        validate_escaped_text(&self.input[value_start..self.position])?;
        self.position += 1;
        Ok(())
    }

    fn parse_end_tag(&mut self) -> Result<Range<usize>, NtStatus> {
        self.position += 2;
        let start = self.position;
        self.parse_name()?;
        let end = self.position;
        skip_whitespace(self.input, &mut self.position);
        if self.input.get(self.position) != Some(&(b'>' as u16)) {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        self.position += 1;
        Ok(start..end)
    }

    fn parse_name(&mut self) -> Result<(), NtStatus> {
        let Some(&first) = self.input.get(self.position) else {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        };
        if !is_name_start(first) {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        self.position += 1;
        while self
            .input
            .get(self.position)
            .copied()
            .is_some_and(is_name_continue)
        {
            self.position += 1;
        }
        Ok(())
    }

    fn skip_document_misc(&mut self) -> Result<(), NtStatus> {
        loop {
            skip_whitespace(self.input, &mut self.position);
            if self.starts_with("<!--") {
                self.skip_comment()?;
            } else if self.starts_with("<?") {
                self.skip_processing_instruction()?;
            } else {
                return Ok(());
            }
        }
    }

    fn skip_comment(&mut self) -> Result<(), NtStatus> {
        let content_start = self.position + 4;
        let end = find_ascii(self.input, content_start, "-->")
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        if find_ascii(self.input, content_start, "--").is_some_and(|bad| bad < end) {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        self.position = end + 3;
        Ok(())
    }

    fn skip_processing_instruction(&mut self) -> Result<(), NtStatus> {
        let end = find_ascii(self.input, self.position + 2, "?>")
            .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        self.position = end + 2;
        Ok(())
    }

    fn starts_with(&self, value: &str) -> bool {
        ascii_eq_at(self.input, self.position, value)
    }
}

fn next_attribute(
    input: &[u16],
    position: &mut usize,
    end: usize,
) -> Result<Option<Attribute>, NtStatus> {
    skip_whitespace_bounded(input, position, end);
    if *position == end {
        return Ok(None);
    }
    let name_start = *position;
    parse_name_bounded(input, position, end)?;
    let name_end = *position;
    skip_whitespace_bounded(input, position, end);
    if *position == end || input[*position] != b'=' as u16 {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    *position += 1;
    skip_whitespace_bounded(input, position, end);
    let quote = *input
        .get(*position)
        .filter(|value| **value == b'\'' as u16 || **value == b'"' as u16)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    *position += 1;
    let value_start = *position;
    while *position < end && input[*position] != quote {
        *position += 1;
    }
    if *position == end {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    let value_end = *position;
    *position += 1;
    Ok(Some(Attribute {
        name_start,
        name_end,
        value_start,
        value_end,
    }))
}

fn ensure_unique_attributes(input: &[u16], start: usize, end: usize) -> Result<(), NtStatus> {
    let mut current_position = start;
    while let Some(current) = next_attribute(input, &mut current_position, end)? {
        let mut previous_position = start;
        while let Some(previous) = next_attribute(input, &mut previous_position, end)? {
            if previous.name_start >= current.name_start {
                break;
            }
            if input[previous.name()] == input[current.name()] {
                return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
            }
        }
    }
    Ok(())
}

fn resolve_element_namespace(
    input: &[u16],
    tag: Tag,
    stack: &[Frame],
) -> Result<Vec<u16>, NtStatus> {
    let qualified = &input[tag.name()];
    let prefix_end = qualified
        .iter()
        .rposition(|unit| *unit == b':' as u16)
        .unwrap_or(0);
    let prefix = if prefix_end == 0 {
        &[][..]
    } else {
        &qualified[..prefix_end]
    };
    if let Some(namespace) = namespace_declared_on_tag(input, tag, prefix)? {
        return Ok(namespace);
    }
    for frame in stack.iter().rev() {
        if let Some(namespace) = namespace_declared_on_tag(input, frame.tag, prefix)? {
            return Ok(namespace);
        }
    }
    Ok(Vec::new())
}

fn namespace_declared_on_tag(
    input: &[u16],
    tag: Tag,
    prefix: &[u16],
) -> Result<Option<Vec<u16>>, NtStatus> {
    let mut position = tag.attrs_start;
    while let Some(attribute) = next_attribute(input, &mut position, tag.attrs_end)? {
        let name = &input[attribute.name()];
        let matches = if prefix.is_empty() {
            ascii_slice_eq(name, "xmlns")
        } else {
            name.len() == 6 + prefix.len()
                && ascii_slice_eq(&name[..6], "xmlns:")
                && name[6..] == *prefix
        };
        if matches {
            return decode_attribute_value(&input[attribute.value()]).map(Some);
        }
    }
    Ok(None)
}

fn local_name(input: &[u16], name: Range<usize>) -> &[u16] {
    let qualified = &input[name];
    let local_start = qualified
        .iter()
        .rposition(|unit| *unit == b':' as u16)
        .map_or(0, |position| position + 1);
    &qualified[local_start..]
}

fn is_assembly_namespace(namespace: &[u16]) -> bool {
    ascii_slice_eq(namespace, "urn:schemas-microsoft-com:asm.v1")
        || ascii_slice_eq(namespace, "urn:schemas-microsoft-com:asm.v2")
        || ascii_slice_eq(namespace, "urn:schemas-microsoft-com:asm.v3")
}

fn is_assembly_v1_namespace(namespace: &[u16]) -> bool {
    namespace.is_empty() || ascii_slice_eq(namespace, "urn:schemas-microsoft-com:asm.v1")
}

fn is_application_setting(namespace: &[u16], name: &[u16]) -> bool {
    (ascii_slice_eq(
        namespace,
        "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
    ) && matches_ascii(name, &["autoElevate", "disableTheming", "dpiAware"]))
        || (ascii_slice_eq(
            namespace,
            "http://schemas.microsoft.com/SMI/2011/WindowsSettings",
        ) && matches_ascii(name, &["disableWindowFiltering", "printerDriverIsolation"]))
        || (ascii_slice_eq(
            namespace,
            "http://schemas.microsoft.com/SMI/2016/WindowsSettings",
        ) && matches_ascii(name, &["dpiAwareness", "longPathAware"]))
        || (ascii_slice_eq(
            namespace,
            "http://schemas.microsoft.com/SMI/2017/WindowsSettings",
        ) && matches_ascii(
            name,
            &[
                "gdiScaling",
                "highResolutionScrollingAware",
                "magicFutureSetting",
                "ultraHighResolutionScrollingAware",
            ],
        ))
        || (ascii_slice_eq(
            namespace,
            "http://schemas.microsoft.com/SMI/2019/WindowsSettings",
        ) && ascii_slice_eq(name, "activeCodePage"))
        || (ascii_slice_eq(
            namespace,
            "http://schemas.microsoft.com/SMI/2020/WindowsSettings",
        ) && ascii_slice_eq(name, "heapType"))
}

fn matches_ascii(input: &[u16], choices: &[&str]) -> bool {
    choices.iter().any(|choice| ascii_slice_eq(input, choice))
}

fn parse_name_bounded(input: &[u16], position: &mut usize, end: usize) -> Result<(), NtStatus> {
    if *position >= end || !is_name_start(input[*position]) {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    *position += 1;
    while *position < end && is_name_continue(input[*position]) {
        *position += 1;
    }
    Ok(())
}

fn decode_attribute_value(input: &[u16]) -> Result<Vec<u16>, NtStatus> {
    let mut output = Vec::new();
    output
        .try_reserve(input.len())
        .map_err(|_| STATUS_NO_MEMORY)?;
    let mut position = 0;
    while position < input.len() {
        if input[position] != b'&' as u16 {
            output.push(input[position]);
            position += 1;
            continue;
        }
        let (scalar, next) = parse_entity(input, position)?;
        if scalar <= 0xffff {
            output.push(scalar as u16);
        } else {
            let scalar = scalar - 0x1_0000;
            output.push(0xd800 | (scalar >> 10) as u16);
            output.push(0xdc00 | (scalar as u16 & 0x03ff));
        }
        position = next;
    }
    Ok(output)
}

fn validate_escaped_text(input: &[u16]) -> Result<(), NtStatus> {
    if find_ascii(input, 0, "]]>").is_some() {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    let mut position = 0;
    while position < input.len() {
        if input[position] == b'&' as u16 {
            position = parse_entity(input, position)?.1;
        } else {
            position += 1;
        }
    }
    Ok(())
}

fn parse_entity(input: &[u16], start: usize) -> Result<(u32, usize), NtStatus> {
    let semicolon = input[start + 1..]
        .iter()
        .position(|value| *value == b';' as u16)
        .map(|offset| start + 1 + offset)
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let body = &input[start + 1..semicolon];
    let scalar = if ascii_slice_eq(body, "lt") {
        b'<' as u32
    } else if ascii_slice_eq(body, "gt") {
        b'>' as u32
    } else if ascii_slice_eq(body, "amp") {
        b'&' as u32
    } else if ascii_slice_eq(body, "apos") {
        b'\'' as u32
    } else if ascii_slice_eq(body, "quot") {
        b'"' as u32
    } else if body.first() == Some(&(b'#' as u16)) {
        let (digits, radix) =
            if body.get(1) == Some(&(b'x' as u16)) || body.get(1) == Some(&(b'X' as u16)) {
                (&body[2..], 16u32)
            } else {
                (&body[1..], 10u32)
            };
        if digits.is_empty() {
            return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
        }
        let mut value = 0u32;
        for &digit in digits {
            let digit = match digit {
                value if (b'0' as u16..=b'9' as u16).contains(&value) => value as u32 - b'0' as u32,
                value if radix == 16 && (b'a' as u16..=b'f' as u16).contains(&value) => {
                    value as u32 - b'a' as u32 + 10
                }
                value if radix == 16 && (b'A' as u16..=b'F' as u16).contains(&value) => {
                    value as u32 - b'A' as u32 + 10
                }
                _ => return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT),
            };
            value = value
                .checked_mul(radix)
                .and_then(|current| current.checked_add(digit))
                .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
        }
        value
    } else {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    };
    if !is_xml_character(scalar) {
        return Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT);
    }
    Ok((scalar, semicolon + 1))
}

fn is_name_start(value: u16) -> bool {
    value == b':' as u16
        || value == b'_' as u16
        || (b'A' as u16..=b'Z' as u16).contains(&value)
        || (b'a' as u16..=b'z' as u16).contains(&value)
        || value >= 0x80
}

fn is_name_continue(value: u16) -> bool {
    is_name_start(value)
        || value == b'-' as u16
        || value == b'.' as u16
        || (b'0' as u16..=b'9' as u16).contains(&value)
}

fn skip_whitespace(input: &[u16], position: &mut usize) {
    while input.get(*position).copied().is_some_and(is_whitespace) {
        *position += 1;
    }
}

fn skip_whitespace_bounded(input: &[u16], position: &mut usize, end: usize) {
    while *position < end && is_whitespace(input[*position]) {
        *position += 1;
    }
}

fn is_whitespace(value: u16) -> bool {
    matches!(value, 0x09 | 0x0a | 0x0d | 0x20)
}

fn local_eq(input: &[u16], name: Range<usize>, expected: &str) -> bool {
    let qualified = &input[name];
    let local_start = qualified
        .iter()
        .rposition(|value| *value == b':' as u16)
        .map_or(0, |position| position + 1);
    ascii_slice_eq(&qualified[local_start..], expected)
}

fn attribute_eq(input: &[u16], attribute: Attribute, expected: &str) -> bool {
    ascii_slice_eq(&input[attribute.name()], expected)
}

fn local_frame_suffix(input: &[u16], stack: &[Frame], expected: &[&str]) -> bool {
    stack.len() == expected.len() + 1
        && local_eq(input, stack[0].tag.name(), "assembly")
        && stack[1..]
            .iter()
            .zip(expected)
            .all(|(frame, expected)| local_eq(input, frame.tag.name(), expected))
}

fn ascii_slice_eq(input: &[u16], expected: &str) -> bool {
    input.len() == expected.len()
        && input
            .iter()
            .zip(expected.bytes())
            .all(|(left, right)| *left == right as u16)
}

fn ascii_slice_eq_ci(input: &[u16], expected: &str) -> bool {
    input.len() == expected.len()
        && input
            .iter()
            .zip(expected.bytes())
            .all(|(left, right)| *left <= 0x7f && (*left as u8).eq_ignore_ascii_case(&right))
}

fn ascii_eq_at(input: &[u16], start: usize, expected: &str) -> bool {
    input
        .get(start..start.saturating_add(expected.len()))
        .is_some_and(|value| ascii_slice_eq(value, expected))
}

fn find_ascii(input: &[u16], start: usize, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(start.min(input.len()));
    }
    (start..=input.len().saturating_sub(needle.len()))
        .find(|position| ascii_eq_at(input, *position, needle))
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    fn utf16_bytes(text: &str, big_endian: bool, bom: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        if bom {
            bytes.extend_from_slice(if big_endian {
                &[0xfe, 0xff]
            } else {
                &[0xff, 0xfe]
            });
        }
        for unit in text.encode_utf16() {
            let encoded = if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            };
            bytes.extend_from_slice(&encoded);
        }
        bytes
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn interface_guid(first: u32, last: u8) -> Guid {
        Guid {
            data1: first,
            data2: 0x8888,
            data3: 0x7777,
            data4: [0x66, 0x66, 0x55, 0x55, 0x55, 0x55, 0x55, last],
        }
    }

    #[test]
    fn parses_direct_prefixed_file_elements() {
        let manifest = br#"<?xml version="1.0"?>
            <asm:assembly xmlns:asm="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
              <asm:file asm:name="first.dll" />
              <file name="second.dll" loadFrom="side\second.dll"></file>
              <file name="empty.dll" loadFrom="" />
            </asm:assembly>"#;
        let parsed = parse_manifest(manifest).unwrap();
        assert_eq!(
            parsed.dll_redirects,
            vec![
                DllRedirect {
                    name: wide("first.dll"),
                    load_from: None,
                },
                DllRedirect {
                    name: wide("second.dll"),
                    load_from: Some(wide("side\\second.dll")),
                },
                DllRedirect {
                    name: wide("empty.dll"),
                    load_from: Some(Vec::new()),
                },
            ]
        );
    }

    #[test]
    fn detects_utf8_and_both_utf16_byte_orders() {
        let xml = "<assembly manifestVersion=\"1.0\"><file name=\"encoded.dll\"/></assembly>";
        let mut utf8_bom = vec![0xef, 0xbb, 0xbf];
        utf8_bom.extend_from_slice(xml.as_bytes());
        for bytes in [
            utf8_bom,
            utf16_bytes(xml, false, true),
            utf16_bytes(xml, true, true),
            utf16_bytes(xml, false, false),
            utf16_bytes(xml, true, false),
        ] {
            let parsed = parse_manifest(&bytes).unwrap();
            assert_eq!(parsed.dll_redirects[0].name, wide("encoded.dll"));
        }
    }

    #[test]
    fn decodes_named_decimal_and_hex_entities() {
        let manifest = br#"<assembly manifestVersion="1.0">
            <file name="a&amp;b.dll" loadFrom="sub&#x2f;&#100;.dll"/>
            </assembly>"#;
        let parsed = parse_manifest(manifest).unwrap();
        assert_eq!(parsed.dll_redirects[0].name, wide("a&b.dll"));
        assert_eq!(parsed.dll_redirects[0].load_from, Some(wide("sub/d.dll")));
    }

    #[test]
    fn retains_and_encodes_root_assembly_identity() {
        let manifest = br#"<assembly manifestVersion="1.0">
            <assemblyIdentity name="sample.app" processorArchitecture="amd64"
                publicKeyToken="001122aabbccddff" type="win32" version="6.1.2.345"/>
            </assembly>"#;
        let parsed = parse_manifest(manifest).unwrap();
        assert_eq!(parsed.assembly_identity.name, Some(wide("sample.app")));
        assert_eq!(parsed.assembly_identity.version, [6, 1, 2, 345]);
        assert_eq!(
            encode_assembly_identity(&parsed.assembly_identity).unwrap(),
            wide(
                "sample.app,processorArchitecture=\"amd64\",publicKeyToken=\"001122aabbccddff\",type=\"win32\",version=\"6.1.2.345\""
            )
        );
    }

    #[test]
    fn rejects_duplicate_identity_and_invalid_versions() {
        for manifest in [
            br#"<assembly manifestVersion="1.0"><assemblyIdentity version="1.2.3.4.5"/></assembly>"#
                .as_slice(),
            br#"<assembly manifestVersion="1.0"><assemblyIdentity version="1.2.x.4"/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><assemblyIdentity/><assemblyIdentity/></assembly>"#,
        ] {
            assert_eq!(
                parse_manifest(manifest),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
            );
        }
    }

    #[test]
    fn zero_fills_omitted_identity_version_components() {
        let parsed = parse_manifest(
            br#"<assembly manifestVersion="1.0"><assemblyIdentity version="1.2.3"/></assembly>"#,
        )
        .unwrap();
        assert_eq!(parsed.assembly_identity.version, [1, 2, 3, 0]);
    }

    #[test]
    fn parses_compatibility_and_requested_execution_level() {
        let manifest = br#"<assembly manifestVersion="1.0">
            <compatibility><application>
              <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
              <supportedOS Id="not-a-guid"/>
              <maxversiontested Id="10.0.18358"/>
              <maxversiontested Id="2.3.4.5"/>
            </application></compatibility>
            <asmv3:trustInfo><asmv3:security><asmv3:requestedPrivileges>
              <asmv3:requestedExecutionLevel level="RequireAdministrator" uiAccess="TRUE"/>
            </asmv3:requestedPrivileges></asmv3:security></asmv3:trustInfo>
            </assembly>"#;
        let parsed = parse_manifest(manifest).unwrap();
        assert_eq!(parsed.compatibility.len(), 3);
        assert_eq!(parsed.compatibility[0].id.data1, 0x3513_8b9a);
        assert_eq!(parsed.compatibility[0].kind, COMPATIBILITY_ELEMENT_TYPE_OS);
        assert_eq!(
            parsed.compatibility[1].kind,
            COMPATIBILITY_ELEMENT_TYPE_MAX_VERSION_TESTED
        );
        assert_eq!(
            parsed.compatibility[1].max_version_tested,
            0x000a_0000_47b6_0000
        );
        assert_eq!(
            parsed.compatibility[2].max_version_tested,
            0x0002_0003_0004_0005
        );
        assert_eq!(parsed.run_level, RUN_LEVEL_REQUIRE_ADMIN);
        assert_eq!(parsed.ui_access, 1);
    }

    #[test]
    fn ignores_compatibility_elements_outside_the_native_hierarchy() {
        let parsed = parse_manifest(
            br#"<assembly manifestVersion="1.0">
                <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
                <requestedExecutionLevel level="asInvoker" uiAccess="true"/>
                </assembly>"#,
        )
        .unwrap();
        assert!(parsed.compatibility.is_empty());
        assert_eq!(parsed.run_level, RUN_LEVEL_UNSPECIFIED);
        assert_eq!(parsed.ui_access, 0);
    }

    #[test]
    fn rejects_duplicate_recognized_requested_execution_levels() {
        let manifest = br#"<assembly manifestVersion="1.0">
            <trustInfo><security><requestedPrivileges>
              <requestedExecutionLevel level="asInvoker"/>
              <requestedExecutionLevel level="highestAvailable"/>
            </requestedPrivileges></security></trustInfo>
            </assembly>"#;
        assert_eq!(
            parse_manifest(manifest),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
    }

    #[test]
    fn rejects_invalid_max_version_tested() {
        let manifest = br#"<assembly manifestVersion="1.0">
            <compatibility><application><maxversiontested Id="10.x"/></application></compatibility>
            </assembly>"#;
        assert_eq!(
            parse_manifest(manifest),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
    }

    #[test]
    fn rejects_malformed_xml_and_invalid_roots() {
        for manifest in [
            br#"<assembly manifestVersion="1.0"><file name="x.dll"></assembly>"#.as_slice(),
            br#"<assembly manifestVersion="1.0"><file name="x&bogus;.dll"/></assembly>"#,
            br#"<notAssembly manifestVersion="1.0"/>"#,
            br#"<assembly><file name="x.dll"/></assembly>"#,
        ] {
            assert_eq!(
                parse_manifest(manifest),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
            );
        }
    }

    #[test]
    fn parses_dependency_identity_and_binding_flags() {
        let manifest = br#"<assembly manifestVersion="1.0">
            <dependency optional="YeS"><dependentAssembly allowDelayedBinding="true">
              <assemblyIdentity name="shared" type="win32" version="6.0.1.2"
                processorArchitecture="*" publicKeyToken="6595b64144ccf1df"
                language="neutral"/>
              <bindingRedirect oldVersion="1.0.0.0-6.0.1.2" newVersion="6.0.1.2"/>
            </dependentAssembly></dependency>
            </assembly>"#;
        let parsed = parse_manifest_details(manifest).unwrap();
        assert_eq!(parsed.dependencies.len(), 1);
        let dependency = &parsed.dependencies[0];
        assert_eq!(dependency.identity.name, Some(wide("shared")));
        assert_eq!(dependency.identity.kind, Some(wide("win32")));
        assert_eq!(dependency.identity.version, [6, 0, 1, 2]);
        assert_eq!(dependency.identity.processor_architecture, Some(wide("*")));
        assert_eq!(
            dependency.identity.public_key_token,
            Some(wide("6595b64144ccf1df"))
        );
        assert_eq!(dependency.language, Some(wide("neutral")));
        assert!(dependency.optional);
        assert!(dependency.delayed);
        assert_eq!(parse_manifest(manifest), Err(STATUS_SXS_CANT_GEN_ACTCTX));
    }

    #[test]
    fn accepts_empty_dependencies_and_ignores_unrelated_binding_elements() {
        let parsed = parse_manifest_details(
            br#"<assembly manifestVersion="1.0">
              <assemblyIdentity name="root" language="en-US"/>
              <dependency/>
              <assemblyBinding><bindingRedirect oldVersion="1" newVersion="2"/></assemblyBinding>
            </assembly>"#,
        )
        .unwrap();
        assert!(parsed.dependencies.is_empty());
        assert_eq!(parsed.root.assembly_identity.name, Some(wide("root")));
        assert_eq!(parsed.root_language, Some(wide("en-US")));
        assert_eq!(
            encode_assembly_identity(&parsed.root.assembly_identity).unwrap(),
            wide("root,version=\"0.0.0.0\"")
        );
    }

    #[test]
    fn window_classes_remain_associated_with_their_files() {
        let parsed = parse_manifest_details(
            br#"<assembly manifestVersion="1.0">
              <file name="first.dll">
                <windowClass versioned="YES">First&amp;Class</windowClass>
                <windowClass>DefaultClass</windowClass>
              </file>
              <file name="second.dll">
                <windowClass versioned="no"><![CDATA[Second<Class]]></windowClass>
              </file>
            </assembly>"#,
        )
        .unwrap();
        assert_eq!(parsed.root.dll_redirects.len(), 2);
        assert_eq!(
            parsed.window_classes,
            vec![
                ManifestWindowClass {
                    file_index: 0,
                    name: wide("First&Class"),
                    versioned: true,
                },
                ManifestWindowClass {
                    file_index: 0,
                    name: wide("DefaultClass"),
                    versioned: true,
                },
                ManifestWindowClass {
                    file_index: 1,
                    name: wide("Second<Class"),
                    versioned: false,
                },
            ]
        );
        assert_eq!(
            parsed.root.dll_redirects[parsed.window_classes[2].file_index].name,
            wide("second.dll")
        );
    }

    #[test]
    fn parses_file_and_external_com_interface_proxy_stubs() {
        let parsed = parse_manifest_details(
            br#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
              <file name="testlib.dll">
                <comInterfaceProxyStub name="Iifaceps"
                  iid="{66666666-8888-7777-6666-555555555555}"
                  proxyStubClsid32="{66666666-8888-7777-6666-555555555556}"
                  tlbid="{99999999-8888-7777-6666-555555555558}"
                  numMethods="10"
                  baseInterface="{66666666-8888-7777-6666-555555555557}"
                  threadingModel="Free"/>
              </file>
              <comInterfaceExternalProxyStub name="Iifaceps2"
                iid="{76666666-8888-7777-6666-555555555555}"
                proxyStubClsid32="{66666666-8888-7777-6666-555555555556}"
                tlbid="{99999999-8888-7777-6666-555555555558}"
                numMethods="10"
                baseInterface="{66666666-8888-7777-6666-555555555557}"/>
              <comInterfaceExternalProxyStub name="Iifaceps3"
                iid="{86666666-8888-7777-6666-555555555555}"
                numMethods=""></comInterfaceExternalProxyStub>
            </assembly>"#,
        )
        .unwrap();
        assert_eq!(parsed.com_interfaces.len(), 3);
        assert_eq!(
            parsed.com_interfaces[0],
            ManifestComInterface {
                file_index: Some(0),
                iid: interface_guid(0x6666_6666, 0x55),
                name: Some(wide("Iifaceps")),
                proxy_stub_clsid32: Some(interface_guid(0x6666_6666, 0x56)),
                type_library: Some(interface_guid(0x9999_9999, 0x58)),
                base_interface: Some(interface_guid(0x6666_6666, 0x57)),
                num_methods: Some(10),
            }
        );
        assert_eq!(parsed.com_interfaces[1].file_index, None);
        assert_eq!(
            parsed.com_interfaces[1].iid,
            interface_guid(0x7666_6666, 0x55)
        );
        assert_eq!(
            parsed.com_interfaces[1].proxy_stub_clsid32,
            Some(interface_guid(0x6666_6666, 0x56))
        );
        assert_eq!(parsed.com_interfaces[2].file_index, None);
        assert_eq!(
            parsed.com_interfaces[2].iid,
            interface_guid(0x8666_6666, 0x55)
        );
        assert_eq!(parsed.com_interfaces[2].num_methods, Some(0));
        assert_eq!(parsed.com_interfaces[2].name, Some(wide("Iifaceps3")));
    }

    #[test]
    fn com_interfaces_require_valid_identifiers_names_and_method_counts() {
        for manifest in [
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub/></assembly>"#
                .as_slice(),
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub iid="bad"/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub iid="{76666666-8888-7777-6666-555555555555}" name=""/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub iid="{76666666-8888-7777-6666-555555555555}" tlbid="bad"/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub iid="{76666666-8888-7777-6666-555555555555}" baseInterface="bad"/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub iid="{76666666-8888-7777-6666-555555555555}" proxyStubClsid32="bad"/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub iid="{76666666-8888-7777-6666-555555555555}" numMethods="1x"/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub iid="{76666666-8888-7777-6666-555555555555}" numMethods="4294967296"/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub iid="{76666666-8888-7777-6666-555555555555}">text</comInterfaceExternalProxyStub></assembly>"#,
            br#"<assembly manifestVersion="1.0"><comInterfaceExternalProxyStub iid="{76666666-8888-7777-6666-555555555555}"><child/></comInterfaceExternalProxyStub></assembly>"#,
        ] {
            assert_eq!(
                parse_manifest_details(manifest),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
            );
        }
    }

    #[test]
    fn com_interfaces_obey_scope_namespace_and_exact_attribute_names() {
        let parsed = parse_manifest_details(
            br#"<assembly manifestVersion="1.0">
              <comInterfaceProxyStub iid="{16666666-8888-7777-6666-555555555555}"/>
              <file name="test.dll">
                <comInterfaceExternalProxyStub iid="{26666666-8888-7777-6666-555555555555}"/>
                <bad:comInterfaceProxyStub xmlns:bad="urn:wrong"
                  iid="{36666666-8888-7777-6666-555555555555}"/>
                <comInterfaceProxyStub iid="{46666666-8888-7777-6666-555555555555}"
                  xmlns:iid="ignored">
                </comInterfaceProxyStub>
              </file>
              <bad:comInterfaceExternalProxyStub xmlns:bad="urn:wrong"
                iid="{56666666-8888-7777-6666-555555555555}"/>
              <comInterfaceExternalProxyStub iid="{66666666-8888-7777-6666-555555555555}"
                proxyStubClsid32="{00000000-0000-0000-0000-000000000000}"/>
            </assembly>"#,
        )
        .unwrap();
        assert_eq!(parsed.com_interfaces.len(), 2);
        assert_eq!(parsed.com_interfaces[0].file_index, Some(0));
        assert_eq!(
            parsed.com_interfaces[0].iid,
            interface_guid(0x4666_6666, 0x55)
        );
        assert_eq!(parsed.com_interfaces[1].file_index, None);
        assert_eq!(
            parsed.com_interfaces[1].proxy_stub_clsid32,
            Some(Guid::default())
        );
    }

    #[test]
    fn parses_root_clr_surrogates_and_preserves_optional_versions() {
        let parsed = parse_manifest_details(
            br#"<assembly manifestVersion="1.0">
              <clrSurrogate clsid="{96666666-8888-7777-6666-555555555555}"
                name="test&amp;surrogate" runtimeVersion="v2.0.50727"/>
              <asm:clrSurrogate clsid="{96666666-8888-7777-6666-555555555556}"
                name="unversioned"></asm:clrSurrogate>
              <clrSurrogate clsid="{96666666-8888-7777-6666-555555555557}"
                name="empty-version" runtimeVersion=""/>
            </assembly>"#,
        )
        .unwrap();
        assert_eq!(parsed.clr_surrogates.len(), 3);
        assert_eq!(
            parsed.clr_surrogates[0].clsid,
            Guid {
                data1: 0x9666_6666,
                data2: 0x8888,
                data3: 0x7777,
                data4: [0x66, 0x66, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55],
            }
        );
        assert_eq!(parsed.clr_surrogates[0].name, wide("test&surrogate"));
        assert_eq!(
            parsed.clr_surrogates[0].runtime_version,
            Some(wide("v2.0.50727"))
        );
        assert_eq!(parsed.clr_surrogates[1].name, wide("unversioned"));
        assert_eq!(parsed.clr_surrogates[1].runtime_version, None);
        assert_eq!(parsed.clr_surrogates[2].runtime_version, Some(Vec::new()));
    }

    #[test]
    fn clr_surrogates_require_root_level_valid_clsid_and_name() {
        let nested = parse_manifest_details(
            br#"<assembly manifestVersion="1.0"><wrapper>
              <clrSurrogate clsid="{96666666-8888-7777-6666-555555555555}" name="ignored"/>
            </wrapper></assembly>"#,
        )
        .unwrap();
        assert!(nested.clr_surrogates.is_empty());

        for manifest in [
            br#"<assembly manifestVersion="1.0"><clrSurrogate name="missing-clsid"/></assembly>"#
                .as_slice(),
            br#"<assembly manifestVersion="1.0"><clrSurrogate clsid="{96666666-8888-7777-6666-555555555555}"/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><clrSurrogate clsid="96666666-8888-7777-6666-555555555555" name="bad-guid"/></assembly>"#,
            br#"<assembly manifestVersion="1.0"><clrSurrogate clsid="{96666666-8888-7777-6666-555555555555}" name=""/></assembly>"#,
        ] {
            assert_eq!(
                parse_manifest_details(manifest),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
            );
        }
    }

    #[test]
    fn clr_surrogate_attributes_use_exact_namespace_matching() {
        let parsed = parse_manifest_details(
            br#"<assembly manifestVersion="1.0">
              <clrSurrogate clsid="{96666666-8888-7777-6666-555555555555}"
                name="real" runtimeVersion="v4"
                xmlns:clsid="ignored" xmlns:name="ignored" xmlns:runtimeVersion="ignored"/>
            </assembly>"#,
        )
        .unwrap();
        assert_eq!(parsed.clr_surrogates.len(), 1);
        assert_eq!(parsed.clr_surrogates[0].name, wide("real"));
        assert_eq!(parsed.clr_surrogates[0].runtime_version, Some(wide("v4")));
    }

    #[test]
    fn rejects_invalid_window_classes_and_duplicate_dependency_identity() {
        for manifest in [
            br#"<assembly manifestVersion="1.0"><file name="x.dll"><windowClass versioned="maybe">X</windowClass></file></assembly>"#.as_slice(),
            br#"<assembly manifestVersion="1.0"><file name="x.dll"><windowClass></windowClass></file></assembly>"#,
            br#"<assembly manifestVersion="1.0"><file name="x.dll"><windowClass>Foo<b>Bar</b>Baz</windowClass></file></assembly>"#,
            br#"<assembly manifestVersion="1.0"><dependency><dependentAssembly><assemblyIdentity name="a"/><assemblyIdentity name="b"/></dependentAssembly></dependency></assembly>"#,
        ] {
            assert_eq!(
                parse_manifest_details(manifest),
                Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
            );
        }
    }

    #[test]
    fn rejects_mismatched_same_leading_element_names() {
        assert_eq!(
            parse_manifest_details(
                br#"<assembly manifestVersion="1.0"><dependency></dependentAnything></assembly>"#
            ),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );
    }

    #[test]
    fn dependency_defaults_and_attributes_follow_native_matching() {
        let parsed = parse_manifest_details(
            br#"<assembly manifestVersion="1.0">
              <assemblyIdentity name="root"/>
              <dependency optional="yes" xmlns:optional="urn:ignored">
                <dependentAssembly allowDelayedBinding="TRUE" xmlns:allowDelayedBinding="true">
                  <assemblyIdentity name="first" xmlns:name="urn:ignored"
                    version="1.2.3.4" xmlns:version="not-a-version"/>
                </dependentAssembly>
              </dependency>
              <dependency><dependentAssembly><assemblyIdentity name="second"/></dependentAssembly></dependency>
              <wrapper><assemblyIdentity name="not-root"/></wrapper>
            </assembly>"#,
        )
        .unwrap();
        assert_eq!(parsed.root.assembly_identity.name, Some(wide("root")));
        assert_eq!(parsed.dependencies.len(), 2);
        assert_eq!(parsed.dependencies[0].identity.name, Some(wide("first")));
        assert_eq!(parsed.dependencies[0].identity.version, [1, 2, 3, 4]);
        assert!(parsed.dependencies[0].optional);
        assert!(!parsed.dependencies[0].delayed);
        assert!(!parsed.dependencies[1].optional);
        assert!(!parsed.dependencies[1].delayed);
    }

    #[test]
    fn window_class_namespace_attributes_and_self_closing_form_are_ignored() {
        let parsed = parse_manifest_details(
            br#"<assembly manifestVersion="1.0"><file name="x.dll">
              <windowClass versioned="no" xmlns:versioned="yes">PlainClass</windowClass>
              <windowClass/>
            </file></assembly>"#,
        )
        .unwrap();
        assert_eq!(
            parsed.window_classes,
            vec![ManifestWindowClass {
                file_index: 0,
                name: wide("PlainClass"),
                versioned: false,
            }]
        );
    }

    #[test]
    fn accepts_non_self_closing_empty_dependency() {
        let parsed = parse_manifest_details(
            br#"<assembly manifestVersion="1.0"><dependency></dependency></assembly>"#,
        )
        .unwrap();
        assert!(parsed.dependencies.is_empty());
    }

    #[test]
    fn parses_application_settings_with_scoped_namespaces() {
        let parsed = parse_manifest_details(
            br#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
                xmlns:asm="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0">
              <asm:application xmlns:ws="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
                <asm:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
                  <ws:dpiAware>true&amp;yes</ws:dpiAware>
                  <ws:dpiAwareness xmlns:ws="http://schemas.microsoft.com/SMI/2016/WindowsSettings"><![CDATA[per monitor]]></ws:dpiAwareness>
                  <ws:dpiAware>sibling</ws:dpiAware>
                  <dpiAware xmlns="">ignored</dpiAware>
                  <dpiAware>default-again</dpiAware>
                </asm:windowsSettings>
              </asm:application>
            </assembly>"#,
        )
        .unwrap();
        assert_eq!(
            parsed.application_settings,
            vec![
                ManifestApplicationSetting {
                    namespace: wide("http://schemas.microsoft.com/SMI/2005/WindowsSettings"),
                    name: wide("dpiAware"),
                    value: wide("true&yes"),
                },
                ManifestApplicationSetting {
                    namespace: wide("http://schemas.microsoft.com/SMI/2016/WindowsSettings"),
                    name: wide("dpiAwareness"),
                    value: wide("per monitor"),
                },
                ManifestApplicationSetting {
                    namespace: wide("http://schemas.microsoft.com/SMI/2005/WindowsSettings"),
                    name: wide("dpiAware"),
                    value: wide("sibling"),
                },
                ManifestApplicationSetting {
                    namespace: wide("http://schemas.microsoft.com/SMI/2005/WindowsSettings"),
                    name: wide("dpiAware"),
                    value: wide("default-again"),
                },
            ]
        );
    }

    #[test]
    fn application_settings_use_first_nonempty_application() {
        let parsed = parse_manifest_details(
            br#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
              <application/>
              <application xmlns="urn:schemas-microsoft-com:asm.v3">
                <windowsSettings>
                  <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings"></dpiAware>
                  <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings"/>
                </windowsSettings>
              </application>
              <application xmlns="urn:schemas-microsoft-com:asm.v3">
                <windowsSettings>
                  <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">late</dpiAwareness>
                </windowsSettings>
              </application>
            </assembly>"#,
        )
        .unwrap();
        assert_eq!(
            parsed.application_settings,
            vec![ManifestApplicationSetting {
                namespace: wide("http://schemas.microsoft.com/SMI/2005/WindowsSettings"),
                name: wide("dpiAware"),
                value: Vec::new(),
            }]
        );
    }

    #[test]
    fn ignores_unbound_or_wrong_application_setting_namespaces() {
        let parsed = parse_manifest_details(
            br#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
              <asmv3:application>
                <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
                  <dpiAware>true</dpiAware>
                </asmv3:windowsSettings>
              </asmv3:application>
              <application xmlns="urn:schemas-microsoft-com:asm.v3">
                <windowsSettings>
                  <dpiAware xmlns="urn:not-windows-settings">true</dpiAware>
                  <DpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</DpiAware>
                </windowsSettings>
              </application>
            </assembly>"#,
        )
        .unwrap();
        assert!(parsed.application_settings.is_empty());
    }
}
