//! Pure, bounded activation-context dependency resolution.
//!
//! Filesystem and WinSxS probing remain outside this module. Callers inject an
//! [`ActivationManifestCatalog`] which returns an owned manifest source for a normalized request;
//! the resolver parses and verifies every returned manifest before assigning it a roster index.
//! This keeps dependency graph handling host-testable and lets the target-side loader choose its
//! eventual file-query mechanism independently.

use alloc::vec::Vec;

use crate::NtStatus;

use super::activation::{
    MAX_MANIFEST_BYTES, STATUS_SXS_CANT_GEN_ACTCTX, STATUS_SXS_INVALID_ACTCTXDATA_FORMAT,
};
use super::activation_manifest::{
    parse_manifest_details, AssemblyIdentity, ManifestDependency, ParsedManifestDetails,
};
use super::strings::equal_unicode_string;

const STATUS_NO_MEMORY: NtStatus = 0xC000_0017;

/// An owned manifest and the paths needed to expose it through activation-context queries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActivationManifestSource {
    /// The source passed to activation-context creation, such as an executable or manifest path.
    pub source: Vec<u16>,
    /// The actual manifest path. This may differ from `source` for PE resources and sidecars.
    pub manifest_path: Vec<u16>,
    /// Directory from which private assembly files are loaded.
    pub assembly_directory: Vec<u16>,
    /// Raw manifest bytes retained for activation-context query information.
    pub manifest: Vec<u8>,
    /// Shared WinSxS assemblies permit a newer build/revision; private assemblies require exact
    /// version equality.
    pub shared: bool,
}

/// A normalized assembly request passed to the injected manifest catalog.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssemblyRequest {
    pub identity: AssemblyIdentity,
    pub language: Option<Vec<u16>>,
}

/// Filesystem-independent dependency lookup.
///
/// Implementations may probe WinSxS, application-private paths, or an in-memory fixture catalog.
/// A returned source is not trusted: its manifest identity is parsed and checked against `request`
/// before the assembly is admitted to the resolved roster.
pub trait ActivationManifestCatalog {
    fn resolve(
        &mut self,
        request: &AssemblyRequest,
    ) -> Result<Option<ActivationManifestSource>, NtStatus>;
}

/// Hard limits for one atomic dependency-resolution transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationResolverLimits {
    /// Root plus all successfully resolved dependent assemblies.
    pub max_assemblies: usize,
    /// Total dependency requests admitted to the breadth-first work queue.
    pub max_dependency_requests: usize,
    /// Maximum dependency edge depth. The root is depth zero.
    pub max_depth: usize,
    /// Sum of raw manifest byte lengths, including the root.
    pub max_manifest_bytes: usize,
}

impl Default for ActivationResolverLimits {
    fn default() -> Self {
        Self {
            max_assemblies: 256,
            max_dependency_requests: 1_024,
            max_depth: 32,
            max_manifest_bytes: MAX_MANIFEST_BYTES,
        }
    }
}

/// One parsed assembly in activation-context roster order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedActivationAssembly {
    /// Native activation-context roster indices are one-based; the root always receives index 1.
    pub roster_index: u32,
    pub source: ActivationManifestSource,
    pub details: ParsedManifestDetails,
}

/// An atomically resolved activation-context assembly roster.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedActivationContext {
    pub assemblies: Vec<ResolvedActivationAssembly>,
    pub manifest_bytes: usize,
}

#[derive(Debug)]
struct PendingDependency {
    request: AssemblyRequest,
    depth: usize,
    required: bool,
}

/// Resolve `root` and its transitive dependencies in deterministic breadth-first order.
///
/// `current_processor_architecture` normalizes a dependency architecture of `*`, matching the
/// native loader's treatment before catalog lookup. If it is absent, `*` remains literal, so
/// target-side callers should always supply their native architecture.
///
/// Identity matching follows ReactOS: name, architecture, and public-key token compare
/// case-insensitively; language absence or `*` is a wildcard; major/minor are exact; and candidate
/// build/revision may be newer than requested for shared WinSxS manifests. Private manifests
/// require all four version components to match exactly. The assembly `type` attribute is not part
/// of identity matching.
pub fn resolve_activation_dependencies<C: ActivationManifestCatalog>(
    root: ActivationManifestSource,
    current_processor_architecture: Option<&[u16]>,
    limits: ActivationResolverLimits,
    catalog: &mut C,
) -> Result<ResolvedActivationContext, NtStatus> {
    if limits.max_assemblies == 0 || root.manifest.len() > limits.max_manifest_bytes {
        return Err(STATUS_SXS_CANT_GEN_ACTCTX);
    }

    let root_details = parse_manifest_details(&root.manifest)?;
    let mut assemblies = Vec::new();
    assemblies
        .try_reserve(limits.max_assemblies.min(4))
        .map_err(|_| STATUS_NO_MEMORY)?;
    assemblies.push(ResolvedActivationAssembly {
        roster_index: 1,
        source: root,
        details: root_details,
    });

    let mut queue = Vec::new();
    queue
        .try_reserve(limits.max_dependency_requests.min(8))
        .map_err(|_| STATUS_NO_MEMORY)?;
    enqueue_assembly_dependencies(
        0,
        1,
        current_processor_architecture,
        &limits,
        &assemblies,
        &mut queue,
        0,
    )?;

    let mut cursor = 0usize;
    let mut manifest_bytes = assemblies[0].source.manifest.len();
    while cursor < queue.len() {
        let pending = &queue[cursor];
        let required = pending.required;
        let depth = pending.depth;
        let source = match catalog.resolve(&pending.request) {
            Ok(Some(source)) => source,
            Ok(None) => {
                if required {
                    return Err(STATUS_SXS_CANT_GEN_ACTCTX);
                }
                cursor += 1;
                continue;
            }
            Err(status) => {
                if required {
                    return Err(status);
                }
                cursor += 1;
                continue;
            }
        };
        cursor += 1;

        let candidate = (|| {
            if assemblies.len() >= limits.max_assemblies {
                return Err(STATUS_SXS_CANT_GEN_ACTCTX);
            }
            let next_manifest_bytes = manifest_bytes
                .checked_add(source.manifest.len())
                .filter(|total| *total <= limits.max_manifest_bytes)
                .ok_or(STATUS_SXS_CANT_GEN_ACTCTX)?;
            let details = parse_manifest_details(&source.manifest)?;
            if !assembly_request_matches_source(
                &queue[cursor - 1].request,
                &details.root.assembly_identity,
                details.root_language.as_deref(),
                source.shared,
            ) {
                return Err(STATUS_SXS_CANT_GEN_ACTCTX);
            }
            Ok((details, next_manifest_bytes))
        })();
        let (details, next_manifest_bytes) = match candidate {
            Ok(candidate) => candidate,
            Err(_) if !required => continue,
            Err(status) => return Err(status),
        };
        manifest_bytes = next_manifest_bytes;

        let roster_index = assemblies
            .len()
            .checked_add(1)
            .and_then(|index| u32::try_from(index).ok())
            .ok_or(STATUS_SXS_CANT_GEN_ACTCTX)?;
        assemblies.try_reserve(1).map_err(|_| STATUS_NO_MEMORY)?;
        assemblies.push(ResolvedActivationAssembly {
            roster_index,
            source,
            details,
        });
        let dependency_depth = depth.checked_add(1).ok_or(STATUS_SXS_CANT_GEN_ACTCTX)?;
        enqueue_assembly_dependencies(
            assemblies.len() - 1,
            dependency_depth,
            current_processor_architecture,
            &limits,
            &assemblies,
            &mut queue,
            cursor,
        )?;
    }

    Ok(ResolvedActivationContext {
        assemblies,
        manifest_bytes,
    })
}

fn enqueue_assembly_dependencies(
    assembly_index: usize,
    dependency_depth: usize,
    current_processor_architecture: Option<&[u16]>,
    limits: &ActivationResolverLimits,
    assemblies: &[ResolvedActivationAssembly],
    queue: &mut Vec<PendingDependency>,
    queue_cursor: usize,
) -> Result<(), NtStatus> {
    for dependency in &assemblies[assembly_index].details.dependencies {
        let request = normalize_dependency(dependency, current_processor_architecture)?;
        let required = !dependency.optional && !dependency.delayed;

        if assemblies.iter().any(|assembly| {
            assembly_request_matches(
                &request,
                &assembly.details.root.assembly_identity,
                assembly.details.root_language.as_deref(),
            )
        }) {
            continue;
        }
        if let Some(existing) = queue[queue_cursor..]
            .iter_mut()
            .find(|pending| request_is_satisfied_by(&request, &pending.request))
        {
            // A duplicate is required if any occurrence cannot be skipped.
            existing.required |= required;
            continue;
        }
        if dependency_depth > limits.max_depth || queue.len() >= limits.max_dependency_requests {
            return Err(STATUS_SXS_CANT_GEN_ACTCTX);
        }
        queue.try_reserve(1).map_err(|_| STATUS_NO_MEMORY)?;
        queue.push(PendingDependency {
            request,
            depth: dependency_depth,
            required,
        });
    }
    Ok(())
}

fn normalize_dependency(
    dependency: &ManifestDependency,
    current_processor_architecture: Option<&[u16]>,
) -> Result<AssemblyRequest, NtStatus> {
    let mut identity = try_clone_identity(&dependency.identity)?;
    if identity
        .processor_architecture
        .as_deref()
        .is_some_and(is_wildcard)
    {
        if let Some(architecture) = current_processor_architecture {
            identity.processor_architecture = Some(try_copy_units(architecture)?);
        }
    }
    Ok(AssemblyRequest {
        identity,
        language: try_clone_optional_units(dependency.language.as_deref())?,
    })
}

fn try_clone_identity(identity: &AssemblyIdentity) -> Result<AssemblyIdentity, NtStatus> {
    Ok(AssemblyIdentity {
        name: try_clone_optional_units(identity.name.as_deref())?,
        processor_architecture: try_clone_optional_units(
            identity.processor_architecture.as_deref(),
        )?,
        public_key_token: try_clone_optional_units(identity.public_key_token.as_deref())?,
        kind: try_clone_optional_units(identity.kind.as_deref())?,
        version: identity.version,
    })
}

fn try_clone_optional_units(value: Option<&[u16]>) -> Result<Option<Vec<u16>>, NtStatus> {
    value.map(try_copy_units).transpose()
}

fn try_copy_units(value: &[u16]) -> Result<Vec<u16>, NtStatus> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(value.len())
        .map_err(|_| STATUS_NO_MEMORY)?;
    copy.extend_from_slice(value);
    Ok(copy)
}

/// Check a parsed candidate identity against a normalized dependency request.
///
/// Name, processor architecture, and public-key token use case-insensitive string comparison.
/// Language follows the native behavior where `*` on either side, or an omitted language, matches
/// any language. Major/minor must match exactly; the candidate's `(build, revision)` pair must be
/// at least the requested pair. The assembly `type` attribute is deliberately ignored.
pub fn assembly_request_matches(
    request: &AssemblyRequest,
    candidate_identity: &AssemblyIdentity,
    candidate_language: Option<&[u16]>,
) -> bool {
    optional_units_equal_ci(
        request.identity.name.as_deref(),
        candidate_identity.name.as_deref(),
    ) && optional_units_equal_ci(
        request.identity.processor_architecture.as_deref(),
        candidate_identity.processor_architecture.as_deref(),
    ) && optional_units_equal_ci(
        request.identity.public_key_token.as_deref(),
        candidate_identity.public_key_token.as_deref(),
    ) && version_matches(request.identity.version, candidate_identity.version)
        && language_matches(request.language.as_deref(), candidate_language)
}

fn assembly_request_matches_source(
    request: &AssemblyRequest,
    candidate_identity: &AssemblyIdentity,
    candidate_language: Option<&[u16]>,
    shared: bool,
) -> bool {
    assembly_request_matches(request, candidate_identity, candidate_language)
        && (shared || request.identity.version == candidate_identity.version)
}

fn request_is_satisfied_by(request: &AssemblyRequest, candidate: &AssemblyRequest) -> bool {
    assembly_request_matches(request, &candidate.identity, candidate.language.as_deref())
}

fn optional_units_equal_ci(left: Option<&[u16]>, right: Option<&[u16]>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => equal_unicode_string(left, right, true),
        (None, None) => true,
        _ => false,
    }
}

fn version_matches(request: [u16; 4], candidate: [u16; 4]) -> bool {
    request[0] == candidate[0]
        && request[1] == candidate[1]
        && (candidate[2], candidate[3]) >= (request[2], request[3])
}

fn language_matches(left: Option<&[u16]>, right: Option<&[u16]>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            is_wildcard(left) || is_wildcard(right) || equal_unicode_string(left, right, true)
        }
        _ => true,
    }
}

fn is_wildcard(value: &[u16]) -> bool {
    value == [b'*' as u16]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WinsxsManifestCandidateRank {
    pub non_builtin: bool,
    pub build: u16,
    pub revision: u16,
}

/// Build ReactOS's WinSxS manifest enumeration pattern for a normalized request.
///
/// `None` means the identity lacks one of the fields required for shared-assembly lookup.
pub fn winsxs_manifest_pattern(request: &AssemblyRequest) -> Result<Option<Vec<u16>>, NtStatus> {
    let (Some(architecture), Some(name), Some(token)) = (
        request.identity.processor_architecture.as_deref(),
        request.identity.name.as_deref(),
        request.identity.public_key_token.as_deref(),
    ) else {
        return Ok(None);
    };
    if architecture.is_empty() || name.is_empty() || token.is_empty() {
        return Ok(None);
    }
    let language = match request.language.as_deref() {
        Some(language)
            if !language.is_empty()
                && !equal_unicode_string(language, &ascii_units("neutral"), true) =>
        {
            language
        }
        _ => &[b'*' as u16],
    };

    let mut pattern = Vec::new();
    pattern
        .try_reserve(
            architecture
                .len()
                .checked_add(name.len())
                .and_then(|length| length.checked_add(token.len()))
                .and_then(|length| length.checked_add(language.len()))
                .and_then(|length| length.checked_add(48))
                .ok_or(STATUS_NO_MEMORY)?,
        )
        .map_err(|_| STATUS_NO_MEMORY)?;
    pattern.extend_from_slice(architecture);
    pattern.push(b'_' as u16);
    pattern.extend_from_slice(name);
    pattern.push(b'_' as u16);
    pattern.extend_from_slice(token);
    pattern.push(b'_' as u16);
    append_decimal(&mut pattern, request.identity.version[0])?;
    pattern.push(b'.' as u16);
    append_decimal(&mut pattern, request.identity.version[1])?;
    pattern.extend_from_slice(&ascii_units(".*.*_"));
    pattern.extend_from_slice(language);
    pattern.extend_from_slice(&ascii_units("_*.manifest"));
    Ok(Some(pattern))
}

/// Build the private-assembly directory identity exposed by activation-context queries.
pub fn private_assembly_directory_name(request: &AssemblyRequest) -> Result<Vec<u16>, NtStatus> {
    let none = [b'n' as u16, b'o' as u16, b'n' as u16, b'e' as u16];
    let architecture = request
        .identity
        .processor_architecture
        .as_deref()
        .unwrap_or(&none);
    let name = request.identity.name.as_deref().unwrap_or(&none);
    let token = request
        .identity
        .public_key_token
        .as_deref()
        .unwrap_or(&none);
    let language = request.language.as_deref().unwrap_or(&none);

    let capacity = architecture
        .len()
        .checked_add(name.len())
        .and_then(|length| length.checked_add(token.len()))
        .and_then(|length| length.checked_add(language.len()))
        .and_then(|length| length.checked_add(48))
        .ok_or(STATUS_NO_MEMORY)?;
    let mut directory = Vec::new();
    directory
        .try_reserve(capacity)
        .map_err(|_| STATUS_NO_MEMORY)?;
    directory.extend_from_slice(architecture);
    directory.push(b'_' as u16);
    directory.extend_from_slice(name);
    directory.push(b'_' as u16);
    directory.extend_from_slice(token);
    directory.push(b'_' as u16);
    for (index, component) in request.identity.version.iter().copied().enumerate() {
        if index != 0 {
            directory.push(b'.' as u16);
        }
        append_decimal(&mut directory, component)?;
    }
    directory.push(b'_' as u16);
    directory.extend_from_slice(language);
    directory.extend_from_slice(&ascii_units("_deadbeef"));
    Ok(directory)
}

/// Validate and rank one filename returned for [`winsxs_manifest_pattern`].
pub fn rank_winsxs_manifest_candidate(
    request: &AssemblyRequest,
    filename: &[u16],
) -> Result<Option<WinsxsManifestCandidateRank>, NtStatus> {
    let Some(pattern) = winsxs_manifest_pattern(request)? else {
        return Ok(None);
    };
    let version_wildcard = ascii_units(".*.*_");
    let wildcard = pattern
        .windows(version_wildcard.len())
        .position(|units| units == version_wildcard.as_slice())
        .ok_or(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)?;
    let mut prefix = pattern[..wildcard].to_vec();
    prefix.push(b'.' as u16);
    if filename.len() <= prefix.len()
        || !equal_unicode_string(&filename[..prefix.len()], &prefix, true)
        || !ends_with_ascii_ci(filename, ".manifest")
    {
        return Ok(None);
    }

    let mut cursor = prefix.len();
    let Some(build) = parse_decimal_component(filename, &mut cursor, b'.' as u16) else {
        return Ok(None);
    };
    let Some(revision) = parse_decimal_component(filename, &mut cursor, b'_' as u16) else {
        return Ok(None);
    };
    if cursor >= filename.len() {
        return Ok(None);
    }
    let requested = (request.identity.version[2], request.identity.version[3]);
    if (build, revision) < requested {
        return Ok(None);
    }
    let Some(language_end) = filename[cursor..]
        .iter()
        .position(|unit| *unit == b'_' as u16)
        .map(|offset| cursor + offset)
    else {
        return Ok(None);
    };
    let language = &filename[cursor..language_end];
    if language.is_empty() {
        return Ok(None);
    }
    if let Some(requested_language) = request.language.as_deref().filter(|language| {
        !language.is_empty()
            && !is_wildcard(language)
            && !equal_unicode_string(language, &ascii_units("neutral"), true)
    }) {
        if !equal_unicode_string(language, requested_language, true) {
            return Ok(None);
        }
    }
    let trailer_start = language_end + 1;
    if trailer_start >= filename.len() {
        return Ok(None);
    }
    let builtin = equal_unicode_string(
        &filename[trailer_start..],
        &ascii_units("deadbeef.manifest"),
        true,
    );
    Ok(Some(WinsxsManifestCandidateRank {
        non_builtin: !builtin,
        build,
        revision,
    }))
}

fn append_decimal(output: &mut Vec<u16>, value: u16) -> Result<(), NtStatus> {
    let mut divisor = 10_000u16;
    while divisor > 1 && value / divisor == 0 {
        divisor /= 10;
    }
    loop {
        output.try_reserve(1).map_err(|_| STATUS_NO_MEMORY)?;
        output.push(b'0' as u16 + (value / divisor) % 10);
        if divisor == 1 {
            return Ok(());
        }
        divisor /= 10;
    }
}

fn parse_decimal_component(input: &[u16], cursor: &mut usize, delimiter: u16) -> Option<u16> {
    let start = *cursor;
    let mut value = 0u16;
    while *cursor < input.len() && input[*cursor] != delimiter {
        let unit = input[*cursor];
        if !(b'0' as u16..=b'9' as u16).contains(&unit) {
            return None;
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(unit - b'0' as u16))?;
        *cursor += 1;
    }
    if *cursor == start || *cursor >= input.len() {
        return None;
    }
    *cursor += 1;
    Some(value)
}

fn ascii_units(value: &str) -> Vec<u16> {
    value.bytes().map(u16::from).collect()
}

fn ends_with_ascii_ci(value: &[u16], suffix: &str) -> bool {
    let suffix = ascii_units(suffix);
    value.len() >= suffix.len()
        && equal_unicode_string(&value[value.len() - suffix.len()..], &suffix, true)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::rtl::activation_section::{
        build_clr_surrogate_section, build_dll_redirection_section_for_assemblies,
        build_window_class_redirection_section, validate_dll_redirection_section,
        validate_window_class_redirection_section, ClrSurrogateAssembly, DllRedirectAssembly,
        WindowClassAssembly,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn source(name: &str, manifest: &[u8]) -> ActivationManifestSource {
        ActivationManifestSource {
            source: wide(name),
            manifest_path: wide(&alloc::format!("{name}.manifest")),
            assembly_directory: wide(name),
            manifest: manifest.to_vec(),
            shared: true,
        }
    }

    fn private_source(name: &str, manifest: &[u8]) -> ActivationManifestSource {
        let mut source = source(name, manifest);
        source.shared = false;
        source
    }

    struct MockCatalog {
        entries: Vec<(Vec<u16>, ActivationManifestSource)>,
        requests: Vec<AssemblyRequest>,
    }

    impl MockCatalog {
        fn new(entries: Vec<(Vec<u16>, ActivationManifestSource)>) -> Self {
            Self {
                entries,
                requests: Vec::new(),
            }
        }
    }

    impl ActivationManifestCatalog for MockCatalog {
        fn resolve(
            &mut self,
            request: &AssemblyRequest,
        ) -> Result<Option<ActivationManifestSource>, NtStatus> {
            self.requests.push(request.clone());
            let requested_name = request.identity.name.as_deref();
            let position = self.entries.iter().position(|(name, _)| {
                requested_name.is_some_and(|requested| equal_unicode_string(name, requested, true))
            });
            Ok(position.map(|position| self.entries.remove(position).1))
        }
    }

    const ROOT_WITH_DEP: &[u8] = br#"<assembly manifestVersion="1.0">
      <assemblyIdentity name="root" version="1.0.0.0"/>
      <dependency><dependentAssembly>
        <assemblyIdentity name="dep" version="1.0.0.0"/>
      </dependentAssembly></dependency>
    </assembly>"#;
    const DEP: &[u8] = br#"<assembly manifestVersion="1.0">
      <assemblyIdentity name="dep" version="1.0.0.0"/>
      <file name="dep.dll"/>
    </assembly>"#;
    const COMMON_CONTROLS_582: &[u8] = include_bytes!(
        "../../../../references/reactos/dll/win32/comctl32/amd64_microsoft.windows.common-controls_6595b64144ccf1df_5.82.2600.2982_none_deadbeef.manifest"
    );
    const COMMON_CONTROLS_600: &[u8] = include_bytes!(
        "../../../../references/reactos/dll/win32/comctl32/amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef.manifest"
    );

    #[test]
    fn resolves_exact_amd64_common_controls_manifests_and_builds_sections() {
        for (manifest, version, versioned) in [
            (COMMON_CONTROLS_582, [5, 82, 2600, 2982], false),
            (COMMON_CONTROLS_600, [6, 0, 2600, 2982], true),
        ] {
            let parsed = parse_manifest_details(manifest).unwrap();
            assert_eq!(parsed.root.assembly_identity.version, version);
            assert_eq!(parsed.root.dll_redirects.len(), 1);
            assert_eq!(parsed.root.dll_redirects[0].name, wide("comctl32.dll"));
            assert!(parsed.dependencies.is_empty());
            assert_eq!(parsed.window_classes.len(), 28);
            assert!(
                parsed
                    .window_classes
                    .iter()
                    .all(|class| class.file_index == 0 && class.versioned == versioned)
            );

            let mut catalog = MockCatalog::new(vec![]);
            let resolved = resolve_activation_dependencies(
                source("common-controls", manifest),
                Some(&wide("amd64")),
                ActivationResolverLimits::default(),
                &mut catalog,
            )
            .unwrap();
            assert!(catalog.requests.is_empty());
            assert_eq!(resolved.assemblies.len(), 1);
            assert_eq!(resolved.manifest_bytes, manifest.len());

            let assembly = &resolved.assemblies[0].details;
            let dll_section = build_dll_redirection_section_for_assemblies(&[
                DllRedirectAssembly {
                    redirects: &assembly.root.dll_redirects,
                },
            ])
            .unwrap();
            assert_eq!(
                validate_dll_redirection_section(&dll_section)
                    .unwrap()
                    .count,
                1
            );

            let window_section =
                build_window_class_redirection_section(&[WindowClassAssembly {
                    version: assembly.root.assembly_identity.version,
                    files: &assembly.root.dll_redirects,
                    classes: &assembly.window_classes,
                }])
                .unwrap();
            assert_eq!(
                validate_window_class_redirection_section(&window_section, 1)
                    .unwrap()
                    .count,
                28
            );

            let clr_section = build_clr_surrogate_section(&[ClrSurrogateAssembly {
                surrogates: &assembly.clr_surrogates,
            }])
            .unwrap();
            assert_eq!(clr_section.len(), 40);
        }
    }

    #[test]
    fn resolves_root_and_dependency_in_roster_order() {
        let mut catalog = MockCatalog::new(vec![(wide("dep"), source("dep", DEP))]);
        let resolved = resolve_activation_dependencies(
            source("root.exe", ROOT_WITH_DEP),
            None,
            ActivationResolverLimits::default(),
            &mut catalog,
        )
        .unwrap();

        assert_eq!(resolved.assemblies.len(), 2);
        assert_eq!(resolved.assemblies[0].roster_index, 1);
        assert_eq!(resolved.assemblies[1].roster_index, 2);
        assert_eq!(
            resolved.assemblies[1].details.root.assembly_identity.name,
            Some(wide("dep"))
        );
        assert_eq!(
            resolved.assemblies[1].details.root.dll_redirects[0].name,
            wide("dep.dll")
        );
        assert_eq!(resolved.assemblies[1].source.manifest.as_slice(), DEP);
        assert_eq!(resolved.manifest_bytes, ROOT_WITH_DEP.len() + DEP.len());
    }

    #[test]
    fn mandatory_missing_fails_but_optional_or_delayed_missing_is_skipped() {
        let mandatory = source("root", ROOT_WITH_DEP);
        let mut empty = MockCatalog::new(vec![]);
        assert_eq!(
            resolve_activation_dependencies(
                mandatory,
                None,
                ActivationResolverLimits::default(),
                &mut empty
            ),
            Err(STATUS_SXS_CANT_GEN_ACTCTX)
        );

        for manifest in [
            br#"<assembly manifestVersion="1.0"><assemblyIdentity name="root"/>
              <dependency optional="yes"><dependentAssembly><assemblyIdentity name="missing"/>
              </dependentAssembly></dependency></assembly>"#
                .as_slice(),
            br#"<assembly manifestVersion="1.0"><assemblyIdentity name="root"/>
              <dependency><dependentAssembly allowDelayedBinding="true">
              <assemblyIdentity name="missing"/></dependentAssembly></dependency></assembly>"#,
        ] {
            let mut empty = MockCatalog::new(vec![]);
            let resolved = resolve_activation_dependencies(
                source("root", manifest),
                None,
                ActivationResolverLimits::default(),
                &mut empty,
            )
            .unwrap();
            assert_eq!(resolved.assemblies.len(), 1);
        }
    }

    #[test]
    fn resolves_diamonds_breadth_first_and_deduplicates_cycles() {
        let root = br#"<assembly manifestVersion="1.0"><assemblyIdentity name="A"/>
          <dependency><dependentAssembly><assemblyIdentity name="B"/></dependentAssembly></dependency>
          <dependency><dependentAssembly><assemblyIdentity name="C"/></dependentAssembly></dependency>
        </assembly>"#;
        let b = br#"<assembly manifestVersion="1.0"><assemblyIdentity name="B"/>
          <dependency><dependentAssembly><assemblyIdentity name="D"/></dependentAssembly></dependency>
        </assembly>"#;
        let c = br#"<assembly manifestVersion="1.0"><assemblyIdentity name="C"/>
          <dependency><dependentAssembly><assemblyIdentity name="D"/></dependentAssembly></dependency>
        </assembly>"#;
        let d = br#"<assembly manifestVersion="1.0"><assemblyIdentity name="D"/>
          <dependency><dependentAssembly><assemblyIdentity name="A"/></dependentAssembly></dependency>
        </assembly>"#;
        let mut catalog = MockCatalog::new(vec![
            (wide("B"), source("B", b)),
            (wide("C"), source("C", c)),
            (wide("D"), source("D", d)),
        ]);

        let resolved = resolve_activation_dependencies(
            source("A", root),
            None,
            ActivationResolverLimits::default(),
            &mut catalog,
        )
        .unwrap();

        let names: Vec<Vec<u16>> = resolved
            .assemblies
            .iter()
            .map(|assembly| {
                assembly
                    .details
                    .root
                    .assembly_identity
                    .name
                    .clone()
                    .unwrap()
            })
            .collect();
        assert_eq!(names, vec![wide("A"), wide("B"), wide("C"), wide("D")]);
        let requests: Vec<Vec<u16>> = catalog
            .requests
            .iter()
            .map(|request| request.identity.name.clone().unwrap())
            .collect();
        assert_eq!(requests, vec![wide("B"), wide("C"), wide("D")]);
    }

    #[test]
    fn normalizes_architecture_and_matches_identity_and_language_case_insensitively() {
        let root = br#"<assembly manifestVersion="1.0"><assemblyIdentity name="root"/>
          <dependency><dependentAssembly><assemblyIdentity name="ShArEd" type="WIN32"
            version="6.0.1.2" processorArchitecture="*" publicKeyToken="ABC"
            language="*"/></dependentAssembly></dependency>
        </assembly>"#;
        let dependency = br#"<assembly manifestVersion="1.0">
          <assemblyIdentity name="shared" type="not-part-of-identity" version="6.0.1.2"
            processorArchitecture="AMD64" publicKeyToken="abc" language="en-US"/>
        </assembly>"#;
        let mut catalog = MockCatalog::new(vec![(wide("shared"), source("shared", dependency))]);

        let resolved = resolve_activation_dependencies(
            source("root", root),
            Some(&wide("amd64")),
            ActivationResolverLimits::default(),
            &mut catalog,
        )
        .unwrap();

        assert_eq!(resolved.assemblies.len(), 2);
        assert_eq!(
            catalog.requests[0].identity.processor_architecture,
            Some(wide("amd64"))
        );
    }

    #[test]
    fn enforces_assembly_queue_depth_and_byte_budgets() {
        let cases = [
            ActivationResolverLimits {
                max_assemblies: 1,
                ..ActivationResolverLimits::default()
            },
            ActivationResolverLimits {
                max_manifest_bytes: ROOT_WITH_DEP.len() + DEP.len() - 1,
                ..ActivationResolverLimits::default()
            },
        ];
        for limits in cases {
            let mut catalog = MockCatalog::new(vec![(wide("dep"), source("dep", DEP))]);
            assert_eq!(
                resolve_activation_dependencies(
                    source("root", ROOT_WITH_DEP),
                    None,
                    limits,
                    &mut catalog
                ),
                Err(STATUS_SXS_CANT_GEN_ACTCTX)
            );
        }

        let two_dependencies = br#"<assembly manifestVersion="1.0">
          <assemblyIdentity name="root"/>
          <dependency><dependentAssembly><assemblyIdentity name="one"/></dependentAssembly></dependency>
          <dependency><dependentAssembly><assemblyIdentity name="two"/></dependentAssembly></dependency>
        </assembly>"#;
        let mut catalog = MockCatalog::new(vec![]);
        assert_eq!(
            resolve_activation_dependencies(
                source("root", two_dependencies),
                None,
                ActivationResolverLimits {
                    max_dependency_requests: 1,
                    ..ActivationResolverLimits::default()
                },
                &mut catalog
            ),
            Err(STATUS_SXS_CANT_GEN_ACTCTX)
        );

        let child_with_dependency = br#"<assembly manifestVersion="1.0">
          <assemblyIdentity name="dep" version="1.0.0.0"/>
          <dependency><dependentAssembly><assemblyIdentity name="grandchild"/>
          </dependentAssembly></dependency>
        </assembly>"#;
        let mut catalog =
            MockCatalog::new(vec![(wide("dep"), source("dep", child_with_dependency))]);
        assert_eq!(
            resolve_activation_dependencies(
                source("root", ROOT_WITH_DEP),
                None,
                ActivationResolverLimits {
                    max_depth: 1,
                    ..ActivationResolverLimits::default()
                },
                &mut catalog
            ),
            Err(STATUS_SXS_CANT_GEN_ACTCTX)
        );
    }

    #[test]
    fn accepts_newer_build_revision_and_rejects_older_candidates() {
        let request = br#"<assembly manifestVersion="1.0"><assemblyIdentity name="root"/>
          <dependency><dependentAssembly><assemblyIdentity name="dep" version="6.0.2.4"/>
          </dependentAssembly></dependency></assembly>"#;
        let newer = br#"<assembly manifestVersion="1.0">
          <assemblyIdentity name="dep" version="6.0.3.0"/>
        </assembly>"#;
        let mut catalog = MockCatalog::new(vec![(wide("dep"), source("dep", newer))]);
        let resolved = resolve_activation_dependencies(
            source("root", request),
            None,
            ActivationResolverLimits::default(),
            &mut catalog,
        )
        .unwrap();
        assert_eq!(
            resolved.assemblies[1]
                .details
                .root
                .assembly_identity
                .version,
            [6, 0, 3, 0]
        );

        let mut catalog = MockCatalog::new(vec![(wide("dep"), private_source("dep", newer))]);
        assert_eq!(
            resolve_activation_dependencies(
                source("root", request),
                None,
                ActivationResolverLimits::default(),
                &mut catalog
            ),
            Err(STATUS_SXS_CANT_GEN_ACTCTX)
        );

        let older = br#"<assembly manifestVersion="1.0">
          <assemblyIdentity name="dep" version="6.0.2.3"/>
        </assembly>"#;
        let mut catalog = MockCatalog::new(vec![(wide("dep"), source("dep", older))]);
        assert_eq!(
            resolve_activation_dependencies(
                source("root", request),
                None,
                ActivationResolverLimits::default(),
                &mut catalog
            ),
            Err(STATUS_SXS_CANT_GEN_ACTCTX)
        );
    }

    #[test]
    fn optional_invalid_or_mismatched_candidates_are_skipped() {
        let root = br#"<assembly manifestVersion="1.0"><assemblyIdentity name="root"/>
          <dependency optional="yes"><dependentAssembly><assemblyIdentity name="bad"/>
          </dependentAssembly></dependency>
          <dependency><dependentAssembly allowDelayedBinding="true">
          <assemblyIdentity name="wrong"/></dependentAssembly></dependency></assembly>"#;
        let wrong =
            br#"<assembly manifestVersion="1.0"><assemblyIdentity name="other"/></assembly>"#;
        let mut catalog = MockCatalog::new(vec![
            (wide("bad"), source("bad", b"not xml")),
            (wide("wrong"), source("wrong", wrong)),
        ]);
        let resolved = resolve_activation_dependencies(
            source("root", root),
            None,
            ActivationResolverLimits::default(),
            &mut catalog,
        )
        .unwrap();
        assert_eq!(resolved.assemblies.len(), 1);
    }

    #[test]
    fn rejects_corrupt_or_mismatched_catalog_results() {
        let mut corrupt = MockCatalog::new(vec![(
            wide("dep"),
            source("dep", b"<assembly manifestVersion=\"1.0\">"),
        )]);
        assert_eq!(
            resolve_activation_dependencies(
                source("root", ROOT_WITH_DEP),
                None,
                ActivationResolverLimits::default(),
                &mut corrupt
            ),
            Err(STATUS_SXS_INVALID_ACTCTXDATA_FORMAT)
        );

        let wrong_identity = br#"<assembly manifestVersion="1.0">
          <assemblyIdentity name="other" version="1.0.0.0"/>
        </assembly>"#;
        let mut mismatched = MockCatalog::new(vec![(wide("dep"), source("other", wrong_identity))]);
        assert_eq!(
            resolve_activation_dependencies(
                source("root", ROOT_WITH_DEP),
                None,
                ActivationResolverLimits::default(),
                &mut mismatched
            ),
            Err(STATUS_SXS_CANT_GEN_ACTCTX)
        );
    }

    #[test]
    fn builds_and_ranks_winsxs_manifest_candidates() {
        let request = AssemblyRequest {
            identity: AssemblyIdentity {
                name: Some(wide("microsoft.windows.common-controls")),
                processor_architecture: Some(wide("amd64")),
                public_key_token: Some(wide("6595b64144ccf1df")),
                version: [6, 0, 0, 0],
                ..AssemblyIdentity::default()
            },
            language: Some(wide("neutral")),
        };
        assert_eq!(
            winsxs_manifest_pattern(&request).unwrap().unwrap(),
            wide("amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.*.*_*_*.manifest")
        );
        assert_eq!(
            private_assembly_directory_name(&request).unwrap(),
            wide(
                "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.0.0_neutral_deadbeef"
            )
        );
        let builtin = rank_winsxs_manifest_candidate(
            &request,
            &wide(
                "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef.manifest",
            ),
        )
        .unwrap()
        .unwrap();
        let native = rank_winsxs_manifest_candidate(
            &request,
            &wide(
                "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.3000.1_en-us_native.manifest",
            ),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            builtin,
            WinsxsManifestCandidateRank {
                non_builtin: false,
                build: 2600,
                revision: 2982,
            }
        );
        assert!(native > builtin);

        let mut localized = request.clone();
        localized.language = Some(wide("en-us"));
        assert_eq!(
            rank_winsxs_manifest_candidate(
                &localized,
                &wide(
                    "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.3000.1_fr-fr_native.manifest",
                ),
            )
            .unwrap(),
            None
        );

        let mut newer_request = request;
        newer_request.identity.version = [6, 0, 2601, 0];
        assert_eq!(
            rank_winsxs_manifest_candidate(
                &newer_request,
                &wide(
                    "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef.manifest",
                ),
            )
            .unwrap(),
            None
        );
    }
}
