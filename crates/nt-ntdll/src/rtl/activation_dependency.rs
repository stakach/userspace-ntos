//! Pure, bounded activation-context dependency resolution.
//!
//! Filesystem and WinSxS probing remain outside this module. Callers inject an
//! [`ActivationManifestCatalog`] which returns an owned manifest source for a normalized request;
//! the resolver parses and verifies every returned manifest before assigning it a roster index.
//! This keeps dependency graph handling host-testable and lets the target-side loader choose its
//! eventual file-query mechanism independently.

use alloc::vec::Vec;

use crate::NtStatus;

#[cfg(test)]
use super::activation::STATUS_SXS_INVALID_ACTCTXDATA_FORMAT;
use super::activation::{MAX_MANIFEST_BYTES, STATUS_SXS_CANT_GEN_ACTCTX};
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
/// build/revision may be newer than requested. The assembly `type` attribute is not part of
/// identity matching.
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
        let source = catalog.resolve(&pending.request)?;
        cursor += 1;

        let Some(source) = source else {
            if required {
                return Err(STATUS_SXS_CANT_GEN_ACTCTX);
            }
            continue;
        };
        if assemblies.len() >= limits.max_assemblies {
            return Err(STATUS_SXS_CANT_GEN_ACTCTX);
        }
        manifest_bytes = manifest_bytes
            .checked_add(source.manifest.len())
            .filter(|total| *total <= limits.max_manifest_bytes)
            .ok_or(STATUS_SXS_CANT_GEN_ACTCTX)?;

        let details = parse_manifest_details(&source.manifest)?;
        if !assembly_request_matches(
            &queue[cursor - 1].request,
            &details.root.assembly_identity,
            details.root_language.as_deref(),
        ) {
            return Err(STATUS_SXS_CANT_GEN_ACTCTX);
        }

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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn source(name: &str, manifest: &[u8]) -> ActivationManifestSource {
        ActivationManifestSource {
            source: wide(name),
            manifest_path: wide(&alloc::format!("{name}.manifest")),
            assembly_directory: wide(name),
            manifest: manifest.to_vec(),
        }
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
}
