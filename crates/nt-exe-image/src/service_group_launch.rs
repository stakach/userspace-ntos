//! Historical process-group launch evidence at foreign initial-thread admission.
//!
//! Matching a CM declaration to a real child says which process group was launched. A shared
//! process can host several services, so this receipt never identifies or authorizes a service.

use nt_memory_manager::{ProcessIdentity, SectionFileIdentity};

use crate::{MAX_COMMAND_LINE, MAX_NT_IMAGE_PATH};

/// A declared process group from one accepted, generation-bound CM snapshot. The native
/// adapter resolves its image to an exact mounted Section backing before matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclaredServiceGroup<'a> {
    pub mount_generation: u64,
    pub image: SectionFileIdentity,
    pub nt_image_path: &'a [u8],
    pub command_line: &'a [u8],
}

/// The caller and child must come from their exact live thread/process bindings. The child
/// fields are read from its PEB after the creator writes process parameters, before its initial
/// thread is admitted. No caller-provided parent process handle participates in this contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForeignInitialThreadEvidence<'a> {
    pub caller: ProcessIdentity,
    pub child: ProcessIdentity,
    pub mount_generation: u64,
    pub section_image: SectionFileIdentity,
    pub nt_image_path: &'a [u8],
    pub command_line: &'a [u8],
}

/// Historical group observation. This is not an execution role or a service permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchedServiceGroup {
    pub caller: ProcessIdentity,
    pub child: ProcessIdentity,
    pub mount_generation: u64,
    pub section_image: SectionFileIdentity,
}

fn valid_text(bytes: &[u8], maximum: usize) -> bool {
    !bytes.is_empty()
        && bytes.len() <= maximum
        && !bytes.contains(&0)
        && core::str::from_utf8(bytes).is_ok()
}

/// Match one complete group declaration to the exact captured launch. The `scm` argument must
/// be the registered SCM's live execution identity, not an image observation or a parent handle.
pub fn match_declared_group(
    declared: DeclaredServiceGroup<'_>,
    scm: ProcessIdentity,
    actual: ForeignInitialThreadEvidence<'_>,
) -> Option<MatchedServiceGroup> {
    if !scm.is_valid()
        || !actual.child.is_valid()
        || actual.child == scm
        || actual.caller != scm
        || declared.mount_generation == 0
        || actual.mount_generation != declared.mount_generation
        || declared.image.mount.value() == 0
        || declared.image.file_id == 0
        || actual.section_image != declared.image
        || !valid_text(declared.nt_image_path, MAX_NT_IMAGE_PATH)
        || !valid_text(actual.nt_image_path, MAX_NT_IMAGE_PATH)
        || !valid_text(declared.command_line, MAX_COMMAND_LINE)
        || !valid_text(actual.command_line, MAX_COMMAND_LINE)
        || declared.nt_image_path != actual.nt_image_path
        || declared.command_line != actual.command_line
    {
        return None;
    }
    Some(MatchedServiceGroup {
        caller: scm,
        child: actual.child,
        mount_generation: declared.mount_generation,
        section_image: declared.image,
    })
}
