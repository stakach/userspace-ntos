//! Generation-bound execution roles and actual initial-thread creator lineage.
//!
//! The image catalog supplies immutable registration and mounted File provenance. The effectful
//! executive must supply the *actual* caller and child process identities from live thread
//! bindings when it invokes these transitions; a process parent handle is only a hint.

use crate::{HostedProcessRole, OwnedHostedImageCatalog, SpawnTarget};
use nt_memory_manager::{ProcessGeneration, ProcessIdentity, SectionFileIdentity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionRoleError {
    InvalidIdentity,
    InvalidBacking,
    StaleTarget,
    UnregisteredRole,
    UnauthorizedCreator,
    AlreadyAdmitted,
    Full,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForeignInitialThreadLineageEvidence {
    pub caller: ProcessIdentity,
    pub child: ProcessIdentity,
    pub child_target: SpawnTarget,
    pub section_image: SectionFileIdentity,
    /// Untrusted process parent selected through the caller's process handle.
    pub parent_handle_hint: Option<ProcessIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForeignInitialThreadRoleEvidence {
    pub caller: ProcessIdentity,
    pub child: ProcessIdentity,
    pub child_target: SpawnTarget,
    pub registered_target: SpawnTarget,
    pub section_image: SectionFileIdentity,
    /// Untrusted process parent selected through the caller's process handle.
    pub parent_handle_hint: Option<ProcessIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    target: SpawnTarget,
    process: ProcessIdentity,
    role: HostedProcessRole,
    creator: Option<ProcessIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionRoleLedger<const N: usize> {
    entries: [Option<Entry>; N],
}

impl<const N: usize> Default for ExecutionRoleLedger<N> {
    fn default() -> Self { Self::new() }
}

impl<const N: usize> ExecutionRoleLedger<N> {
    pub const fn new() -> Self { Self { entries: [None; N] } }

    pub fn seed_bootstrap_root(
        &mut self,
        catalog: &OwnedHostedImageCatalog<N>,
        target: SpawnTarget,
        process: ProcessIdentity,
    ) -> Result<(), ExecutionRoleError> {
        if !valid_process(process) { return Err(ExecutionRoleError::InvalidIdentity); }
        if target.role != HostedProcessRole::NativeSession
            || catalog.registered_launch_policy(target)
                .is_none_or(|(_, creator)| creator != target.role)
        {
            return Err(ExecutionRoleError::UnregisteredRole);
        }
        self.insert(catalog, target, process, target.role, None)
    }

    pub fn admit_foreign_initial_thread(
        &mut self,
        catalog: &OwnedHostedImageCatalog<N>,
        evidence: ForeignInitialThreadRoleEvidence,
    ) -> Result<(), ExecutionRoleError> {
        let ForeignInitialThreadRoleEvidence {
            caller, child, child_target, registered_target, section_image, ..
        } = evidence;
        let creator_role = self.live_caller_role(caller)?;
        let image = catalog.get_by_pi(child_target.pi)
            .ok_or(ExecutionRoleError::StaleTarget)?;
        if SpawnTarget::from_image(image) != child_target
            || image.observation_target() != Some(registered_target)
        {
            return Err(ExecutionRoleError::StaleTarget);
        }
        let Some((backing, allowed_creator)) =
            catalog.registered_launch_policy(registered_target) else {
                return Err(ExecutionRoleError::UnregisteredRole);
            };
        if backing != section_image || backing.file_id == 0 || backing.mount.value() == 0 {
            return Err(ExecutionRoleError::InvalidBacking);
        }
        if creator_role != allowed_creator {
            return Err(ExecutionRoleError::UnauthorizedCreator);
        }
        self.insert(catalog, child_target, child, registered_target.role, Some(caller))
    }

    /// Record actual lineage for ordinary children without promoting a historical image role.
    pub fn record_foreign_initial_thread(
        &mut self,
        catalog: &OwnedHostedImageCatalog<N>,
        evidence: ForeignInitialThreadLineageEvidence,
    ) -> Result<(), ExecutionRoleError> {
        if evidence.section_image.file_id == 0 || evidence.section_image.mount.value() == 0 {
            return Err(ExecutionRoleError::InvalidBacking);
        }
        if !matches!(evidence.child_target.role,
            HostedProcessRole::Application | HostedProcessRole::NativeApplication)
        {
            return Err(ExecutionRoleError::UnregisteredRole);
        }
        self.live_caller_role(evidence.caller)?;
        self.insert(catalog, evidence.child_target, evidence.child,
            evidence.child_target.role, Some(evidence.caller))
    }

    pub fn role(&self, target: SpawnTarget, process: ProcessIdentity) -> Option<HostedProcessRole> {
        self.entry(target, process).map(|entry| entry.role)
    }

    pub fn creator_of(&self, target: SpawnTarget, process: ProcessIdentity) -> Option<ProcessIdentity> {
        self.entry(target, process).and_then(|entry| entry.creator)
    }

    pub fn can_own_installer_service_work(
        &self,
        target: SpawnTarget,
        process: ProcessIdentity,
    ) -> bool {
        self.role(target, process)
            .is_some_and(HostedProcessRole::is_noninteractive_service_class)
    }

    /// Follow only live, exact-generation creator records. A retired link cuts the chain.
    pub fn installer_service_ancestor(
        &self,
        target: SpawnTarget,
        process: ProcessIdentity,
    ) -> Option<ProcessIdentity> {
        let mut current = self.entry(target, process)?;
        for _ in 0..N {
            if current.role.is_noninteractive_service_class() {
                return Some(current.process);
            }
            let creator = current.creator?;
            current = self.entries.iter().flatten().find(|entry| entry.process == creator)?;
        }
        None
    }

    pub fn retire_exact(
        &mut self,
        target: SpawnTarget,
        process: ProcessIdentity,
    ) -> Result<(), ExecutionRoleError> {
        let index = self.entries.iter()
            .position(|entry| entry.is_some_and(|entry|
                entry.target == target && entry.process == process))
            .ok_or(ExecutionRoleError::NotFound)?;
        self.entries[index] = None;
        Ok(())
    }

    fn entry(&self, target: SpawnTarget, process: ProcessIdentity) -> Option<&Entry> {
        self.entries.iter().flatten()
            .find(|entry| entry.target == target && entry.process == process)
    }

    fn live_caller_role(&self, process: ProcessIdentity) -> Result<HostedProcessRole, ExecutionRoleError> {
        self.entries.iter().flatten().find(|entry| entry.process == process)
            .map(|entry| entry.role).ok_or(ExecutionRoleError::UnauthorizedCreator)
    }

    fn insert(
        &mut self,
        catalog: &OwnedHostedImageCatalog<N>,
        target: SpawnTarget,
        process: ProcessIdentity,
        role: HostedProcessRole,
        creator: Option<ProcessIdentity>,
    ) -> Result<(), ExecutionRoleError> {
        if !valid_process(process) { return Err(ExecutionRoleError::InvalidIdentity); }
        if catalog.get_by_pi(target.pi).map(SpawnTarget::from_image) != Some(target) {
            return Err(ExecutionRoleError::StaleTarget);
        }
        if self.entries.iter().flatten().any(|entry|
            entry.target == target || entry.process == process || entry.target.pi == target.pi)
        {
            return Err(ExecutionRoleError::AlreadyAdmitted);
        }
        let slot = self.entries.iter_mut().find(|entry| entry.is_none())
            .ok_or(ExecutionRoleError::Full)?;
        *slot = Some(Entry { target, process, role, creator });
        Ok(())
    }
}

fn valid_process(process: ProcessIdentity) -> bool {
    process.pid != 0 && matches!(process.generation, ProcessGeneration::Hosted(value) if value != 0)
}
