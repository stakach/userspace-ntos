//! Immutable physical File provenance retained with a dynamic process image.

use crate::{CapturedImageObservation, HostedProcessImageRef, OwnedHostedImageCatalog, SpawnTarget};
use nt_memory_manager::SectionFileIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessImageSourceError {
    InvalidFile,
    ObservationMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessImageSourceEvidence {
    target: SpawnTarget,
    file: SectionFileIdentity,
    registered_file: Option<SectionFileIdentity>,
    observation: Option<SpawnTarget>,
}

impl ProcessImageSourceEvidence {
    /// Capture the Section's File and observation at process admission. A historical observation
    /// stays historical if its registration later retires; it cannot select another File or PI.
    pub fn capture(
        image: HostedProcessImageRef<'_>,
        file: SectionFileIdentity,
        observation: Option<CapturedImageObservation>,
    ) -> Result<Self, ProcessImageSourceError> {
        Self::capture_with_registered_file(image, file, Some(file), observation)
    }

    pub fn capture_with_registered_file(
        image: HostedProcessImageRef<'_>,
        file: SectionFileIdentity,
        registered_file: Option<SectionFileIdentity>,
        observation: Option<CapturedImageObservation>,
    ) -> Result<Self, ProcessImageSourceError> {
        if file.file_id == 0 || file.mount.value() == 0 {
            return Err(ProcessImageSourceError::InvalidFile);
        }
        let observation = observation.map(CapturedImageObservation::target);
        if image.observation_target() != observation {
            return Err(ProcessImageSourceError::ObservationMismatch);
        }
        Ok(Self { target: SpawnTarget::from_image(image), file, registered_file, observation })
    }

    pub const fn file(self) -> SectionFileIdentity { self.file }
    pub const fn registered_file(self) -> Option<SectionFileIdentity> { self.registered_file }
    pub const fn observation(self) -> Option<SpawnTarget> { self.observation }
    pub fn matches_target(self, target: SpawnTarget) -> bool { self.target == target }

    /// Role promotion requires the current registered generation and its exact physical File.
    pub fn registered_target_for_role<const N: usize>(
        self,
        catalog: &OwnedHostedImageCatalog<N>,
    ) -> Option<SpawnTarget> {
        let child = catalog.get_by_pi(self.target.pi)?;
        if SpawnTarget::from_image(child) != self.target
            || child.observation_target() != self.observation
        { return None; }
        let registered = self.observation?;
        catalog.registered_launch_policy(registered)
            .and_then(|(file, _)| (Some(file) == self.registered_file).then_some(registered))
    }
}
