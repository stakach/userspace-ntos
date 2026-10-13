//! Retained reverse projection of class devices into the port driver's domain.
//!
//! The attached class PortDO FDO is the result of `IoGetAttachedDeviceReference`
//! traversal. The main ClassDO is the first argument to the class callback.
//! Those are separate canonical devices and need separate native aliases.

use nt_status::NtStatus;

use crate::{HostedDevicePointerRegistration, HostedDeviceProjectionReference, IoManager};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReverseClassAliasIdentity {
    pub source_port_fdo: HostedDevicePointerRegistration,
    pub source_main: HostedDevicePointerRegistration,
    pub alias_port_fdo: HostedDevicePointerRegistration,
    pub alias_main: HostedDevicePointerRegistration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReverseClassAliasPhase {
    Prepared,
    Staged,
    Entered,
    Published,
    Uncertain,
    Retiring,
    Retired,
}

/// Keeps both exact class-domain projections live while the port domain can
/// observe their aliases. Native publication must begin only after `stage`.
#[must_use = "retire both aliases and release their exact source projections"]
pub struct ReverseClassAliasProjection {
    source_port_fdo: Option<HostedDeviceProjectionReference>,
    source_main: Option<HostedDeviceProjectionReference>,
    identity: Option<ReverseClassAliasIdentity>,
    phase: ReverseClassAliasPhase,
}

impl ReverseClassAliasProjection {
    pub fn new<P>(
        io: &mut IoManager<P>,
        source_port_fdo: HostedDevicePointerRegistration,
        source_main: HostedDevicePointerRegistration,
    ) -> Result<Self, NtStatus> {
        if source_port_fdo.domain() != source_main.domain()
            || source_port_fdo == source_main
            || source_port_fdo.device_id() == source_main.device_id()
            || !Self::live(io, source_port_fdo)
            || !Self::live(io, source_main)
            || !Self::attached_class_port_fdo(io, source_port_fdo)
        {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let mut port = io.retain_hosted_device_projection_reference(source_port_fdo)?;
        let main = match io.retain_hosted_device_projection_reference(source_main) {
            Ok(main) => main,
            Err(status) => {
                port.release(io)?;
                return Err(status);
            }
        };
        Ok(Self {
            source_port_fdo: Some(port),
            source_main: Some(main),
            identity: None,
            phase: ReverseClassAliasPhase::Prepared,
        })
    }

    pub const fn phase(&self) -> ReverseClassAliasPhase {
        self.phase
    }

    fn live<P>(io: &IoManager<P>, registration: HostedDevicePointerRegistration) -> bool {
        io.hosted_device_pointer_registration(registration.domain(), registration.address())
            == Some(registration)
            && io
                .device(registration.device_id())
                .is_some_and(|record| !record.delete_pending)
    }

    fn attached_class_port_fdo<P>(
        io: &IoManager<P>,
        registration: HostedDevicePointerRegistration,
    ) -> bool {
        io.device(registration.device_id()).is_some_and(|record| {
            record.attached_to.is_some()
                && record.top_of_stack == registration.device_id()
                && !record.delete_pending
        })
    }

    fn valid_identity<P>(&self, io: &IoManager<P>, identity: ReverseClassAliasIdentity) -> bool {
        self.source_port_fdo.as_ref().is_some_and(|owner| {
            owner.is_held() && owner.registration() == identity.source_port_fdo
        }) && self
            .source_main
            .as_ref()
            .is_some_and(|owner| owner.is_held() && owner.registration() == identity.source_main)
            && identity.source_port_fdo.domain() == identity.source_main.domain()
            && identity.alias_port_fdo.domain() == identity.alias_main.domain()
            && identity.alias_port_fdo.domain() != identity.source_port_fdo.domain()
            && identity.alias_port_fdo != identity.alias_main
            && identity.alias_port_fdo.device_id() == identity.source_port_fdo.device_id()
            && identity.alias_main.device_id() == identity.source_main.device_id()
            && Self::live(io, identity.source_port_fdo)
            && Self::live(io, identity.source_main)
            && Self::live(io, identity.alias_port_fdo)
            && Self::live(io, identity.alias_main)
            && Self::attached_class_port_fdo(io, identity.source_port_fdo)
    }

    /// The native adapter creates and registers both aliases before any native
    /// pointer is made visible. This binds their exact generations to this owner.
    pub fn stage<P>(
        &mut self,
        io: &IoManager<P>,
        identity: ReverseClassAliasIdentity,
    ) -> Result<(), NtStatus> {
        if self.phase != ReverseClassAliasPhase::Prepared {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if !self.valid_identity(io, identity) {
            return Err(NtStatus::INVALID_HANDLE);
        }
        self.identity = Some(identity);
        self.phase = ReverseClassAliasPhase::Staged;
        Ok(())
    }

    /// Native alias allocation or its reply can be uncertain before both
    /// registrations exist. Keep the source pins and forbid a second attempt.
    pub fn block_prepublication(&mut self) -> Result<(), NtStatus> {
        if !matches!(
            self.phase,
            ReverseClassAliasPhase::Prepared | ReverseClassAliasPhase::Staged
        ) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.phase = ReverseClassAliasPhase::Uncertain;
        Ok(())
    }

    /// Record ownership before exposing either native alias. Any uncertain
    /// effect after this transition must call `block_uncertain`.
    pub fn begin_publication<P>(
        &mut self,
        io: &IoManager<P>,
        identity: ReverseClassAliasIdentity,
    ) -> Result<(), NtStatus> {
        if self.phase != ReverseClassAliasPhase::Staged {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self.identity != Some(identity) || !self.valid_identity(io, identity) {
            return Err(NtStatus::INVALID_HANDLE);
        }
        self.phase = ReverseClassAliasPhase::Entered;
        Ok(())
    }

    pub fn complete_publication<P>(
        &mut self,
        io: &IoManager<P>,
        identity: ReverseClassAliasIdentity,
    ) -> Result<(), NtStatus> {
        if self.phase != ReverseClassAliasPhase::Entered {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self.identity != Some(identity) || !self.valid_identity(io, identity) {
            return Err(NtStatus::INVALID_HANDLE);
        }
        self.phase = ReverseClassAliasPhase::Published;
        Ok(())
    }

    pub fn block_uncertain(&mut self) -> Result<(), NtStatus> {
        if !matches!(
            self.phase,
            ReverseClassAliasPhase::Entered | ReverseClassAliasPhase::Published
        ) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.phase = ReverseClassAliasPhase::Uncertain;
        Ok(())
    }

    fn published_alias<P>(
        &self,
        io: &IoManager<P>,
        select: impl FnOnce(ReverseClassAliasIdentity) -> HostedDevicePointerRegistration,
    ) -> Result<HostedDevicePointerRegistration, NtStatus> {
        if self.phase == ReverseClassAliasPhase::Retiring
            || self.phase == ReverseClassAliasPhase::Retired
        {
            return Err(NtStatus::DELETE_PENDING);
        }
        if self.phase != ReverseClassAliasPhase::Published {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let identity = self.identity.ok_or(NtStatus::INVALID_HANDLE)?;
        if !self.valid_identity(io, identity) {
            return Err(NtStatus::INVALID_HANDLE);
        }
        Ok(select(identity))
    }

    pub fn alias_for_attached_traversal<P>(
        &self,
        io: &IoManager<P>,
    ) -> Result<HostedDevicePointerRegistration, NtStatus> {
        self.published_alias(io, |identity| identity.alias_port_fdo)
    }

    pub fn alias_for_callback_first_argument<P>(
        &self,
        io: &IoManager<P>,
    ) -> Result<HostedDevicePointerRegistration, NtStatus> {
        self.published_alias(io, |identity| identity.alias_main)
    }

    /// No new traversal or callback may start after this transition.
    pub fn begin_retirement(&mut self) -> Result<(), NtStatus> {
        if self.phase != ReverseClassAliasPhase::Published {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.phase = ReverseClassAliasPhase::Retiring;
        Ok(())
    }

    /// Native must first retire both aliases and all their caller references.
    /// A failed source release leaves the remaining exact owner available for
    /// reconciliation; it cannot reopen publication.
    pub fn finish_retirement<P>(&mut self, io: &mut IoManager<P>) -> Result<(), NtStatus> {
        if self.phase != ReverseClassAliasPhase::Retiring {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let identity = self.identity.ok_or(NtStatus::INVALID_HANDLE)?;
        if io
            .hosted_device_pointer_registration(
                identity.alias_port_fdo.domain(),
                identity.alias_port_fdo.address(),
            )
            .is_some()
            || io
                .hosted_device_pointer_registration(
                    identity.alias_main.domain(),
                    identity.alias_main.address(),
                )
                .is_some()
        {
            return Err(NtStatus::DEVICE_BUSY);
        }
        if let Some(port) = &mut self.source_port_fdo {
            port.release(io)?;
            self.source_port_fdo = None;
        }
        if let Some(main) = &mut self.source_main {
            main.release(io)?;
            self.source_main = None;
        }
        self.phase = ReverseClassAliasPhase::Retired;
        Ok(())
    }
}

#[cfg(test)]
#[path = "reverse_class_alias_projection/tests.rs"]
mod tests;
