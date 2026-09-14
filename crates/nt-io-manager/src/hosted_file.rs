//! Exact hosted FILE_OBJECT projection identities and explicit publication leases.
//!
//! Bindings pin final File record removal, not CLOSE entry. A publication lease prevents projection
//! unbind/free; its caller separately retains the canonical File through the operation. Neither a
//! binding nor a lease holds a FileReference, avoiding a CLOSE/unbind ownership cycle.

use crate::{FileId, FileState, HostedDomainIdentity, IoManager};
use alloc::vec::Vec;
use nt_status::NtStatus;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedFileIdentity {
    manager: u64,
    domain: HostedDomainIdentity,
    file: FileId,
    address: u64,
    sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedFileUnbindOutcome {
    Removed,
    AlreadyAbsent,
}

impl HostedFileIdentity {
    pub const fn domain(self) -> HostedDomainIdentity {
        self.domain
    }
    pub const fn file_id(self) -> FileId {
        self.file
    }
    pub const fn address(self) -> u64 {
        self.address
    }
    pub const fn binding_generation(self) -> u64 {
        self.sequence
    }
}

/// Explicit projection ownership cannot be copied or implicitly released by dropping the token.
///
/// ```compile_fail
/// use nt_io_manager::HostedFilePublicationLease;
/// fn duplicate(lease: HostedFilePublicationLease) {
///     let moved = lease;
///     let _ = lease.is_held();
/// }
/// ```
#[derive(Debug)]
#[must_use = "explicitly release the publication lease before unbinding its FILE_OBJECT"]
pub struct HostedFilePublicationLease {
    identity: HostedFileIdentity,
    held: bool,
}

impl HostedFilePublicationLease {
    pub const fn identity(&self) -> HostedFileIdentity {
        self.identity
    }
    pub const fn is_held(&self) -> bool {
        self.held
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HostedFileBinding {
    identity: HostedFileIdentity,
    leases: u64,
}

impl<P> IoManager<P> {
    /// Bind before native publication. An exact live replay returns the same receipt; unbind then
    /// rebind receives a new nonwrapping sequence even when every public identity is unchanged.
    /// CREATE may still be pending. Native adapters must independently authenticate that CREATE.
    pub fn bind_hosted_file_identity(
        &mut self,
        domain: HostedDomainIdentity,
        address: u64,
        file: FileId,
    ) -> Result<HostedFileIdentity, NtStatus> {
        let record = self.file(file).ok_or(NtStatus::INVALID_HANDLE)?;
        let closing = record.state == FileState::Closed || record.close_dispatched;
        if address == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let record = self
            .hosted_domains
            .get(domain.domain_id)
            .filter(|record| domain.cookie != 0 && record.cookie() == domain.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if let Some(binding) = record
            .files
            .iter()
            .find(|binding| binding.identity.address == address || binding.identity.file == file)
        {
            if binding.identity.address == address && binding.identity.file == file {
                return Ok(binding.identity);
            }
            return Err(if closing {
                NtStatus::FILE_CLOSED
            } else {
                NtStatus::OBJECT_NAME_COLLISION
            });
        }
        if closing {
            return Err(NtStatus::FILE_CLOSED);
        }
        let sequence = record
            .file_binding_sequence
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        let manager = self.ensure_ownership_identity()?;
        let record = self.hosted_domains.get_mut(domain.domain_id).unwrap();
        record
            .files
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let identity = HostedFileIdentity {
            manager,
            domain,
            file,
            address,
            sequence,
        };
        record.files.push(HostedFileBinding {
            identity,
            leases: 0,
        });
        record.file_binding_sequence = sequence;
        Ok(identity)
    }

    fn hosted_file_binding_index(&self, identity: HostedFileIdentity) -> Result<usize, NtStatus> {
        if identity.manager == 0 || identity.manager != self.ownership_identity() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let record = self
            .hosted_domains
            .get(identity.domain.domain_id)
            .filter(|record| {
                identity.domain.cookie != 0 && record.cookie() == identity.domain.cookie
            })
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        record
            .files
            .iter()
            .position(|binding| binding.identity == identity)
            .ok_or(NtStatus::INVALID_PARAMETER)
    }

    /// Observe only the exact authenticated domain/File/address tuple. Retirement may outlive
    /// the canonical File record, so absence is independent of File lookup and device topology.
    /// The receipt grants no lifetime; acquire a publication lease before using its projection.
    pub fn hosted_file_identity_at(
        &self,
        domain: HostedDomainIdentity,
        file: FileId,
        address: u64,
    ) -> Result<Option<HostedFileIdentity>, NtStatus> {
        if file == FileId::NULL || address == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let record = self
            .hosted_domains
            .get(domain.domain_id)
            .filter(|record| domain.cookie != 0 && record.cookie() == domain.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        Ok(record
            .files
            .iter()
            .find(|binding| binding.identity.file == file && binding.identity.address == address)
            .map(|binding| binding.identity))
    }

    /// Retire a wire identity only in the broker-authenticated domain. Historical generations
    /// are idempotent, but zero/future generations are not valid retirement receipts. A stored
    /// opaque receipt is required for removal; no receipt is reconstructed from caller fields.
    pub fn unbind_authenticated_hosted_file(
        &mut self,
        domain: HostedDomainIdentity,
        file: FileId,
        address: u64,
        generation: u64,
    ) -> Result<HostedFileUnbindOutcome, NtStatus> {
        if file == FileId::NULL || address == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let record = self
            .hosted_domains
            .get(domain.domain_id)
            .filter(|record| domain.cookie != 0 && record.cookie() == domain.cookie)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if generation == 0 || generation > record.file_binding_sequence {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let identity = record
            .files
            .iter()
            .find(|binding| {
                binding.identity.file == file
                    && binding.identity.address == address
                    && binding.identity.sequence == generation
            })
            .map(|binding| binding.identity);
        match identity {
            Some(identity) => self.unbind_hosted_file_identity(identity),
            None => Ok(HostedFileUnbindOutcome::AlreadyAbsent),
        }
    }

    /// Exact teardown remains valid after CLOSE; leased native storage must not be freed yet.
    /// Retrying a retired receipt returns AlreadyAbsent without removing any replacement binding.
    /// The final unbind only queues retained close work; it invokes no backend or callback.
    pub fn unbind_hosted_file_identity(
        &mut self,
        identity: HostedFileIdentity,
    ) -> Result<HostedFileUnbindOutcome, NtStatus> {
        if identity.manager == 0 || identity.manager != self.ownership_identity() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let record = self
            .hosted_domains
            .get_mut(identity.domain.domain_id)
            .filter(|record| {
                identity.domain.cookie != 0 && record.cookie() == identity.domain.cookie
            })
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let Some(index) = record
            .files
            .iter()
            .position(|binding| binding.identity == identity)
        else {
            return Ok(HostedFileUnbindOutcome::AlreadyAbsent);
        };
        if record.files[index].leases != 0 {
            return Err(NtStatus::DELETE_PENDING);
        }
        record.files.swap_remove(index);
        if !self.has_hosted_file_bindings(identity.file)
            && self
                .file(identity.file)
                .is_some_and(|file| file.close_deferred || file.close_dispatched)
        {
            self.queue_deferred_file_close(identity.file);
        }
        Ok(HostedFileUnbindOutcome::Removed)
    }

    /// Snapshot all exact projections without consulting device attachment topology. The returned
    /// receipts grant no lifetime; acquire explicit leases before crossing a publication boundary.
    pub fn hosted_file_identities(
        &self,
        file: FileId,
    ) -> Result<Vec<HostedFileIdentity>, NtStatus> {
        self.file(file).ok_or(NtStatus::INVALID_HANDLE)?;
        let count = self
            .hosted_domains
            .iter()
            .map(|(_, domain)| {
                domain
                    .files
                    .iter()
                    .filter(|binding| binding.identity.file == file)
                    .count()
            })
            .sum();
        let mut identities = Vec::new();
        identities
            .try_reserve(count)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        for (_, domain) in self.hosted_domains.iter() {
            identities.extend(
                domain
                    .files
                    .iter()
                    .filter(|binding| binding.identity.file == file)
                    .map(|binding| binding.identity),
            );
        }
        Ok(identities)
    }

    pub fn has_hosted_file_bindings(&self, file: FileId) -> bool {
        self.hosted_domains.iter().any(|(_, domain)| {
            domain
                .files
                .iter()
                .any(|binding| binding.identity.file == file)
        })
    }

    /// Pin only this exact projection. The caller separately owns the canonical File reference.
    /// Dropping the returned non-Clone token does not release it or permit unbinding.
    pub fn lease_hosted_file_identity(
        &mut self,
        identity: HostedFileIdentity,
    ) -> Result<HostedFilePublicationLease, NtStatus> {
        let index = self.hosted_file_binding_index(identity)?;
        let record = self
            .hosted_domains
            .get_mut(identity.domain.domain_id)
            .unwrap();
        let binding = &mut record.files[index];
        binding.leases = binding
            .leases
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        Ok(HostedFilePublicationLease {
            identity,
            held: true,
        })
    }

    pub fn release_hosted_file_publication(
        &mut self,
        lease: &mut HostedFilePublicationLease,
    ) -> Result<(), NtStatus> {
        if !lease.held {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let index = self.hosted_file_binding_index(lease.identity)?;
        let record = self
            .hosted_domains
            .get_mut(lease.identity.domain.domain_id)
            .unwrap();
        let binding = &mut record.files[index];
        let count = binding
            .leases
            .checked_sub(1)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        binding.leases = count;
        lease.held = false;
        Ok(())
    }

    pub fn hosted_file_by_identity(
        &self,
        domain: HostedDomainIdentity,
        address: u64,
    ) -> Option<FileId> {
        let record = self.hosted_domains.get(domain.domain_id)?;
        if domain.cookie == 0 || record.cookie() != domain.cookie {
            return None;
        }
        let file = record
            .files
            .iter()
            .find(|binding| binding.identity.address == address)?
            .identity
            .file;
        self.file(file).map(|_| file)
    }

    pub fn hosted_file_address_by_identity(
        &self,
        domain: HostedDomainIdentity,
        file: FileId,
    ) -> Option<u64> {
        self.file(file)?;
        let record = self.hosted_domains.get(domain.domain_id)?;
        if domain.cookie == 0 || record.cookie() != domain.cookie {
            return None;
        }
        record
            .files
            .iter()
            .find(|binding| binding.identity.file == file)
            .map(|binding| binding.identity.address)
    }
}

#[cfg(test)]
mod tests;
