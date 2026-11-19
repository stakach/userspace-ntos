//! Exact-owner, bounded UTF-16 directory-name uploads for native object operations.

use alloc::vec::Vec;

/// A UNICODE_STRING length is a 16-bit byte count.
pub const MAX_NAME_UNITS: usize = (u16::MAX as usize) / 2;
pub const MAX_CHUNK_UNITS: usize = 64;
/// Upper bound for a provider-supplied self-relative creator security descriptor.
pub const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 4096;
pub const MAX_SECURITY_CHUNK_BYTES: usize = 64;

/// Identity supplied only after the adapter authenticates the physical route and caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryUploadOwner<R, D, C> {
    pub route: R,
    pub dispatch: D,
    pub caller: C,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryNameMetadata {
    pub root_directory: u64,
    pub attributes: u32,
    pub desired_access: u32,
    pub total_units: usize,
}

/// COMMIT transfers the exact, complete name to the native operation owner.
#[derive(Debug, PartialEq, Eq)]
pub struct DirectoryNameCapture {
    pub root_directory: u64,
    pub attributes: u32,
    pub desired_access: u32,
    pub name: Vec<u16>,
    /// The creator's self-relative SECURITY_DESCRIPTOR bytes, structurally unvalidated:
    /// the Object Manager owner validates them exactly as a captured client descriptor.
    pub security_descriptor: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryUploadPhase {
    Uploading,
    Committed,
    EffectUncertain,
    Aborted,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryUploadError {
    RouteOccupied,
    WrongOwner,
    InvalidLength,
    InvalidChunk,
    WrongOffset,
    Overflow,
    Incomplete,
    InvalidPhase,
    NoMemory,
}

struct Entry<R, D, C> {
    owner: DirectoryUploadOwner<R, D, C>,
    metadata: DirectoryNameMetadata,
    name: Vec<u16>,
    /// Declared length and bytes received so far.
    security: Option<(usize, Vec<u8>)>,
    phase: DirectoryUploadPhase,
}

/// Each route retains at most one generation. An unresolved commit owns its route;
/// a retired or aborted generation permits only a different dispatch to replace it.
/// The adapter must authenticate that dispatch against the live physical route.
pub struct DirectoryNameUploads<R, D, C> {
    entries: Vec<Entry<R, D, C>>,
}

impl<R: Copy + Eq, D: Copy + Eq, C: Copy + Eq> DirectoryNameUploads<R, D, C> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn begin(
        &mut self,
        owner: DirectoryUploadOwner<R, D, C>,
        metadata: DirectoryNameMetadata,
    ) -> Result<(), DirectoryUploadError> {
        if metadata.total_units == 0 || metadata.total_units > MAX_NAME_UNITS {
            return Err(DirectoryUploadError::InvalidLength);
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.owner.route == owner.route)
        {
            if entry.owner.dispatch == owner.dispatch
                || !matches!(
                    entry.phase,
                    DirectoryUploadPhase::Aborted | DirectoryUploadPhase::Retired
                )
            {
                return Err(DirectoryUploadError::RouteOccupied);
            }
            entry.owner = owner;
            entry.metadata = metadata;
            entry.name.clear();
            entry.security = None;
            entry.phase = DirectoryUploadPhase::Uploading;
            return Ok(());
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| DirectoryUploadError::NoMemory)?;
        self.entries.push(Entry {
            owner,
            metadata,
            name: Vec::new(),
            security: None,
            phase: DirectoryUploadPhase::Uploading,
        });
        Ok(())
    }

    pub fn append(
        &mut self,
        owner: DirectoryUploadOwner<R, D, C>,
        offset_units: usize,
        chunk: &[u16],
    ) -> Result<(), DirectoryUploadError> {
        let entry = self.entry_mut(owner)?;
        if entry.phase != DirectoryUploadPhase::Uploading {
            return Err(DirectoryUploadError::InvalidPhase);
        }
        if chunk.is_empty() || chunk.len() > MAX_CHUNK_UNITS {
            return Err(DirectoryUploadError::InvalidChunk);
        }
        if offset_units != entry.name.len() {
            return Err(DirectoryUploadError::WrongOffset);
        }
        let end = offset_units
            .checked_add(chunk.len())
            .ok_or(DirectoryUploadError::Overflow)?;
        if end > entry.metadata.total_units {
            return Err(DirectoryUploadError::Overflow);
        }
        entry
            .name
            .try_reserve(chunk.len())
            .map_err(|_| DirectoryUploadError::NoMemory)?;
        entry.name.extend_from_slice(chunk);
        Ok(())
    }

    /// Declare a creator security descriptor of `length` bytes for this upload.
    pub fn begin_security(
        &mut self,
        owner: DirectoryUploadOwner<R, D, C>,
        length: usize,
    ) -> Result<(), DirectoryUploadError> {
        let entry = self.entry_mut(owner)?;
        if entry.phase != DirectoryUploadPhase::Uploading || entry.security.is_some() {
            return Err(DirectoryUploadError::InvalidPhase);
        }
        if length == 0 || length > MAX_SECURITY_DESCRIPTOR_BYTES {
            return Err(DirectoryUploadError::InvalidLength);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| DirectoryUploadError::NoMemory)?;
        entry.security = Some((length, bytes));
        Ok(())
    }

    pub fn append_security(
        &mut self,
        owner: DirectoryUploadOwner<R, D, C>,
        offset: usize,
        chunk: &[u8],
    ) -> Result<(), DirectoryUploadError> {
        let entry = self.entry_mut(owner)?;
        if entry.phase != DirectoryUploadPhase::Uploading {
            return Err(DirectoryUploadError::InvalidPhase);
        }
        let (length, bytes) = entry.security.as_mut().ok_or(DirectoryUploadError::InvalidPhase)?;
        if chunk.is_empty() || chunk.len() > MAX_SECURITY_CHUNK_BYTES {
            return Err(DirectoryUploadError::InvalidChunk);
        }
        if offset != bytes.len() {
            return Err(DirectoryUploadError::WrongOffset);
        }
        if offset.checked_add(chunk.len()).is_none_or(|end| end > *length) {
            return Err(DirectoryUploadError::Overflow);
        }
        bytes.extend_from_slice(chunk);
        Ok(())
    }

    pub fn commit(
        &mut self,
        owner: DirectoryUploadOwner<R, D, C>,
    ) -> Result<DirectoryNameCapture, DirectoryUploadError> {
        let entry = self.entry_mut(owner)?;
        if entry.phase != DirectoryUploadPhase::Uploading {
            return Err(DirectoryUploadError::InvalidPhase);
        }
        if entry.name.len() != entry.metadata.total_units
            || entry.security.as_ref().is_some_and(|(length, bytes)| bytes.len() != *length)
        {
            return Err(DirectoryUploadError::Incomplete);
        }
        entry.phase = DirectoryUploadPhase::Committed;
        Ok(DirectoryNameCapture {
            root_directory: entry.metadata.root_directory,
            attributes: entry.metadata.attributes,
            desired_access: entry.metadata.desired_access,
            name: core::mem::take(&mut entry.name),
            security_descriptor: entry.security.take().map(|(_, bytes)| bytes),
        })
    }

    /// Called before an effect whose completion cannot yet be established. Neither replay nor
    /// ABORT is admitted afterward; only an external exact completion can settle that effect.
    pub fn mark_effect_uncertain(
        &mut self,
        owner: DirectoryUploadOwner<R, D, C>,
    ) -> Result<(), DirectoryUploadError> {
        let entry = self.entry_mut(owner)?;
        if entry.phase != DirectoryUploadPhase::Committed {
            return Err(DirectoryUploadError::InvalidPhase);
        }
        entry.phase = DirectoryUploadPhase::EffectUncertain;
        Ok(())
    }

    pub fn abort(
        &mut self,
        owner: DirectoryUploadOwner<R, D, C>,
    ) -> Result<(), DirectoryUploadError> {
        let entry = self.entry_mut(owner)?;
        if entry.phase != DirectoryUploadPhase::Uploading {
            return Err(DirectoryUploadError::InvalidPhase);
        }
        entry.name.clear();
        entry.security = None;
        entry.phase = DirectoryUploadPhase::Aborted;
        Ok(())
    }

    /// Only a canonical, definite completion may retire a committed effect. A timeout or lost
    /// reply is not completion and must leave the route occupied in `EffectUncertain`.
    pub fn retire_definite(
        &mut self,
        owner: DirectoryUploadOwner<R, D, C>,
    ) -> Result<(), DirectoryUploadError> {
        let entry = self.entry_mut(owner)?;
        if !matches!(
            entry.phase,
            DirectoryUploadPhase::Committed | DirectoryUploadPhase::EffectUncertain
        ) {
            return Err(DirectoryUploadError::InvalidPhase);
        }
        entry.phase = DirectoryUploadPhase::Retired;
        Ok(())
    }

    pub fn phase(&self, owner: DirectoryUploadOwner<R, D, C>) -> Option<DirectoryUploadPhase> {
        self.entries
            .iter()
            .find(|entry| entry.owner == owner)
            .map(|entry| entry.phase)
    }

    /// Canonical completion drops only uploads owned by its exact physical dispatch.
    pub fn retire_matching(
        &mut self,
        mut matches: impl FnMut(DirectoryUploadOwner<R, D, C>) -> bool,
    ) {
        self.entries.retain(|entry| !matches(entry.owner));
    }

    fn entry_mut(
        &mut self,
        owner: DirectoryUploadOwner<R, D, C>,
    ) -> Result<&mut Entry<R, D, C>, DirectoryUploadError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.owner.route == owner.route)
            .ok_or(DirectoryUploadError::WrongOwner)?;
        if entry.owner != owner {
            return Err(DirectoryUploadError::WrongOwner);
        }
        Ok(entry)
    }
}

impl<R: Copy + Eq, D: Copy + Eq, C: Copy + Eq> Default for DirectoryNameUploads<R, D, C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "provider_directory_name_tests.rs"]
mod tests;
