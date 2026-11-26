//! Checked observations of CM's mounted SYSTEM incarnation, not exclusive mount ownership.

use super::{
    Backend, ConfigClient, LeasedHiveKeyInformation, SystemHiveKeyLease, STATUS_DEVICE_BUSY,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use core::num::NonZeroU64;
use nt_config_abi::{hive_mount, opcode, CmSystemHiveMountRequest, CM_ABI_VERSION};

/// An opaque CM-issued mount identity. Ordinary edits preserve it; remount replaces it.
/// It is neither an authorization decision nor a pin on the current mount. Revalidate at the
/// caller's captured generation; retained mutations must separately bind their protocol ownership.
///
/// ```compile_fail
/// use nt_config_client::SystemHiveMount;
/// let forged = SystemHiveMount(7);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemHiveMount(NonZeroU64);

impl SystemHiveMount {
    /// Stable, non-authorizing identity for correlating work across ordinary hive edits.
    pub fn identity_token(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn wire_identity(self) -> u64 {
        self.0.get()
    }
}

/// One successful read-only observation. It can become stale as soon as the query completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemHiveMountState {
    mount: SystemHiveMount,
    generation: NonZeroU64,
}

impl SystemHiveMountState {
    pub fn mount(self) -> SystemHiveMount {
        self.mount
    }

    pub fn generation(self) -> u64 {
        self.generation.get()
    }
}

impl<B: Backend> ConfigClient<B> {
    /// Revalidate a retained key at one exact CM generation and mount identity.
    /// The caller must supply a generation authorized by its own publication contract;
    /// this observation does not prove physical WAL durability.
    pub fn query_leased_system_hive_key_at_exact_mount(
        &mut self,
        lease: SystemHiveKeyLease,
        mount: SystemHiveMount,
        expected_generation: u64,
    ) -> Result<LeasedHiveKeyInformation, i32> {
        if expected_generation == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let information = self.query_leased_system_hive_key_information(lease)?;
        if information.mount_generation != expected_generation {
            return Err(STATUS_DEVICE_BUSY);
        }
        self.validate_system_hive_mount(mount, expected_generation)?;
        Ok(information)
    }

    /// Discover the mount currently serving exactly the caller's semantic generation.
    /// Never use discovery to silently replace a previously retained mount identity.
    pub fn query_system_hive_mount(
        &mut self,
        expected_generation: u64,
    ) -> Result<SystemHiveMountState, i32> {
        self.system_hive_mount_call(None, expected_generation)
    }

    /// Revalidate the retained incarnation, including after a legitimate generation advance.
    pub fn validate_system_hive_mount(
        &mut self,
        mount: SystemHiveMount,
        expected_generation: u64,
    ) -> Result<SystemHiveMountState, i32> {
        self.system_hive_mount_call(Some(mount), expected_generation)
    }

    /// Observe the exact CM hive-log sequence under the retained mount and published
    /// generation. This is read-only; it is neither a storage lease nor a durability proof.
    pub fn query_system_hive_sequence_at_mount(
        &mut self,
        mount: SystemHiveMount,
        expected_generation: u64,
    ) -> Result<u64, i32> {
        let request = Self::system_hive_mount_request(Some(mount), expected_generation)?;
        let response = self.backend.call(
            opcode::CM_OP_QUERY_SYSTEM_HIVE_SEQUENCE,
            request.as_bytes(),
            &mut [],
        );
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        if response.information != 0 || response.detail0 != expected_generation {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(response.detail1)
    }

    fn system_hive_mount_request(
        expected_mount: Option<SystemHiveMount>,
        expected_generation: u64,
    ) -> Result<CmSystemHiveMountRequest, i32> {
        NonZeroU64::new(expected_generation).ok_or(STATUS_INVALID_PARAMETER)?;
        Ok(CmSystemHiveMountRequest {
            abi_size: core::mem::size_of::<CmSystemHiveMountRequest>() as u16,
            abi_version: CM_ABI_VERSION,
            mount: hive_mount::SYSTEM,
            _reserved: 0,
            expected_generation,
            expected_identity: expected_mount.map_or(0, |mount| mount.0.get()),
        })
    }

    fn system_hive_mount_call(
        &mut self,
        expected_mount: Option<SystemHiveMount>,
        expected_generation: u64,
    ) -> Result<SystemHiveMountState, i32> {
        let generation = NonZeroU64::new(expected_generation).ok_or(STATUS_INVALID_PARAMETER)?;
        let request = Self::system_hive_mount_request(expected_mount, expected_generation)?;
        let response = self.backend.call(
            opcode::CM_OP_QUERY_SYSTEM_HIVE_MOUNT,
            request.as_bytes(),
            &mut [],
        );
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        let mount =
            SystemHiveMount(NonZeroU64::new(response.detail1).ok_or(STATUS_INVALID_PARAMETER)?);
        if response.information != 0
            || response.detail0 != expected_generation
            || expected_mount.is_some_and(|expected| expected != mount)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(SystemHiveMountState { mount, generation })
    }
}

#[cfg(test)]
mod tests;
