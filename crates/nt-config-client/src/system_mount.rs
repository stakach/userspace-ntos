//! Checked observations of CM's mounted SYSTEM incarnation, not exclusive mount ownership.

use super::{Backend, ConfigClient, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
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

    fn system_hive_mount_call(
        &mut self,
        expected_mount: Option<SystemHiveMount>,
        expected_generation: u64,
    ) -> Result<SystemHiveMountState, i32> {
        let generation = NonZeroU64::new(expected_generation).ok_or(STATUS_INVALID_PARAMETER)?;
        let request = CmSystemHiveMountRequest {
            abi_size: core::mem::size_of::<CmSystemHiveMountRequest>() as u16,
            abi_version: CM_ABI_VERSION,
            mount: hive_mount::SYSTEM,
            _reserved: 0,
            expected_generation,
            expected_identity: expected_mount.map_or(0, |mount| mount.0.get()),
        };
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
