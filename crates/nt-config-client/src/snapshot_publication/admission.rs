//! Validate the exact still-prepared CM owner before touching a journal or snapshot device.

use crate::{
    Backend, ConfigClient, PreparedSystemHiveMutation, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use nt_config_abi::{
    hive_mount, hive_mutation_transfer, opcode, CmHiveMutationRequest, CM_ABI_VERSION,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemHiveStorageAdmissionPhase {
    Pending,
    InFlight,
    Validated,
    Taken,
}

/// Retain this object before issuing validation. A returned error permits retry or release;
/// unwind leaves InFlight and cannot implicitly release the preparation or caller.
///
/// ```compile_fail
/// use nt_config_client::{Backend, SystemHiveStorageAdmission};
/// fn duplicate<B: Backend, C>(value: SystemHiveStorageAdmission<'_, B, C>) { let _ = value.clone(); }
/// ```
#[must_use = "retain the admission until validation or explicit pre-storage release"]
pub struct SystemHiveStorageAdmission<'a, B: Backend, C> {
    client: Option<&'a mut ConfigClient<B>>,
    prepared: Option<PreparedSystemHiveMutation>,
    continuation: Option<C>,
    phase: SystemHiveStorageAdmissionPhase,
}

/// Checked prepared authority tied to the same exclusively borrowed CM connection. This is not
/// proof that a filesystem/path belongs to the hive; native storage association remains separate.
///
/// ```compile_fail
/// use nt_config_client::{Backend, ValidatedSystemHivePreparation};
/// fn duplicate<B: Backend>(value: ValidatedSystemHivePreparation<'_, B>) { let _ = value.clone(); }
/// ```
#[must_use]
pub struct ValidatedSystemHivePreparation<'a, B: Backend> {
    pub(super) client: &'a mut ConfigClient<B>,
    pub(super) prepared: PreparedSystemHiveMutation,
}

impl<'a, B: Backend> ValidatedSystemHivePreparation<'a, B> {
    /// Withdraw before storage acquisition, retaining the exact connection and preparation.
    /// This performs no abort: the caller must still complete or explicitly cancel CM work.
    pub fn into_preparation(self) -> (&'a mut ConfigClient<B>, PreparedSystemHiveMutation) {
        (self.client, self.prepared)
    }
}

impl<'a, B: Backend, C> SystemHiveStorageAdmission<'a, B, C> {
    pub fn new(
        client: &'a mut ConfigClient<B>,
        prepared: PreparedSystemHiveMutation,
        continuation: C,
    ) -> Self {
        Self {
            client: Some(client),
            prepared: Some(prepared),
            continuation: Some(continuation),
            phase: SystemHiveStorageAdmissionPhase::Pending,
        }
    }

    pub fn phase(&self) -> SystemHiveStorageAdmissionPhase {
        self.phase
    }
    pub fn continuation(&self) -> Option<&C> {
        self.continuation.as_ref()
    }

    pub fn validate(&mut self) -> Result<(), i32> {
        if self.phase != SystemHiveStorageAdmissionPhase::Pending {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.phase = SystemHiveStorageAdmissionPhase::InFlight;
        let result = self
            .client
            .as_mut()
            .expect("retained connection")
            .validate_system_hive_preparation_for_storage(
                self.prepared.as_ref().expect("retained preparation"),
            );
        self.phase = if result.is_ok() {
            SystemHiveStorageAdmissionPhase::Validated
        } else {
            SystemHiveStorageAdmissionPhase::Pending
        };
        result
    }

    pub fn take_validated(&mut self) -> Option<(ValidatedSystemHivePreparation<'a, B>, C)> {
        if self.phase != SystemHiveStorageAdmissionPhase::Validated {
            return None;
        }
        self.phase = SystemHiveStorageAdmissionPhase::Taken;
        Some((
            ValidatedSystemHivePreparation {
                client: self.client.take().expect("retained connection"),
                prepared: self.prepared.take().expect("retained preparation"),
            },
            self.continuation.take().expect("retained caller"),
        ))
    }

    /// No storage or CM mutation was issued. Return the original preparation/caller even after
    /// successful observation, but never abandon an in-flight exchange. This does not abort CM.
    pub fn release_before_storage(&mut self) -> Option<(PreparedSystemHiveMutation, C)> {
        if !matches!(
            self.phase,
            SystemHiveStorageAdmissionPhase::Pending | SystemHiveStorageAdmissionPhase::Validated
        ) {
            return None;
        }
        self.phase = SystemHiveStorageAdmissionPhase::Taken;
        self.client.take();
        Some((
            self.prepared.take().expect("retained preparation"),
            self.continuation.take().expect("retained caller"),
        ))
    }
}

impl<B: Backend> ConfigClient<B> {
    pub(crate) fn validate_system_hive_preparation_for_storage(
        &mut self,
        prepared: &PreparedSystemHiveMutation,
    ) -> Result<(), i32> {
        if prepared.lease_token == 0
            || prepared.expected_generation == 0
            || prepared.expected_generation.checked_add(1) != Some(prepared.next_generation)
            || prepared.semantic_journal_len == 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let request = CmHiveMutationRequest {
            abi_size: core::mem::size_of::<CmHiveMutationRequest>() as u16,
            abi_version: CM_ABI_VERSION,
            operation: hive_mutation_transfer::VALIDATE_PREPARED,
            mount: hive_mount::SYSTEM,
            expected_mount: prepared.mount.wire_identity(),
            expected_generation: prepared.expected_generation,
            lease_token: prepared.lease_token,
            journal_len_bytes: prepared.semantic_journal_len,
            journal_offset: u32::try_from(prepared.durable_journal.len())
                .map_err(|_| STATUS_INVALID_PARAMETER)?,
            chunk_offset: 0,
            chunk_len_bytes: 0,
        };
        let response = self.backend.call(
            opcode::CM_OP_MUTATE_SYSTEM_HIVE,
            request.as_bytes(),
            &mut [],
        );
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        if response.information != 0
            || response.detail0 != prepared.next_generation
            || response.detail1 != prepared.lease_token
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
