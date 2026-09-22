//! Short transport access for retained registry mutation owners.
//!
//! The caller records its in-flight phase before entering here. These adapters never infer
//! cancellation from an error, replace a captured generation, or discard a receipt.

use crate::{CONFIG_CLIENT_PTR, CONFIG_STATUS_DEVICE_NOT_READY};
use nt_config_client::*;

pub(crate) unsafe fn begin(exchange: &CmMutationBeginExchange) -> CmMutationBeginResponse {
    match CONFIG_CLIENT_PTR.as_mut() {
        Some(client) => client.exchange_system_hive_mutation_begin(exchange),
        None => CmMutationBeginResponse::transport_error(CONFIG_STATUS_DEVICE_NOT_READY),
    }
}

pub(crate) unsafe fn prepare(
    exchange: &CmMutationPreparationExchange,
) -> CmMutationPreparationResponse {
    match CONFIG_CLIENT_PTR.as_mut() {
        Some(client) => client.exchange_system_hive_mutation_preparation(exchange),
        None => CmMutationPreparationResponse::transport_error(CONFIG_STATUS_DEVICE_NOT_READY),
    }
}

pub(crate) unsafe fn commit(
    prepared: &PreparedSystemHiveMutation,
) -> Result<SystemHiveMutationCommitReceipt, i32> {
    CONFIG_CLIENT_PTR
        .as_mut()
        .ok_or(CONFIG_STATUS_DEVICE_NOT_READY)?
        .commit_system_hive_mutation_retained(prepared)
}

pub(crate) unsafe fn validate_storage(prepared: &PreparedSystemHiveMutation) -> Result<(), i32> {
    CONFIG_CLIENT_PTR
        .as_mut()
        .ok_or(CONFIG_STATUS_DEVICE_NOT_READY)?
        .validate_system_hive_preparation_for_storage(prepared)
}

pub(crate) unsafe fn acknowledge(
    receipt: SystemHiveMutationCommitReceipt,
) -> Result<SystemHiveMutationAcknowledgement, i32> {
    CONFIG_CLIENT_PTR
        .as_mut()
        .ok_or(CONFIG_STATUS_DEVICE_NOT_READY)?
        .acknowledge_system_hive_mutation_commit(receipt)
}

pub(crate) unsafe fn abort(
    prepared: &PreparedSystemHiveMutation,
) -> Result<SystemHiveMutationAbortReceipt, i32> {
    CONFIG_CLIENT_PTR
        .as_mut()
        .ok_or(CONFIG_STATUS_DEVICE_NOT_READY)?
        .abort_prepared_system_hive_mutation_retained(prepared)
}

pub(crate) unsafe fn acknowledge_abort(
    receipt: SystemHiveMutationAbortReceipt,
) -> Result<SystemHiveMutationAbortAcknowledgement, i32> {
    CONFIG_CLIENT_PTR
        .as_mut()
        .ok_or(CONFIG_STATUS_DEVICE_NOT_READY)?
        .acknowledge_system_hive_mutation_abort(receipt)
}
