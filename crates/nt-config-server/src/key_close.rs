//! Retryable close receipts outlive key release, but occupy only reusable receipt slots.

use super::*;
use crate::key_lease::CloseAcknowledgement;
use nt_config_abi::{
    hive_key_close_disposition as disposition, hive_key_close_operation as operation,
    CmHiveKeyCloseReply, CmHiveKeyCloseRequest,
};

impl CmServer {
    pub(crate) fn op_system_hive_key_close(&mut self, input: &[u8], output: &mut [u8]) -> CmReply {
        let Some(request) = CmHiveKeyCloseRequest::from_bytes(input) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if input.len() != core::mem::size_of::<CmHiveKeyCloseRequest>()
            || request.abi_size as usize != input.len()
            || request.abi_version != CM_ABI_VERSION
            || request.mount != hive_mount::SYSTEM
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        match request.operation {
            operation::PREPARE
                if request.lease_token != 0
                    && request.receipt_bank == 0
                    && request.receipt_slot == 0
                    && request.receipt_generation == 0 => {}
            operation::ACKNOWLEDGE
                if request.lease_token == 0
                    && request.receipt_bank != 0
                    && request.receipt_generation != 0 => {}
            _ => return reply(STATUS_INVALID_PARAMETER, 0),
        }
        let size = core::mem::size_of::<CmHiveKeyCloseReply>();
        if output.len() < size {
            return reply_with_info(STATUS_BUFFER_TOO_SMALL, size as u32, 0, 0);
        }
        let mut body = CmHiveKeyCloseReply {
            abi_size: size as u16,
            abi_version: CM_ABI_VERSION,
            ..CmHiveKeyCloseReply::default()
        };
        match request.operation {
            operation::PREPARE => {
                let receipt = match self.system_key_leases.prepare_close(request.lease_token) {
                    Ok(receipt) => receipt,
                    Err(SystemKeyLeaseError::Exhausted) => {
                        return reply(STATUS_INSUFFICIENT_RESOURCES, 0);
                    }
                    Err(SystemKeyLeaseError::Invalid) => return reply(STATUS_INVALID_HANDLE, 0),
                };
                body.disposition = disposition::RETAINED;
                body.lease_token = receipt.lease_token;
                body.receipt_bank = receipt.bank;
                body.receipt_slot = receipt.slot;
                body.receipt_generation = receipt.generation;
            }
            operation::ACKNOWLEDGE => {
                body.disposition = match self.system_key_leases.acknowledge_close(
                    request.receipt_bank,
                    request.receipt_slot,
                    request.receipt_generation,
                ) {
                    Ok(CloseAcknowledgement::Acknowledged) => disposition::ACKNOWLEDGED,
                    Ok(CloseAcknowledgement::AlreadyAcknowledged) => {
                        disposition::ALREADY_ACKNOWLEDGED
                    }
                    Err(_) => return reply(STATUS_INVALID_HANDLE, 0),
                };
                body.receipt_bank = request.receipt_bank;
                body.receipt_slot = request.receipt_slot;
                body.receipt_generation = request.receipt_generation;
            }
            _ => unreachable!(),
        }
        output[..size].copy_from_slice(body.as_bytes());
        reply_with_info(
            STATUS_SUCCESS,
            size as u32,
            body.receipt_bank,
            body.receipt_generation,
        )
    }
}

#[cfg(test)]
mod tests;
