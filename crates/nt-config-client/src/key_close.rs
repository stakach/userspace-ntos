//! A close receipt proves release independently of whether either IPC reply was observed.

use crate::{Backend, ConfigClient, SystemHiveKeyLease, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use nt_config_abi::{
    hive_key_close_disposition as disposition, hive_key_close_operation as operation, hive_mount,
    opcode, CmHiveKeyCloseReply, CmHiveKeyCloseRequest, CM_ABI_VERSION,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "retain the exact receipt until acknowledged"]
pub struct SystemHiveKeyCloseReceipt {
    lease_token: u64,
    bank: u64,
    slot: u64,
    generation: u64,
}

impl SystemHiveKeyCloseReceipt {
    pub const fn lease_token(self) -> u64 {
        self.lease_token
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemHiveKeyCloseAcknowledgement {
    Acknowledged,
    AlreadyAcknowledged,
}

impl<B: Backend> ConfigClient<B> {
    /// On an uncertain reply repeat PREPARE with the same lease. Once this returns a receipt, retain
    /// it before sending ACK; later retries must use that receipt, not restart the close.
    pub fn prepare_system_hive_key_close(
        &mut self,
        lease: SystemHiveKeyLease,
    ) -> Result<SystemHiveKeyCloseReceipt, i32> {
        if lease.token == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let body = self.exchange_system_hive_key_close(CmHiveKeyCloseRequest {
            operation: operation::PREPARE,
            lease_token: lease.token,
            ..CmHiveKeyCloseRequest::default()
        })?;
        if body.disposition != disposition::RETAINED || body.lease_token != lease.token {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(SystemHiveKeyCloseReceipt {
            lease_token: lease.token,
            bank: body.receipt_bank,
            slot: body.receipt_slot,
            generation: body.receipt_generation,
        })
    }

    /// ACK may be repeated after an uncertain response, including after the receipt slot is reused.
    /// Only these two explicit outcomes prove acknowledgement. INVALID_HANDLE is never success.
    pub fn acknowledge_system_hive_key_close(
        &mut self,
        receipt: SystemHiveKeyCloseReceipt,
    ) -> Result<SystemHiveKeyCloseAcknowledgement, i32> {
        let body = self.exchange_system_hive_key_close(CmHiveKeyCloseRequest {
            operation: operation::ACKNOWLEDGE,
            receipt_bank: receipt.bank,
            receipt_slot: receipt.slot,
            receipt_generation: receipt.generation,
            ..CmHiveKeyCloseRequest::default()
        })?;
        if body.lease_token != 0
            || body.receipt_bank != receipt.bank
            || body.receipt_slot != receipt.slot
            || body.receipt_generation != receipt.generation
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        match body.disposition {
            disposition::ACKNOWLEDGED => Ok(SystemHiveKeyCloseAcknowledgement::Acknowledged),
            disposition::ALREADY_ACKNOWLEDGED => {
                Ok(SystemHiveKeyCloseAcknowledgement::AlreadyAcknowledged)
            }
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    fn exchange_system_hive_key_close(
        &mut self,
        mut request: CmHiveKeyCloseRequest,
    ) -> Result<CmHiveKeyCloseReply, i32> {
        request.abi_size = core::mem::size_of::<CmHiveKeyCloseRequest>() as u16;
        request.abi_version = CM_ABI_VERSION;
        request.mount = hive_mount::SYSTEM;
        let mut output = [0u8; core::mem::size_of::<CmHiveKeyCloseReply>()];
        let response = self.backend.call(
            opcode::CM_OP_SYSTEM_HIVE_KEY_CLOSE,
            request.as_bytes(),
            &mut output,
        );
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        if response.information as usize != output.len() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let body = CmHiveKeyCloseReply::from_bytes(&output).ok_or(STATUS_INVALID_PARAMETER)?;
        if body.abi_size as usize != output.len()
            || body.abi_version != CM_ABI_VERSION
            || body.reserved != 0
            || body.receipt_bank == 0
            || body.receipt_generation == 0
            || response.detail0 != body.receipt_bank
            || response.detail1 != body.receipt_generation
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests;
