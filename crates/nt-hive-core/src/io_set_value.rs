//! Prepared value publication with exact write-ahead record ownership.

use super::{FlushMode, HiveIoError, HiveIoProvider, HiveManager};
use crate::{
    try_encode_log_record, CellId, Hive, HiveEncodeError, HiveLogOp, RegistryValueType,
    SetValueError,
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiveSetValueError {
    Prepare(SetValueError),
    Encode(HiveEncodeError),
    Io(HiveIoError),
    RetainedPublication,
    SequenceOverflow,
    SequenceMismatch,
    PathMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HiveSetValueReceipt {
    pub value: CellId,
    pub durable: bool,
}

impl<P: HiveIoProvider> HiveManager<P> {
    /// Prepare all live and log storage before entering the provider, then publish after ACK.
    ///
    /// The supplied relative path must identify this exact key. Provider errors retain the
    /// exact entered record on the hive, without replaying or publishing its live value. A fresh
    /// manager cannot retire that uncertainty. Strict mode requires the log durability ACK;
    /// lazy and volatile edits never claim durability in their receipt.
    pub fn try_set_value(
        &mut self,
        hive: &mut Hive,
        key: CellId,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: &[u8],
    ) -> Result<HiveSetValueReceipt, HiveSetValueError> {
        if hive.retained_value_journal().is_some() {
            return Err(HiveSetValueError::RetainedPublication);
        }
        usize::try_from(key.0)
            .map_err(|_| HiveSetValueError::Prepare(SetValueError::KeyNotFound))?;
        let volatile = hive
            .key(key)
            .ok_or(HiveSetValueError::Prepare(SetValueError::KeyNotFound))?
            .volatile;
        if hive.open_key(path) != Some(key) {
            return Err(HiveSetValueError::PathMismatch);
        }
        let next_sequence = if volatile {
            None
        } else {
            let expected_sequence = hive
                .sequence
                .checked_add(1)
                .ok_or(HiveSetValueError::SequenceOverflow)?;
            if self.next_log_sequence != expected_sequence {
                return Err(HiveSetValueError::SequenceMismatch);
            }
            Some(
                self.next_log_sequence
                    .checked_add(1)
                    .filter(|_| self.next_log_sequence != 0)
                    .ok_or(HiveSetValueError::SequenceOverflow)?,
            )
        };
        let mut owned_data = Vec::new();
        owned_data
            .try_reserve_exact(data.len())
            .map_err(|_| HiveSetValueError::Prepare(SetValueError::InsufficientResources))?;
        owned_data.extend_from_slice(data);
        let mut prepared = hive
            .try_prepare_set_value(key, name, value_type, owned_data)
            .map_err(HiveSetValueError::Prepare)?;
        let Some(next_sequence) = next_sequence else {
            return Ok(HiveSetValueReceipt {
                value: prepared.commit(),
                durable: false,
            });
        };
        let record = try_encode_log_record(
            &HiveLogOp::SetValue {
                path,
                name,
                value_type,
                data,
            },
            self.next_log_sequence,
        )
        .map_err(HiveSetValueError::Encode)?;

        // Record the entered effect before invoking a provider that may fail after writing.
        prepared.begin_journal(self.next_log_sequence, record);
        self.provider
            .append_log_record(prepared.journal_record())
            .map_err(HiveSetValueError::Io)?;
        let durable = self.flush_mode == FlushMode::Strict;
        if durable {
            prepared.enter_journal_flush();
            self.provider.flush_log().map_err(HiveSetValueError::Io)?;
        }
        let value = prepared.commit();
        hive.pending_value_journal = None;
        self.next_log_sequence = next_sequence;
        Ok(HiveSetValueReceipt { value, durable })
    }
}
