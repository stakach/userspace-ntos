//! One exact prepared mutable-hive edit, shared by the Boot-route WAL journal and the native WAL
//! work. Either owner enters its record, then publishes it only against the matching anchor.

use nt_fs::{AnchoredWalPublication, RegistryWalContinuation, VerifiedPairedWalSnapshot};
use nt_hive_core::{CellId, MutableHiveSet, OwnedPreparedCreateChild, OwnedPreparedDeleteKey,
    OwnedPreparedDeleteValue, OwnedPreparedSetKeySecurity, OwnedPreparedSetValue};

pub(crate) enum PreparedEdit {
    Value(OwnedPreparedSetValue),
    Child(OwnedPreparedCreateChild),
    Security(OwnedPreparedSetKeySecurity),
    DeleteValue(OwnedPreparedDeleteValue),
    DeleteKey(OwnedPreparedDeleteKey),
}

/// Where an anchored record was written: the hive log file and its length before the record.
pub(crate) struct AnchoredRecord<'a> {
    pub(crate) anchored: AnchoredWalPublication,
    pub(crate) file_id: u64,
    pub(crate) expected_log_len: u64,
    pub(crate) log_path: &'a str,
}

/// A published edit: the created child, if any, and the continuation and paired proof that
/// its journal owner installs next.
pub(crate) type Published = (Option<CellId>, RegistryWalContinuation, VerifiedPairedWalSnapshot);

impl PreparedEdit {
    pub(crate) fn record(&self) -> &[u8] {
        match self {
            Self::Value(value) => value.record(), Self::Child(child) => child.record(),
            Self::Security(security) => security.record(),
            Self::DeleteValue(delete) => delete.record(), Self::DeleteKey(delete) => delete.record(),
        }
    }

    /// # Safety
    /// Only when the exact record may have physically entered the WAL route.
    pub(crate) unsafe fn mark_entered(&mut self) {
        match self {
            Self::Value(value) => value.mark_entered(), Self::Child(child) => child.mark_entered(),
            Self::Security(security) => security.mark_entered(),
            Self::DeleteValue(delete) => delete.mark_entered(),
            Self::DeleteKey(delete) => delete.mark_entered(),
        }
    }

    /// Release an edit none of whose record entered the WAL. A refusal returns it pinned.
    pub(crate) fn release_unentered(self, hives: &mut MutableHiveSet) -> Result<(), Self> {
        match self {
            Self::Value(prepared) => hives.release_unentered_owned_set_value(prepared)
                .map_err(|(_, prepared)| Self::Value(prepared)),
            Self::Child(prepared) => hives.release_unentered_owned_create_child(prepared)
                .map_err(|(_, prepared)| Self::Child(prepared)),
            Self::Security(prepared) => hives.release_unentered_owned_set_key_security(prepared)
                .map_err(|(_, prepared)| Self::Security(prepared)),
            Self::DeleteValue(prepared) => hives.release_unentered_owned_delete_value(prepared)
                .map_err(|(_, prepared)| Self::DeleteValue(prepared)),
            Self::DeleteKey(prepared) => hives.release_unentered_owned_delete_key(prepared)
                .map_err(|(_, prepared)| Self::DeleteKey(prepared)),
        }
    }

    /// Publish against the exact anchored record. A refusal returns both move-only owners.
    pub(crate) fn publish(self, hives: &mut MutableHiveSet, record: AnchoredRecord<'_>)
        -> Result<Published, (Self, AnchoredWalPublication)>
    {
        let AnchoredRecord { anchored, file_id, expected_log_len, log_path } = record;
        match self {
            Self::Value(prepared) => nt_fs::publish_anchored_hive_value(
                hives, prepared, anchored, file_id, expected_log_len, log_path,
            ).map(|(_, continuation, pair)| (None, continuation, pair))
                .map_err(|(_, prepared, anchored)| (Self::Value(prepared), anchored)),
            Self::Child(prepared) => nt_fs::publish_anchored_hive_child(
                hives, prepared, anchored, file_id, expected_log_len, log_path,
            ).map(|(child, continuation, pair)| (Some(child), continuation, pair))
                .map_err(|(_, prepared, anchored)| (Self::Child(prepared), anchored)),
            Self::Security(prepared) => nt_fs::publish_anchored_hive_security(
                hives, prepared, anchored, file_id, expected_log_len, log_path,
            ).map(|(continuation, pair)| (None, continuation, pair))
                .map_err(|(_, prepared, anchored)| (Self::Security(prepared), anchored)),
            Self::DeleteValue(prepared) => nt_fs::publish_anchored_hive_delete_value(
                hives, prepared, anchored, file_id, expected_log_len, log_path,
            ).map(|(continuation, pair)| (None, continuation, pair))
                .map_err(|(_, prepared, anchored)| (Self::DeleteValue(prepared), anchored)),
            Self::DeleteKey(prepared) => nt_fs::publish_anchored_hive_delete_key(
                hives, prepared, anchored, file_id, expected_log_len, log_path,
            ).map(|(continuation, pair)| (None, continuation, pair))
                .map_err(|(_, prepared, anchored)| (Self::DeleteKey(prepared), anchored)),
        }
    }
}
