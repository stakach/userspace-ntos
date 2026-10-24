//! Publication of a mounted hive edit only from the exact newly anchored WAL payload.

use nt_hive_core::{CellId, MutableHiveSet, OwnedPreparedSetValue};

use crate::{
    decode_volume_wal_payload, AnchoredWalPublication, HiveLogWalPayload,
    RegistryWalContinuation, VerifiedPairedWalSnapshot, VolumeWalPayload,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiveWalPublicationError {
    WrongPayload,
    WrongHiveOwner,
}

/// A refusal returns both move-only owners. A physically anchored record cannot be retried
/// against a different hive or discarded as though no effect had entered.
pub type HiveWalPublicationRefusal =
    (HiveWalPublicationError, OwnedPreparedSetValue, AnchoredWalPublication);

/// Publish a pre-reserved hive edit after the newly committed WAL record crossed both native
/// snapshot header barriers. The payload must name the exact protected log file and contain the
/// exact encoded record owned by `prepared`. No scalar serial can substitute for that proof.
pub fn publish_anchored_hive_value(
    set: &mut MutableHiveSet,
    mut prepared: OwnedPreparedSetValue,
    anchored: AnchoredWalPublication,
    file_id: u64,
    expected_log_len: u64,
    log_path: &str,
) -> Result<(CellId, RegistryWalContinuation, VerifiedPairedWalSnapshot), HiveWalPublicationRefusal> {
    // An anchored receipt at this publication boundary may represent an entered effect.
    // Keep the prepared owner pinned on mismatch; pre-entry release is no longer legal.
    unsafe { prepared.mark_entered(); }
    let expected = HiveLogWalPayload {
        file_id, expected_log_len, path: log_path, record: prepared.record(),
    };
    if decode_volume_wal_payload(anchored.payload()) != Ok(VolumeWalPayload::HiveLog(expected)) {
        return Err((HiveWalPublicationError::WrongPayload, prepared, anchored));
    }
    let sequence = prepared.sequence();
    // The opaque receipt owns this exact newly marked payload and was minted only after the
    // marker and paired header write/flush terminals were acknowledged on the retained device.
    let value = match unsafe { set.publish_owned_set_value_unchecked(prepared, sequence) } {
        Ok(value) => value,
        Err((_, prepared)) => {
            return Err((HiveWalPublicationError::WrongHiveOwner, prepared, anchored));
        }
    };
    let (continuation, pair, _) = anchored.into_parts();
    Ok((value, continuation, pair))
}
