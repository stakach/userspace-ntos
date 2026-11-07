//! Publication of a mounted hive edit only from the exact newly anchored WAL payload.

use nt_hive_core::{
    CellId, MutableHiveSet, OwnedPreparedCreateChild, OwnedPreparedDeleteKey,
    OwnedPreparedDeleteValue, OwnedPreparedSetKeySecurity, OwnedPreparedSetValue,
};

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

/// A refused child keeps both the retained hive edit and the exact anchor receipt.
pub type HiveChildWalPublicationRefusal =
    (HiveWalPublicationError, OwnedPreparedCreateChild, AnchoredWalPublication);

/// A refused security edit retains both the prepared descriptor and anchor receipt.
pub type HiveSecurityWalPublicationRefusal =
    (HiveWalPublicationError, OwnedPreparedSetKeySecurity, AnchoredWalPublication);

/// A refused value deletion retains both the edit and the exact anchor receipt.
pub type HiveDeleteValueWalPublicationRefusal =
    (HiveWalPublicationError, OwnedPreparedDeleteValue, AnchoredWalPublication);

/// A refused key deletion retains both the edit and the exact anchor receipt.
pub type HiveDeleteKeyWalPublicationRefusal =
    (HiveWalPublicationError, OwnedPreparedDeleteKey, AnchoredWalPublication);

fn matches_exact_hive_record(
    anchored: &AnchoredWalPublication,
    record: &[u8],
    file_id: u64,
    expected_log_len: u64,
    log_path: &str,
) -> bool {
    let expected = HiveLogWalPayload { file_id, expected_log_len, path: log_path, record };
    decode_volume_wal_payload(anchored.payload()) == Ok(VolumeWalPayload::HiveLog(expected))
}

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
    if !matches_exact_hive_record(&anchored, prepared.record(), file_id, expected_log_len, log_path) {
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

/// Publish a reserved child only from its exact newly anchored hive log record.
pub fn publish_anchored_hive_child(
    set: &mut MutableHiveSet,
    mut prepared: OwnedPreparedCreateChild,
    anchored: AnchoredWalPublication,
    file_id: u64,
    expected_log_len: u64,
    log_path: &str,
) -> Result<(CellId, RegistryWalContinuation, VerifiedPairedWalSnapshot), HiveChildWalPublicationRefusal> {
    // The receipt proves a physical WAL effect already entered. A mismatched publication
    // cannot turn the child reservation back into an unentered, releasable edit.
    unsafe { prepared.mark_entered(); }
    if !matches_exact_hive_record(&anchored, prepared.record(), file_id, expected_log_len, log_path) {
        return Err((HiveWalPublicationError::WrongPayload, prepared, anchored));
    }
    let sequence = prepared.sequence();
    let child = match unsafe { set.publish_owned_create_child_unchecked(prepared, sequence) } {
        Ok(child) => child,
        Err((_, prepared)) => {
            return Err((HiveWalPublicationError::WrongHiveOwner, prepared, anchored));
        }
    };
    let (continuation, pair, _) = anchored.into_parts();
    Ok((child, continuation, pair))
}

/// Publish one key security descriptor only from its exact newly anchored hive log record.
pub fn publish_anchored_hive_security(
    set: &mut MutableHiveSet,
    mut prepared: OwnedPreparedSetKeySecurity,
    anchored: AnchoredWalPublication,
    file_id: u64,
    expected_log_len: u64,
    log_path: &str,
) -> Result<(RegistryWalContinuation, VerifiedPairedWalSnapshot), HiveSecurityWalPublicationRefusal> {
    unsafe { prepared.mark_entered(); }
    if !matches_exact_hive_record(&anchored, prepared.record(), file_id, expected_log_len, log_path) {
        return Err((HiveWalPublicationError::WrongPayload, prepared, anchored));
    }
    let sequence = prepared.sequence();
    if let Err((_, prepared)) = unsafe {
        set.publish_owned_set_key_security_unchecked(prepared, sequence)
    } {
        return Err((HiveWalPublicationError::WrongHiveOwner, prepared, anchored));
    }
    let (continuation, pair, _) = anchored.into_parts();
    Ok((continuation, pair))
}

/// Publish a value deletion only from its exact newly anchored hive log record.
pub fn publish_anchored_hive_delete_value(
    set: &mut MutableHiveSet,
    mut prepared: OwnedPreparedDeleteValue,
    anchored: AnchoredWalPublication,
    file_id: u64,
    expected_log_len: u64,
    log_path: &str,
) -> Result<(RegistryWalContinuation, VerifiedPairedWalSnapshot), HiveDeleteValueWalPublicationRefusal> {
    unsafe { prepared.mark_entered(); }
    if !matches_exact_hive_record(&anchored, prepared.record(), file_id, expected_log_len, log_path) {
        return Err((HiveWalPublicationError::WrongPayload, prepared, anchored));
    }
    let sequence = prepared.sequence();
    if let Err((_, prepared)) = unsafe { set.publish_owned_delete_value_unchecked(prepared, sequence) } {
        return Err((HiveWalPublicationError::WrongHiveOwner, prepared, anchored));
    }
    let (continuation, pair, _) = anchored.into_parts();
    Ok((continuation, pair))
}

/// Publish a leaf key deletion only from its exact newly anchored hive log record.
pub fn publish_anchored_hive_delete_key(
    set: &mut MutableHiveSet,
    mut prepared: OwnedPreparedDeleteKey,
    anchored: AnchoredWalPublication,
    file_id: u64,
    expected_log_len: u64,
    log_path: &str,
) -> Result<(RegistryWalContinuation, VerifiedPairedWalSnapshot), HiveDeleteKeyWalPublicationRefusal> {
    unsafe { prepared.mark_entered(); }
    if !matches_exact_hive_record(&anchored, prepared.record(), file_id, expected_log_len, log_path) {
        return Err((HiveWalPublicationError::WrongPayload, prepared, anchored));
    }
    let sequence = prepared.sequence();
    if let Err((_, prepared)) = unsafe { set.publish_owned_delete_key_unchecked(prepared, sequence) } {
        return Err((HiveWalPublicationError::WrongHiveOwner, prepared, anchored));
    }
    let (continuation, pair, _) = anchored.into_parts();
    Ok((continuation, pair))
}
