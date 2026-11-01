//! A native WAL continuation recheck keeps the relation publication's prepared CM mutation.
//! `DEVICE_BUSY` during admission is a pending transition, not an abort receipt.

const RELATION: &str = include_str!("../../../components/ntos-executive/src/hosted_relation_publication.rs");
const PERSISTENCE: &str = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");

#[test]
fn native_relation_admission_waits_for_exact_wal_recheck() {
    let admit = RELATION.split_once("Phase::Admit => {").expect("relation admission").1
        .split_once("Phase::Durable => {").expect("next phase").0;
    assert!(PERSISTENCE.contains("PersistenceOwner::Admitting { recheck_id, bytes }")
        && PERSISTENCE.contains("take_rechecked_wal_continuation(recheck_id)"),
        "native WAL admission retains its bytes and exact continuation recheck");
    assert!(admit.contains("owner.persistence.admitting()")
        && admit.contains("Vec::new()"),
        "a retry must consume the bytes retained by the first admission, not clone new bytes");
    assert!(admit.contains("status == nt_status::NtStatus::DEVICE_BUSY.raw() as u32")
        && admit.contains("return owner.pending()"),
        "DEVICE_BUSY must retain the prepared relation and wait for WAL recheck");
    assert!(admit.contains("owner.phase = Phase::Abort"),
        "certain admission failures still enter the real abort path");
}

#[test]
fn prepared_storage_validation_retries_busy_without_aborting_either_owner() {
    let relation_admit = RELATION.split_once("Phase::Admit => {").expect("relation admission").1
        .split_once("Phase::Durable => {").expect("next relation phase").0;
    let mutation_admit = PERSISTENCE.split_once("        Phase::Admit => {")
        .expect("registry admission").1.split_once("        Phase::Durable => {")
        .expect("next registry phase").0;
    for (name, admit) in [("relation", relation_admit), ("registry mutation", mutation_admit)] {
        let validation = admit.split_once("validate_storage(prepared)")
            .unwrap_or_else(|| panic!("{name} must validate prepared storage")).1
            .split_once("let bytes =").expect("admission bytes after validation").0;
        assert!(validation.contains("NtStatus::DEVICE_BUSY")
            && (validation.contains("return owner.pending()")
                || validation.contains("return Err(status)")),
            "{name} must retain its prepared owner when validation reports busy");
        assert!(validation.contains("Phase::Abort"),
            "{name} must still abort on a certain validation failure");
    }
}
