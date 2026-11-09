use super::*;

#[test]
fn suspended_mid_pump_invocation_keeps_exact_dispatched_irp_until_one_resume() {
    let mut f = fixture();
    let prepared = f.io.prepare_external_file_irp_owned(read(&f), buffers()).unwrap();
    let id = prepared.irp_id();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let key = ExternalFileIrpPumpKey::new(&invocation, 17).unwrap();
    let stale = ExternalFileIrpPumpKey::new(&invocation, 18).unwrap();
    let suspended = invocation.suspend_for_pump(key).unwrap();
    assert_eq!(f.io.irp(id).unwrap().state, IrpState::Dispatched);
    assert!(f.io.completed_irp(id).is_none());
    assert!(f.trace.borrow().calls.is_empty());
    let suspended = suspended.resume(stale).unwrap_err();
    assert_eq!(suspended.key(), key);
    let invocation = suspended.resume(key).unwrap();
    let result = f.io.finish_external_file_irp(
        invocation.returned(ExternalFileIrpOutcome::Pending),
    ).unwrap();
    let ExternalFileIrpResult::Pending(retained) = result else {
        panic!("a resumed dispatch must retain the genuine pending IRP")
    };
    assert_eq!(retained.irp_id(), id);
    assert!(f.io.completed_irp(id).is_none());
    assert!(f.trace.borrow().calls.is_empty());
}

#[test]
fn uncertain_mid_pump_effect_fences_resume_without_fabricating_completion() {
    let mut f = fixture();
    let prepared = f.io.prepare_external_file_irp_owned(read(&f), buffers()).unwrap();
    let id = prepared.irp_id();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let key = ExternalFileIrpPumpKey::new(&invocation, 27).unwrap();
    let stale = ExternalFileIrpPumpKey::new(&invocation, 28).unwrap();
    let mut suspended = invocation.suspend_for_pump(key).unwrap();
    assert!(suspended.quarantine(stale).is_err());
    suspended.quarantine(key).unwrap();
    let suspended = suspended.resume(key).unwrap_err();
    assert_eq!(suspended.key(), key);
    let suspended = suspended.into_indeterminate(stale, NtStatus::UNSUCCESSFUL).unwrap_err();
    let report = suspended.into_indeterminate(key, NtStatus::UNSUCCESSFUL).unwrap();
    let ExternalFileIrpResult::Indeterminate { retained, .. } =
        f.io.finish_external_file_irp(report).unwrap()
    else {
        panic!("uncertain transport must remain retained")
    };
    assert!(retained.is_indeterminate());
    assert_eq!(retained.irp_id(), id);
    assert!(f.io.completed_irp(id).is_none());
    assert!(f.trace.borrow().calls.is_empty());
}
