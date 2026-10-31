use nt_process::{HandleObject, ProcessManager, PROCESS_QUERY_INFORMATION, STATUS_INVALID_HANDLE};

#[test]
fn process_query_handle_rejects_noncanonical_upper_bits_before_table_lookup() {
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let target = pm.create_process("target.exe", None, None);
    let handle = pm
        .insert_handle(
            caller,
            HandleObject::Process(target),
            PROCESS_QUERY_INFORMATION,
        )
        .unwrap();
    assert_eq!(
        pm.resolve_process_handle(caller, u64::from(handle), PROCESS_QUERY_INFORMATION),
        Ok(target)
    );
    for forged in [u64::from(handle) | 1u64 << 32, u64::from(handle) | 1u64 << 63] {
        assert_eq!(
            pm.resolve_process_handle(caller, forged, PROCESS_QUERY_INFORMATION),
            Err(STATUS_INVALID_HANDLE)
        );
    }
    assert_eq!(
        pm.resolve_process_handle(caller, u64::MAX, PROCESS_QUERY_INFORMATION),
        Ok(caller)
    );
}
