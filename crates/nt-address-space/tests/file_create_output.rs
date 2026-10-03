use nt_address_space::copy::MemoryCopyFailure;
use nt_address_space::native_output::{
    file_create_output_plan, publish_file_create_result_checked, FileCreateOutputPlan,
};

#[test]
fn completed_create_severity_controls_output_surfaces() {
    // ReactOS IopCreateFile: ordinary errors preserve outputs, warnings publish only IOSB.
    for status in [0xc000_0034, 0xc000_0005, 0xc000_0185, 0x103] {
        assert_eq!(file_create_output_plan(status), FileCreateOutputPlan::None);
        assert_eq!(publish_file_create_result_checked(u64::MAX, u64::MAX, 9, status, 7,
            |_, _| panic!("failed or pending CREATE must not store outputs")), Ok(()));
    }
    assert_eq!(file_create_output_plan(0x8000_0005), FileCreateOutputPlan::IoStatus);
    for status in [0, 0x4000_0000] {
        assert_eq!(file_create_output_plan(status), FileCreateOutputPlan::HandleAndIoStatus);
    }
}

#[test]
fn successful_create_publishes_handle_then_information_then_status() {
    let mut writes = Vec::new();
    publish_file_create_result_checked(0x1000, 0x2000, 42, 0, 3, |address, bytes| {
        writes.push((address, bytes.to_vec()));
        Ok(())
    }).unwrap();
    assert_eq!(writes, vec![
        (0x1000, 42u64.to_le_bytes().to_vec()),
        (0x2008, 3u64.to_le_bytes().to_vec()),
        (0x2000, 0u32.to_le_bytes().to_vec()),
    ]);
}

#[test]
fn warning_publishes_actual_information_and_status_without_handle() {
    let mut writes = Vec::new();
    publish_file_create_result_checked(u64::MAX, 0x2000, 0, 0x8000_0005, 17,
        |address, bytes| { writes.push((address, bytes.to_vec())); Ok(()) }).unwrap();
    assert_eq!(writes, vec![
        (0x2008, 17u64.to_le_bytes().to_vec()),
        (0x2000, 0x8000_0005u32.to_le_bytes().to_vec()),
    ]);
}

#[test]
fn first_output_failure_preserves_origin_and_accepted_prefix() {
    for failure in [MemoryCopyFailure::UserFault(0x8000_0001), MemoryCopyFailure::Retry(0xc000_009a)] {
        for failed_store in 0..3 {
            let mut accepted = Vec::new();
            let result = publish_file_create_result_checked(0x1000, 0x2000, 42, 0, 3,
                |address, bytes| {
                    if accepted.len() == failed_store { return Err(failure); }
                    accepted.push((address, bytes.to_vec()));
                    Ok(())
                });
            assert_eq!(result, Err(failure));
            assert_eq!(accepted.len(), failed_store);
            if failed_store != 0 {
                assert_eq!(accepted[0], (0x1000, 42u64.to_le_bytes().to_vec()));
            }
        }
    }
}

#[test]
fn address_overflow_cannot_publish_an_invalid_store() {
    let fault = MemoryCopyFailure::UserFault(nt_address_space::STATUS_ACCESS_VIOLATION);
    assert_eq!(publish_file_create_result_checked(u64::MAX - 6, 0x2000, 42, 0, 3,
        |_, _| panic!("invalid Handle range")), Err(fault));
    let mut writes = Vec::new();
    assert_eq!(publish_file_create_result_checked(0x1000, u64::MAX - 14, 42, 0, 3,
        |address, bytes| { writes.push((address, bytes.to_vec())); Ok(()) }), Err(fault));
    assert_eq!(writes, vec![(0x1000, 42u64.to_le_bytes().to_vec())]);
}
