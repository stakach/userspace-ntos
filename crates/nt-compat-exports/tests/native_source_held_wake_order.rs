//! Source-side regression for a Reply that resumes the lower IRP before redrive returns.

fn assert_retained_row_is_visible_before_source_wake(source: &str) {
    let advance = source.split("unsafe fn advance(&mut self").nth(1).unwrap();
    let advance = advance.split("unsafe fn redrive_one(").next().unwrap();
    assert!(!advance.contains("runtime::wake_hosted_forward_service("),
        "Work::advance must not wake its source while WORK[index] is checked out");
    assert!(!advance.contains("runtime::wake_query_path_service("),
        "Work::advance must not wake its ACK while WORK[index] is checked out");

    let redrive = source.split("unsafe fn redrive_one(").nth(1).unwrap();
    let redrive = redrive.split("pub(super) unsafe fn redrive(").next().unwrap();
    let compact: String = redrive.chars().filter(|c| !c.is_whitespace()).collect();
    let restore = compact.find("WORK))[index]=Some(work)").unwrap();
    let clear = compact.find("EXECUTING)).pop()").unwrap();
    let wake = compact.find("wake_after_restore(wake)").unwrap();
    assert!(restore < clear && clear < wake,
        "the exact row and its executing guard must be restored before Reply can resume source op4");
}

#[test]
fn scsi_and_buffered_control_restore_owned_row_before_reply() {
    assert_retained_row_is_visible_before_source_wake(include_str!(
        "../../../components/ntos-executive/src/hosted_scsi_srb_work.rs"
    ));
    assert_retained_row_is_visible_before_source_wake(include_str!(
        "../../../components/ntos-executive/src/hosted_device_forward_work.rs"
    ));
}
