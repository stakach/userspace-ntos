use std::fs;
use std::path::PathBuf;

fn source() -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::read_to_string(root.join("components/ntos-executive/src/hosted_kernel_win32k_source_ioctl.rs"))
        .expect("IOCTL source owner")
}

#[test]
fn nested_ioctl_terminal_drives_only_the_preselected_physical_work() {
    let source = source();
    let exact = source.split("unsafe fn redrive_selected_nested_terminal(").nth(1)
        .expect("exact nested IOCTL entry");
    let exact = exact.split("\n}").next().expect("entry body");
    assert!(exact.contains(".is_some_and(|key| selection.matches(key))"));
    assert!(exact.contains("NestedIoctlTerminalStep::"));
    assert!(!exact.contains("CURSOR"), "cursor must not choose a different child after park");
    let retired = exact.find("} else if done {").expect("final retirement branch");
    let settled = exact.find("NestedIoctlTerminalStep::Settled(").expect("settled receipt");
    assert!(retired < settled, "packet ACK alone cannot settle the child");
    assert!(exact.contains("if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }"),
        "unfinished Work must retain its Reply and terminal transport");
}

#[test]
fn resuming_parent_lends_its_page_only_to_the_exact_nested_ioctl_terminal() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut owner = fs::read_to_string(
        root.join("components/ntos-executive/src/component_ingress_nested.rs"),
    ).expect("retained physical parent owner");
    owner.push_str(&fs::read_to_string(
        root.join("components/ntos-executive/src/component_ingress_nested_source_ioctl.rs"),
    ).expect("source child owner"));
    let resume = fs::read_to_string(root.join("components/ntos-executive/src/win32k_glue.rs"))
        .expect("hosted provider resume");

    // The generic source redriver cannot enter while a Resuming provider owns the singleton
    // Win32k page. Selection and the full parent page must instead live with the exact parked
    // physical Reply across no-effect retries, entered effects, and uncertain completion.
    assert!(owner.contains("NestedPreEntryCheckpoint<")
        && owner.contains("NestedIoctlSelection")
        && owner.contains("SharedResumeSnapshot"),
        "RED: the retained parent row must own checkpoint, exact child and full page");
    assert!(owner.contains("select_nested_win32k_source_ioctl_terminal(")
        && owner.contains("redrive_selected_win32k_source_ioctl_terminal("),
        "RED: both existing exact-selection adapters must be used by the physical owner");
    assert!(owner.contains("acknowledge_child(")
        && owner.contains("restore_applied("),
        "packet ACK alone must never restore or retire the parent Reply");
    let provider = resume.split("pub(crate) unsafe fn resume_suspended_provider_wait_component(")
        .nth(1).expect("provider wait resume");
    let after_page = provider.split("select_and_restore_shared_resume_snapshot(")
        .nth(1).expect("parent page restore");
    let before_pump = after_page.split("component_pump_resume_provider_wait(")
        .next().expect("provider pump entry");
    assert!(before_pump.contains("nested::park_resuming_source_ioctl(")
        && before_pump.contains("nested::redrive_selected_source_ioctl_terminal(")
        && before_pump.contains("nested::restore_settled_source_ioctl_parent("),
        "RED: the selected terminal must run after the exact parent page restore and before its pump");
}
