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
