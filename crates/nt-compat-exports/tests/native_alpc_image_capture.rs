//! ALPC port names may be static strings in a newly mapped SEC_IMAGE view. The
//! kernel must fault in that exact view before copying the caller's bytes.

#[test]
fn alpc_connect_reads_the_callers_image_through_the_residency_path() {
    let alpc = include_str!("../../../components/ntos-executive/src/native_alpc_connect_accept_work.rs");
    let connect = alpc
        .split_once("pub(crate) unsafe fn begin_connect(")
        .expect("native ALPC connect entry")
        .1
        .split_once("pub(crate) unsafe fn begin_accept(")
        .expect("native ALPC accept entry")
        .0;
    let capture = connect
        .split_once("capture_connect_port(args,")
        .expect("connect input capture")
        .1
        .split_once("if captured.timeout.is_some()")
        .expect("end of connect input capture")
        .0;
    assert!(capture.contains("process_memory_read_status("),
        "ALPC capture must fault in an exact mapped image view before reading its port name");
    assert!(!capture.contains("xas_read("),
        "the legacy PE fallback does not know dynamically mapped image views");

    let copy = include_str!("../../../components/ntos-executive/src/exec_virtual_memory_copy.rs");
    let reader = copy
        .split_once("unsafe fn copy_read_page(")
        .expect("page reader")
        .1
        .split_once("unsafe fn copy_write_page(")
        .expect("end of page reader")
        .0;
    assert!(reader.contains("self.prepare_copy_page(pi, address, FaultAccess::Read)?"));
    assert!(reader.contains("client_copyin_process_mapped_for("));
}
