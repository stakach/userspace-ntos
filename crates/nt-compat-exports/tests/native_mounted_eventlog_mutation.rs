//! Boot119: EventLog's mounted C: file flush and EOF reset must reach the
//! opened overlay file, and the resulting size must survive close/reopen.

use nt_fs::{
    FileSystem, MemFs, FILE_END_OF_FILE_INFORMATION, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_READ_DATA, FILE_WRITE_DATA, STATUS_SUCCESS,
};

const BACKEND: &str = include_str!(
    "../../../components/ntos-executive/src/mounted_volume_backend.rs"
);

fn method_body(name: &str) -> &str {
    let marker = format!("fn {name}(");
    let tail = BACKEND.split_once(&marker).expect("mounted FSD method").1;
    tail.split_once("\n    fn ").map_or(tail, |(body, _)| body)
}

#[test]
fn mounted_eventlog_flush_and_eof_set_route_to_open_file() {
    let dispatch = BACKEND
        .split_once("fn dispatch_irp(")
        .expect("mounted FSD dispatch")
        .1
        .split_once("fn cancel_irp(")
        .expect("bounded dispatch")
        .0;
    assert!(
        dispatch.contains("IRP_MJ_FLUSH_BUFFERS => self.flush("),
        "Boot119: EventLog FlushBuffersFile fell through to invalid device request"
    );
    assert!(
        dispatch.contains("IRP_MJ_SET_INFORMATION => self.set_information("),
        "Boot119: EventLog FileEndOfFileInformation fell through to invalid device request"
    );
    let opened = method_body("opened_overlay_file");
    assert!(opened.contains("LayeredOpenSource::Overlay"));
    assert!(opened.contains("binding.overlay_open"));
    let flush = method_body("flush");
    assert!(flush.contains("opened_overlay_file(context, binding, file_id)"));
    assert!(flush.contains("writable_fs::flush(overlay_file)"));
    let set = method_body("set_information");
    assert!(set.contains("FILE_END_OF_FILE_INFORMATION"));
    assert!(set.contains("opened_overlay_file(context, binding, file_id)"));
    assert!(set.contains("writable_fs::set_information("));
    assert!(set.contains("overlay_file, parameters.info_class"));
}

#[test]
fn eventlog_eof_reset_persists_across_close_reopen_and_snapshot_restore() {
    const PATH: &str = r"\??\C:\Windows\System32\config\AppEvent.Evt";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(PATH, b"corrupt-event-log"));
    let file = fs.zw_create_file(
        PATH, FILE_READ_DATA | FILE_WRITE_DATA, 0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(file.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_flush_buffers_file(file.handle), STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(
            file.handle, FILE_END_OF_FILE_INFORMATION, &0u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    assert_eq!(fs.zw_flush_buffers_file(file.handle), STATUS_SUCCESS);
    assert_eq!(fs.zw_close(file.handle), STATUS_SUCCESS);

    let snapshot = fs.export_volume_snapshot().expect("durable overlay snapshot");
    let mut restored = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    let reopened = restored.zw_create_file(
        PATH, FILE_READ_DATA, 0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(reopened.status, STATUS_SUCCESS);
    assert_eq!(
        restored.zw_query_standard_information(reopened.handle)
            .unwrap().end_of_file,
        0
    );
}
