use nt_fs::{DirectoryChange, DirectoryNotifyId, DirectoryNotifyTable};
use nt_io_manager::*;

const IRP: u64 = 71;
const TID: u64 = 17;

fn start() -> (
    DirectoryNotifyTable<u64>,
    PendingFileIoTable,
    usize,
    DirectoryNotifyId,
) {
    let mut fsd = DirectoryNotifyTable::new();
    let notify = fsd
        .register(
            9,
            r"\watch",
            nt_fs::FILE_NOTIFY_CHANGE_FILE_NAME,
            false,
            256,
            IRP,
        )
        .unwrap();
    let mut io = PendingFileIoTable::new();
    let slot = io
        .park(PendingFileIo {
            file_id: 9,
            irp_id: IRP,
            tid: TID,
            major: nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
            operation: PendingFileIoOperation::LocalDirectoryNotify(PendingLocalDirectoryNotify {
                notify_id: notify.raw(),
                status: nt_status::NtStatus::PENDING.raw() as u32,
                information: 0,
                alertable: false,
            }),
            output_va: 0x1000,
            output_len: 256,
            iosb_va: 0x2000,
            event_obj_idx: 7,
            signal_file: true,
            reply_required: true,
            reply_cap: 11,
            ..PendingFileIo::default()
        })
        .unwrap();
    (fsd, io, slot, notify)
}

fn change(fsd: &mut DirectoryNotifyTable<u64>) {
    assert_eq!(
        fsd.report_change(DirectoryChange {
            full_path: r"\watch\new.bin",
            filter: nt_fs::FILE_NOTIFY_CHANGE_FILE_NAME,
            action: nt_fs::FILE_ACTION_ADDED,
        }),
        1
    );
}

fn publish_surfaces(io: &mut PendingFileIoTable, slot: usize) {
    for flag in [
        IO_DELIVERY_IOSB_PUBLISHED,
        IO_DELIVERY_EVENT_PUBLISHED,
        IO_DELIVERY_FILE_PUBLISHED,
    ] {
        assert!(io.finish_exact(slot, IRP).is_none());
        io.mark_delivery_exact(slot, IRP, flag).unwrap();
    }
    assert_eq!(io.claim_reply_cap_exact(slot, IRP), Some(Some(11)));
    io.mark_reply_published_exact(slot, IRP).unwrap();
    assert!(io.completion_surfaces_settled_exact(slot, IRP));
}

#[test]
fn partial_copy_and_late_surface_retries_retain_exact_fsd_bytes_until_ack() {
    let (mut fsd, mut io, slot, notify) = start();
    change(&mut fsd);
    let completion = fsd.completion_exact(notify, &IRP).unwrap().unwrap();
    let bytes_pointer = completion.bytes.as_ptr();
    let information = completion.information;
    let mut output = vec![0; information as usize];
    let split = 13;
    fsd.copy_completion_bytes(notify, &IRP, 0, &mut output[..split])
        .unwrap();
    io.advance_output_exact(slot, IRP, split as u32, information)
        .unwrap();
    // A failed user copy changes no delivery progress and consumes no FSD payload.
    let mut scratch = vec![0; output.len() - split];
    fsd.copy_completion_bytes(notify, &IRP, split, &mut scratch)
        .unwrap();
    assert_eq!(io.get(slot).unwrap().output_offset, split as u32);
    assert_eq!(
        fsd.completion_exact(notify, &IRP)
            .unwrap()
            .unwrap()
            .bytes
            .as_ptr(),
        bytes_pointer
    );
    fsd.copy_completion_bytes(notify, &IRP, split, &mut output[split..])
        .unwrap();
    io.advance_output_exact(slot, IRP, scratch.len() as u32, information)
        .unwrap();
    assert!(io.complete_local_directory_notify_exact(IRP, notify.raw(), 0, information, true));
    assert_eq!(
        io.get(slot).unwrap().local_terminal_result(),
        Some((0, information as u64))
    );
    publish_surfaces(&mut io, slot);
    assert_eq!(
        output,
        fsd.completion_exact(notify, &IRP).unwrap().unwrap().bytes
    );
    assert!(fsd.acknowledge_completion(notify, &(IRP + 1)).is_err());
    assert!(io.finish_exact(slot, IRP).is_none());
    fsd.acknowledge_completion(notify, &IRP).unwrap();
    io.mark_backend_acked_exact(slot, IRP).unwrap();
    // Filesystem release can be Busy after ACK: the I/O owner, not a consumed FSD entry,
    // supplies the result on every subsequent redrive.
    for _ in 0..3 {
        assert!(fsd.completion_exact(notify, &IRP).unwrap().is_none());
        assert_eq!(
            io.get(slot).unwrap().local_terminal_result(),
            Some((0, information as u64))
        );
        assert!(io.finish_exact(slot, IRP).is_none());
    }
    io.mark_local_reference_released_exact(slot, IRP).unwrap();
    assert!(io.finish_exact(slot, IRP).is_some());
    assert!(io.finish_exact(slot, IRP).is_none());
    assert!(fsd.acknowledge_completion(notify, &IRP).is_err());
}

#[test]
fn consumer_teardown_after_change_keeps_nonempty_terminal_result_for_ack() {
    let (mut fsd, mut io, slot, notify) = start();
    change(&mut fsd);
    let information = fsd
        .completion_exact(notify, &IRP)
        .unwrap()
        .unwrap()
        .information;
    assert_eq!(io.abandon_thread_transfers_with(TID, |_| {}), 1);
    assert!(!fsd.cancel(notify)); // The real namespace result already won cancellation.
    assert!(io.complete_local_directory_notify_exact(IRP, notify.raw(), 0, information, false));
    assert!(io.completion_surfaces_settled_exact(slot, IRP));
    fsd.acknowledge_completion(notify, &IRP).unwrap();
    io.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(io.finish_exact(slot, IRP).is_none());
    io.mark_local_reference_released_exact(slot, IRP).unwrap();
    assert!(io.finish_exact(slot, IRP).unwrap().consumer_abandoned);
}

#[test]
fn cancel_and_cleanup_results_follow_the_same_retained_delivery_lifecycle() {
    for cleanup in [false, true] {
        let (mut fsd, mut io, slot, notify) = start();
        let status = if cleanup {
            assert_eq!(fsd.cleanup_file_object(9), 1);
            nt_fs::STATUS_NOTIFY_CLEANUP
        } else {
            assert!(fsd.cancel(notify));
            nt_fs::STATUS_CANCELLED
        };
        io.advance_output_exact(slot, IRP, 0, 0).unwrap();
        assert!(io.complete_local_directory_notify_exact(IRP, notify.raw(), status, 0, true));
        assert_eq!(fsd.copy_completion_bytes(notify, &IRP, 0, &mut []), Ok(0));
        publish_surfaces(&mut io, slot);
        fsd.acknowledge_completion(notify, &IRP).unwrap();
        io.mark_backend_acked_exact(slot, IRP).unwrap();
        io.mark_local_reference_released_exact(slot, IRP).unwrap();
        assert_eq!(
            io.finish_exact(slot, IRP).unwrap().local_terminal_result(),
            Some((status, 0))
        );
    }
}
