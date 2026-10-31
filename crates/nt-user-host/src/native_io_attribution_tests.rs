use super::native_io_attribution::{NativeIoCall, NativeIoKind, NativeIoOutcome};
use nt_syscall::NativeService;

#[test]
fn captures_exact_read_write_and_completion_port_arguments() {
    let args = [0x44, 0, 0, 0x88, 0x1000, 0x2000, 4096, 0, 0];
    let read = NativeIoCall::capture(NativeService::NtReadFile, &args).unwrap();
    assert_eq!(read.kind, NativeIoKind::Read);
    assert_eq!(read.handle, 0x44);
    assert_eq!(read.requested_bytes, Some(4096));
    assert_eq!(read.iosb_address, 0x1000);
    let write = NativeIoCall::capture(NativeService::NtWriteFile, &args).unwrap();
    assert_eq!(write.kind, NativeIoKind::Write);
    assert_eq!(write.requested_bytes, Some(4096));
    let remove = NativeIoCall::capture(NativeService::NtRemoveIoCompletion, &args).unwrap();
    assert_eq!(remove.kind, NativeIoKind::RemoveCompletion);
    assert_eq!(remove.handle, 0x44);
    assert_eq!(remove.requested_bytes, None);
    assert_eq!(remove.iosb_address, 0x88);
    assert!(NativeIoCall::capture(NativeService::NtClose, &args).is_none());
}

#[test]
fn pending_never_claims_completed_bytes_or_active_wait_time() {
    let read = NativeIoCall::capture(NativeService::NtReadFile,
        &[0x44, 0, 0, 0, 0x1000, 0x2000, 512, 0, 0]).unwrap();
    assert_eq!(read.classify(0x103, Some(512), false), NativeIoOutcome::PendingAsync);
    assert_eq!(read.classify(0x103, Some(512), true), NativeIoOutcome::PendingPark);
    assert_eq!(read.classify(0xc000_0005, Some(512), false), NativeIoOutcome::Failed);
    assert_eq!(read.classify(0, Some(600), false), NativeIoOutcome::Completed(None));
    assert_eq!(read.classify(0, Some(512), false), NativeIoOutcome::Completed(Some(512)));
    assert_eq!(read.classify(0, None, false), NativeIoOutcome::Completed(None));
}

#[test]
fn completion_packet_information_is_not_mislabeled_as_file_bytes() {
    let remove = NativeIoCall::capture(NativeService::NtRemoveIoCompletion,
        &[0x55, 0x2000, 0x3000, 0x4000, 0]).unwrap();
    assert_eq!(remove.classify(0, Some(1234), false), NativeIoOutcome::Completed(Some(1234)));
    assert_eq!(remove.classify(0x103, Some(1234), true), NativeIoOutcome::PendingPark);
    assert_eq!(remove.classify(0x102, Some(1234), false), NativeIoOutcome::TimedOut);
}

#[test]
fn geometric_slow_sampling_keeps_late_calls_visible() {
    use super::native_io_attribution::sample_slow_ordinal;
    assert!(sample_slow_ordinal(1));
    assert!(sample_slow_ordinal(2));
    assert!(!sample_slow_ordinal(3));
    assert!(sample_slow_ordinal(512));
    assert!(sample_slow_ordinal(1024));
    assert!(!sample_slow_ordinal(u32::MAX));
}
