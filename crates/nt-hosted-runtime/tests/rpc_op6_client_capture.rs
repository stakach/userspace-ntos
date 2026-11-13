use nt_hosted_runtime::{RpcCaptureDirection, RpcClientKey, RpcOp6ClientCapture};

fn key() -> RpcClientKey {
    RpcClientKey { pid: 42, generation: 7, file_id: 0x100_0001, npfs_fid: 0x38 }
}

fn request() -> [u8; 24] {
    let mut pdu = [0u8; 24];
    pdu[0] = 5;
    pdu[2] = 0;
    pdu[8..10].copy_from_slice(&24u16.to_le_bytes());
    pdu[12..16].copy_from_slice(&91u32.to_le_bytes());
    pdu[22..24].copy_from_slice(&6u16.to_le_bytes());
    pdu
}

fn response() -> [u8; 24] {
    let mut pdu = request();
    pdu[2] = 2;
    pdu[12..16].copy_from_slice(&1u32.to_le_bytes());
    pdu
}

#[test]
fn pending_write_and_fragmented_read_pair_on_exact_client_file() {
    let mut capture = RpcOp6ClientCapture::<2>::new();
    let request = request();
    assert!(capture.stage_write(key(), 101, &request[..9]));
    assert!(capture.complete_write(key(), 101, 0, 9).is_none());
    assert!(capture.stage_write(key(), 102, &request[9..]));
    let sent = capture.complete_write(key(), 102, 0, 15).unwrap();
    assert_eq!(sent.direction, RpcCaptureDirection::Request);
    assert_eq!(sent.length, 24);
    assert_eq!(&sent.sample[..sent.sample_len], &request);
    let response = response();
    assert!(capture.read_chunk(key(), &response[..7], 0).is_none());
    let received = capture.read_chunk(key(), &response[7..], 0).unwrap();
    assert_eq!(received.direction, RpcCaptureDirection::Response);
    assert_eq!(received.call_id, 1); // Response call ID is not the pairing authority.
    assert_eq!(received.key, key());
}

#[test]
fn pending_overlap_wrong_identity_and_uncertain_terminal_do_not_publish() {
    let mut capture = RpcOp6ClientCapture::<3>::new();
    let req = request();
    assert!(capture.stage_write(key(), 100, &req));
    assert!(!capture.stage_write(key(), 101, &req));
    assert!(capture.complete_write(key(), 101, 0, 24).is_none());
    let mut wrong = key(); wrong.generation += 1;
    assert!(capture.complete_write(wrong, 100, 0, 24).is_none());
    assert!(capture.complete_write(key(), 100, 0xC000_0001, 24).is_none());
    assert!(capture.read_chunk(key(), &response(), 0).is_none());
    assert!(capture.rejected() >= 3);
}

#[test]
fn transceive_terminal_uses_success_status_not_output_byte_count() {
    let mut capture = RpcOp6ClientCapture::<1>::new();
    let req = request();
    assert!(capture.stage_transceive(key(), 77, &req));
    assert!(capture.complete_write(key(), 77, 0, 4096).is_some());
    assert!(capture.read_chunk(key(), &response(), 0).is_some());
}

#[test]
fn non_op6_request_cannot_claim_following_response() {
    let mut capture = RpcOp6ClientCapture::<1>::new();
    assert!(capture.write(key(), &request(), 0, 24).is_some());
    let mut other = request(); other[22..24].copy_from_slice(&7u16.to_le_bytes());
    assert!(capture.write(key(), &other, 0, 24).is_none());
    assert!(capture.read_chunk(key(), &response(), 0).is_none());
}

#[test]
fn exact_file_and_fid_are_both_required() {
    let mut capture = RpcOp6ClientCapture::<3>::new();
    assert!(capture.write(key(), &request(), 0, 24).is_some());
    let mut wrong_file = key(); wrong_file.file_id += 1;
    assert!(capture.read_chunk(wrong_file, &response(), 0).is_none());
    let mut wrong_fid = key(); wrong_fid.npfs_fid += 1;
    assert!(capture.read_chunk(wrong_fid, &response(), 0).is_none());
    assert!(capture.read_chunk(key(), &response(), 0).is_some());
}

#[test]
fn overlapping_requests_suppress_response_claim_until_file_cleanup() {
    let mut capture = RpcOp6ClientCapture::<1>::new();
    assert!(capture.write(key(), &request(), 0, 24).is_some());
    assert!(capture.write(key(), &request(), 0, 24).is_some());
    assert_eq!(capture.ambiguities(), 1);
    assert!(capture.read_chunk(key(), &response(), 0).is_none());
    assert!(capture.read_chunk(key(), &response(), 0).is_none());
    capture.retire_file(key().file_id);
    assert!(capture.write(key(), &request(), 0, 24).is_some());
    assert!(capture.read_chunk(key(), &response(), 0).is_some());
}

#[test]
fn full_capture_reports_overflow_and_cleanup_reuses_slot() {
    let mut capture = RpcOp6ClientCapture::<1>::new();
    assert!(capture.write(key(), &request(), 0, 24).is_some());
    let mut other = key(); other.file_id += 1;
    assert!(capture.write(other, &request(), 0, 24).is_none());
    assert_eq!(capture.overflow(), 1);
    capture.retire_file(key().file_id);
    assert!(capture.write(other, &request(), 0, 24).is_some());
}
