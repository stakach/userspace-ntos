use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};

struct Scratch {
    bytes: Vec<u8>,
    released: bool,
}

impl AsRef<[u8]> for Scratch {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for Scratch {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        assert!(
            self.released,
            "scratch owner dropped without explicit release"
        );
    }
}

struct Mock {
    replies: VecDeque<Result<PropertyQueryReply, NtStatus>>,
    requests: Vec<PropertyQueryRequest>,
    shared_bank: [u8; PROPERTY_QUERY_CHUNK_BYTES],
    allocations: Vec<usize>,
    releases: usize,
    fail_allocation: bool,
    undersized_allocation: bool,
    fail_abort: bool,
}

impl Mock {
    fn new(replies: Vec<Result<PropertyQueryReply, NtStatus>>) -> Self {
        Self {
            replies: replies.into(),
            requests: Vec::new(),
            shared_bank: [0; PROPERTY_QUERY_CHUNK_BYTES],
            allocations: Vec::new(),
            releases: 0,
            fail_allocation: false,
            undersized_allocation: false,
            fail_abort: false,
        }
    }

    fn aborted(&self) -> Vec<u64> {
        self.requests
            .iter()
            .filter_map(|request| match request {
                PropertyQueryRequest::Abort { pdo, token } => {
                    assert_eq!(*pdo, 0x1000);
                    Some(*token)
                }
                _ => None,
            })
            .collect()
    }
}

impl PropertyQueryTransport for Mock {
    type Scratch = Scratch;

    fn exchange(&mut self, request: PropertyQueryRequest) -> Result<PropertyQueryReply, NtStatus> {
        self.requests.push(request);
        if matches!(request, PropertyQueryRequest::Abort { .. }) {
            return if self.fail_abort {
                Err(NtStatus::DEVICE_NOT_READY)
            } else {
                Ok(reply(0, 0, &[]))
            };
        }
        let mut result = self.replies.pop_front().expect("unexpected exchange")?;
        self.shared_bank = result.data;
        result.data.copy_from_slice(&self.shared_bank);
        Ok(result)
    }

    fn allocate(&mut self, bytes: usize) -> Option<Scratch> {
        self.allocations.push(bytes);
        self.shared_bank.fill(0xcc);
        if self.fail_allocation {
            return None;
        }
        let len = if self.undersized_allocation {
            bytes - 1
        } else {
            bytes
        };
        Some(Scratch {
            bytes: vec![0xa5; len],
            released: false,
        })
    }

    fn release(&mut self, mut scratch: Scratch) {
        assert!(!scratch.released);
        scratch.released = true;
        self.releases += 1;
        self.shared_bank.fill(0xdd);
    }
}

fn reply(total_len: u64, token: u64, bytes: &[u8]) -> PropertyQueryReply {
    let mut data = [0; PROPERTY_QUERY_CHUNK_BYTES];
    data[..bytes.len()].copy_from_slice(bytes);
    PropertyQueryReply {
        status: NtStatus::SUCCESS,
        total_len,
        token,
        chunk_len: bytes.len() as u64,
        data,
    }
}

fn run(client: &mut Mock, capacity: u32) -> PropertyQueryResult<Scratch> {
    query_device_property(client, 0x1000, 12, capacity)
}

fn assert_failure(result: PropertyQueryResult<Scratch>, status: NtStatus, required_len: u32) {
    assert_eq!(result.status, status);
    assert_eq!(result.required_len, required_len);
    assert!(result.snapshot.is_none());
}

#[test]
fn snapshot_precedes_allocator_ipc_clobber_and_requires_explicit_release() {
    let mut client = Mock::new(vec![Ok(reply(3, 0, &[1, 2, 3]))]);
    let result = run(&mut client, 8);
    assert_eq!(result.status, NtStatus::SUCCESS);
    assert_eq!(result.required_len, 3);
    let scratch = result.snapshot.unwrap();
    assert_eq!(scratch.as_ref(), &[1, 2, 3]);
    assert_eq!(client.shared_bank, [0xcc; PROPERTY_QUERY_CHUNK_BYTES]);
    assert_eq!(client.allocations, [3]);
    assert_eq!(client.releases, 0);
    assert_eq!(
        client.requests,
        [PropertyQueryRequest::Begin {
            pdo: 0x1000,
            property: 12,
            capacity: 8
        }]
    );
    client.release(scratch);
    assert_eq!(client.releases, 1);
}

#[test]
fn multi_bank_snapshot_is_collected_in_strict_monotonic_order() {
    let mut client = Mock::new(vec![
        Ok(reply(7, 42, &[1, 2])),
        Ok(reply(7, 42, &[3, 4, 5])),
        Ok(reply(7, 42, &[6, 7])),
    ]);
    let result = run(&mut client, 7);
    assert_eq!(result.status, NtStatus::SUCCESS);
    let scratch = result.snapshot.unwrap();
    assert_eq!(scratch.as_ref(), &[1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(
        &client.requests[1..],
        &[
            PropertyQueryRequest::Pull {
                pdo: 0x1000,
                token: 42,
                offset: 2
            },
            PropertyQueryRequest::Pull {
                pdo: 0x1000,
                token: 42,
                offset: 5
            },
        ]
    );
    assert_eq!(client.allocations, [7]);
    assert!(client.aborted().is_empty());
    client.release(scratch);
}

#[test]
fn zero_length_success_needs_no_scratch_or_token() {
    let mut client = Mock::new(vec![Ok(reply(0, 0, &[]))]);
    let result = run(&mut client, 0);
    assert_eq!(result.status, NtStatus::SUCCESS);
    assert_eq!(result.required_len, 0);
    assert!(result.snapshot.is_none());
    assert!(client.allocations.is_empty());
    assert!(client.aborted().is_empty());
}

#[test]
fn non_success_begin_preserves_status_length_and_aborts_decoded_token() {
    for status in [
        NtStatus::BUFFER_TOO_SMALL,
        NtStatus::ACCESS_DENIED,
        NtStatus::PENDING,
    ] {
        let mut first = reply(19, 42, &[]);
        first.status = status;
        first.chunk_len = u64::MAX;
        let mut client = Mock::new(vec![Ok(first)]);
        assert_failure(run(&mut client, 0), status, 19);
        assert_eq!(client.aborted(), [42]);
        assert!(client.allocations.is_empty());
    }
}

#[test]
fn unrepresentable_begin_length_is_rejected_and_token_aborted() {
    for status in [NtStatus::SUCCESS, NtStatus::BUFFER_TOO_SMALL] {
        let mut first = reply(u64::from(u32::MAX) + 1, 42, &[1]);
        first.status = status;
        let mut client = Mock::new(vec![Ok(first)]);
        assert_failure(run(&mut client, u32::MAX), NtStatus::INVALID_PARAMETER, 0);
        assert_eq!(client.aborted(), [42]);
        assert!(client.allocations.is_empty());
    }
}

#[test]
fn oversized_success_reports_required_length_without_allocation() {
    let mut client = Mock::new(vec![Ok(reply(9, 42, &[1, 2]))]);
    assert_failure(run(&mut client, 8), NtStatus::BUFFER_TOO_SMALL, 9);
    assert_eq!(client.aborted(), [42]);
    assert!(client.allocations.is_empty());
}

#[test]
fn malformed_begin_chunks_and_tokens_never_allocate() {
    for (total, token, chunk) in [
        (3, 42, 4),
        (1000, 42, 929),
        (3, 42, 0),
        (3, 0, 1),
        (3, 42, 3),
        (0, 42, 0),
        (0, 0, 1),
    ] {
        let mut first = reply(total, token, &[]);
        first.chunk_len = chunk;
        let mut client = Mock::new(vec![Ok(first)]);
        assert_failure(
            run(&mut client, 1000),
            NtStatus::INVALID_PARAMETER,
            total as u32,
        );
        assert_eq!(
            client.aborted(),
            if token == 0 { vec![] } else { vec![token] }
        );
        assert!(client.allocations.is_empty());
        assert_eq!(client.releases, 0);
    }
}

#[test]
fn allocator_exhaustion_aborts_without_pulling_or_publishing() {
    let mut client = Mock::new(vec![Ok(reply(3, 42, &[1]))]);
    client.fail_allocation = true;
    assert_failure(run(&mut client, 3), NtStatus::INSUFFICIENT_RESOURCES, 3);
    assert_eq!(client.allocations, [3]);
    assert_eq!(client.aborted(), [42]);
    assert_eq!(client.requests.len(), 2);
    assert_eq!(client.releases, 0);
}

#[test]
fn undersized_scratch_is_explicitly_released_before_failure_return() {
    let mut client = Mock::new(vec![Ok(reply(3, 42, &[1]))]);
    client.undersized_allocation = true;
    assert_failure(run(&mut client, 3), NtStatus::INSUFFICIENT_RESOURCES, 3);
    assert_eq!(client.aborted(), [42]);
    assert_eq!(client.releases, 1);
}

#[test]
fn malformed_pull_aborts_original_token_and_releases_partial_snapshot() {
    for (total, token, chunk) in [
        (4, 42, 1),
        (3, 43, 1),
        (3, 0, 1),
        (3, 42, 0),
        (3, 42, 3),
        (3, 42, 929),
        (u64::MAX, 42, 1),
    ] {
        let mut pull = reply(total, token, &[]);
        pull.chunk_len = chunk;
        let mut client = Mock::new(vec![Ok(reply(3, 42, &[1])), Ok(pull)]);
        assert_failure(run(&mut client, 3), NtStatus::INVALID_PARAMETER, 3);
        assert_eq!(client.aborted(), [42]);
        assert_eq!(client.releases, 1);
    }
}

#[test]
fn pull_cannot_exceed_bank_even_when_remaining_length_allows_it() {
    let mut pull = reply(2000, 42, &[]);
    pull.chunk_len = 929;
    let mut client = Mock::new(vec![Ok(reply(2000, 42, &[1])), Ok(pull)]);
    assert_failure(run(&mut client, 2000), NtStatus::INVALID_PARAMETER, 2000);
    assert_eq!(client.aborted(), [42]);
    assert_eq!(client.releases, 1);
}

#[test]
fn genuine_pull_error_wins_over_malformed_envelope_and_cleanup_failure() {
    let mut pull = reply(u64::MAX, 77, &[]);
    pull.status = NtStatus::ACCESS_DENIED;
    let mut client = Mock::new(vec![Ok(reply(3, 42, &[1])), Ok(pull)]);
    client.fail_abort = true;
    assert_failure(run(&mut client, 3), NtStatus::ACCESS_DENIED, 3);
    assert_eq!(client.aborted(), [42]);
    assert_eq!(client.releases, 1);
}

#[test]
fn transport_failure_before_begin_has_no_retained_resources() {
    let mut client = Mock::new(vec![Err(NtStatus::DEVICE_NOT_READY)]);
    assert_failure(run(&mut client, 3), NtStatus::DEVICE_NOT_READY, 0);
    assert!(client.aborted().is_empty());
    assert!(client.allocations.is_empty());
}

#[test]
fn transport_failure_after_pull_aborts_and_releases() {
    let mut client = Mock::new(vec![
        Ok(reply(3, 42, &[1])),
        Err(NtStatus::DEVICE_NOT_READY),
    ]);
    assert_failure(run(&mut client, 3), NtStatus::DEVICE_NOT_READY, 3);
    assert_eq!(client.aborted(), [42]);
    assert_eq!(client.releases, 1);
}

#[test]
fn contradictory_transport_success_error_is_never_published_as_success() {
    let mut begin = Mock::new(vec![Err(NtStatus::SUCCESS)]);
    assert_failure(run(&mut begin, 3), NtStatus::INVALID_PARAMETER, 0);
    let mut pull = Mock::new(vec![Ok(reply(3, 42, &[1])), Err(NtStatus::SUCCESS)]);
    assert_failure(run(&mut pull, 3), NtStatus::INVALID_PARAMETER, 3);
    assert_eq!(pull.aborted(), [42]);
    assert_eq!(pull.releases, 1);
}

#[test]
fn failure_after_multiple_valid_chunks_never_returns_partial_output() {
    let mut client = Mock::new(vec![
        Ok(reply(7, 42, &[1, 2])),
        Ok(reply(7, 42, &[3, 4])),
        Ok(reply(7, 42, &[5, 6])),
        Ok(reply(7, 42, &[])),
    ]);
    assert_failure(run(&mut client, 7), NtStatus::INVALID_PARAMETER, 7);
    assert_eq!(client.aborted(), [42]);
    assert_eq!(client.releases, 1);
    assert_eq!(
        client.requests[3],
        PropertyQueryRequest::Pull {
            pdo: 0x1000,
            token: 42,
            offset: 6
        }
    );
}

#[test]
fn u32_max_required_length_does_not_truncate_or_attempt_pull_on_exhaustion() {
    let mut client = Mock::new(vec![Ok(reply(u64::from(u32::MAX), 42, &[1]))]);
    client.fail_allocation = true;
    assert_failure(
        run(&mut client, u32::MAX),
        NtStatus::INSUFFICIENT_RESOURCES,
        u32::MAX,
    );
    assert_eq!(client.allocations, [u32::MAX as usize]);
    assert_eq!(client.aborted(), [42]);
}
