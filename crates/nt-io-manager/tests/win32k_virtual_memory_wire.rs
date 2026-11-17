use nt_io_manager::win32k_virtual_memory_wire::{VirtualMemoryRequest, VirtualMemoryWireError};

#[test]
fn every_request_round_trips_through_four_words() {
    for request in [
        VirtualMemoryRequest::Secure {
            address: 0x7ff0_0001_0000,
            size: 0x80,
            protection: 0x04,
        },
        VirtualMemoryRequest::Unsecure { handle: 9 },
        VirtualMemoryRequest::Allocate {
            base: 0,
            size: 0x1_0000,
            allocation_type: 0x2000,
            protection: 0x04,
        },
        VirtualMemoryRequest::Allocate {
            base: 0x3000_0000,
            size: 0x1000,
            allocation_type: 0x1000,
            protection: 0x02,
        },
        VirtualMemoryRequest::Free {
            base: 0x3000_0000,
            size: 0,
            free_type: 0x8000,
        },
    ] {
        assert_eq!(VirtualMemoryRequest::decode(request.encode()), Ok(request));
    }
}

#[test]
fn malformed_and_unknown_requests_are_refused() {
    assert_eq!(
        VirtualMemoryRequest::decode([0, 0, 0, 0]),
        Err(VirtualMemoryWireError::UnknownOperation)
    );
    assert_eq!(
        VirtualMemoryRequest::decode([5, 0, 0, 0]),
        Err(VirtualMemoryWireError::UnknownOperation)
    );
    assert_eq!(
        VirtualMemoryRequest::decode([1, 0x1000, 0x1000, 1 << 32]),
        Err(VirtualMemoryWireError::Malformed)
    );
    assert_eq!(
        VirtualMemoryRequest::decode([2, 9, 1, 0]),
        Err(VirtualMemoryWireError::Malformed)
    );
    assert_eq!(
        VirtualMemoryRequest::decode([4, 0x1000, 0, 1 << 32]),
        Err(VirtualMemoryWireError::Malformed)
    );
}
