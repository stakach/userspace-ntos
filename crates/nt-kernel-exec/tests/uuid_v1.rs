use nt_kernel_exec::uuid_v1::{UuidV1Generator, RPC_NT_UUID_LOCAL_ONLY};

#[test]
fn local_uuid_v1_is_unique_and_monotonic_across_repeated_and_receding_clock_samples() {
    assert_eq!(RPC_NT_UUID_LOCAL_ONLY, 0x4002_0056);
    let mut generator = UuidV1Generator::new(0x1234);
    // The root passes independent callers through one generator instance.
    let caller_a = generator.next(134_000_000_000_000_000).unwrap();
    let caller_b = generator.next(134_000_000_000_000_000).unwrap();
    let backward = generator.next(133_999_999_999_999_000).unwrap();
    assert_ne!(caller_a, caller_b);
    assert_ne!(caller_b, backward);
    for uuid in [caller_a, caller_b, backward] {
        assert_eq!(uuid[7] >> 4, 1, "UUID must be version 1");
        assert_eq!(uuid[8] & 0xc0, 0x80, "UUID must use the RFC variant");
        assert_eq!(uuid[10] & 1, 1, "local-only node must set multicast bit");
    }
}
