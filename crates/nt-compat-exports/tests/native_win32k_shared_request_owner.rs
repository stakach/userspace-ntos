//! A parked callback's immutable request identity comes from its retained owner, even when
//! another native dispatch has reused the one physical Win32k request page.

#[path = "../../../components/ntos-executive/src/win32k_shared_request_owner.rs"]
mod shared_request_owner;

use shared_request_owner::{canonicalize, RequestOwner, WORDS};

#[test]
fn nested_dispatch_cannot_replace_the_parked_callbacks_request_identity() {
    let mut observed = [0u64; WORDS];
    observed[7] = 0xfeed; // mutable request state retained from the parked component
    observed[0] = 0x1076; // nested dispatch's syscall number
    observed[20] = 0; // native callback cleared PID
    observed[25] = 0; // native callback cleared TID
    observed[37] = 0; // native callback cleared hosted generation
    let owner = RequestOwner {
        ssn: 0x10fa, pid: 212, pi: 16, tid: 292, generation: 11,
        token_auth: 0x1234, token_sid_len: 28, token_sid_ptr: 0x8000,
    };
    canonicalize(&mut observed, owner);
    assert_eq!(observed[0], 0x10fa);
    assert_eq!(observed[20], 212);
    assert_eq!(observed[22], 16);
    assert_eq!(observed[25], 292);
    assert_eq!(observed[29], 0x1234);
    assert_eq!(observed[30], 28);
    assert_eq!(observed[31], 0x8000);
    assert_eq!(observed[37], 11);
    assert_eq!(observed[7], 0xfeed);
}
