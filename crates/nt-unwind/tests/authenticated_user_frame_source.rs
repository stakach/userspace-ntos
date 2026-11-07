//! Flags=1 needs a user source tied to the exact paused caller, not a guessed kernel address.

use nt_unwind::exception_walk::{ExceptionFunction, ExceptionImageError, ExceptionImageReader};
use nt_unwind::user_frame_source::{
    AuthenticatedUserFrameSource, UserFrameIdentity, UserFrameSnapshot, UserTrapRegisters,
};
use nt_unwind::{Context, ImageReader, RuntimeFunction, StackReader};

const USER_IMAGE: u64 = 0x500000;

struct UserImage;
impl ImageReader for UserImage {
    fn lookup_function(&self, _: u64) -> Option<(u64, RuntimeFunction)> { None }
    fn read_u8(&self, _: u64, _: u32) -> Option<u8> { None }
}
impl ExceptionImageReader for UserImage {
    fn lookup_exception_function(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
        if (USER_IMAGE..USER_IMAGE + 0x1000).contains(&pc) {
            Ok(ExceptionFunction::Leaf)
        } else {
            Err(ExceptionImageError::UnknownImage)
        }
    }
}

struct UserStack;
impl StackReader for UserStack {
    fn read_u64(&self, address: u64) -> Option<u64> {
        match address {
            0x8000 => Some(USER_IMAGE + 0x20),
            0x8008 => Some(0x4000_1000), // foreign code, never publish
            _ => None,
        }
    }
}

fn identity(generation: u64) -> UserFrameIdentity {
    UserFrameIdentity { process_generation: generation, thread_activation: 9, tcb: 77, teb: 0x6000 }
}

fn snapshot(generation: u64, rip: u64, rsp: u64, low: u64, high: u64) -> UserFrameSnapshot {
    let mut context = Context::default();
    context.rip = rip;
    context.set_rsp(rsp);
    UserFrameSnapshot { identity: identity(generation), context, teb_stack_low: low, teb_stack_high: high }
}

#[test]
fn exact_user_owner_and_admitted_image_bound_the_walk() {
    let source = AuthenticatedUserFrameSource::admit(
        identity(4),
        snapshot(4, USER_IMAGE + 0x10, 0x8000, 0x7000, 0x9000),
        0x6000, // runtime allocation base
        0x9000, // runtime stack top
        &UserImage,
    )
    .expect("same process, thread, TCB and TEB with a bounded admitted frame");
    let mut callers = [0xdead_beefu64; 3];
    let count = source.walk(&mut callers, 0, &UserImage, &UserStack).unwrap();
    assert_eq!(count, 1);
    assert_eq!(callers, [USER_IMAGE + 0x20, 0xdead_beef, 0xdead_beef]);
}

#[test]
fn stale_or_unmapped_user_source_cannot_authorize_flags_one() {
    for identity in [
        UserFrameIdentity { thread_activation: 10, ..identity(4) },
        UserFrameIdentity { tcb: 78, ..identity(4) },
        UserFrameIdentity { teb: 0x7000, ..identity(4) },
    ] {
        assert!(AuthenticatedUserFrameSource::admit(
            identity, snapshot(4, USER_IMAGE + 0x10, 0x8000, 0x7000, 0x9000),
            0x6000, 0x9000, &UserImage,
        ).is_err());
    }
    for candidate in [
        snapshot(5, USER_IMAGE + 0x10, 0x8000, 0x7000, 0x9000), // reused process
        snapshot(4, 0x4000_1000, 0x8000, 0x7000, 0x9000), // foreign PC
        snapshot(4, USER_IMAGE + 0x10, 0x5000, 0x7000, 0x9000), // bad trap RSP
        snapshot(4, USER_IMAGE + 0x10, 0x8000, 0x5000, 0x9000), // TEB outside allocation
        snapshot(4, USER_IMAGE + 0x10, 0x8000, 0x7000, 0xa000), // wrong runtime stack top
    ] {
        assert!(AuthenticatedUserFrameSource::admit(
            identity(4), candidate, 0x6000, 0x9000, &UserImage,
        ).is_err());
    }
}

#[test]
fn sel4_trap_register_projection_preserves_user_unwind_inputs() {
    // seL4_UserContext order: RIP, RSP, RFLAGS, RAX, RBX, RCX, RDX, RSI, RDI, RBP, R8..R15.
    let words = [
        USER_IMAGE + 0x10, 0x8000, 0x202, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 0,
    ];
    let context = UserTrapRegisters::from_sel4_words(&words).expect("checked saved TCB context");
    assert_eq!(context.rip, USER_IMAGE + 0x10);
    assert_eq!(context.rsp(), 0x8000);
    assert_eq!(context.gpr[0], 1); // RAX
    assert_eq!(context.gpr[1], 3); // RCX
    assert_eq!(context.gpr[2], 4); // RDX
    assert_eq!(context.gpr[3], 2); // RBX
    assert_eq!(context.gpr[4], 0x8000); // RSP
    assert_eq!(context.gpr[5], 7); // RBP
    assert_eq!(context.gpr[6], 5); // RSI
    assert_eq!(context.gpr[7], 6); // RDI
    assert_eq!(context.gpr[8..12], [8, 9, 10, 11]);
    assert_eq!(context.gpr[12..16], [12, 13, 14, 15]);
    assert!(UserTrapRegisters::from_sel4_words(&words[..19]).is_none());
    let mut empty = words;
    empty[0] = 0;
    assert!(UserTrapRegisters::from_sel4_words(&empty).is_none());
    assert!(UserTrapRegisters::exact_sel4_reply(20));
    for malformed in [0, 19, 21, (1 << 7) | 20, (1 << 12) | 20] {
        assert!(!UserTrapRegisters::exact_sel4_reply(malformed));
    }
}

#[test]
fn attached_user_continuation_publishes_trap_pc_once_and_shares_skip_budget() {
    let source = AuthenticatedUserFrameSource::admit(
        identity(4), snapshot(4, USER_IMAGE + 0x10, 0x8000, 0x7000, 0x9000),
        0x6000, 0x9000, &UserImage,
    ).unwrap();
    let mut callers = [0xdead_beefu64; 3];
    assert_eq!(source.walk_continuation(&mut callers, 0, &UserImage, &UserStack), Ok(2));
    assert_eq!(callers, [USER_IMAGE + 0x10, USER_IMAGE + 0x20, 0xdead_beef]);
    callers.fill(0xdead_beef);
    assert_eq!(source.walk_continuation(&mut callers, 1, &UserImage, &UserStack), Ok(2));
    assert_eq!(callers, [USER_IMAGE + 0x20, 0xdead_beef, 0xdead_beef]);
    callers.fill(0xdead_beef);
    assert_eq!(source.walk_continuation(&mut callers, 2, &UserImage, &UserStack), Ok(2));
    assert_eq!(callers, [0xdead_beef; 3]);
}
