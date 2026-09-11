use super::*;

const TOP: u64 = 0x7fff_ffff_ffff;
const DISPATCHER: u64 = 0x8012_3000;
const STATUS_USER_APC: u32 = 0xc0;
const PAYLOAD: UserApcPayload = UserApcPayload {
    routine: 0x8014_0000,
    normal_context: 0x11,
    system_argument1: 0x22,
    system_argument2: 0x33,
};

fn live() -> [u64; 20] {
    let mut registers = core::array::from_fn(|index| 0x100 + index as u64);
    registers[0] = 0x8010_1234;
    registers[1] = 0x10_0000 - 168;
    registers[2] = 0x202;
    registers
}

fn fp() -> [u8; LEGACY_FLOATING_POINT_BYTES] {
    let mut image = [0; LEGACY_FLOATING_POINT_BYTES];
    image[..2].copy_from_slice(&0x037fu16.to_le_bytes());
    image[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    image[32..160].fill(0x5a);
    image[160..416].fill(0xa5);
    image
}

fn word(frame: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(frame[offset..offset + 8].try_into().unwrap())
}

#[test]
fn native_restores_stub_envelope_and_preserves_its_stack() {
    let live = live();
    let plan = prepare_user_apc(&live, &fp(), UserApcContinuation::NativeCall,
        DISPATCHER, PAYLOAD, STATUS_USER_APC, TOP).unwrap();
    assert_eq!(word(&plan.frame, 0xf8), live[0]);
    assert_eq!(word(&plan.frame, 0x98), live[1]);
    assert_eq!(word(&plan.frame, 0xa8), 1); // RSI: native reply envelope
    assert_eq!(word(&plan.frame, 0xc8), u64::from(STATUS_USER_APC)); // R10: MR0
    assert!(plan.frame_va + AMD64_CONTEXT_SIZE as u64 <= live[1]);
    assert_eq!(plan.frame_va & 15, 0);
    assert_eq!(word(&plan.frame, 0x90), live[4]); // RBX
    assert_eq!(word(&plan.frame, 0xd8), live[14]); // R12
    assert_eq!(plan.install.registers[0], DISPATCHER);
    assert_eq!(plan.install.registers[1], plan.frame_va);
    assert_eq!(plan.install.register_mask & ((1 << 18) | (1 << 19)), 0);
    assert!(plan.install.floating_point.is_none());
    assert!(plan.install.debug.is_none());
}

#[test]
fn fault_restores_canonical_syscall_coordinates_and_status() {
    let live = live();
    let plan = prepare_user_apc(&live, &fp(), UserApcContinuation::Fault {
        resume_ip: 0x8020_0020, resume_sp: 0x20_0000, resume_flags: 0x246,
    }, DISPATCHER, PAYLOAD, STATUS_USER_APC, TOP).unwrap();
    assert_eq!(word(&plan.frame, 0xf8), 0x8020_0020);
    assert_eq!(word(&plan.frame, 0x98), 0x20_0000);
    assert_eq!(word(&plan.frame, 0x78), u64::from(STATUS_USER_APC));
    assert_eq!(word(&plan.frame, 0x80), 0x8020_0020);
    assert_eq!(word(&plan.frame, 0xd0), 0x246);
    assert_eq!(word(&plan.frame, 0xa8), live[7]);
    assert_eq!(word(&plan.frame, 0xc8), live[12]);
    assert_eq!(plan.frame_va, 0x20_0000 - AMD64_CONTEXT_SIZE as u64);
}

#[test]
fn payload_and_legacy_floating_point_survive_context_roundtrip() {
    let registers = live();
    let image = fp();
    let plan = prepare_user_apc(&registers, &image, UserApcContinuation::NativeCall,
        DISPATCHER, PAYLOAD, STATUS_USER_APC, TOP).unwrap();
    for (offset, value) in [(0, 0x11), (8, 0x22), (16, 0x33), (24, PAYLOAD.routine)] {
        assert_eq!(word(&plan.frame, offset), value);
    }
    let context = CapturedAmd64Context { bytes: plan.frame };
    let restored = context.extract_legacy_floating_point().unwrap().unwrap();
    assert_eq!(&restored[32..416], &image[32..416]);
    assert_eq!(&restored[24..28], &image[24..28]);
    assert_eq!(registers, live());
    assert_eq!(image, fp());
}

#[test]
fn invalid_addresses_and_unsupported_flags_refuse_before_publication() {
    for dispatcher in [0, TOP + 1] {
        assert!(prepare_user_apc(&live(), &fp(), UserApcContinuation::NativeCall,
            dispatcher, PAYLOAD, STATUS_USER_APC, TOP).is_err());
    }
    for sp in [0, AMD64_CONTEXT_SIZE as u64, TOP + 1] {
        let mut live = live();
        live[1] = sp;
        assert!(prepare_user_apc(&live, &fp(), UserApcContinuation::NativeCall,
            DISPATCHER, PAYLOAD, STATUS_USER_APC, TOP).is_err());
    }
    let mut registers = live();
    registers[0] = 0;
    assert!(prepare_user_apc(&registers, &fp(), UserApcContinuation::NativeCall,
        DISPATCHER, PAYLOAD, STATUS_USER_APC, TOP).is_err());
    registers = live();
    registers[2] |= 1 << 18;
    assert_eq!(prepare_user_apc(&registers, &fp(), UserApcContinuation::NativeCall,
        DISPATCHER, PAYLOAD, STATUS_USER_APC, TOP), Err(CodecError::UnsupportedAlignmentCheck));
}
