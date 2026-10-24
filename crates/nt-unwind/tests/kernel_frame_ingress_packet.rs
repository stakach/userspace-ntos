//! A native frame walk begins with the exact Win64 caller state captured before a Rust prologue.

use nt_unwind::kernel_frame_ingress::{
    KernelFrameIngressPacket, FRAME_CHAIN_RESULT_CAPACITY, FRAME_INGRESS_BYTES,
    FRAME_INGRESS_MAGIC, FRAME_PACKET_BYTES, FRAME_RESULT_OFFSET,
};
use nt_unwind::StackReader;

struct LanePacket {
    base: u64,
    words: [u64; 32],
    live: bool,
}

impl StackReader for LanePacket {
    fn read_u64(&self, address: u64) -> Option<u64> {
        let index = usize::try_from(address.checked_sub(self.base)? / 8).ok()?;
        (self.live && address & 7 == 0).then(|| self.words.get(index).copied()).flatten()
    }
}

#[test]
fn packet_preserves_caller_return_slot_and_nonvolatile_unwind_state() {
    let mut words = [0u64; 32];
    words[0] = FRAME_INGRESS_MAGIC;
    words[1] = 0x2000 - 8; // address of the return slot at native function entry
    words[2] = 0x2800; // caller-owned output, never an executive pointer
    words[3] = (0x100u64 << 32) | 3; // skip one frame, request three callers
    words[4..12].copy_from_slice(&[11, 12, 13, 14, 15, 16, 17, 18]);
    for (index, word) in words[12..].iter_mut().enumerate() {
        *word = 0x1000 + index as u64;
    }

    let packet = KernelFrameIngressPacket::from_words(&words).expect("complete packet");
    assert_eq!(packet.entry_rsp(), 0x1ff8);
    assert_eq!(packet.callers(), 0x2800);
    assert_eq!(packet.count(), 3);
    assert_eq!(packet.flags(), 0x100);
    assert_eq!(packet.walk_capacity(), 4);
    assert_eq!(packet.published_result_count(0), Some(0));
    assert_eq!(packet.published_result_count(1), Some(0)); // one skipped frame
    assert_eq!(packet.published_result_count(3), Some(2));
    assert_eq!(packet.published_result_count(4), Some(3));
    assert_eq!(packet.published_result_count(5), None); // impossible reply
    assert_eq!(FRAME_RESULT_OFFSET, FRAME_INGRESS_BYTES);
    assert_eq!(FRAME_PACKET_BYTES, FRAME_RESULT_OFFSET + FRAME_CHAIN_RESULT_CAPACITY * 8);

    let context = packet.context_at_return(0x1234_5678);
    assert_eq!(context.rip, 0x1234_5678);
    assert_eq!(context.rsp(), 0x2000);
    assert_eq!(context.gpr[3], 11); // RBX
    assert_eq!(context.gpr[5], 12); // RBP
    assert_eq!(context.gpr[6], 13); // RSI
    assert_eq!(context.gpr[7], 14); // RDI
    assert_eq!(context.gpr[12..16], [15, 16, 17, 18]);
    assert_eq!(context.xmm[6], [0x1000, 0x1001]);
    assert_eq!(context.xmm[15], [0x1012, 0x1013]);
}

#[test]
fn incomplete_or_forged_packet_is_not_a_frame_source() {
    let mut words = [0u64; 32];
    words[0] = FRAME_INGRESS_MAGIC;
    words[1] = 0x1ff8;
    words[2] = 0x2800;
    words[3] = 1;
    assert!(KernelFrameIngressPacket::from_words(&words[..31]).is_none());
    words[0] ^= 1;
    assert!(KernelFrameIngressPacket::from_words(&words).is_none());
    words[0] = FRAME_INGRESS_MAGIC;
    words[1] = u64::MAX;
    assert!(KernelFrameIngressPacket::from_words(&words).is_none());
}

#[test]
fn packet_admits_bounded_user_transition_but_refuses_other_low_flags() {
    let mut words = [0u64; 32];
    words[0] = FRAME_INGRESS_MAGIC;
    words[1] = 0x1ff8;
    words[2] = 0x2800;
    words[3] = (1u64 << 32) | 1; // Native broker must still authenticate the user source.
    assert!(KernelFrameIngressPacket::from_words(&words).is_some());
    words[3] = (2u64 << 32) | 1;
    assert!(KernelFrameIngressPacket::from_words(&words).is_none());

    words[3] = (1u64 << 8 << 32) | FRAME_CHAIN_RESULT_CAPACITY as u64;
    assert!(KernelFrameIngressPacket::from_words(&words).is_none());
    words[3] = FRAME_CHAIN_RESULT_CAPACITY as u64;
    assert!(KernelFrameIngressPacket::from_words(&words).is_some());
}

#[test]
fn capture_requires_the_live_bounded_lane_and_exact_entry_layout() {
    let base = 0x1800;
    let mut lane = LanePacket { base, words: [0; 32], live: true };
    lane.words[0] = FRAME_INGRESS_MAGIC;
    lane.words[1] = base + FRAME_PACKET_BYTES as u64 + 8;
    lane.words[2] = 0x2800;
    lane.words[3] = 1;
    assert!(KernelFrameIngressPacket::capture_bounded(
        base, base, base + FRAME_PACKET_BYTES as u64 + 16, &lane
    ).is_some());

    lane.live = false; // an otherwise identical packet on a retired route has no authority
    assert!(KernelFrameIngressPacket::capture_bounded(
        base, base, base + FRAME_PACKET_BYTES as u64 + 16, &lane
    ).is_none());
    lane.live = true;
    lane.words[1] += 8; // packet no longer matches its own native ingress frame
    assert!(KernelFrameIngressPacket::capture_bounded(
        base, base, base + FRAME_PACKET_BYTES as u64 + 16, &lane
    ).is_none());
    lane.words[1] -= 8;
    assert!(KernelFrameIngressPacket::capture_bounded(
        base, base, base + FRAME_PACKET_BYTES as u64 - 8, &lane
    ).is_none()); // staged suffix is not fully inside the leased stack
}
