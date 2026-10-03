use super::*;
use crate::rtl::exception::raw_context::RAW_CONTEXT_SIZE;
use crate::rtl::exception::{virtual_unwind, Context, ImageReader, RuntimeFunction, StackReader};
use alloc::collections::BTreeMap;

struct Image;

impl ImageReader for Image {
    fn lookup_function(&self, pc: u64) -> Option<(u64, RuntimeFunction)> {
        let function = if (0x1100..0x1200).contains(&pc) {
            function(0x100, 0x300)
        } else if (0x1400..0x1500).contains(&pc) {
            function(0x400, 0x600)
        } else {
            return None;
        };
        Some((0x1000, function))
    }

    fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
        if base != 0x1000 {
            return None;
        }
        // SAVE_XMM128 XMM6 at frame+128, PUSH_NONVOL R15, PUSH_NONVOL RBP.
        let unwind = [1, 8, 4, 0, 8, 0x68, 8, 0, 6, 0xf0, 4, 0x50];
        for start in [0x300, 0x600] {
            if let Some(offset) = rva.checked_sub(start) {
                if let Some(byte) = unwind.get(offset as usize) {
                    return Some(*byte);
                }
            }
        }
        if (0x100..0x200).contains(&rva) || (0x400..0x500).contains(&rva) {
            Some(0x90)
        } else {
            None
        }
    }
}

struct Stack(BTreeMap<u64, u64>);

impl StackReader for Stack {
    fn read_u64(&self, address: u64) -> Option<u64> {
        self.0.get(&address).copied()
    }
}

fn function(begin: u32, unwind_info: u32) -> RuntimeFunction {
    RuntimeFunction {
        begin,
        end: begin + 0x100,
        unwind_info,
    }
}

#[test]
fn completed_walk_restores_target_nonvolatiles_not_inner_or_target_caller() {
    let mut inner = Context::default();
    inner.gpr[4] = 0x8000;
    inner.gpr[5] = 0x1df61;
    inner.gpr[15] = 0x1df5b;
    inner.xmm[6] = [0x1111, 0x2222];
    inner.rip = 0x1110;
    let mut stack = Stack(BTreeMap::new());
    for (base, rbp, r15, xmm, rip) in [
        (0x8000, 0x8100, 0x8150, [0x3333, 0x4444], 0x1410),
        (0x8018, 0x9100, 0x9150, [0x5555, 0x6666], 0x1710),
    ] {
        stack.0.insert(base, r15);
        stack.0.insert(base + 8, rbp);
        stack.0.insert(base + 16, rip);
        stack.0.insert(base + 128, xmm[0]);
        stack.0.insert(base + 136, xmm[1]);
    }
    let mut restoration = RawContext::from_bytes([0xa5; RAW_CONTEXT_SIZE]);
    restoration.update_from_context(&inner);
    let mut raw_work = restoration.clone();
    let mut work = inner;
    let result = virtual_unwind(
        0,
        0x1000,
        work.rip,
        function(0x100, 0x300),
        &mut work,
        &Image,
        &stack,
    )
    .unwrap();
    assert_eq!(result.establisher_frame, 0x8000);
    assert_eq!(work.gpr[5], 0x8100);
    assert_eq!(work.gpr[15], 0x8150);
    assert_eq!(work.xmm[6], [0x3333, 0x4444]);
    // A completed termination handler may modify raw state not represented by Context.
    for (offset, byte) in raw_work.as_bytes_mut().iter_mut().enumerate() {
        if !modeled(offset) {
            *byte = (offset as u8).wrapping_mul(3).wrapping_add(7);
        }
    }
    let handler_bytes = raw_work.clone();
    raw_work.update_from_context(&work);
    for offset in 0..RAW_CONTEXT_SIZE {
        if !modeled(offset) {
            assert_eq!(
                raw_work.as_bytes()[offset],
                handler_bytes.as_bytes()[offset]
            );
        }
    }
    publish_completed_frame(&mut restoration, &raw_work);

    let target = raw_work.clone();
    let result = virtual_unwind(
        0,
        0x1000,
        work.rip,
        function(0x400, 0x600),
        &mut work,
        &Image,
        &stack,
    )
    .unwrap();
    assert_eq!(result.establisher_frame, 0x8018);
    assert_eq!(work.gpr[5], 0x9100);
    assert_eq!(work.gpr[15], 0x9150);
    assert_eq!(work.xmm[6], [0x5555, 0x6666]);
    raw_work.update_from_context(&work);
    raw_work.as_bytes_mut()[0x4a0] ^= 0xff;
    // The target's virtual pop is only a probe: do not publish its caller's context.
    assert_eq!(restoration, target);
}

fn modeled(offset: usize) -> bool {
    (0x78..0x100).contains(&offset) || (0x1a0..0x2a0).contains(&offset)
}

#[test]
fn completed_leaf_pop_publishes_stack_and_pc_without_changing_nonvolatiles() {
    let mut restoration = Context::default();
    restoration.gpr[4] = 0x8000;
    restoration.gpr[5] = 0x8100;
    restoration.gpr[15] = 0x8150;
    restoration.xmm[6] = [0x3333, 0x4444];
    restoration.rip = 0x1100;
    let mut raw_restoration = RawContext::from_bytes([0xa5; RAW_CONTEXT_SIZE]);
    raw_restoration.update_from_context(&restoration);
    let mut unwound = raw_restoration.clone();
    restoration.gpr[4] += 8;
    restoration.rip = 0x1400;
    unwound.update_from_context(&restoration);
    publish_completed_frame(&mut raw_restoration, &unwound);
    assert_eq!(raw_restoration, unwound);
}
