use super::*;

fn write_function(img: &mut MockImage, rva: u32, begin: u32, end: u32, unwind_info: u32) {
    img.write(rva, &begin.to_le_bytes());
    img.write(rva + 4, &end.to_le_bytes());
    img.write(rva + 8, &unwind_info.to_le_bytes());
}

fn run(
    img: &MockImage,
    pc_rva: u32,
    handler_type: u8,
    ctx: &mut Context,
    stack: &dyn StackReader,
) -> Option<UnwindResult> {
    let pc = img.base + u64::from(pc_rva);
    let (base, func) = img.lookup_function(pc)?;
    virtual_unwind(handler_type, base, pc, func, ctx, img, stack)
}

#[test]
fn primary_handler_and_data_survive_odd_padded_chain() {
    for flags in [1, 2, 3] {
        for requested in [0, 1, 2, 3] {
            let mut img = img_with_unwind(&[4, 0x12], 0x21, 8, 1, 0);
            write_function(&mut img, 0x2008, 0x800, 0x900, 0x2100);
            img.write(0x2100, &[1 | flags << 3, 8, 1, 0, 1, 0x30]);
            img.write(0x2108, &0x3000u32.to_le_bytes());
            let mut stack = MockStack::new();
            stack.put(0x9010, 0x1234);
            stack.put(0x9018, 0x1400_2222);
            let mut ctx = Context::default();
            ctx.set_rsp(0x9000);
            let result = run(&img, 0x1050, requested, &mut ctx, &stack).unwrap();
            assert_eq!(ctx.gpr[REG_RBX], 0x1234);
            assert_eq!(ctx.rip, 0x1400_2222);
            assert_eq!(ctx.rsp(), 0x9020);
            assert_eq!(result.establisher_frame, 0x9000);
            let has_handler = flags & requested != 0;
            assert_eq!(result.handler_rva, if has_handler { 0x3000 } else { 0 });
            assert_eq!(
                result.handler_data_rva,
                if has_handler { 0x210c } else { 0 }
            );
        }
    }
}

#[test]
fn handler_and_code_admission_use_primary_prologue_offset() {
    for chained in [false, true] {
        let mut img = img_with_unwind(&[], 0x21, 0, 0, 0);
        if chained {
            write_function(&mut img, 0x2004, 0x1000, 0x1100, 0x2100);
        } else {
            img.set_pdata(vec![RuntimeFunction {
                begin: 0x1000,
                end: 0x1100,
                unwind_info: 0x2100,
            }]);
        }
        img.write(0x2100, &[0x09, 8, 1, 0, 4, 0x12]);
        img.write(0x2108, &0x3000u32.to_le_bytes());
        let mut stack = MockStack::new();
        stack.put(0x9000, 0x1400_2222);
        stack.put(0x9010, 0x1400_3333);
        for offset in [0, 2, 4, 7, 8, 9] {
            let mut ctx = Context::default();
            ctx.set_rsp(0x9000);
            let result = run(&img, 0x1000 + offset, 1, &mut ctx, &stack).unwrap();
            assert_eq!(ctx.rsp(), if offset >= 4 { 0x9018 } else { 0x9008 });
            assert_eq!(
                ctx.rip,
                if offset >= 4 {
                    0x1400_3333
                } else {
                    0x1400_2222
                }
            );
            assert_eq!(result.handler_rva, if offset >= 8 { 0x3000 } else { 0 });
        }
    }
}

#[test]
fn secondary_prologue_uses_established_frame_and_primary_handler() {
    let mut img = img_with_unwind(&[], 0x21, 16, 0, 0x25);
    write_function(&mut img, 0x2004, 0x800, 0x900, 0x2100);
    img.write(0x2100, &[0x09, 8, 1, 0x25, 4, 3]); // SET_FPREG in primary prologue
    img.write(0x2108, &0x3000u32.to_le_bytes());
    let mut stack = MockStack::new();
    stack.put(0x9000, 0x1400_2222);
    let mut ctx = Context::default();
    ctx.set_rsp(0x8000); // dynamic allocation below the established frame
    ctx.gpr[REG_RBP] = 0x9020;
    let result = run(&img, 0x1002, 1, &mut ctx, &stack).unwrap();
    assert_eq!(result.establisher_frame, 0x9000);
    assert_eq!(result.handler_rva, 0x3000);
    assert_eq!(ctx.rsp(), 0x9008);
}

#[test]
fn fragmented_primary_can_follow_the_original_control_pc() {
    let mut img = img_with_unwind(&[], 0x21, 0, 0, 0);
    write_function(&mut img, 0x2004, 0x1200, 0x1300, 0x2100);
    img.write(0x2100, &[0x09, 8, 1, 0, 4, 0x12]);
    img.write(0x2108, &0x3000u32.to_le_bytes());
    let mut stack = MockStack::new();
    stack.put(0x9010, 0x1400_2222);
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    let result = run(&img, 0x1050, 1, &mut ctx, &stack).unwrap();
    assert_eq!(result.handler_rva, 0x3000);
    assert_eq!(ctx.rip, 0x1400_2222);
    assert_eq!(ctx.rsp(), 0x9018);
}

#[test]
fn nested_chain_resolves_indirect_runtime_functions_at_both_entry_points() {
    let mut img = img_with_unwind(&[4, 0x12], 0x21, 8, 1, 0);
    img.set_pdata(vec![RuntimeFunction {
        begin: 0x1000,
        end: 0x1100,
        unwind_info: 0x3001,
    }]);
    write_function(&mut img, 0x3000, 0x800, 0x900, 0x2000);
    write_function(&mut img, 0x2008, 0x600, 0x700, 0x3101);
    write_function(&mut img, 0x3100, 0x600, 0x700, 0x2100);
    img.write(0x2100, &[0x21, 8, 1, 0, 4, 0x02]); // another 8-byte allocation
    write_function(&mut img, 0x2108, 0x400, 0x500, 0x2200);
    img.write(0x2200, &[0x09, 0, 0, 0]);
    img.write(0x2204, &0x3500u32.to_le_bytes());
    let mut stack = MockStack::new();
    stack.put(0x9018, 0x1400_2222);
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    let result = run(&img, 0x1050, 1, &mut ctx, &stack).unwrap();
    assert_eq!(result.handler_rva, 0x3500);
    assert_eq!(result.handler_data_rva, 0x2208);
    assert_eq!(result.establisher_frame, 0x9000);
    assert_eq!(ctx.rip, 0x1400_2222);
    assert_eq!(ctx.rsp(), 0x9020);
}

#[test]
fn primary_machine_frame_never_pops_the_restored_stack() {
    for error_code in [0u8, 1] {
        let mut img = img_with_unwind(&[4, 0x12], 0x21, 8, 1, 0);
        write_function(&mut img, 0x2008, 0x800, 0x900, 0x2100);
        img.write(0x2100, &[0x09, 8, 1, 0, 1, 0x0a | error_code << 4]);
        img.write(0x2108, &0x3000u32.to_le_bytes());
        let frame = 0x9010 + u64::from(error_code) * 8;
        let mut stack = MockStack::new();
        stack.put(frame, 0x1400_2222);
        stack.put(frame + 0x18, 0xa000); // no readable memory at the restored stack
        let stack = BoundedStack::new(&stack, 0x9000, 0x9040).unwrap();
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        let result = run(&img, 0x1050, 1, &mut ctx, &stack).unwrap();
        assert_eq!(ctx.rip, 0x1400_2222);
        assert_eq!(ctx.rsp(), 0xa000);
        assert_eq!(result.handler_rva, 0x3000);
    }
}

#[test]
fn malformed_machine_frame_placement_fails_even_before_it_executes() {
    for (flags, codes, count) in [(1, vec![1, 0x0a, 0, 0x02], 2), (0x21, vec![1, 0x0a], 1)] {
        let img = img_with_unwind(&codes, flags, 8, count, 0);
        for pc in [0x1000, 0x1050] {
            let mut stack = MockStack::new();
            stack.put(0x9000, 0x1400_2222);
            stack.put(0x9018, 0xa000);
            let mut ctx = Context::default();
            ctx.set_rsp(0x9000);
            let before = ctx;
            assert_eq!(run(&img, pc, 0, &mut ctx, &stack), None);
            assert_eq!(ctx, before);
        }
    }
}

#[test]
fn chain_cycles_are_bounded_and_restore_the_original_context() {
    for kind in 0..3 {
        let mut img = img_with_unwind(&[1, 0x02], 0x21, 8, 1, 0);
        match kind {
            0 => write_function(&mut img, 0x2008, 0x800, 0x900, 0x2000),
            1 => {
                write_function(&mut img, 0x2008, 0x800, 0x900, 0x3001);
                write_function(&mut img, 0x3000, 0x800, 0x900, 0x3101);
                write_function(&mut img, 0x3100, 0x800, 0x900, 0x3001);
            }
            _ => {
                write_function(&mut img, 0x2008, 0x800, 0x900, 0x3001);
                write_function(&mut img, 0x3000, 0x800, 0x900, 0x2000);
            }
        }
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        let before = ctx;
        assert_eq!(run(&img, 0x1050, 0, &mut ctx, &MockStack::new()), None);
        assert_eq!(ctx, before);
    }
}

#[test]
fn direct_and_indirect_links_share_one_budget() {
    for links in [31u32, 32, 33] {
        let mut img = img_with_unwind(&[], 1, 0, 0, 0);
        let mut rva = 0x2000;
        for pair in 0..links / 2 {
            img.write(rva, &[0x21, 0, 0, 0]);
            let indirect = 0x4000 + pair * 0x20;
            write_function(&mut img, rva + 4, 0x800, 0x900, indirect | 1);
            write_function(&mut img, indirect, 0x800, 0x900, rva + 0x20);
            rva += 0x20;
        }
        if links & 1 != 0 {
            img.write(rva, &[0x21, 0, 0, 0]);
            write_function(&mut img, rva + 4, 0x800, 0x900, rva + 0x20);
            rva += 0x20;
        }
        img.write(rva, &[1, 0, 0, 0]);
        let mut stack = MockStack::new();
        stack.put(0x9000, 0x1400_2222);
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        let before = ctx;
        let result = run(&img, 0x1050, 0, &mut ctx, &stack);
        assert_eq!(result.is_some(), links <= 32);
        if links > 32 {
            assert_eq!(ctx, before);
        } else {
            assert_eq!(ctx.rsp(), 0x9008);
        }
    }
}

#[test]
fn unreadable_primary_handler_rolls_back_secondary_register_restores() {
    let mut img = img_with_unwind(&[1, 0x30], 0x21, 8, 1, 0);
    write_function(&mut img, 0x2008, 0x800, 0x900, 0x2100);
    img.write(0x2100, &[0x09, 0, 0, 0]); // requested handler tail is absent
    let mut stack = MockStack::new();
    stack.put(0x9000, 0x1234);
    stack.put(0x9008, 0x1400_2222);
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    let before = ctx;
    assert_eq!(run(&img, 0x1050, 1, &mut ctx, &stack), None);
    assert_eq!(ctx, before);
}

#[test]
fn truncated_or_invalid_chain_entry_fails_without_publishing_context() {
    for (begin, end, bytes) in [
        (0x800u32, 0x900u32, 8),
        (0x900, 0x800, 12),
        (0x800, 0x800, 12),
    ] {
        let mut img = img_with_unwind(&[], 0x21, 0, 0, 0);
        write_function(&mut img, 0x2004, begin, end, 0x2100);
        if bytes < 12 {
            img.bytes.remove(&(0x2004 + bytes));
        }
        img.write(0x2100, &[1, 0, 0, 0]);
        let mut stack = MockStack::new();
        stack.put(0x9000, 0x1400_2222);
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        let before = ctx;
        assert_eq!(run(&img, 0x1050, 0, &mut ctx, &stack), None);
        assert_eq!(ctx, before);
    }
}

#[test]
fn register_saves_use_establisher_frame_despite_dynamic_stack_allocation() {
    for (save, slots, xmm) in [
        (vec![8, 0x64, 2, 0], 2, false),
        (vec![8, 0x65, 0x10, 0, 0, 0], 3, false),
        (vec![8, 0x68, 1, 0], 2, true),
        (vec![8, 0x69, 0x10, 0, 0, 0], 3, true),
    ] {
        let mut codes = save;
        codes.extend_from_slice(&[4, 3]); // SET_FPREG executes after SAVE during unwind
        let img = img_with_unwind(&codes, 1, 8, slots + 1, 0x25);
        let mut stack = MockStack::new();
        stack.put(0x9010, 0x1234);
        stack.put(0x9018, 0x5678);
        stack.put(0x9000, 0x1400_2222);
        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);
        ctx.gpr[REG_RBP] = 0x9020;
        let result = run(&img, 0x1050, 0, &mut ctx, &stack).unwrap();
        assert_eq!(result.establisher_frame, 0x9000);
        if xmm {
            assert_eq!(ctx.xmm[6], [0x1234, 0x5678]);
        } else {
            assert_eq!(ctx.gpr[REG_RSI], 0x1234);
        }
        assert_eq!(ctx.rsp(), 0x9008);
    }
}

#[test]
fn primary_save_offsets_remain_fixed_after_secondary_stack_adjustments() {
    let mut img = img_with_unwind(&[4, 0x12], 0x21, 8, 1, 0);
    write_function(&mut img, 0x2008, 0x800, 0x900, 0x2100);
    img.write(0x2100, &[1, 8, 2, 0, 4, 0x64, 3, 0]); // SAVE RSI at frame + 24
    let mut stack = MockStack::new();
    stack.put(0x9010, 0x1400_2222);
    stack.put(0x9018, 0x1234);
    stack.put(0x9028, 0xdead_beef); // wrong if the adjusted RSP is used as the base
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    run(&img, 0x1050, 0, &mut ctx, &stack).unwrap();
    assert_eq!(ctx.gpr[REG_RSI], 0x1234);
    assert_eq!(ctx.rip, 0x1400_2222);
    assert_eq!(ctx.rsp(), 0x9018);
}
