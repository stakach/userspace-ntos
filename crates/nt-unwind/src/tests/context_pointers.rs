use super::*;

fn run(
    img: &MockImage,
    pc_rva: u32,
    handler: u8,
    context: &mut Context,
    stack: &dyn StackReader,
    pointers: &mut ContextPointers,
) -> Option<UnwindResult> {
    let pc = img.base + u64::from(pc_rva);
    let (base, function) = img.lookup_function(pc)?;
    virtual_unwind_with_pointers(handler, base, pc, function, context, img, stack, pointers)
}

fn seeded_pointers() -> ContextPointers {
    ContextPointers {
        integer: core::array::from_fn(|index| Some(0xa000 + index as u64 * 8)),
        floating: core::array::from_fn(|index| Some(0xb000 + index as u64 * 16)),
    }
}

fn seeded_context(rsp: u64) -> Context {
    let mut context = Context {
        gpr: core::array::from_fn(|index| 0xc000 + index as u64),
        rip: 0x1400_1050,
        xmm: core::array::from_fn(|index| [0xd000 + index as u64, 0xe000 + index as u64]),
    };
    context.set_rsp(rsp);
    context
}

// Each instruction ends at offset 8; SAVE offsets are in their opcode's actual encoded units.
fn operations() -> [(Vec<u8>, u8, usize, u64, bool, bool); 5] {
    [
        (vec![8, 0x30], 1, REG_RBX, 0, false, true),
        (vec![8, 0x64, 4, 0], 2, REG_RSI, 0x20, false, false),
        (vec![8, 0x75, 0x00, 0x02, 0, 0], 3, REG_RDI, 0x200, false, false),
        (vec![8, 0x68, 2, 0], 2, 6, 0x20, true, false),
        (vec![8, 0xf9, 0x00, 0x02, 0, 0], 3, 15, 0x200, true, false),
    ]
}

#[test]
fn every_register_restore_reports_exact_address_and_preserves_untouched_slots() {
    for (codes, count, register, offset, xmm, pop) in operations() {
        let img = img_with_unwind(&codes, 1, 16, count, 0);
        let address = 0x8000 + offset;
        let mut stack = MockStack::new();
        stack.put(address, 0x1234);
        if xmm {
            stack.put(address + 8, 0x5678);
        }
        stack.put(if pop { 0x8008 } else { 0x8000 }, 0x1400_3333);
        let mut context = seeded_context(0x8000);
        let mut legacy = context;
        let mut pointers = seeded_pointers();
        let mut expected = pointers;
        if xmm {
            expected.floating[register] = Some(address);
        } else {
            expected.integer[register] = Some(address);
        }
        let result = run(&img, 0x1050, 0, &mut context, &stack, &mut pointers).unwrap();
        assert_eq!(pointers, expected);
        assert_eq!(context.rip, 0x1400_3333);
        if xmm {
            assert_eq!(context.xmm[register], [0x1234, 0x5678]);
        } else {
            assert_eq!(context.gpr[register], 0x1234);
        }
        let pc = img.base + 0x1050;
        let (base, function) = img.lookup_function(pc).unwrap();
        assert_eq!(
            virtual_unwind(0, base, pc, function, &mut legacy, &img, &stack),
            Some(result)
        );
        assert_eq!(legacy, context);
    }
}

#[test]
fn partially_executed_prologues_do_not_publish_skipped_saved_addresses() {
    for (codes, count, register, offset, xmm, pop) in operations() {
        let img = img_with_unwind(&codes, 1, 16, count, 0);
        for executed in [false, true] {
            let mut stack = MockStack::new();
            let mut context = seeded_context(0x8000);
            let mut pointers = seeded_pointers();
            let mut expected = pointers;
            if executed {
                stack.put(0x8000 + offset, 0x1234);
                if xmm {
                    stack.put(0x8008 + offset, 0x5678);
                    expected.floating[register] = Some(0x8000 + offset);
                } else {
                    expected.integer[register] = Some(0x8000 + offset);
                }
            }
            stack.put(if executed && pop { 0x8008 } else { 0x8000 }, 0x1400_3333);
            run(&img, if executed { 0x1008 } else { 0x1007 }, 0, &mut context, &stack, &mut pointers)
                .unwrap();
            assert_eq!(pointers, expected);
        }
    }
}

#[test]
fn frame_based_saves_point_into_established_frame_not_dynamic_rsp() {
    for (save, count, xmm) in [
        (vec![8, 0x64, 2, 0], 2, false),
        (vec![8, 0x65, 0x10, 0, 0, 0], 3, false),
        (vec![8, 0x68, 1, 0], 2, true),
        (vec![8, 0x69, 0x10, 0, 0, 0], 3, true),
    ] {
        let mut codes = save;
        codes.extend_from_slice(&[4, 3]);
        let img = img_with_unwind(&codes, 1, 8, count + 1, 0x25);
        let mut stack = MockStack::new();
        stack.put(0x9000, 0x1400_3333);
        stack.put(0x9010, 0x1234);
        stack.put(0x9018, 0x5678);
        stack.put(0x8010, 0xdead);
        let mut context = seeded_context(0x8000);
        context.gpr[REG_RBP] = 0x9020;
        let mut pointers = ContextPointers::default();
        let result = run(&img, 0x1050, 0, &mut context, &stack, &mut pointers).unwrap();
        let mut expected = ContextPointers::default();
        if xmm {
            expected.floating[6] = Some(0x9010);
        } else {
            expected.integer[REG_RSI] = Some(0x9010);
        }
        assert_eq!(pointers, expected);
        assert_eq!(result.establisher_frame, 0x9000);
        assert_eq!(context.rsp(), 0x9008);
    }
}

fn write_function(img: &mut MockImage, rva: u32, unwind: u32) {
    img.write(rva, &0x800u32.to_le_bytes());
    img.write(rva + 4, &0x900u32.to_le_bytes());
    img.write(rva + 8, &unwind.to_le_bytes());
}

#[test]
fn chained_levels_accumulate_pointers_using_original_frame_and_latest_restore() {
    for indirect in [false, true] {
        let mut img = img_with_unwind(&[8, 0x30], 0x21, 16, 1, 0);
        if indirect {
            write_function(&mut img, 0x2008, 0x3001);
            write_function(&mut img, 0x3000, 0x2100);
        } else {
            write_function(&mut img, 0x2008, 0x2100);
        }
        // The primary restores RBX again, then XMM6; neither SAVE follows the advanced RSP.
        img.write(0x2100, &[1, 8, 4, 0, 8, 0x34, 4, 0, 4, 0x68, 3, 0]);
        let mut stack = MockStack::new();
        stack.put(0x8000, 0x1111);
        stack.put(0x8008, 0x1400_3333);
        stack.put(0x8020, 0x2222);
        stack.put(0x8030, 0x4444);
        stack.put(0x8038, 0x5555);
        let mut context = seeded_context(0x8000);
        let mut pointers = seeded_pointers();
        let mut expected = pointers;
        expected.integer[REG_RBX] = Some(0x8020);
        expected.floating[6] = Some(0x8030);
        run(&img, 0x1050, 0, &mut context, &stack, &mut pointers).unwrap();
        assert_eq!(pointers, expected);
        assert_eq!(context.gpr[REG_RBX], 0x2222);
        assert_eq!(context.xmm[6], [0x4444, 0x5555]);
        assert_eq!(context.rsp(), 0x8010);
    }
}

#[test]
fn epilogue_pops_publish_only_remaining_stack_slots() {
    let mut img = img_with_unwind(&[], 1, 8, 0, 0);
    img.write(0x1050, &[0x48, 0x83, 0xc4, 0x20, 0x5b, 0x41, 0x5c, 0xc3]);
    let mut stack = MockStack::new();
    stack.put(0x8020, 0x1234);
    stack.put(0x8028, 0x5678);
    stack.put(0x8030, 0x1400_3333);
    for (pc, rsp) in [(0x1050, 0x8000), (0x1054, 0x8020), (0x1055, 0x8028), (0x1057, 0x8030)] {
        let mut context = seeded_context(rsp);
        let mut pointers = seeded_pointers();
        let mut expected = pointers;
        if pc <= 0x1054 {
            expected.integer[REG_RBX] = Some(0x8020);
        }
        if pc <= 0x1055 {
            expected.integer[12] = Some(0x8028);
        }
        run(&img, pc, 0, &mut context, &stack, &mut pointers).unwrap();
        assert_eq!(pointers, expected);
        assert_eq!(context.rsp(), 0x8038);
    }
}

#[test]
fn frame_register_epilogue_records_addresses_after_lea() {
    let mut img = img_with_unwind(&[4, 3], 1, 8, 1, 0x25);
    img.write(0x1050, &[0x48, 0x8d, 0x65, 0x10, 0x5d, 0xc2, 0x10, 0]);
    let mut stack = MockStack::new();
    stack.put(0x9010, 0x1234);
    stack.put(0x9018, 0x1400_3333);
    let mut context = seeded_context(0x8000);
    context.gpr[REG_RBP] = 0x9000;
    let mut pointers = ContextPointers::default();
    run(&img, 0x1050, 0, &mut context, &stack, &mut pointers).unwrap();
    let mut expected = ContextPointers::default();
    expected.integer[REG_RBP] = Some(0x9010);
    assert_eq!(pointers, expected);
    assert_eq!(context.rsp(), 0x9030);
}

#[test]
fn every_failed_restore_read_and_return_pop_preserves_both_outputs() {
    for (codes, count, _, offset, xmm, pop) in operations() {
        let img = img_with_unwind(&codes, 1, 16, count, 0);
        let address = 0x8000 + offset;
        let return_address = if pop { 0x8008 } else { 0x8000 };
        for missing in [address, if xmm { address + 8 } else { address }, return_address] {
            let mut stack = MockStack::new();
            stack.put(address, 0x1234);
            if xmm {
                stack.put(address + 8, 0x5678);
            }
            stack.put(return_address, 0x1400_3333);
            stack.cells.remove(&missing);
            let mut context = seeded_context(0x8000);
            let before = context;
            let mut pointers = seeded_pointers();
            let before_pointers = pointers;
            assert_eq!(run(&img, 0x1050, 0, &mut context, &stack, &mut pointers), None);
            assert_eq!(context, before);
            assert_eq!(pointers, before_pointers);
        }
    }
}

#[test]
fn late_primary_handler_failure_does_not_publish_secondary_pointers() {
    let mut img = img_with_unwind(&[8, 0x30], 0x21, 16, 1, 0);
    write_function(&mut img, 0x2008, 0x2100);
    img.write(0x2100, &[0x09, 0, 0, 0]);
    let mut stack = MockStack::new();
    stack.put(0x8000, 0x1234);
    stack.put(0x8008, 0x1400_3333);
    let mut context = seeded_context(0x8000);
    let before = context;
    let mut pointers = seeded_pointers();
    let before_pointers = pointers;
    assert_eq!(run(&img, 0x1050, 1, &mut context, &stack, &mut pointers), None);
    assert_eq!(context, before);
    assert_eq!(pointers, before_pointers);
}

#[test]
fn failed_epilogue_pop_or_return_never_publishes_a_prefix() {
    let mut img = img_with_unwind(&[], 1, 8, 0, 0);
    img.write(0x1050, &[0x5b, 0x41, 0x5c, 0xc3]);
    for missing in [0x8000, 0x8008, 0x8010] {
        let mut stack = MockStack::new();
        stack.put(0x8000, 0x1234);
        stack.put(0x8008, 0x5678);
        stack.put(0x8010, 0x1400_3333);
        stack.cells.remove(&missing);
        let mut context = seeded_context(0x8000);
        let before = context;
        let mut pointers = seeded_pointers();
        let before_pointers = pointers;
        assert_eq!(run(&img, 0x1050, 0, &mut context, &stack, &mut pointers), None);
        assert_eq!(context, before);
        assert_eq!(pointers, before_pointers);
    }
}

#[test]
fn overflowing_save_addresses_and_epilogue_stack_updates_preserve_outputs() {
    for (codes, count, _, _, _, _) in operations() {
        let img = img_with_unwind(&codes, 1, 16, count, 0);
        let mut context = seeded_context(u64::MAX - 3);
        let before = context;
        let mut pointers = seeded_pointers();
        let before_pointers = pointers;
        let mut stack = MockStack::new();
        stack.put(u64::MAX - 3, 0x1234);
        assert_eq!(run(&img, 0x1050, 0, &mut context, &stack, &mut pointers), None);
        assert_eq!(context, before);
        assert_eq!(pointers, before_pointers);
    }
    let mut img = img_with_unwind(&[], 1, 8, 0, 0);
    img.write(0x1050, &[0x5b, 0xc2, 0x10, 0]);
    let mut stack = MockStack::new();
    stack.put(u64::MAX - 15, 0x1234);
    stack.put(u64::MAX - 7, 0x1400_3333);
    let mut context = seeded_context(u64::MAX - 15);
    let before = context;
    let mut pointers = seeded_pointers();
    let before_pointers = pointers;
    assert_eq!(run(&img, 0x1050, 0, &mut context, &stack, &mut pointers), None);
    assert_eq!(context, before);
    assert_eq!(pointers, before_pointers);
}

#[test]
fn xmm_high_half_address_overflow_does_not_publish_the_low_half() {
    let img = img_with_unwind(&[8, 0x68, 0, 0], 1, 16, 2, 0);
    let mut stack = MockStack::new();
    stack.put(u64::MAX - 7, 0x1234);
    let mut context = seeded_context(u64::MAX - 7);
    let before = context;
    let mut pointers = seeded_pointers();
    let before_pointers = pointers;
    assert_eq!(run(&img, 0x1050, 0, &mut context, &stack, &mut pointers), None);
    assert_eq!(context, before);
    assert_eq!(pointers, before_pointers);
}

#[test]
fn machine_frame_restores_do_not_report_a_nonvolatile_register_location() {
    let img = img_with_unwind(&[8, 0x0a], 1, 16, 1, 0);
    let mut stack = MockStack::new();
    stack.put(0x8000, 0x1400_3333);
    stack.put(0x8018, 0x9000);
    let mut context = seeded_context(0x8000);
    let mut pointers = seeded_pointers();
    let expected = pointers;
    run(&img, 0x1050, 0, &mut context, &stack, &mut pointers).unwrap();
    assert_eq!(pointers, expected);
    assert_eq!(context.rsp(), 0x9000);
}
