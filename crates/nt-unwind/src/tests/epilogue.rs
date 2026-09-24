use super::*;

fn covering(end: u32) -> RuntimeFunction {
    RuntimeFunction {
        begin: 0x1000,
        end,
        unwind_info: 0x2000,
    }
}

fn run(code: &[u8], frame: u8, ctx: &mut Context, stack: &dyn StackReader) -> Option<bool> {
    let mut image = img_with_unwind(&[], 1, 0, 0, frame);
    image.write(0x1050, code);
    crate::epilogue::unwind_return(
        image.base,
        0x1050,
        covering(0x1100),
        frame,
        ctx,
        &image,
        stack,
        &mut ContextPointers::default(),
    )
}

#[test]
fn return_variants_can_precede_trailing_code_and_padding() {
    for (code, extra) in [
        (vec![0xc3], 0),
        (vec![0xc2, 0x18, 0], 0x18),
        (vec![0xf3, 0xc3], 0),
        (vec![0x48, 0xc3], 0),
    ] {
        let mut stack = MockStack::new();
        stack.put(0x9000, 0x1400_2222);
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        assert_eq!(run(&code, 0, &mut ctx, &stack), Some(true));
        assert_eq!(ctx.rip, 0x1400_2222);
        assert_eq!(ctx.rsp(), 0x9008 + extra);
    }
}

#[test]
fn direct_tail_jump_after_stack_restore_pops_the_real_caller() {
    for (rva, code) in [
        (0x1050, vec![0xe9, 0xab, 0x01, 0, 0]),
        (0x10f0, vec![0xeb, 0x20]),
    ] {
        let mut img = img_with_unwind(&[4, 0x32], 1, 8, 1, 0);
        img.write(rva, &code);
        let pc = img.base + u64::from(rva);
        let (base, function) = img.lookup_function(pc).unwrap();
        let mut stack = MockStack::new();
        stack.put(0x9020, 0x1400_2222);
        stack.put(0x9040, 0x1400_3333);
        let mut ctx = Context::default();
        ctx.set_rsp(0x9020); // ADD RSP, 0x20 already executed before the interrupted jump
        virtual_unwind(1, base, pc, function, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.rip, 0x1400_2222);
        assert_eq!(ctx.rsp(), 0x9028);
    }
}

#[test]
fn direct_jump_within_the_same_chained_function_is_not_a_return() {
    for chained_fragment in [false, true] {
        let mut img = img_with_unwind(&[], 1, 0, 0, 0);
        let displacement = if chained_fragment { 0x1abu32 } else { 0x0b };
        let mut jump = [0xe9, 0, 0, 0, 0];
        jump[1..].copy_from_slice(&displacement.to_le_bytes());
        img.write(0x1050, &jump);
        if chained_fragment {
            img.set_pdata(vec![
                RuntimeFunction {
                    begin: 0x1000,
                    end: 0x1100,
                    unwind_info: 0x2100,
                },
                RuntimeFunction {
                    begin: 0x1200,
                    end: 0x1300,
                    unwind_info: 0x3001,
                },
            ]);
            img.write(0x3000, &0x1000u32.to_le_bytes());
            img.write(0x3004, &0x1100u32.to_le_bytes());
            img.write(0x3008, &0x2100u32.to_le_bytes());
        }
        let mut ctx = Context::default();
        ctx.set_rsp(0x9020);
        let before = ctx;
        let function = img.lookup_function(img.base + 0x1050).unwrap().1;
        assert_eq!(
            crate::epilogue::unwind_return(
                img.base,
                0x1050,
                function,
                0,
                &mut ctx,
                &img,
                &NoStackReads,
                &mut ContextPointers::default(),
            ),
            Some(false)
        );
        assert_eq!(ctx, before);
    }
}

#[test]
fn direct_jump_to_a_different_function_is_a_return_epilogue() {
    let mut img = img_with_unwind(&[], 1, 0, 0, 0);
    img.set_pdata(vec![
        RuntimeFunction {
            begin: 0x1000,
            end: 0x1100,
            unwind_info: 0x2100,
        },
        RuntimeFunction {
            begin: 0x1200,
            end: 0x1300,
            unwind_info: 0x2200,
        },
    ]);
    img.write(0x1050, &[0xe9, 0xab, 0x01, 0, 0]);
    let mut stack = MockStack::new();
    stack.put(0x9000, 0x1400_2222);
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    let function = img.lookup_function(img.base + 0x1050).unwrap().1;
    assert_eq!(
        crate::epilogue::unwind_return(
            img.base,
            0x1050,
            function,
            0,
            &mut ctx,
            &img,
            &stack,
            &mut ContextPointers::default(),
        ),
        Some(true)
    );
    assert_eq!(ctx.rip, 0x1400_2222);
    assert_eq!(ctx.rsp(), 0x9008);
}

#[test]
fn indirect_tail_jumps_pop_the_real_caller_after_stack_restore() {
    for code in [
        vec![0xff, 0x25, 0x10, 0, 0, 0], // JMP [RIP+16]
        vec![0x48, 0xff, 0xe0],          // JMP RAX
        vec![0x48, 0xff, 0xe7],          // JMP RDI
    ] {
        let mut stack = MockStack::new();
        stack.put(0x9020, 0x1400_2222);
        let mut ctx = Context::default();
        ctx.set_rsp(0x9020);
        assert_eq!(run(&code, 0, &mut ctx, &stack), Some(true));
        assert_eq!(ctx.rip, 0x1400_2222);
        assert_eq!(ctx.rsp(), 0x9028);
    }
}

#[test]
fn unrelated_or_truncated_indirect_jump_encodings_are_not_return_epilogues() {
    for code in [
        vec![0xff, 0xd0],       // CALL RAX
        vec![0xff, 0xe0],       // non-canonical JMP RAX without REX.W
        vec![0x49, 0xff, 0xe0], // REX.B is not the canonical register tail jump
    ] {
        let mut ctx = Context::default();
        ctx.set_rsp(0x9020);
        let before = ctx;
        let result = run(&code, 0, &mut ctx, &NoStackReads);
        assert!(matches!(result, Some(false) | None));
        assert_eq!(ctx, before);
    }
    let mut image = img_with_unwind(&[], 1, 0, 0, 0);
    image.write(0x1050, &[0xff, 0x25, 1, 2, 3]);
    image.bytes.remove(&0x1055);
    let mut ctx = Context::default();
    ctx.set_rsp(0x9020);
    let before = ctx;
    assert_eq!(
        crate::epilogue::unwind_return(
            image.base,
            0x1050,
            covering(0x1100),
            0,
            &mut ctx,
            &image,
            &NoStackReads,
            &mut ContextPointers::default(),
        ),
        None
    );
    assert_eq!(ctx, before);
}

#[test]
fn add_immediates_are_sign_extended() {
    for (code, return_slot) in [
        (vec![0x48, 0x83, 0xc4, 0x20, 0xc3], 0x9020),
        (vec![0x48, 0x83, 0xc4, 0xf0, 0xc3], 0x8ff0),
        (vec![0x48, 0x81, 0xc4, 0x20, 0, 0, 0, 0xc3], 0x9020),
        (vec![0x48, 0x81, 0xc4, 0xf0, 0xff, 0xff, 0xff, 0xc3], 0x8ff0),
    ] {
        let mut stack = MockStack::new();
        stack.put(return_slot, 0x1400_2222);
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        assert_eq!(run(&code, 0, &mut ctx, &stack), Some(true));
        assert_eq!(ctx.rsp(), return_slot + 8);
        assert_eq!(ctx.rip, 0x1400_2222);
    }
}

#[test]
fn lea_uses_the_declared_frame_register_and_signed_displacement() {
    for (code, frame, return_slot) in [
        (vec![0x48, 0x8d, 0x65, 0xe0, 0xc3], 5, 0x8fe0),
        (vec![0x49, 0x8d, 0x65, 0x20, 0xc3], 13, 0x9020),
        (
            vec![0x48, 0x8d, 0xa5, 0xe0, 0xff, 0xff, 0xff, 0xc3],
            5,
            0x8fe0,
        ),
        (vec![0x49, 0x8d, 0xa5, 0x20, 0, 0, 0, 0xc3], 13, 0x9020),
    ] {
        let mut stack = MockStack::new();
        stack.put(return_slot, 0x1400_2222);
        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);
        ctx.gpr[frame as usize] = 0x9000;
        assert_eq!(run(&code, frame, &mut ctx, &stack), Some(true));
        assert_eq!(ctx.rsp(), return_slot + 8);
    }
}

#[test]
fn remaining_pop_sequences_accept_rex_prefixes_and_partial_epilogue_entry() {
    let code = [0x48, 0x83, 0xc4, 0x20, 0x5b, 0x48, 0x5e, 0x49, 0x5c, 0xc3];
    for (offset, rsp) in [
        (0, 0x9000),
        (4, 0x9020),
        (5, 0x9028),
        (7, 0x9030),
        (9, 0x9038),
    ] {
        let mut stack = MockStack::new();
        stack.put(0x9020, 0x1111);
        stack.put(0x9028, 0x2222);
        stack.put(0x9030, 0x3333);
        stack.put(0x9038, 0x1400_2222);
        let mut ctx = Context::default();
        ctx.gpr[REG_RBX] = 0x1111;
        ctx.gpr[REG_RSI] = 0x2222;
        ctx.gpr[12] = 0x3333;
        ctx.set_rsp(rsp);
        assert_eq!(run(&code[offset..], 0, &mut ctx, &stack), Some(true));
        assert_eq!(ctx.gpr[REG_RBX], 0x1111);
        assert_eq!(ctx.gpr[REG_RSI], 0x2222);
        assert_eq!(ctx.gpr[12], 0x3333);
        assert_eq!(ctx.rsp(), 0x9040);
        assert_eq!(ctx.rip, 0x1400_2222);
    }
}

struct NoStackReads;

impl StackReader for NoStackReads {
    fn read_u64(&self, _: u64) -> Option<u64> {
        panic!("stack read before complete epilogue recognition")
    }
}

#[test]
fn ordinary_body_code_never_reads_the_stack() {
    for code in [
        vec![0x5b, 0x90, 0xc3],
        vec![0x48, 0x83, 0xc4, 0x20, 0x5b, 0x90, 0xc3],
        vec![0x90, 0xc3],
    ] {
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        let before = ctx;
        assert_eq!(run(&code, 0, &mut ctx, &NoStackReads), Some(false));
        assert_eq!(ctx, before);
    }
}

#[test]
fn invalid_stack_adjustment_encodings_are_not_epilogues() {
    for code in [
        vec![0x49, 0x83, 0xc4, 0x20, 0xc3],       // ADD targets R12
        vec![0x48, 0x83, 0xc5, 0x20, 0xc3],       // ADD targets RBP
        vec![0x48, 0x8d, 0x25, 0, 0, 0, 0, 0xc3], // RIP-relative LEA
        vec![0x48, 0x8d, 0x64, 0x24, 0, 0xc3],    // SIB LEA
        vec![0x4c, 0x8d, 0x65, 0, 0xc3],          // REX.R changes the destination
        vec![0x4a, 0x8d, 0x65, 0, 0xc3],          // REX.X is not canonical
        vec![0x48, 0x8d, 0xe5, 0xc3],             // register-direct LEA
        vec![0x49, 0x8d, 0x65, 0, 0xc3],          // undeclared frame register R13
    ] {
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        let before = ctx;
        assert_eq!(run(&code, 5, &mut ctx, &NoStackReads), Some(false));
        assert_eq!(ctx, before);
    }
}

#[test]
fn recognized_epilogue_read_failure_does_not_retry_metadata_unwind() {
    let mut img = img_with_unwind(&[4, 0x02], 0x09, 8, 1, 0);
    img.write(0x1050, &[0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3]);
    img.write(0x2008, &0x3000u32.to_le_bytes());
    let mut stack = MockStack::new();
    stack.put(0x9008, 0x1400_3333); // readable if metadata is incorrectly retried
    stack.put(0x9020, 0xdead_beef); // saved RBX succeeds; epilogue return slot is missing
    let pc = img.base + 0x1050;
    let (base, func) = img.lookup_function(pc).unwrap();
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    let before = ctx;
    assert_eq!(
        virtual_unwind(1, base, pc, func, &mut ctx, &img, &stack),
        None
    );
    assert_eq!(ctx, before);
}

#[test]
fn stack_arithmetic_overflow_and_underflow_preserve_context() {
    for (code, rsp) in [
        (vec![0x48, 0x83, 0xc4, 0x20, 0xc3], u64::MAX - 7),
        (vec![0x48, 0x83, 0xc4, 0xe0, 0xc3], 8),
        (vec![0xc3], u64::MAX - 7),
        (vec![0x5b, 0xc3], u64::MAX - 7),
        (vec![0xc2, 0x20, 0], u64::MAX - 15),
    ] {
        let mut stack = MockStack::new();
        stack.put(rsp, 0x1400_2222);
        let mut ctx = Context::default();
        ctx.set_rsp(rsp);
        let before = ctx;
        assert_eq!(run(&code, 0, &mut ctx, &stack), None);
        assert_eq!(ctx, before);
    }
}

#[test]
fn truncated_code_never_reads_past_the_covering_function() {
    struct BoundedImage {
        inner: MockImage,
        end: u32,
    }
    impl ImageReader for BoundedImage {
        fn lookup_function(&self, pc: u64) -> Option<(u64, RuntimeFunction)> {
            self.inner.lookup_function(pc)
        }
        fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
            assert!(rva < self.end, "instruction read crossed the function end");
            self.inner.read_u8(base, rva)
        }
    }
    for bytes in [
        vec![],
        vec![0x48],
        vec![0xf3],
        vec![0xc2, 0x10],
        vec![0x48, 0x83, 0xc4],
        vec![0x48, 0x81, 0xc4, 1, 2, 3],
        vec![0xe9, 1, 2, 3],
        vec![0xeb],
    ] {
        let end = 0x1050 + bytes.len() as u32;
        let mut inner = img_with_unwind(&[], 1, 0, 0, 0);
        inner.write(0x1050, &bytes);
        let image = BoundedImage { inner, end };
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        let before = ctx;
        assert_eq!(
            crate::epilogue::unwind_return(
                image.inner.base,
                0x1050,
                covering(end),
                0,
                &mut ctx,
                &image,
                &NoStackReads,
                &mut ContextPointers::default(),
            ),
            None
        );
        assert_eq!(ctx, before);
    }
}

#[test]
fn zero_code_metadata_and_first_instruction_return_still_decode_ret_immediate() {
    let mut img = img_with_unwind(&[], 0x09, 0, 0, 0);
    img.write(0x1000, &[0xc2, 0x20, 0]); // no handler tail needed for an epilogue
    let pc = img.base + 0x1000;
    let (base, func) = img.lookup_function(pc).unwrap();
    let mut stack = MockStack::new();
    stack.put(0x9000, 0x1400_2222);
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    let result = virtual_unwind(1, base, pc, func, &mut ctx, &img, &stack).unwrap();
    assert_eq!(result.handler_rva, 0);
    assert_eq!(ctx.rsp(), 0x9028);
}

#[test]
fn unreadable_instruction_inside_a_valid_function_is_a_failure() {
    let mut image = img_with_unwind(&[], 1, 0, 0, 0);
    image.write(0x1050, &[0x48, 0x83, 0xc4, 0x20, 0xc3]);
    image.bytes.remove(&0x1053);
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    let before = ctx;
    assert_eq!(
        crate::epilogue::unwind_return(
            image.base,
            0x1050,
            covering(0x1100),
            0,
            &mut ctx,
            &image,
            &NoStackReads,
            &mut ContextPointers::default(),
        ),
        None
    );
    assert_eq!(ctx, before);
}

#[test]
fn return_needs_no_instruction_bytes_after_it() {
    let mut image = img_with_unwind(&[], 1, 0, 0, 0);
    image.write(0x1050, &[0xc3]);
    image.bytes.remove(&0x1051);
    let mut stack = MockStack::new();
    stack.put(0x9000, 0x1400_2222);
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    assert_eq!(
        crate::epilogue::unwind_return(
            image.base,
            0x1050,
            covering(0x1100),
            0,
            &mut ctx,
            &image,
            &stack,
            &mut ContextPointers::default(),
        ),
        Some(true)
    );
}

#[test]
fn pop_rsp_installs_the_popped_value_without_an_extra_increment() {
    let mut stack = MockStack::new();
    stack.put(0x9000, 0xa000);
    stack.put(0xa000, 0x1400_2222);
    let mut ctx = Context::default();
    ctx.set_rsp(0x9000);
    assert_eq!(run(&[0x5c, 0xc3], 0, &mut ctx, &stack), Some(true));
    assert_eq!(ctx.rsp(), 0xa008);
    assert_eq!(ctx.rip, 0x1400_2222);
}
