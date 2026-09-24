use super::*;
use crate::{
    raw_context::{RawContext, CONTEXT_AMD64_FULL_SEGMENTS},
    seh_handler_packet::{HandlerPacketError, SehHandlerPacket},
    REG_RBX,
};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::Cell;

const BASE: u64 = 0x10_0000;
const LOW: u64 = 0x1000;
const HIGH: u64 = 0x1040;

struct Fixture {
    image: [u8; 0x1100],
    functions: Vec<RuntimeFunction>,
    stack: BTreeMap<u64, u64>,
    image_error: Option<ExceptionImageError>,
    stack_reads: Cell<usize>,
}

impl Fixture {
    fn new(handler_flags: u8) -> Self {
        let mut fixture = Self {
            image: [0x90; 0x1100],
            functions: Vec::new(),
            stack: BTreeMap::new(),
            image_error: None,
            stack_reads: Cell::new(0),
        };
        for index in 0..2 {
            let begin = 0x100 + index * 0x100;
            let unwind = 0x1000 + index * 0x20;
            fixture.functions.push(RuntimeFunction {
                begin,
                end: begin + 0x80,
                unwind_info: unwind,
            });
            // sub rsp,16 after push rbx: Current and Previous are 32 bytes apart.
            fixture.image[unwind as usize..unwind as usize + 12].copy_from_slice(&[
                1 | (handler_flags << 3),
                4,
                2,
                0,
                4,
                0x12,
                1,
                0x30,
                0,
                8,
                0,
                0,
            ]);
        }
        fixture.stack.insert(LOW + 0x10, 0x55);
        fixture.stack.insert(LOW + 0x18, BASE + 0x210);
        fixture.stack.insert(LOW + 0x30, 0x77);
        fixture.stack.insert(LOW + 0x38, BASE + 0x310);
        fixture
    }

    fn walk(&self, mode: WalkMode) -> ExceptionWalk {
        ExceptionWalk::new(mode, record(), context(), LOW, HIGH, 8).unwrap()
    }
}

impl ImageReader for Fixture {
    fn lookup_function(&self, pc: u64) -> Option<(u64, RuntimeFunction)> {
        let rva = u32::try_from(pc.checked_sub(BASE)?).ok()?;
        self.functions
            .iter()
            .find(|function| function.covers(rva))
            .copied()
            .map(|function| (BASE, function))
    }

    fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
        if base != BASE {
            return None;
        }
        self.image.get(rva as usize).copied()
    }
}

impl StackReader for Fixture {
    fn read_u64(&self, address: u64) -> Option<u64> {
        self.stack_reads.set(self.stack_reads.get() + 1);
        self.stack.get(&address).copied()
    }
}

impl ExceptionImageReader for Fixture {
    fn lookup_exception_function(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
        if let Some(error) = self.image_error {
            return Err(error);
        }
        if !(BASE..BASE + self.image.len() as u64).contains(&pc) {
            return Err(ExceptionImageError::UnknownImage);
        }
        Ok(match self.lookup_function(pc) {
            Some((image_base, function)) => ExceptionFunction::Function {
                image_base,
                function,
            },
            None => ExceptionFunction::Leaf,
        })
    }

    fn validate_collision_scope(&self, image_base: u64, handler_data: u64, index: u32) -> bool {
        image_base == BASE && handler_data == BASE + 0x100c && index <= 2
    }
}

fn context() -> Context {
    let mut context = Context::default();
    context.rip = BASE + 0x110;
    context.set_rsp(LOW);
    context.gpr[REG_RBX] = 0x33;
    context
}

fn record() -> ExceptionRecord {
    ExceptionRecord {
        code: 0xc000_0005,
        flags: 0,
        address: BASE + 0x110,
        information: Vec::new(),
    }
}

fn invoke(step: WalkStep) -> HandlerInvocation {
    match step {
        WalkStep::Invoke(invocation) => invocation,
        other => panic!("expected handler, got {other:?}"),
    }
}

fn continued(step: WalkStep) -> ExceptionWalk {
    match step {
        WalkStep::Continue(walk) => walk,
        other => panic!("expected continuation, got {other:?}"),
    }
}

fn unwind(target: Option<u64>) -> WalkMode {
    WalkMode::Unwind {
        target_frame: target,
        target_ip: BASE + 0x700,
        return_value: 42,
    }
}

fn raise_context(entry_rsp: u64) -> Context {
    let mut captured = Context::default();
    captured.rip = BASE + 0x444;
    captured.set_rsp(entry_rsp);
    captured.gpr[REG_RBX] = 0x34;
    captured
}

#[test]
fn software_raise_admits_exact_caller_and_builds_noncontinuable_search() {
    let mut fixture = Fixture::new(0);
    fixture.stack.insert(LOW + 8, BASE + 0x110);
    let walk = SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, HIGH, &fixture, &fixture)
        .unwrap()
        .into_search(0xc000_0005, 3)
        .unwrap();
    assert_eq!(fixture.stack_reads.get(), 1);
    assert_eq!(walk.exception.code, 0xc000_0005);
    assert_eq!(walk.exception.flags, EXCEPTION_NONCONTINUABLE);
    assert_eq!(walk.exception.address, BASE + 0x110);
    assert!(walk.exception.information.is_empty());
    assert_eq!(walk.state.mode, WalkMode::Search);
    assert_eq!(walk.state.original.rip, BASE + 0x110);
    assert_eq!(walk.state.original.rsp(), LOW + 0x10);
    assert_eq!(walk.state.original.gpr[REG_RBX], 0x34);
    assert_eq!(walk.state.frames_left, 3);
}

#[test]
fn software_raise_rejects_unreadable_or_unadmitted_caller() {
    let mut fixture = Fixture::new(0);
    assert!(matches!(
        SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, HIGH, &fixture, &fixture),
        Err(WalkError::StackRead)
    ));
    fixture.stack.insert(LOW + 8, BASE - 1);
    assert!(matches!(
        SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, HIGH, &fixture, &fixture),
        Err(WalkError::ImageLookup(ExceptionImageError::UnknownImage))
    ));
    fixture.stack.insert(LOW + 8, BASE + 0x110);
    fixture.image_error = Some(ExceptionImageError::UnreadableImage);
    assert!(matches!(
        SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, HIGH, &fixture, &fixture),
        Err(WalkError::ImageLookup(ExceptionImageError::UnreadableImage))
    ));
}

#[test]
fn software_raise_rejects_invalid_stack_before_reading_it() {
    let fixture = Fixture::new(0);
    for (entry_rsp, low, high, expected) in [
        (LOW + 8, HIGH, LOW, WalkError::InvalidStackBounds),
        (LOW, LOW, HIGH, WalkError::BadStack),
        (LOW + 8, LOW + 0x10, HIGH, WalkError::BadStack),
        (LOW + 0x38, LOW, HIGH - 1, WalkError::BadStack),
        (u64::MAX, LOW, HIGH, WalkError::BadStack),
    ] {
        assert!(matches!(
            SoftwareRaiseSite::admit(raise_context(entry_rsp), low, high, &fixture, &fixture),
            Err(error) if error == expected
        ));
    }
    assert_eq!(fixture.stack_reads.get(), 0);
}

#[test]
fn software_raise_rejects_zero_frame_budget() {
    let mut fixture = Fixture::new(0);
    fixture.stack.insert(LOW + 8, BASE + 0x110);
    let site =
        SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, HIGH, &fixture, &fixture).unwrap();
    assert!(matches!(
        site.into_search(0xc000_0005, 0),
        Err(WalkError::InvalidBudget)
    ));
}

#[test]
fn software_raise_search_stops_at_the_first_owned_handler() {
    let mut fixture = Fixture::new(unw_flag::EHANDLER);
    fixture.stack.insert(LOW + 8, BASE + 0x110);
    fixture.stack.insert(LOW + 0x20, 0x55);
    fixture.stack.insert(LOW + 0x28, BASE + 0x210);
    let site =
        SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, HIGH, &fixture, &fixture).unwrap();
    let FirstRaiseStep::Invoke(invocation) = site
        .search_to_first_handler(0xc000_0022, 4, &fixture, &fixture)
        .unwrap()
    else {
        panic!("expected the first language handler");
    };
    assert_eq!(invocation.control_pc, BASE + 0x110);
    assert_eq!(invocation.exception.code, 0xc000_0022);
    assert_eq!(invocation.exception.flags, EXCEPTION_NONCONTINUABLE);
    assert_eq!(invocation.handler, BASE + 0x800);
}

#[test]
fn software_raise_search_fails_closed_on_changed_image_or_unreadable_stack() {
    let mut fixture = Fixture::new(unw_flag::EHANDLER);
    fixture.stack.insert(LOW + 8, BASE + 0x110);
    let site =
        SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, HIGH, &fixture, &fixture).unwrap();
    assert!(matches!(
        site.search_to_first_handler(0xc000_0022, 4, &fixture, &fixture),
        Err(WalkError::UnwindData)
    ));

    fixture.stack.insert(LOW + 0x20, 0x55);
    fixture.stack.insert(LOW + 0x28, BASE + 0x210);
    let site =
        SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, HIGH, &fixture, &fixture).unwrap();
    fixture.image_error = Some(ExceptionImageError::UnreadableImage);
    assert!(matches!(
        site.search_to_first_handler(0xc000_0022, 4, &fixture, &fixture),
        Err(WalkError::ImageLookup(ExceptionImageError::UnreadableImage))
    ));
}

#[test]
fn software_raise_search_honors_frame_budget_before_second_frame() {
    let mut fixture = Fixture::new(0);
    fixture.stack.insert(LOW + 8, BASE + 0x110);
    fixture.stack.insert(LOW + 0x20, 0x55);
    fixture.stack.insert(LOW + 0x28, BASE + 0x210);
    let site =
        SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, HIGH, &fixture, &fixture).unwrap();
    assert!(matches!(
        site.search_to_first_handler(0xc000_0022, 1, &fixture, &fixture),
        Err(WalkError::FrameLimit)
    ));
}

#[test]
fn software_raise_search_returns_owned_unhandled_outcome() {
    let mut fixture = Fixture::new(0);
    fixture.stack.insert(LOW + 8, BASE + 0x310);
    fixture.stack.insert(LOW + 0x10, BASE + 0x310);
    let high = LOW + 0x18;
    let site =
        SoftwareRaiseSite::admit(raise_context(LOW + 8), LOW, high, &fixture, &fixture).unwrap();
    let FirstRaiseStep::Complete(WalkOutcome::Unhandled { exception, context }) = site
        .search_to_first_handler(0xc000_0022, 4, &fixture, &fixture)
        .unwrap()
    else {
        panic!("expected a terminal unhandled search");
    };
    assert_eq!(exception.code, 0xc000_0022);
    assert_eq!(context.rsp(), LOW + 0x10);
}

#[test]
fn native_handler_packet_preserves_raw_state_and_exact_component_pointers() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    let mut captured = RawContext::zeroed();
    captured.set_context_flags(CONTEXT_AMD64_FULL_SEGMENTS);
    captured.as_bytes_mut()[0x4a0] = 0x5a;
    let packet = SehHandlerPacket::prepare_search(&captured, &invocation, 0x8000).unwrap();
    assert_eq!(packet.exception.code, invocation.exception.code);
    assert_eq!(packet.exception_pointers.exception_record, 0x8000);
    assert_eq!(packet.exception_pointers.context_record, 0x80b0);
    assert_eq!(packet.dispatcher.context_record, 0x8580);
    assert_eq!(packet.dispatcher.function_entry, 0x8aa0);
    assert_eq!(packet.dispatcher.language_handler, invocation.handler);
    assert_eq!(packet.original_context.rip(), BASE + 0x110);
    assert_eq!(packet.unwound_context.rip(), BASE + 0x210);
    assert_eq!(packet.original_context.as_bytes()[0x4a0], 0x5a);
    assert_eq!(packet.unwound_context.as_bytes()[0x4a0], 0x5a);
}

#[test]
fn native_handler_packet_rejects_wrong_mode_bad_address_and_excess_information() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    let captured = RawContext::zeroed();
    assert!(matches!(
        SehHandlerPacket::prepare_search(&captured, &invocation, 0x8008),
        Err(HandlerPacketError::Address)
    ));
    assert!(matches!(
        SehHandlerPacket::prepare_search(&captured, &invocation, u64::MAX - 15),
        Err(HandlerPacketError::Address)
    ));
    invocation.exception.information = vec![0; 16];
    assert!(matches!(
        SehHandlerPacket::prepare_search(&captured, &invocation, 0x8000),
        Err(HandlerPacketError::InformationCount)
    ));

    let fixture = Fixture::new(unw_flag::UHANDLER);
    let invocation = invoke(fixture.walk(unwind(None)).step(&fixture, &fixture).unwrap());
    assert!(matches!(
        SehHandlerPacket::prepare_search(&captured, &invocation, 0x8000),
        Err(HandlerPacketError::NotSearch)
    ));
}

#[test]
fn search_has_original_and_distinct_unwound_contexts() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    assert_eq!(invocation.control_pc, record().address);
    assert_eq!(invocation.establisher_frame, LOW);
    assert_eq!(invocation.handler, BASE + 0x800);
    assert_eq!(invocation.handler_data, BASE + 0x100c);
    match invocation.contexts {
        HandlerContexts::Search { exception, unwound } => {
            assert_eq!(exception, context());
            assert_eq!(unwound.rsp(), LOW + 0x20);
            assert_eq!(unwound.gpr[REG_RBX], 0x55);
            assert_eq!(unwound.rip, BASE + 0x210);
        }
        _ => panic!("wrong context contract"),
    }
}

#[test]
fn continue_execution_uses_handler_modified_original_context() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    if let HandlerContexts::Search { exception, .. } = &mut invocation.contexts {
        exception.rip = BASE + 0x444;
        exception.gpr[REG_RBX] = 0x999;
    }
    match invocation.returned(0).unwrap() {
        WalkStep::Complete(WalkOutcome::Handled {
            context: result, ..
        }) => {
            assert_eq!(result.rip, BASE + 0x444);
            assert_eq!(result.rsp(), LOW);
            assert_eq!(result.gpr[REG_RBX], 0x999);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn noncontinuable_cannot_be_cleared_by_handler() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut exception = record();
    exception.flags = EXCEPTION_NONCONTINUABLE;
    let walk = ExceptionWalk::new(WalkMode::Search, exception, context(), LOW, HIGH, 8).unwrap();
    let mut invocation = invoke(walk.step(&fixture, &fixture).unwrap());
    invocation.exception.flags = 0;
    assert_eq!(
        invocation.returned(0).unwrap_err(),
        WalkError::NoncontinuableException
    );
}

#[test]
fn handler_can_make_exception_noncontinuable() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    invocation.exception.flags |= EXCEPTION_NONCONTINUABLE;
    assert_eq!(
        invocation.returned(0).unwrap_err(),
        WalkError::NoncontinuableException
    );
}

#[test]
fn invalid_dispositions_are_not_continue_search() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    for raw in [-1, 4, i32::MAX] {
        let invocation = invoke(
            fixture
                .walk(WalkMode::Search)
                .step(&fixture, &fixture)
                .unwrap(),
        );
        assert_eq!(
            invocation.returned(raw).unwrap_err(),
            WalkError::InvalidDisposition(raw)
        );
    }
}

fn saved_dispatcher(invocation: &HandlerInvocation) -> CollisionDispatcher {
    CollisionDispatcher {
        control_pc: invocation.control_pc,
        image_base: invocation.image_base,
        function: invocation.function,
        establisher_frame: invocation.establisher_frame,
        handler: invocation.handler,
        handler_data: invocation.handler_data,
        scope_index: 1,
        context: context(),
    }
}

#[test]
fn collision_requires_an_explicit_saved_dispatcher() {
    let fixture = Fixture::new(unw_flag::EHANDLER | unw_flag::UHANDLER);
    for mode in [WalkMode::Search, unwind(Some(LOW + 0x20))] {
        let invocation = invoke(fixture.walk(mode).step(&fixture, &fixture).unwrap());
        assert_eq!(
            invocation.returned(3).unwrap_err(),
            WalkError::InvalidCollisionDispatcher
        );
    }
}

#[test]
fn collided_unwind_reinvokes_saved_handler_without_advancing_outer_frame() {
    let fixture = Fixture::new(unw_flag::EHANDLER | unw_flag::UHANDLER);
    for mode in [WalkMode::Search, unwind(Some(LOW + 0x20))] {
        let mut first = invoke(fixture.walk(mode).step(&fixture, &fixture).unwrap());
        first.collision = Some(saved_dispatcher(&first));
        let walk = continued(first.returned(3).unwrap());
        let second = invoke(walk.step(&fixture, &fixture).unwrap());
        assert_eq!(second.control_pc, BASE + 0x110);
        assert_eq!(second.establisher_frame, LOW);
        assert_eq!(second.scope_index, 1);
        assert_eq!(
            second.exception.flags & EXCEPTION_COLLIDED_UNWIND,
            EXCEPTION_COLLIDED_UNWIND
        );
        assert_eq!(second.handler, BASE + 0x800);
        let next = second.returned(1).unwrap();
        if mode == WalkMode::Search {
            assert!(matches!(
                next,
                WalkStep::Complete(WalkOutcome::Unhandled { .. })
            ));
        } else {
            assert!(matches!(next, WalkStep::Continue(_)));
        }
    }
}

#[test]
fn collision_rejects_untrusted_image_function_handler_frame_and_scope() {
    let fixture = Fixture::new(unw_flag::EHANDLER | unw_flag::UHANDLER);
    for mutation in 0..6 {
        let mut invocation = invoke(
            fixture
                .walk(unwind(Some(LOW + 0x20)))
                .step(&fixture, &fixture)
                .unwrap(),
        );
        let mut saved = saved_dispatcher(&invocation);
        match mutation {
            0 => saved.control_pc = BASE + 0x4000,
            1 => saved.function.begin += 1,
            2 => saved.handler += 1,
            3 => saved.establisher_frame = LOW + 8,
            4 => saved.scope_index = 3,
            _ => saved.scope_index = 4097,
        }
        invocation.collision = Some(saved);
        let walk = continued(invocation.returned(3).unwrap());
        let error = walk.step(&fixture, &fixture).unwrap_err();
        assert!(matches!(
            error,
            WalkError::InvalidCollisionDispatcher | WalkError::BadStack | WalkError::ImageLookup(_)
        ));
    }
}

#[test]
fn repeated_collision_is_bounded_even_with_one_outer_frame() {
    let fixture = Fixture::new(unw_flag::EHANDLER | unw_flag::UHANDLER);
    let walk =
        ExceptionWalk::new(unwind(Some(LOW + 0x20)), record(), context(), LOW, HIGH, 1).unwrap();
    let mut first = invoke(walk.step(&fixture, &fixture).unwrap());
    first.collision = Some(saved_dispatcher(&first));
    let walk = continued(first.returned(3).unwrap());
    let mut second = invoke(walk.step(&fixture, &fixture).unwrap());
    second.collision = Some(saved_dispatcher(&second));
    assert_eq!(second.returned(3).unwrap_err(), WalkError::FrameLimit);
}

#[test]
fn target_handler_runs_before_transfer_without_using_previous_registers() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    let invocation = invoke(
        fixture
            .walk(unwind(Some(LOW)))
            .step(&fixture, &fixture)
            .unwrap(),
    );
    assert_eq!(
        invocation.exception.flags,
        EXCEPTION_UNWINDING | EXCEPTION_TARGET_UNWIND
    );
    assert_eq!(invocation.target_ip, BASE + 0x700);
    match invocation.contexts {
        HandlerContexts::Unwind { current } => {
            assert_eq!(current.rsp(), LOW);
            assert_eq!(current.gpr[REG_RBX], 0x33);
            assert_eq!(current.gpr[REG_RAX], 42);
        }
        _ => panic!("wrong context contract"),
    }
    match invocation.returned(1).unwrap() {
        WalkStep::Complete(WalkOutcome::TargetReached { exception, context }) => {
            assert_eq!(
                exception.flags,
                EXCEPTION_UNWINDING | EXCEPTION_TARGET_UNWIND
            );
            assert_eq!(context.rsp(), LOW);
            assert_eq!(context.gpr[REG_RBX], 0x33);
            assert_eq!(context.rip, BASE + 0x700);
            assert_eq!(context.gpr[REG_RAX], 42);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn non_target_advances_to_previous_then_target_restores_that_frame() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(unwind(Some(LOW + 0x20)))
            .step(&fixture, &fixture)
            .unwrap(),
    );
    assert_eq!(invocation.exception.flags, EXCEPTION_UNWINDING);
    if let HandlerContexts::Unwind { current } = &mut invocation.contexts {
        current.gpr[REG_RBX] = 0xdead;
    }
    let walk = continued(invocation.returned(1).unwrap());
    let invocation = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(invocation.establisher_frame, LOW + 0x20);
    match invocation.returned(1).unwrap() {
        WalkStep::Complete(WalkOutcome::TargetReached { context, .. }) => {
            assert_eq!(context.rsp(), LOW + 0x20);
            assert_eq!(context.gpr[REG_RBX], 0x55);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn target_handler_modifications_survive() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(unwind(Some(LOW)))
            .step(&fixture, &fixture)
            .unwrap(),
    );
    if let HandlerContexts::Unwind { current } = &mut invocation.contexts {
        current.gpr[REG_RBX] = 0x1234;
    }
    match invocation.returned(1).unwrap() {
        WalkStep::Complete(WalkOutcome::TargetReached { context, .. }) => {
            assert_eq!(context.gpr[REG_RBX], 0x1234)
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn target_without_language_handler_still_uses_current() {
    let fixture = Fixture::new(0);
    match fixture
        .walk(unwind(Some(LOW)))
        .step(&fixture, &fixture)
        .unwrap()
    {
        WalkStep::Complete(WalkOutcome::TargetReached { context, .. }) => {
            assert_eq!(context.gpr[REG_RBX], 0x33)
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn unwind_rejects_continue_execution_and_nested_exception() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    for raw in [0, 2, 10] {
        let invocation = invoke(
            fixture
                .walk(unwind(Some(LOW)))
                .step(&fixture, &fixture)
                .unwrap(),
        );
        assert_eq!(
            invocation.returned(raw).unwrap_err(),
            WalkError::InvalidDisposition(raw)
        );
    }
}

#[test]
fn search_nested_region_reaches_its_outer_handler_then_clears() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    invocation.establisher_frame = LOW + 0x20;
    let walk = continued(invocation.returned(2).unwrap());
    let invocation = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_ne!(invocation.exception.flags & EXCEPTION_NESTED_CALL, 0);
    let walk = continued(invocation.returned(1).unwrap());
    match walk.step(&fixture, &fixture).unwrap() {
        WalkStep::Complete(WalkOutcome::Unhandled {
            exception,
            context: result,
        }) => {
            assert_eq!(exception.flags & EXCEPTION_NESTED_CALL, 0);
            assert_eq!(result, context());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn nested_exception_rejects_out_of_stack_dispatcher_frame() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    invocation.establisher_frame = HIGH + 0x10;
    assert_eq!(invocation.returned(2).unwrap_err(), WalkError::BadStack);
}

#[test]
fn wrong_context_contract_is_not_accepted() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    invocation.contexts = HandlerContexts::Unwind { current: context() };
    assert_eq!(
        invocation.returned(1).unwrap_err(),
        WalkError::InvalidHandlerContexts
    );
}

#[test]
fn search_follows_returned_dispatcher_context() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    if let HandlerContexts::Search { unwound, .. } = &mut invocation.contexts {
        unwound.set_rsp(HIGH);
    }
    let walk = continued(invocation.returned(1).unwrap());
    assert!(matches!(
        walk.step(&fixture, &fixture).unwrap(),
        WalkStep::Complete(WalkOutcome::Unhandled { .. })
    ));
}

#[test]
fn exit_unwind_finishes_with_second_chance_not_a_jump() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    let mut walk = fixture.walk(unwind(None));
    for _ in 0..2 {
        let invocation = invoke(walk.step(&fixture, &fixture).unwrap());
        assert_eq!(
            invocation.exception.flags,
            EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND
        );
        walk = continued(invocation.returned(1).unwrap());
    }
    match walk.step(&fixture, &fixture).unwrap() {
        WalkStep::Complete(WalkOutcome::SecondChance {
            context, reason, ..
        }) => {
            assert_eq!(reason, SecondChanceReason::ExitUnwind);
            assert_eq!(context.rip, BASE + 0x310);
            assert_eq!(context.rsp(), HIGH);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn unfound_target_is_not_successful_unwind() {
    let fixture = Fixture::new(0);
    let mut walk = fixture.walk(unwind(Some(HIGH)));
    for _ in 0..2 {
        walk = continued(walk.step(&fixture, &fixture).unwrap());
    }
    assert!(matches!(
        walk.step(&fixture, &fixture).unwrap(),
        WalkStep::Complete(WalkOutcome::SecondChance {
            reason: SecondChanceReason::TargetNotFound,
            ..
        })
    ));
}

#[test]
fn passing_target_fails_with_bad_stack() {
    let fixture = Fixture::new(0);
    let walk = fixture.walk(unwind(Some(LOW + 0x10)));
    let walk = continued(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(
        walk.step(&fixture, &fixture).unwrap_err(),
        WalkError::BadStack
    );
}

#[test]
fn leaf_frames_are_bounded_and_do_not_invent_a_target_handler_frame() {
    let mut fixture = Fixture::new(0);
    fixture.functions.clear();
    fixture.stack.insert(LOW, BASE + 0x500);
    let walk = continued(
        fixture
            .walk(unwind(Some(LOW)))
            .step(&fixture, &fixture)
            .unwrap(),
    );
    assert_eq!(walk.state.current.rsp(), LOW + 8);
    assert_eq!(walk.state.current.rip, BASE + 0x500);
}

#[test]
fn unreadable_leaf_return_is_explicit_failure() {
    let mut fixture = Fixture::new(0);
    fixture.functions.clear();
    assert_eq!(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap_err(),
        WalkError::StackRead
    );
}

#[test]
fn malformed_nonleaf_unwind_is_not_a_leaf_fallback() {
    let mut fixture = Fixture::new(0);
    fixture.image[0x1000] = 0xff;
    assert_eq!(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap_err(),
        WalkError::UnwindData
    );
    assert_eq!(fixture.stack_reads.get(), 0);
}

#[test]
fn same_control_pc_and_unchanged_stack_cannot_spin() {
    let mut fixture = Fixture::new(0);
    // A machine frame can restore arbitrary RSP, including the unchanged frame.
    fixture.image[0x1000..0x1008].copy_from_slice(&[1, 1, 1, 0, 1, 0x0a, 0, 0]);
    fixture.stack.insert(LOW, BASE + 0x110);
    fixture.stack.insert(LOW + 0x18, LOW);
    assert_eq!(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap_err(),
        WalkError::BadFunctionTable
    );
}

#[test]
fn recursive_search_accepts_identical_control_pc_with_advancing_stack() {
    let mut fixture = Fixture::new(unw_flag::EHANDLER);
    fixture.stack.insert(LOW + 0x18, BASE + 0x110);
    let first = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    let walk = continued(first.returned(1).unwrap());
    let second = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(second.control_pc, BASE + 0x110);
    assert_eq!(second.establisher_frame, LOW + 0x20);
    assert!(matches!(
        second.returned(0).unwrap(),
        WalkStep::Complete(WalkOutcome::Handled { .. })
    ));
}

#[test]
fn recursive_unwind_accepts_identical_control_pc_and_reaches_outer_target() {
    let mut fixture = Fixture::new(unw_flag::UHANDLER);
    fixture.stack.insert(LOW + 0x18, BASE + 0x110);
    let first = invoke(
        fixture
            .walk(unwind(Some(LOW + 0x20)))
            .step(&fixture, &fixture)
            .unwrap(),
    );
    let walk = continued(first.returned(1).unwrap());
    let second = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(second.control_pc, BASE + 0x110);
    assert_eq!(second.establisher_frame, LOW + 0x20);
    match second.returned(1).unwrap() {
        WalkStep::Complete(WalkOutcome::TargetReached { context, .. }) => {
            assert_eq!(context.rsp(), LOW + 0x20);
            assert_eq!(context.gpr[REG_RBX], 0x55);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn image_admission_errors_never_pop_leaf_stack_or_produce_handler() {
    for error in [
        ExceptionImageError::UnknownImage,
        ExceptionImageError::UnreadableImage,
        ExceptionImageError::CorruptFunctionTable,
    ] {
        let mut fixture = Fixture::new(unw_flag::EHANDLER);
        fixture.image_error = Some(error);
        assert_eq!(
            fixture
                .walk(WalkMode::Search)
                .step(&fixture, &fixture)
                .unwrap_err(),
            WalkError::ImageLookup(error)
        );
        assert_eq!(fixture.stack_reads.get(), 0);
    }
}

#[test]
fn returned_pc_is_classified_before_reading_next_stack_frame() {
    let mut fixture = Fixture::new(0);
    fixture.stack.insert(LOW + 0x18, 0xdead_beef);
    let walk = continued(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    let reads = fixture.stack_reads.get();
    assert_eq!(
        walk.step(&fixture, &fixture).unwrap_err(),
        WalkError::ImageLookup(ExceptionImageError::UnknownImage)
    );
    assert_eq!(fixture.stack_reads.get(), reads);
}

#[test]
fn handler_modified_pc_is_classified_before_reading_next_stack_frame() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    if let HandlerContexts::Search { unwound, .. } = &mut invocation.contexts {
        unwound.rip = 0xdead_beef;
    }
    let walk = continued(invocation.returned(1).unwrap());
    let reads = fixture.stack_reads.get();
    assert_eq!(
        walk.step(&fixture, &fixture).unwrap_err(),
        WalkError::ImageLookup(ExceptionImageError::UnknownImage)
    );
    assert_eq!(fixture.stack_reads.get(), reads);
}

#[test]
fn interleaved_handler_invocations_resume_only_their_own_private_walk() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    let mut first = invoke(
        fixture
            .walk(unwind(Some(LOW)))
            .step(&fixture, &fixture)
            .unwrap(),
    );
    let second_mode = WalkMode::Unwind {
        target_frame: Some(LOW),
        target_ip: BASE + 0x600,
        return_value: 777,
    };
    let mut second = invoke(fixture.walk(second_mode).step(&fixture, &fixture).unwrap());
    // These are handler-visible dispatcher fields, not continuation authority.
    first.target_ip = second.target_ip;
    second.target_ip = BASE + 0x700;
    for (invocation, target_ip, return_value) in
        [(second, BASE + 0x600, 777), (first, BASE + 0x700, 42)]
    {
        match invocation.returned(1).unwrap() {
            WalkStep::Complete(WalkOutcome::TargetReached { context, .. }) => {
                assert_eq!(context.rip, target_ip);
                assert_eq!(context.gpr[REG_RAX], return_value);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn frame_budget_is_a_hard_error() {
    let fixture = Fixture::new(0);
    let walk = ExceptionWalk::new(WalkMode::Search, record(), context(), LOW, HIGH, 1).unwrap();
    let walk = continued(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(
        walk.step(&fixture, &fixture).unwrap_err(),
        WalkError::FrameLimit
    );
}

#[test]
fn constructor_rejects_invalid_bounds_budget_stack_and_target() {
    assert_eq!(
        ExceptionWalk::new(WalkMode::Search, record(), context(), HIGH, LOW, 1).unwrap_err(),
        WalkError::InvalidStackBounds
    );
    assert_eq!(
        ExceptionWalk::new(WalkMode::Search, record(), context(), LOW, HIGH, 0).unwrap_err(),
        WalkError::InvalidBudget
    );
    let mut invalid = context();
    invalid.set_rsp(LOW + 1);
    assert_eq!(
        ExceptionWalk::new(WalkMode::Search, record(), invalid, LOW, HIGH, 1).unwrap_err(),
        WalkError::BadStack
    );
    for target in [LOW - 16, HIGH + 16, LOW + 8] {
        assert_eq!(
            ExceptionWalk::new(unwind(Some(target)), record(), context(), LOW, HIGH, 1)
                .unwrap_err(),
            WalkError::BadStack
        );
    }
}

#[test]
fn unwind_consolidate_is_explicitly_not_implemented() {
    let mut exception = record();
    exception.code = 0x8000_0029;
    assert_eq!(
        ExceptionWalk::new(unwind(Some(LOW)), exception, context(), LOW, HIGH, 1).unwrap_err(),
        WalkError::UnsupportedUnwindConsolidate
    );
}

#[test]
fn handler_record_mutations_are_preserved() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    invocation.exception.code = 0xe123_4567;
    invocation.exception.information.push(123);
    match invocation.returned(0).unwrap() {
        WalkStep::Complete(WalkOutcome::Handled { exception, .. }) => {
            assert_eq!(exception.code, 0xe123_4567);
            assert_eq!(exception.information, [123]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn handler_cannot_introduce_unsupported_consolidate_restore() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(unwind(Some(LOW)))
            .step(&fixture, &fixture)
            .unwrap(),
    );
    invocation.exception.code = 0x8000_0029;
    assert_eq!(
        invocation.returned(1).unwrap_err(),
        WalkError::UnsupportedUnwindConsolidate
    );
}

#[test]
fn current_is_not_adopted_on_invalid_unwind_disposition() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(unwind(Some(LOW)))
            .step(&fixture, &fixture)
            .unwrap(),
    );
    if let HandlerContexts::Unwind { current } = &mut invocation.contexts {
        current.set_rsp(0);
    }
    assert_eq!(
        invocation.returned(9).unwrap_err(),
        WalkError::InvalidDisposition(9)
    );
}

#[test]
fn invalid_handler_target_context_cannot_be_restored() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    let mut invocation = invoke(
        fixture
            .walk(unwind(Some(LOW)))
            .step(&fixture, &fixture)
            .unwrap(),
    );
    if let HandlerContexts::Unwind { current } = &mut invocation.contexts {
        current.set_rsp(HIGH + 8);
    }
    assert_eq!(invocation.returned(1).unwrap_err(), WalkError::BadStack);
}

#[test]
fn search_uses_exception_address_as_first_control_pc() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut initial = context();
    initial.rip = BASE + 0x900;
    let walk = ExceptionWalk::new(WalkMode::Search, record(), initial, LOW, HIGH, 8).unwrap();
    let invocation = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(invocation.control_pc, BASE + 0x110);
}

#[test]
fn search_moves_populated_parameter_allocation_through_handlers_and_completion() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut exception = record();
    exception.information = Vec::with_capacity(15);
    exception.information.extend_from_slice(&[1, 2, 3]);
    let pointer = exception.information.as_ptr();
    let capacity = exception.information.capacity();
    let walk = ExceptionWalk::new(WalkMode::Search, exception, context(), LOW, HIGH, 8).unwrap();
    let mut first = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(first.exception.information.as_ptr(), pointer);
    assert_eq!(first.exception.information.capacity(), capacity);
    first.exception.information.push(4);
    let walk = continued(first.returned(1).unwrap());
    let mut second = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(second.exception.information.as_ptr(), pointer);
    assert_eq!(second.exception.information.capacity(), capacity);
    assert_eq!(second.exception.information, [1, 2, 3, 4]);
    second.exception.information.push(5);
    match second.returned(0).unwrap() {
        WalkStep::Complete(WalkOutcome::Handled { exception, .. }) => {
            assert_eq!(exception.information.as_ptr(), pointer);
            assert_eq!(exception.information.capacity(), capacity);
            assert_eq!(exception.information, [1, 2, 3, 4, 5]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn unwind_moves_populated_parameter_allocation_through_target_handler() {
    let fixture = Fixture::new(unw_flag::UHANDLER);
    let mut exception = record();
    exception.information = Vec::with_capacity(15);
    exception.information.extend_from_slice(&[7, 8, 9]);
    let pointer = exception.information.as_ptr();
    let capacity = exception.information.capacity();
    let walk =
        ExceptionWalk::new(unwind(Some(LOW + 0x20)), exception, context(), LOW, HIGH, 8).unwrap();
    let first = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(first.exception.information.as_ptr(), pointer);
    let walk = continued(first.returned(1).unwrap());
    let mut second = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(second.exception.information.as_ptr(), pointer);
    second.exception.information[1] = 88;
    match second.returned(1).unwrap() {
        WalkStep::Complete(WalkOutcome::TargetReached { exception, .. }) => {
            assert_eq!(exception.information.as_ptr(), pointer);
            assert_eq!(exception.information.capacity(), capacity);
            assert_eq!(exception.information, [7, 88, 9]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn handler_replaced_record_becomes_the_only_record_owner() {
    let fixture = Fixture::new(unw_flag::EHANDLER);
    let mut first = invoke(
        fixture
            .walk(WalkMode::Search)
            .step(&fixture, &fixture)
            .unwrap(),
    );
    let mut replacement = record();
    replacement.code = 0xe123_4567;
    replacement.information.extend_from_slice(&[101, 202]);
    let pointer = replacement.information.as_ptr();
    first.exception = replacement;
    let walk = continued(first.returned(1).unwrap());
    let second = invoke(walk.step(&fixture, &fixture).unwrap());
    assert_eq!(second.exception.code, 0xe123_4567);
    assert_eq!(second.exception.information.as_ptr(), pointer);
    match second.returned(0).unwrap() {
        WalkStep::Complete(WalkOutcome::Handled { exception, .. }) => {
            assert_eq!(exception.code, 0xe123_4567);
            assert_eq!(exception.information.as_ptr(), pointer);
            assert_eq!(exception.information, [101, 202]);
        }
        other => panic!("unexpected {other:?}"),
    }
}
