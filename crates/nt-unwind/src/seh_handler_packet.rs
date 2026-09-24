//! Owned native records prepared for one hosted x64 language-handler call.

use core::mem::{offset_of, size_of};

use crate::{
    exception_walk::{CollisionDispatcher, HandlerContexts, HandlerInvocation},
    raw_context::RawContext,
    raw_exception::{
        RawDispatcherContext, RawExceptionPointers, RawExceptionRecord,
        EXCEPTION_MAXIMUM_PARAMETERS,
    },
    Context, ExceptionRecord, RuntimeFunction, StackReader,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandlerPacketError {
    NotSearch,
    NotUnwind,
    Address,
    InformationCount,
    ChangedPointers,
    ChangedDispatcher,
    InvalidContext,
    CollisionContext,
    CollisionFunction,
}

/// The component allocates this 16-byte-aligned packet on its paused thread's stack. The
/// executive writes it only through the authenticated physical stack alias before an Invoke
/// command. Pointers inside are component VAs, never executive aliases.
#[repr(C, align(16))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SehHandlerPacket {
    pub exception: RawExceptionRecord,
    pub exception_pointers: RawExceptionPointers,
    exception_pointers_padding: u64,
    pub original_context: RawContext,
    pub unwound_context: RawContext,
    pub dispatcher: RawDispatcherContext,
    pub function: RuntimeFunction,
    function_padding: u32,
    /// Validated entrypoints in this instance's sealed SEH support image, not handler input.
    pub filter_wrapper: u64,
    pub finally_wrapper: u64,
    pub search_wrapper: u64,
    pub unwind_wrapper: u64,
    pub token: u64,
    pub resume_va: u64,
}

impl SehHandlerPacket {
    pub fn prepare_search(
        captured: &RawContext,
        invocation: &HandlerInvocation,
        packet_va: u64,
    ) -> Result<Self, HandlerPacketError> {
        let HandlerContexts::Search { exception, unwound } = invocation.contexts else {
            return Err(HandlerPacketError::NotSearch);
        };
        Self::prepare(captured, invocation, packet_va, exception, unwound)
    }

    /// The unwind callback receives Current as its third argument, while its dispatcher points
    /// at the separately virtually unwound Previous context. The caller supplies that Previous
    /// from the still-owned walk continuation; it must not substitute Current for both pointers.
    pub fn prepare_unwind(
        captured: &RawContext,
        invocation: &HandlerInvocation,
        dispatcher_unwound: Context,
        packet_va: u64,
    ) -> Result<Self, HandlerPacketError> {
        let HandlerContexts::Unwind { current } = invocation.contexts else {
            return Err(HandlerPacketError::NotUnwind);
        };
        Self::prepare(captured, invocation, packet_va, current, dispatcher_unwound)
    }

    fn prepare(
        captured: &RawContext,
        invocation: &HandlerInvocation,
        packet_va: u64,
        original: Context,
        unwound: Context,
    ) -> Result<Self, HandlerPacketError> {
        if packet_va == 0 || packet_va & 15 != 0 {
            return Err(HandlerPacketError::Address);
        }
        packet_va
            .checked_add(size_of::<Self>() as u64)
            .ok_or(HandlerPacketError::Address)?;
        if invocation.exception.information.len() > EXCEPTION_MAXIMUM_PARAMETERS {
            return Err(HandlerPacketError::InformationCount);
        }
        let mut record = RawExceptionRecord::software_raise(
            invocation.exception.code,
            invocation.exception.flags,
            invocation.exception.address,
        );
        record.parameter_count = invocation.exception.information.len() as u32;
        record.information[..invocation.exception.information.len()]
            .copy_from_slice(&invocation.exception.information);

        let mut original_context = captured.clone();
        original_context.update_from_context(&original);
        let mut unwound_context = captured.clone();
        unwound_context.update_from_context(&unwound);

        let address = |offset: usize| {
            packet_va
                .checked_add(offset as u64)
                .ok_or(HandlerPacketError::Address)
        };
        let exception_record = address(offset_of!(Self, exception))?;
        let original_record = address(offset_of!(Self, original_context))?;
        let unwound_record = address(offset_of!(Self, unwound_context))?;
        let function_entry = address(offset_of!(Self, function))?;
        Ok(Self {
            exception: record,
            exception_pointers: RawExceptionPointers {
                exception_record,
                context_record: original_record,
            },
            exception_pointers_padding: 0,
            original_context,
            unwound_context,
            dispatcher: RawDispatcherContext {
                control_pc: invocation.control_pc,
                image_base: invocation.image_base,
                function_entry,
                establisher_frame: invocation.establisher_frame,
                target_ip: invocation.target_ip,
                context_record: unwound_record,
                language_handler: invocation.handler,
                handler_data: invocation.handler_data,
                history_table: 0,
                scope_index: invocation.scope_index,
                reserved: 0,
            },
            function: invocation.function,
            function_padding: 0,
            filter_wrapper: 0,
            finally_wrapper: 0,
            search_wrapper: 0,
            unwind_wrapper: 0,
            token: 0,
            resume_va: 0,
        })
    }

    /// Supply wrapper VAs only after the caller has admitted them in this exact support image.
    pub fn set_wrappers(
        &mut self,
        filter: u64,
        finally: u64,
        search: u64,
        unwind: u64,
        resume: u64,
    ) -> Result<(), HandlerPacketError> {
        if filter == 0 || finally == 0 || search == 0 || unwind == 0 || resume == 0 {
            return Err(HandlerPacketError::Address);
        }
        self.filter_wrapper = filter;
        self.finally_wrapper = finally;
        self.search_wrapper = search;
        self.unwind_wrapper = unwind;
        self.resume_va = resume;
        Ok(())
    }

    pub fn set_token(&mut self, token: u64) -> Result<(), HandlerPacketError> {
        if token == 0 {
            return Err(HandlerPacketError::Address);
        }
        self.token = token;
        Ok(())
    }

    /// Copy only the handler's published values into the one-shot invocation. The expected
    /// packet is the executive's pre-call copy; `returned` is copied from the same physical stack
    /// lease after the callback. A collided wrapper may replace its dispatcher with an older one,
    /// so its context and function pointers are read through that lease and revalidated by the
    /// walk against the admitted image catalog on the next step.
    pub fn apply_return(
        &self,
        returned: &Self,
        invocation: &mut HandlerInvocation,
        disposition: i32,
        stack: &dyn StackReader,
        stack_low: u64,
        stack_high: u64,
    ) -> Result<(), HandlerPacketError> {
        if returned.exception_pointers != self.exception_pointers {
            return Err(HandlerPacketError::ChangedPointers);
        }
        if returned.filter_wrapper != self.filter_wrapper
            || returned.finally_wrapper != self.finally_wrapper
            || returned.search_wrapper != self.search_wrapper
            || returned.unwind_wrapper != self.unwind_wrapper
            || returned.token != self.token
            || returned.resume_va != self.resume_va
            || returned.exception_pointers_padding != 0
            || returned.function_padding != 0
        {
            return Err(HandlerPacketError::ChangedDispatcher);
        }
        if returned.exception.parameter_count as usize > EXCEPTION_MAXIMUM_PARAMETERS
            || returned.exception.chained_record != self.exception.chained_record
            || returned.exception.alignment != self.exception.alignment
        {
            return Err(HandlerPacketError::InformationCount);
        }
        if returned.original_context.context_flags() != self.original_context.context_flags()
            || returned.unwound_context.context_flags() != self.unwound_context.context_flags()
        {
            return Err(HandlerPacketError::InvalidContext);
        }
        if disposition != 3
            && (returned.function != self.function
                || returned.dispatcher.image_base != self.dispatcher.image_base
                || returned.dispatcher.function_entry != self.dispatcher.function_entry
                || returned.dispatcher.target_ip != self.dispatcher.target_ip
                || returned.dispatcher.context_record != self.dispatcher.context_record
                || returned.dispatcher.language_handler != self.dispatcher.language_handler
                || returned.dispatcher.handler_data != self.dispatcher.handler_data
                || returned.dispatcher.history_table != self.dispatcher.history_table
                || returned.dispatcher.reserved != self.dispatcher.reserved)
        {
            return Err(HandlerPacketError::ChangedDispatcher);
        }

        let collision = if disposition == 3 {
            let context = RawContext::capture_bounded(
                stack,
                returned.dispatcher.context_record,
                stack_low,
                stack_high,
            )
            .map_err(|_| HandlerPacketError::CollisionContext)?;
            let function = read_collision_function(
                stack,
                returned.dispatcher.function_entry,
                stack_low,
                stack_high,
            )?;
            Some(CollisionDispatcher {
                control_pc: returned.dispatcher.control_pc,
                image_base: returned.dispatcher.image_base,
                function,
                establisher_frame: returned.dispatcher.establisher_frame,
                handler: returned.dispatcher.language_handler,
                handler_data: returned.dispatcher.handler_data,
                scope_index: returned.dispatcher.scope_index,
                context: context.to_context(),
            })
        } else {
            None
        };

        let count = returned.exception.parameter_count as usize;
        invocation.exception = ExceptionRecord {
            code: returned.exception.code,
            flags: returned.exception.flags,
            address: returned.exception.address,
            information: returned.exception.information[..count].to_vec(),
        };
        invocation.establisher_frame = returned.dispatcher.establisher_frame;
        invocation.scope_index = returned.dispatcher.scope_index;
        invocation.contexts = match invocation.contexts {
            HandlerContexts::Search { .. } => HandlerContexts::Search {
                exception: returned.original_context.to_context(),
                unwound: returned.unwound_context.to_context(),
            },
            HandlerContexts::Unwind { .. } => HandlerContexts::Unwind {
                current: returned.original_context.to_context(),
            },
        };
        invocation.collision = collision;
        Ok(())
    }
}

fn read_collision_function(
    stack: &dyn StackReader,
    address: u64,
    low: u64,
    high: u64,
) -> Result<RuntimeFunction, HandlerPacketError> {
    let end = address
        .checked_add(16)
        .ok_or(HandlerPacketError::CollisionFunction)?;
    if address & 7 != 0 || address < low || end > high {
        return Err(HandlerPacketError::CollisionFunction);
    }
    let first = stack
        .read_u64(address)
        .ok_or(HandlerPacketError::CollisionFunction)?;
    let second = stack
        .read_u64(address + 8)
        .ok_or(HandlerPacketError::CollisionFunction)?;
    Ok(RuntimeFunction {
        begin: first as u32,
        end: (first >> 32) as u32,
        unwind_info: second as u32,
    })
}

const _: () = {
    assert!(size_of::<SehHandlerPacket>() == 0xae0);
    assert!(offset_of!(SehHandlerPacket, exception) == 0);
    assert!(offset_of!(SehHandlerPacket, exception_pointers) == 0x98);
    assert!(offset_of!(SehHandlerPacket, exception_pointers_padding) == 0xa8);
    assert!(offset_of!(SehHandlerPacket, original_context) == 0xb0);
    assert!(offset_of!(SehHandlerPacket, unwound_context) == 0x580);
    assert!(offset_of!(SehHandlerPacket, dispatcher) == 0xa50);
    assert!(offset_of!(SehHandlerPacket, function) == 0xaa0);
    assert!(offset_of!(SehHandlerPacket, function_padding) == 0xaac);
    assert!(offset_of!(SehHandlerPacket, filter_wrapper) == 0xab0);
    assert!(offset_of!(SehHandlerPacket, finally_wrapper) == 0xab8);
    assert!(offset_of!(SehHandlerPacket, search_wrapper) == 0xac0);
    assert!(offset_of!(SehHandlerPacket, unwind_wrapper) == 0xac8);
    assert!(offset_of!(SehHandlerPacket, token) == 0xad0);
    assert!(offset_of!(SehHandlerPacket, resume_va) == 0xad8);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        exception_walk::{ExceptionFunction, ExceptionImageError, ExceptionImageReader, ExceptionWalk, WalkMode, WalkStep},
        raw_context::CONTEXT_AMD64_FULL_SEGMENTS,
        ImageReader, EXCEPTION_UNWINDING, REG_RBX,
    };

    const BASE: u64 = 0x10_0000;
    const LOW: u64 = 0x1000;
    const HIGH: u64 = 0x3000;

    struct Frame;

    impl ImageReader for Frame {
        fn lookup_function(&self, _pc: u64) -> Option<(u64, RuntimeFunction)> {
            Some((BASE, RuntimeFunction { begin: 0x100, end: 0x180, unwind_info: 0x1000 }))
        }

        fn read_u8(&self, _base: u64, rva: u32) -> Option<u8> {
            let info = [0x19, 4, 2, 0, 4, 0x12, 1, 0x30, 0, 8, 0, 0];
            if rva >= 0x1100 {
                None
            } else {
                Some(info.get(rva.wrapping_sub(0x1000) as usize).copied().unwrap_or(0x90))
            }
        }
    }

    impl ExceptionImageReader for Frame {
        fn lookup_exception_function(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
            let (image_base, function) = self.lookup_function(pc).unwrap();
            Ok(ExceptionFunction::Function { image_base, function })
        }
    }

    impl StackReader for Frame {
        fn read_u64(&self, address: u64) -> Option<u64> {
            match address {
                address if address == LOW + 0x10 => Some(0x55),
                address if address == LOW + 0x18 => Some(BASE + 0x210),
                _ => None,
            }
        }
    }

    fn invocation(mode: WalkMode) -> HandlerInvocation {
        let mut context = Context::default();
        context.rip = BASE + 0x110;
        context.set_rsp(LOW);
        context.gpr[REG_RBX] = 0x33;
        let record = ExceptionRecord { code: 0xc000_0022, flags: 0, address: context.rip, information: Default::default() };
        let walk = ExceptionWalk::new(mode, record, context, LOW, HIGH, 4).unwrap();
        match walk.step(&Frame, &Frame).unwrap() {
            WalkStep::Invoke(invocation) => invocation,
            other => panic!("expected handler invocation, got {other:?}"),
        }
    }

    fn capture() -> RawContext {
        let mut raw = RawContext::zeroed();
        raw.set_context_flags(CONTEXT_AMD64_FULL_SEGMENTS);
        raw
    }

    #[test]
    fn unwind_packet_keeps_current_and_previous_distinct() {
        let invocation = invocation(WalkMode::Unwind { target_frame: Some(LOW), target_ip: BASE + 0x700, return_value: 42 });
        let mut previous = Context::default();
        previous.rip = BASE + 0x210;
        previous.set_rsp(LOW + 0x20);
        let packet = SehHandlerPacket::prepare_unwind(&capture(), &invocation, previous, 0x8000).unwrap();
        assert_eq!(packet.exception.flags, EXCEPTION_UNWINDING | crate::EXCEPTION_TARGET_UNWIND);
        assert_eq!(packet.original_context.rip(), BASE + 0x110);
        assert_eq!(packet.unwound_context.rip(), BASE + 0x210);
        assert_eq!(packet.dispatcher.context_record, 0x8000 + offset_of!(SehHandlerPacket, unwound_context) as u64);
        assert_eq!(SehHandlerPacket::prepare_search(&capture(), &invocation, 0x8000), Err(HandlerPacketError::NotSearch));
    }

    #[test]
    fn ordinary_return_publishes_mutations_but_rejects_pointer_redirects() {
        let mut invocation = invocation(WalkMode::Search);
        let mut packet = SehHandlerPacket::prepare_search(&capture(), &invocation, 0x8000).unwrap();
        assert_eq!(packet.set_wrappers(0, 2, 3, 4, 5), Err(HandlerPacketError::Address));
        assert_eq!(packet.set_token(0), Err(HandlerPacketError::Address));
        packet.set_wrappers(0x1100, 0x1200, 0x1300, 0x1400, 0x1500).unwrap();
        packet.set_token(9).unwrap();
        let mut changed = packet.clone();
        changed.dispatcher.context_record = 0x9000;
        assert_eq!(packet.apply_return(&changed, &mut invocation, 1, &Frame, LOW, HIGH), Err(HandlerPacketError::ChangedDispatcher));
        changed = packet.clone();
        changed.exception_pointers.context_record = 0x9000;
        assert_eq!(packet.apply_return(&changed, &mut invocation, 1, &Frame, LOW, HIGH), Err(HandlerPacketError::ChangedPointers));
        changed = packet.clone();
        changed.search_wrapper = 0x1500;
        assert_eq!(packet.apply_return(&changed, &mut invocation, 1, &Frame, LOW, HIGH), Err(HandlerPacketError::ChangedDispatcher));
        changed = packet.clone();
        changed.token = 10;
        assert_eq!(packet.apply_return(&changed, &mut invocation, 1, &Frame, LOW, HIGH), Err(HandlerPacketError::ChangedDispatcher));
        changed = packet.clone();
        changed.original_context.set_rip(BASE + 0x120);
        changed.unwound_context.set_gpr(REG_RBX, 0x77);
        changed.exception.flags = 1;
        changed.dispatcher.establisher_frame = LOW + 0x20;
        packet.apply_return(&changed, &mut invocation, 2, &Frame, LOW, HIGH).unwrap();
        assert_eq!(invocation.exception.flags, 1);
        assert_eq!(invocation.establisher_frame, LOW + 0x20);
        let HandlerContexts::Search { exception, unwound } = invocation.contexts else { panic!("search context") };
        assert_eq!(exception.rip, BASE + 0x120);
        assert_eq!(unwound.gpr[REG_RBX], 0x77);
    }
}
