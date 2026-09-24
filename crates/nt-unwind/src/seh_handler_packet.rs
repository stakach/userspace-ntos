//! Owned native records prepared for one hosted x64 language-handler call.

use core::mem::{offset_of, size_of};

use crate::{
    exception_walk::{HandlerContexts, HandlerInvocation},
    raw_context::RawContext,
    raw_exception::{
        RawDispatcherContext, RawExceptionPointers, RawExceptionRecord,
        EXCEPTION_MAXIMUM_PARAMETERS,
    },
    RuntimeFunction,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandlerPacketError {
    NotSearch,
    Address,
    InformationCount,
}

/// The component allocates this 16-byte-aligned packet on its paused thread's stack. The
/// executive writes it only through the authenticated physical stack alias before an Invoke
/// command. Pointers inside are component VAs, never executive aliases.
#[repr(C, align(16))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SehHandlerPacket {
    pub exception: RawExceptionRecord,
    pub exception_pointers: RawExceptionPointers,
    pub original_context: RawContext,
    pub unwound_context: RawContext,
    pub dispatcher: RawDispatcherContext,
    pub function: RuntimeFunction,
}

impl SehHandlerPacket {
    pub fn prepare_search(
        captured: &RawContext,
        invocation: &HandlerInvocation,
        packet_va: u64,
    ) -> Result<Self, HandlerPacketError> {
        if packet_va == 0 || packet_va & 15 != 0 {
            return Err(HandlerPacketError::Address);
        }
        packet_va
            .checked_add(size_of::<Self>() as u64)
            .ok_or(HandlerPacketError::Address)?;
        let HandlerContexts::Search { exception, unwound } = invocation.contexts else {
            return Err(HandlerPacketError::NotSearch);
        };
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
        original_context.update_from_context(&exception);
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
        })
    }
}

const _: () = {
    assert!(size_of::<SehHandlerPacket>() == 0xab0);
    assert!(offset_of!(SehHandlerPacket, exception) == 0);
    assert!(offset_of!(SehHandlerPacket, exception_pointers) == 0x98);
    assert!(offset_of!(SehHandlerPacket, original_context) == 0xb0);
    assert!(offset_of!(SehHandlerPacket, unwound_context) == 0x580);
    assert!(offset_of!(SehHandlerPacket, dispatcher) == 0xa50);
    assert!(offset_of!(SehHandlerPacket, function) == 0xaa0);
};
