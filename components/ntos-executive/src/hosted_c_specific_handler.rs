//! Component-side C language handler for hosted PE drivers.
//!
//! The executive owns the packet; filters and termination handlers execute in the driver's VSpace
//! on the interrupted thread. Image and scope admission comes from that instance's sealed snapshot.

use core::mem::offset_of;
use nt_unwind::{
    exception_snapshot::SealedExceptionView, exception_walk::ExceptionImageReader, next_c_scope,
    seh_handler_packet::SehHandlerPacket, CScopeAction, Disposition, EXCEPTION_NONCONTINUABLE,
    EXCEPTION_UNWIND,
};

use super::hosted_exception_images;

#[repr(C)]
struct ExceptionPointers {
    record: u64,
    context: u64,
}

/// Native x64 exception-routine ABI. The dispatcher pointer is the one embedded in a packet
/// written under the executive's authenticated stack lease.
pub(super) unsafe fn dispatch(
    exception_record: u64,
    establisher_frame: u64,
    context_record: u64,
    dispatcher_context: u64,
) -> i32 {
    let packet_va = dispatcher_context
        .checked_sub(offset_of!(SehHandlerPacket, dispatcher) as u64)
        .filter(|address| *address != 0 && *address & 15 == 0)
        .expect("hosted C handler dispatcher is not in an aligned packet");
    if exception_record != packet_va + offset_of!(SehHandlerPacket, exception) as u64
        || context_record == 0
    {
        panic!("hosted C handler received mismatched exception records");
    }
    let packet = packet_va as *mut SehHandlerPacket;
    let dispatcher = unsafe { core::ptr::addr_of_mut!((*packet).dispatcher) };
    let image_base =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).image_base)) };
    let control_pc =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).control_pc)) };
    let target_ip =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).target_ip)) };
    let handler_data =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).handler_data)) };
    let flags =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*packet).exception.flags)) };
    let filter_wrapper =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*packet).filter_wrapper)) };
    let finally_wrapper =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*packet).finally_wrapper)) };

    unsafe {
        hosted_exception_images::with_component_view(|view| {
            dispatch_with_view(
                view,
                packet_va,
                establisher_frame,
                context_record,
                dispatcher,
                image_base,
                control_pc,
                target_ip,
                handler_data,
                flags,
                filter_wrapper,
                finally_wrapper,
            )
        })
    }
    .expect("hosted C handler lacks its sealed exception snapshot")
}

fn executable(view: &SealedExceptionView<'_>, address: u64) -> bool {
    address != 0 && view.lookup_exception_function(address).is_ok()
}

#[allow(clippy::too_many_arguments)]
fn dispatch_with_view(
    view: &SealedExceptionView<'_>,
    packet_va: u64,
    establisher_frame: u64,
    context_record: u64,
    dispatcher: *mut nt_unwind::raw_exception::RawDispatcherContext,
    image_base: u64,
    control_pc: u64,
    target_ip: u64,
    handler_data: u64,
    flags: u32,
    filter_wrapper: u64,
    finally_wrapper: u64,
) -> i32 {
    if !executable(view, control_pc)
        || !executable(view, filter_wrapper)
        || !executable(view, finally_wrapper)
    {
        panic!("hosted C handler PC or support wrapper is not in sealed executable code");
    }
    let scopes = view
        .read_c_scope_table(image_base, handler_data)
        .expect("hosted C handler scope table was not sealed");
    let pc_rva = control_pc
        .checked_sub(image_base)
        .expect("hosted C handler PC precedes its image");
    let target_rva = target_ip.checked_sub(image_base).unwrap_or(u64::MAX);
    loop {
        let mut index =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*dispatcher).scope_index)) };
        let action = next_c_scope(pc_rva, target_rva, flags, scopes.len(), &mut index, |i| {
            scopes.get(i).expect("sealed C scope index")
        });
        unsafe {
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*dispatcher).scope_index), index)
        };
        match action {
            CScopeAction::ContinueSearch => return Disposition::ContinueSearch.as_raw(),
            CScopeAction::Filter {
                handler_rva,
                target_rva,
                ..
            } => {
                let filter = image_base
                    .checked_add(u64::from(handler_rva))
                    .filter(|address| executable(view, *address))
                    .expect("hosted C filter is not sealed executable code");
                let target = image_base
                    .checked_add(u64::from(target_rva))
                    .filter(|address| executable(view, *address))
                    .expect("hosted C target is not sealed executable code");
                let pointers = ExceptionPointers {
                    record: packet_va + offset_of!(SehHandlerPacket, exception) as u64,
                    context: context_record,
                };
                let wrapper: unsafe extern "win64" fn(
                    u64,
                    *const ExceptionPointers,
                    u64,
                    u64,
                ) -> i32 = unsafe { core::mem::transmute(filter_wrapper as usize) };
                let verdict =
                    unsafe { wrapper(filter, &pointers, establisher_frame, dispatcher as u64) };
                if verdict < 0 {
                    if flags & EXCEPTION_NONCONTINUABLE != 0 {
                        panic!("hosted C filter resumed a noncontinuable exception");
                    }
                    return Disposition::ContinueExecution.as_raw();
                }
                if verdict > 0 {
                    execute_handler_unwind(packet_va, establisher_frame, target);
                }
            }
            CScopeAction::ExecuteHandler { target_rva, .. } => {
                let target = image_base
                    .checked_add(u64::from(target_rva))
                    .filter(|address| executable(view, *address))
                    .expect("hosted C target is not sealed executable code");
                execute_handler_unwind(packet_va, establisher_frame, target);
            }
            CScopeAction::Finally {
                handler_rva,
                end_rva,
            } => {
                if flags & EXCEPTION_UNWIND == 0 {
                    panic!("hosted C termination selected outside unwind");
                }
                let finalizer = image_base
                    .checked_add(u64::from(handler_rva))
                    .filter(|address| executable(view, *address))
                    .expect("hosted C finalizer is not sealed executable code");
                let end_pc = image_base
                    .checked_add(u64::from(end_rva))
                    .expect("hosted C scope end overflows");
                unsafe {
                    core::ptr::write_unaligned(
                        core::ptr::addr_of_mut!((*dispatcher).control_pc),
                        end_pc,
                    )
                };
                let wrapper: unsafe extern "win64" fn(u64, u64, u64) =
                    unsafe { core::mem::transmute(finally_wrapper as usize) };
                unsafe { wrapper(finalizer, establisher_frame, dispatcher as u64) };
            }
        }
    }
}

fn execute_handler_unwind(packet_va: u64, establisher_frame: u64, target_ip: u64) -> ! {
    super::hosted_seh_component::unwind_request(packet_va, establisher_frame, target_ip)
}
