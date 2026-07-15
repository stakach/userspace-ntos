use crate::*;
pub(crate) use nt_loader_trace::LoaderOp;
use nt_loader_trace::{LoaderTrace, NO_REGISTRY_SLOT};

const LOADER_TRACE_CAP: usize = 48;

static mut WINLOGON_LOADER_TRACE: LoaderTrace<LOADER_TRACE_CAP> = LoaderTrace::new();

pub(crate) unsafe fn loader_trace_clear() {
    (*core::ptr::addr_of_mut!(WINLOGON_LOADER_TRACE)).clear();
}

pub(crate) unsafe fn loader_trace_record(
    pi: usize,
    op: LoaderOp,
    status: u32,
    registry_slot: Option<usize>,
    input: u64,
    output: u64,
    path: &[u8],
) {
    if pi != 2 {
        return;
    }
    let slot = registry_slot
        .and_then(|slot| u8::try_from(slot).ok())
        .unwrap_or(NO_REGISTRY_SLOT);
    (*core::ptr::addr_of_mut!(WINLOGON_LOADER_TRACE))
        .record(op, status, slot, input, output, path);
}

fn print_op(op: LoaderOp) {
    print_str(match op {
        LoaderOp::QueryAttributesFile => b"qattr",
        LoaderOp::OpenFile => b"open",
        LoaderOp::CreateSection => b"section",
        LoaderOp::MapViewOfSection => b"map",
        LoaderOp::ProtectVirtualMemory => b"protect",
        LoaderOp::FlushInstructionCache => b"flush",
    });
}

fn print_hex64(value: u64) {
    print_str(b"0x");
    for shift in (0..16).rev() {
        let nibble = ((value >> (shift * 4)) & 0xf) as u8;
        debug_put_char(if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        });
    }
}

pub(crate) unsafe fn loader_trace_dump(reg: &nt_dll_registry::Registry) {
    let trace = &*core::ptr::addr_of!(WINLOGON_LOADER_TRACE);
    print_str(b"[ldr-trace] winlogon tail entries=");
    print_u64(trace.len() as u64);
    print_str(b" omitted=");
    print_u64(trace.omitted());
    print_str(b"\n");
    for index in 0..trace.len() {
        let event = trace.get(index).unwrap();
        print_str(b"[ldr-trace] #");
        print_u64(index as u64);
        print_str(b" op=");
        print_op(event.op);
        print_str(b" status=");
        print_hex(event.status);
        print_str(b" repeat=");
        print_u64(event.repetitions as u64);
        if event.registry_slot != NO_REGISTRY_SLOT {
            print_str(b" slot=");
            print_u64(event.registry_slot as u64);
            print_str(b"(");
            print_str(reg.name(event.registry_slot as usize));
            print_str(b")");
        }
        if !event.path().is_empty() {
            print_str(b" path=\"");
            print_str(event.path());
            print_str(b"\"");
        }
        print_str(b" in=");
        print_hex64(event.input);
        print_str(b" out=");
        print_hex64(event.output);
        print_str(b"\n");
    }
    print_str(b"[ldr-trace] first_failure=");
    if let Some(event) = trace.first_failure() {
        print_str(b"op=");
        print_op(event.op);
        print_str(b" status=");
        print_hex(event.status);
        if !event.path().is_empty() {
            print_str(b" path=\"");
            print_str(event.path());
            print_str(b"\"");
        }
    } else {
        print_str(b"none");
    }
    print_str(b"\n");
}
