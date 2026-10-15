//! Format captured FSD observations without interleaving component debug fragments.

use super::{dcerpc_ptype_name, DceRpcPduView, PipeCcbView};
use core::fmt::Write;
use nt_printf::record::RecordBuffer;

fn emit(record: &RecordBuffer<2048>) {
    let bytes = if record.overflowed() {
        b"[record-truncated]\n" as &[u8]
    } else {
        record.bytes()
    };
    sel4_rt::print_record(bytes);
}

fn pipe_snapshot(record: &mut RecordBuffer<2048>, tag: &str, view: PipeCcbView) {
    let _ = write!(record, "{tag}");
    for (end, q) in view.q.iter().enumerate() {
        let _ = write!(
            record,
            " q{end}={}/{}/{}/{}/{}",
            q.state, q.bytes, q.entries, q.byte_offset, q.quota_used
        );
    }
}

fn rpc_snapshot(record: &mut RecordBuffer<2048>, pdu: DceRpcPduView) {
    let kind = core::str::from_utf8(dcerpc_ptype_name(pdu.ptype)).expect("static RPC type name");
    let _ = write!(
        record,
        " rpc={kind} call={} frag={} flags=0x{:08x}",
        pdu.call_id, pdu.frag_len, pdu.flags
    );
    if let Some(value) = pdu.assoc_gid {
        let _ = write!(record, " assoc={value}");
    }
    if let Some(value) = pdu.alloc_hint {
        let _ = write!(record, " hint={value}");
    }
    if let Some(value) = pdu.opnum {
        let _ = write!(record, " op={value}");
    }
    if let Some(value) = pdu.fault_status {
        let _ = write!(record, " fault=0x{value:08x}");
    }
    for context in pdu.context_handles.iter().flatten() {
        let u = context.uuid;
        let _ = write!(record,
            " ctx@{} attr={} uuid={{{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            context.offset, context.attributes,
            u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6], u[8], u[9],
            u[10], u[11], u[12], u[13], u[14], u[15]);
    }
}

pub(super) fn pipe_rw(
    major: u64,
    file_id: u64,
    fsctx: u64,
    length: u64,
    status: u32,
    info: u64,
    pdu: Option<DceRpcPduView>,
    before: Option<PipeCcbView>,
    after: Option<PipeCcbView>,
) {
    let mut record = RecordBuffer::<2048>::new();
    let _ = write!(&mut record,
        "[fsd-pipe-rw] major={major} fid=0x{:08x} end={} fsctx=0x{:08x} len={length} status=0x{status:08x} info={info}",
        file_id as u32, file_id & 1, fsctx as u32);
    if let Some(view) = pdu {
        rpc_snapshot(&mut record, view);
    }
    if let Some(view) = before {
        pipe_snapshot(&mut record, " before", view);
    }
    if let Some(view) = after {
        pipe_snapshot(&mut record, " after", view);
    }
    let _ = record.write_str("\n");
    emit(&record);
}

pub(super) fn control_failure(
    fsctl: u32,
    handler: u64,
    device: u64,
    returned: u32,
    irp_status: u32,
    irp_information: u64,
    owner_kind: u64,
    final_status: u32,
    information: u64,
    retained_completion: bool,
) {
    let mut record = RecordBuffer::<2048>::new();
    let _ = writeln!(&mut record,
        "[fsd-control-failure] ioctl=0x{fsctl:08x} handler=0x{handler:016x} device=0x{device:016x} return=0x{returned:08x} irp-status=0x{irp_status:08x} irp-information={irp_information} owner-kind={owner_kind} final=0x{final_status:08x} information={information} retained-completion={}",
        u64::from(retained_completion));
    emit(&record);
}
