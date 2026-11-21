//! Bounded trace of the device path a console client takes (#421).
//!
//! Wine's kernelbase AllocConsole opens \Device\ConDrv\Server, opens a reference relative to that
//! handle, issues ConDrv device controls and creates conhost.exe. Boots 44689472419 and
//! 44694366016 log only `Can't allocate console`, so this records, per process generation, each
//! NtCreateFile/NtOpenFile of a \Device\ name or a root-relative name, each
//! NtDeviceIoControlFile code, each process creation and each pended CREATE's completion, with
//! the returned status. Diagnostic only: it reads caller memory after dispatch and changes nothing.
//!
//! There is no global cap. Boot 44841573736 spent a global 512 on the processes before cmd.exe,
//! so the one process the trace exists for logged nothing. Every process generation has its own
//! budgets, which bounds the trace by the processes the boot creates.

use super::*;
use nt_syscall::NativeService;

/// Dispatch records (creates, opens, device controls, process creations) per generation.
const DISPATCHES_PER_PROCESS: u8 = 48;
/// Pended-CREATE records per generation: up to four per open (published, handoff, completed,
/// final), and a console client pends Reference and Connection.
const PENDED_CREATES_PER_PROCESS: u8 = 16;

#[derive(Clone, Copy)]
enum Budget {
    Dispatch,
    PendedCreate,
}

#[derive(Clone, Copy)]
struct ProcessBudget {
    generation: u64,
    dispatches: u8,
    pended_creates: u8,
}

static mut BUDGET: [ProcessBudget; MAX_PI] =
    [ProcessBudget { generation: 0, dispatches: 0, pended_creates: 0 }; MAX_PI];

fn claim_from(budget: Budget, pi: usize, generation: Option<u64>) -> bool {
    let Some(generation) = generation.filter(|value| *value != 0 && pi < MAX_PI) else {
        return false;
    };
    // SAFETY: only the single root dispatch executor records this trace.
    let slot = unsafe { &mut (&mut *core::ptr::addr_of_mut!(BUDGET))[pi] };
    if slot.generation != generation {
        *slot = ProcessBudget { generation, dispatches: 0, pended_creates: 0 };
    }
    let (used, limit) = match budget {
        Budget::Dispatch => (&mut slot.dispatches, DISPATCHES_PER_PROCESS),
        Budget::PendedCreate => (&mut slot.pended_creates, PENDED_CREATES_PER_PROCESS),
    };
    if *used >= limit {
        return false;
    }
    *used += 1;
    true
}

fn claim(pi: usize, generation: Option<u64>) -> bool {
    claim_from(Budget::Dispatch, pi, generation)
}

/// Records per related-file CREATE (staged, published, handoff, direct reply, completed, final).
const RECORDS_PER_RELATED_CREATE: u8 = 8;
/// Related-file CREATEs traced outside the per-generation budget. Boot 44868930483 spent cmd.exe's
/// 16 pended-CREATE records on earlier opens just before its ConDrv `Reference` open, which is
/// relative to the Server handle; a related-file CREATE is rare, so each one is always traced.
const RELATED_CREATES: usize = 64;
static mut RELATED: [(u64, u8); RELATED_CREATES] = [(0, 0); RELATED_CREATES];
static mut RELATED_NEXT: usize = 0;

fn claim_related(file: u64) -> Option<bool> {
    // SAFETY: only the single root dispatch executor records this trace.
    let related = unsafe { &mut *core::ptr::addr_of_mut!(RELATED) };
    let slot = related.iter_mut().find(|(traced, _)| *traced == file && file != 0)?;
    if slot.1 >= RECORDS_PER_RELATED_CREATE {
        return Some(false);
    }
    slot.1 += 1;
    Some(true)
}

fn claim_pended(pi: usize, generation: Option<u64>, file: u64) -> bool {
    claim_related(file).unwrap_or_else(|| claim_from(Budget::PendedCreate, pi, generation))
}

/// A CREATE or open that this dispatch staged as a pended File transfer.
#[derive(Clone, Copy)]
pub(crate) struct StagedCreate {
    generation: Option<u64>,
    file: u64,
}

/// Name a staged pended CREATE. One opened relative to a RootDirectory handle is traced on its
/// own per-File budget from here to its final reply.
pub(crate) fn staged_create(
    handler: &ExecNtHandler,
    service: Option<NativeService>,
    args: &[u64],
    generation: Option<u64>,
) -> Option<StagedCreate> {
    if !matches!(service, Some(NativeService::NtCreateFile | NativeService::NtOpenFile)) {
        return None;
    }
    let file = handler.pending_file_io_transfer?.route.hosted_file_id().unwrap_or(0);
    let mut header = [0u8; 0x10];
    let root = args.get(2)
        .filter(|&&attributes| attributes != 0 && unsafe { handler.xas_read(attributes, &mut header) })
        .map_or(0, |_| u64::from_le_bytes(header[8..16].try_into().unwrap()));
    if root != 0 && file != 0 {
        // SAFETY: only the single root dispatch executor records this trace.
        unsafe {
            let next = &mut *core::ptr::addr_of_mut!(RELATED_NEXT);
            (&mut *core::ptr::addr_of_mut!(RELATED))[*next % RELATED_CREATES] = (file, 0);
            *next = next.wrapping_add(1);
        }
    }
    Some(StagedCreate { generation, file })
}

/// The object name and root of an OBJECT_ATTRIBUTES in the caller, up to 96 UTF-16 units.
unsafe fn object_name(handler: &ExecNtHandler, attributes: u64, out: &mut [u16; 96]) -> Option<(u64, usize)> {
    let mut header = [0u8; 0x18];
    if attributes == 0 || !handler.xas_read(attributes, &mut header) {
        return None;
    }
    let root = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let name = u64::from_le_bytes(header[16..24].try_into().unwrap());
    let mut string = [0u8; 16];
    if name == 0 || !handler.xas_read(name, &mut string) {
        return Some((root, 0));
    }
    let length = (u16::from_le_bytes([string[0], string[1]]) / 2) as usize;
    let buffer = u64::from_le_bytes(string[8..16].try_into().unwrap());
    let units = length.min(out.len());
    let mut bytes = [0u8; 192];
    if buffer == 0 || !handler.xas_read(buffer, &mut bytes[..units * 2]) {
        return Some((root, 0));
    }
    for (index, unit) in out.iter_mut().take(units).enumerate() {
        *unit = u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    }
    Some((root, units))
}

fn is_device_path(name: &[u16]) -> bool {
    const PREFIX: &[u8] = b"\\device\\";
    name.len() >= PREFIX.len()
        && name.iter().zip(PREFIX).all(|(&unit, &byte)| {
            unit < 0x80 && (unit as u8).to_ascii_lowercase() == byte
        })
}

pub(crate) fn record(
    handler: &ExecNtHandler,
    service: Option<NativeService>,
    args: &[u64],
    pi: usize,
    generation: Option<u64>,
    status: u32,
) {
    let Some(service) = service else { return };
    match service {
        NativeService::NtCreateFile | NativeService::NtOpenFile => {
            let Some(&attributes) = args.get(2) else { return };
            let mut name = [0u16; 96];
            let Some((root, units)) = (unsafe { object_name(handler, attributes, &mut name) }) else {
                return;
            };
            if !(root != 0 || is_device_path(&name[..units])) || !claim(pi, generation) {
                return;
            }
            print_str(b"[device-path] pi=");
            print_u64(pi as u64);
            print_str(if service == NativeService::NtCreateFile { b" create" } else { b" open" });
            print_str(b" root=0x");
            print_hex_u64(root);
            print_str(b" name=\"");
            for &unit in &name[..units] {
                let byte = if (0x20..0x7f).contains(&unit) { unit as u8 } else { b'?' };
                print_str(&[byte]);
            }
            print_str(b"\" status=0x");
            print_hex(status);
            // A pended CREATE must park its caller until the IRP completes (IopParseDevice
            // waits); name whether this dispatch staged a parked, waiting transfer.
            print_str(b" staged=");
            print_u64(handler.pending_file_io_transfer.is_some() as u64);
            print_str(b" wait=");
            print_u64(handler.pending_file_io_wait as u64);
            print_str(b"\n");
        }
        NativeService::NtDeviceIoControlFile => {
            if args.len() < 10 || !claim(pi, generation) {
                return;
            }
            print_str(b"[device-path] pi=");
            print_u64(pi as u64);
            print_str(b" ioctl handle=0x");
            print_hex_u64(args[0]);
            print_str(b" code=0x");
            print_hex(args[5] as u32);
            print_str(b" in=");
            print_u64(args[7] as u32 as u64);
            print_str(b" out=");
            print_u64(args[9] as u32 as u64);
            print_str(b" status=0x");
            print_hex(status);
            print_str(b"\n");
        }
        NativeService::NtCreateProcess | NativeService::NtCreateProcessEx => {
            if !claim(pi, generation) {
                return;
            }
            print_str(b"[device-path] pi=");
            print_u64(pi as u64);
            print_str(b" create-process status=0x");
            print_hex(status);
            print_str(b"\n");
        }
        _ => {}
    }
}

/// A pended CREATE's completion as the root publishes it (#421). Boot 44834608861 parked cmd.exe's
/// `Reference` open (STATUS_PENDING, staged, waiting). `phase` is `completed` (the IRP's terminal
/// IoStatus and the driver's FsContext, with the handle publication's result) or `final` (the
/// status and handle the parked caller is answered with). It has its own per-generation budget,
/// so a process's device completions cannot spend its dispatch records.
pub(crate) fn pended_create(
    phase: &[u8],
    pi: usize,
    generation: Option<u64>,
    file: u64,
    irp_status: Option<(u32, u64, u64)>,
    status: u32,
    handle: u64,
) {
    if !claim_pended(pi, generation, file) {
        return;
    }
    print_str(b"[device-path] pi=");
    print_u64(pi as u64);
    print_str(b" pended-create ");
    print_str(phase);
    print_str(b" file=0x");
    print_hex_u64(file);
    if let Some((irp_status, information, file_context)) = irp_status {
        print_str(b" irp-status=0x");
        print_hex(irp_status);
        print_str(b" info=0x");
        print_hex_u64(information);
        print_str(b" fs-context=0x");
        print_hex_u64(file_context);
    }
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" handle=0x");
    print_hex_u64(handle);
    print_str(b"\n");
}

/// One step of a staged pended CREATE's caller handoff (#421), on the pended-CREATE budget.
/// Boot 44866000603 staged cmd.exe's `Reference` open (STATUS_PENDING, staged=1 wait=1) and no
/// completion was ever delivered for it, yet cmd resumed. `published` gives (published, wait),
/// `handoff` (wait, still parked), and `direct-reply` (the status replied, the Reply) when the
/// syscall tail answered the caller itself.
pub(crate) fn pended_create_step(phase: &[u8], pi: usize, staged: StagedCreate, first: u64, second: u64) {
    if !claim_pended(pi, staged.generation, staged.file) {
        return;
    }
    print_str(b"[device-path] pi=");
    print_u64(pi as u64);
    print_str(b" pended-create ");
    print_str(phase);
    print_str(b" file=0x");
    print_hex_u64(staged.file);
    print_str(b" 0x");
    print_hex_u64(first);
    print_str(b" 0x");
    print_hex_u64(second);
    print_str(b"\n");
}
