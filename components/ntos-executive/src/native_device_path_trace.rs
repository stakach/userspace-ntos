//! Bounded trace of the device path a console client takes (#421).
//!
//! Wine's kernelbase AllocConsole opens \Device\ConDrv\Server, opens a reference relative to that
//! handle, issues ConDrv device controls and creates conhost.exe. Boots 44689472419 and
//! 44694366016 log only `Can't allocate console`, so this records, per process generation and
//! globally bounded, each NtCreateFile/NtOpenFile of a \Device\ name or a root-relative name,
//! each NtDeviceIoControlFile code and each process creation, with the returned status.
//! Diagnostic only: it reads caller memory after dispatch and changes nothing.

use super::*;
use nt_syscall::NativeService;

const PER_PROCESS: u8 = 48;
const GLOBAL: u64 = 512;
static TRACED: AtomicU64 = AtomicU64::new(0);
static mut BUDGET: [(u64, u8); MAX_PI] = [(0, 0); MAX_PI];

fn claim(pi: usize, generation: Option<u64>) -> bool {
    let Some(generation) = generation.filter(|value| *value != 0 && pi < MAX_PI) else {
        return false;
    };
    // SAFETY: only the single root dispatch executor records this trace.
    let slot = unsafe { &mut (&mut *core::ptr::addr_of_mut!(BUDGET))[pi] };
    if slot.0 != generation {
        *slot = (generation, 0);
    }
    if slot.1 >= PER_PROCESS || TRACED.load(Ordering::Relaxed) >= GLOBAL {
        return false;
    }
    slot.1 += 1;
    TRACED.fetch_add(1, Ordering::Relaxed);
    true
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
/// `Reference` open (STATUS_PENDING, staged, waiting), but the old globally bounded record had
/// spent its 64 lines before cmd ran. `phase` is `completed` (the IRP's terminal IoStatus and the
/// driver's FsContext with the handle publication's result) or `final` (the status and handle
/// the parked caller is answered with).
pub(crate) fn pended_create(
    phase: &[u8],
    pi: usize,
    generation: Option<u64>,
    file: u64,
    irp_status: Option<(u32, u64, u64)>,
    status: u32,
    handle: u64,
) {
    if !claim(pi, generation) {
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
