//! `ntos-executive` — the trusted NT executive core (P0 seed).
//!
//! The root task the rust-micro kernel boots. It owns the root untyped and the
//! hardware capabilities, spawns the NT executive **services** as isolated seL4
//! components (own CSpace/VSpace), wires the SURT rings between them + itself, and
//! (later) hosts the native syscall trap front-end.
//!
//! This first increment stands up the **Object Manager as an isolated service
//! component** and drives it *from the executive itself* — the executive is the
//! front-end/client, not a spawned test client. It proves the executive shape:
//! broker + front-end composing a real isolated service over SURT + cap transfer.
//! (Reuses `object-service`'s proven server + spawn machinery.)

#![no_std]
#![no_main]

extern crate alloc;

// Re-export the kernel ABI at crate root so `server` can `use crate::*`.
pub use sel4_rt::*;

mod allocator;
mod cm_server;
mod io_server;
mod driver_host;
mod driver_pe;
mod isr;
mod kmdf_host;
mod server;
mod storage_host;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;

use nt_config_abi::CmReply;
use nt_config_client::ConfigClient;
use nt_io_abi::wire::IoReply;
use nt_io_client::IoClient;
use nt_kernel_exec::{EventKind, EventStore, IrqlState, WaitResult};
use nt_object_abi::ObReply;
use nt_object_client::ObjectClient;
use nt_hive_core::apply_ccs_alias;
use nt_hive_regf::{KeyRef, RegfHive};
use nt_syscall::{
    NativeCallContext, NativeService, NativeServiceTable, NativeSyscallDispatcher,
    NativeSyscallHandler, ProcessorMode, SyscallOrigin, UserlandAbiProfile,
};
use nt_types::{AccessMask, HandleValue, ObjAttrFlags, ObjectAttributes, ObjectId, UnicodeString};
use surt_sel4::surt_core::surt_abi::{feature, role, SurtCqe, SurtSqe};
use surt_sel4::surt_core::{init_ring, Consumer, Producer, RingConfig};
use surt_sel4::{drain_blocking, CPtr, Sel4Env, Sel4Notify};

// SURT's wakeup contract: signal a notification / wait on it.
pub struct KernelEnv;
impl Sel4Env for KernelEnv {
    fn signal(&self, ntfn: CPtr) {
        // SAFETY: `ntfn` is a Notification cap; Send length 0 = seL4_Signal.
        unsafe {
            syscall5(SYS_SEND, ntfn, 0, 0, 0, 0);
        }
    }
    fn wait(&self, ntfn: CPtr) {
        // SAFETY: `ntfn` is a Notification cap; Recv = seL4_Wait.
        unsafe {
            let _ = ep_recv(ntfn);
        }
    }
}
pub static ENV: KernelEnv = KernelEnv;

// Component vaddr layout — all inside the one 2 MiB PT of each component. These
// vaddrs are used in BOTH the executive's own VSpace (front-end side) and each
// spawned service's VSpace (they map their own copies of the same frames).
pub const IMAGE_BASE: u64 = 0x0000_0100_0040_0000;
pub const SUB_RING_VADDR: u64 = 0x0000_0100_0050_0000;
pub const COMP_RING_VADDR: u64 = 0x0000_0100_0051_0000;
pub const REQ_DATA_VADDR: u64 = 0x0000_0100_0052_0000;
pub const REP_DATA_VADDR: u64 = 0x0000_0100_0053_0000;
// A SECOND ring set — the executive's side of the Configuration Manager service.
// (Each spawned service maps ITS frames at the shared SUB/COMP/REQ/REP vaddrs above
// in its own VSpace; the executive maps each service's frames at distinct vaddrs.)
pub const CM_SUB_VADDR: u64 = 0x0000_0100_0054_0000;
pub const CM_COMP_VADDR: u64 = 0x0000_0100_0055_0000;
pub const CM_REQ_VADDR: u64 = 0x0000_0100_0056_0000;
pub const CM_REP_VADDR: u64 = 0x0000_0100_0057_0000;
// A THIRD ring set — the executive's side of the I/O Manager service.
pub const IO_SUB_VADDR: u64 = 0x0000_0100_0058_0000;
pub const IO_COMP_VADDR: u64 = 0x0000_0100_0059_0000;
pub const IO_REQ_VADDR: u64 = 0x0000_0100_005A_0000;
pub const IO_REP_VADDR: u64 = 0x0000_0100_005B_0000;
pub const STACK_BASE: u64 = 0x0000_0100_005C_0000;
/// A per-user-thread syscall argument frame, mapped at the SAME vaddr in both the
/// executive and the user thread — so a `UNICODE_STRING` whose `Buffer` points into
/// it is valid in both address spaces (the copyin path for pointer-based `Nt*` args).
pub const SYSARG_VADDR: u64 = 0x0000_0100_005D_0000;
/// A second shared frame, for the blocking-wait demo's two threads (mapped at SYSARG_VADDR in
/// each of them) — read by the executive at this vaddr (its own view of the same frame).
pub const SYSARG2_VADDR: u64 = 0x0000_0100_005D_1000;
/// Where a loaded real PE's image is mapped in its user VSpace (inside the one 2 MiB PT with
/// the stack/sysarg/ipcbuf), and the executive's scratch region to write the code first.
pub const PE_LOAD_BASE: u64 = 0x0000_0100_0056_0000;
/// Where ntdll.dll is (to be) mapped in a loaded process's VSpace — smss's IAT is resolved to
/// NTDLL_BASE + each import's export RVA.
pub const NTDLL_BASE: u64 = 0x0000_0100_0080_0000;
/// smss's process environment (all clear of smss's image extent 0x56-0x57d and the stack 0x5c):
/// a trampoline that sets RCX=PEB then jumps to the entry, a PEB, the process parameters, a TEB.
pub const SMSS_TRAMP_VA: u64 = 0x0000_0100_0055_0000;
pub const SMSS_PEB_VA: u64 = 0x0000_0100_0058_0000;
pub const SMSS_PARAMS_VA: u64 = 0x0000_0100_0059_0000;
pub const SMSS_TEB_VA: u64 = 0x0000_0100_005A_0000;
/// The executive's mirror of smss's stack (same frames), for reading/writing a syscall's
/// stack-based pointer args (copyin/copyout). In the FILEBUF PT (0x60-0x80), present.
pub const SMSS_STACK_MIRROR_VA: u64 = 0x0000_0100_0068_0000;
/// Where the executive backs NtAllocateVirtualMemory for the process (its own PT).
pub const SMSS_ALLOC_VA: u64 = 0x0000_0100_00C0_0000;
/// The executive's mirror of the first window of smss's heap (SMSS_ALLOC_VA). A userspace broker
/// can't walk smss's page tables, so `smss_copyin` reads syscall pointer args (e.g. a loader-built
/// registry key path) from the same frames it mapped, through this parallel mapping. Own PT.
pub const SMSS_HEAP_MIRROR_VA: u64 = 0x0000_0100_0090_0000;
pub const SMSS_HEAP_MIRROR_WINDOW: u64 = 0x0020_0000; // 2 MiB (one PT) of early heap
/// ntdll's NtAllocateVirtualMemory system-service number (from its export stub).
pub const SSN_NT_ALLOCATE_VM: u64 = 0x12;
/// ntdll's NtQuerySystemInformation SSN (RtlCreateHeap needs SystemBasicInformation).
pub const SSN_NT_QUERY_SYSTEM_INFO: u64 = 0xb5;
/// ntdll's NtQueryVirtualMemory SSN (LdrpInitialize queries the region at [TEB+0x10] early).
pub const SSN_NT_QUERY_VIRTUAL_MEM: u64 = 186;
/// ntdll's NtQueryInformationProcess SSN (LdrpInitialize queries ProcessCookie et al.).
pub const SSN_NT_QUERY_INFO_PROCESS: u64 = 161;
/// ntdll's NtOpenKey SSN (LdrpInitialize opens IFEO/options; we have no registry → not-found).
pub const SSN_NT_OPEN_KEY: u64 = 125;
/// ntdll's NtQueryValueKey SSN (registry value lookups; not-found → LdrpInitialize uses defaults).
pub const SSN_NT_QUERY_VALUE_KEY: u64 = 185;
/// ntdll's NtProtectVirtualMemory SSN (LdrpInitialize re-protects image sections).
pub const SSN_NT_PROTECT_VM: u64 = 143;
/// ntdll's NtQueryDefaultLocale SSN (LdrpInitialize caches the default LCID in an ntdll global).
pub const SSN_NT_QUERY_DEFAULT_LOCALE: u64 = 149;
/// ntdll's NtQueryDebugFilterState SSN. DbgPrintEx(component,...) suppresses its message unless
/// this returns (NTSTATUS)TRUE=1 (rtl/debug.c:66). Returning 1 unmasks the SXS/LDR component
/// traces so we can see *which* internal loader step fails (otherwise only DPRINT1/-1 shows).
pub const SSN_NT_QUERY_DEBUG_FILTER_STATE: u64 = 148;
/// No-op-success syscalls: NtFreeVirtualMemory (bump allocator never frees),
/// NtSetInformationThread/Process (attributes we don't model).
pub const SSN_NT_FREE_VM: u64 = 87;
pub const SSN_NT_SET_INFO_THREAD: u64 = 238;
pub const SSN_NT_SET_INFO_PROCESS: u64 = 237;
/// ntdll's NtTestAlert SSN (LdrpInitialize drains pending APCs before the image entry).
pub const SSN_NT_TEST_ALERT: u64 = 268;
/// ntdll's NtFlushInstructionCache SSN — the loader flushes the icache after patching code
/// (IAT snap / relocation). A no-op under TCG (no separate icache to flush).
pub const SSN_NT_FLUSH_INSTRUCTION_CACHE: u64 = 82;
/// ntdll's NtCreateKeyedEvent SSN (RtlpInitializeKeyedEvent, ldrinit.c:2436). Bare success — a
/// NULL GlobalKeyedEventHandle makes ntdll use the non-keyed critical-section wait path. This is
/// the last loader syscall before LdrpInitialize returns and the trampoline enters smss's entry.
pub const SSN_NT_CREATE_KEYED_EVENT: u64 = 289;
/// SmpInit object-creation SSNs (all take the out handle in RCX): NtCreatePort creates \SmApiPort,
/// NtCreateThread the SM API-loop thread, plus events + sections. Faked with distinct handles.
pub const SSN_NT_CREATE_PORT: u64 = 48;
pub const SSN_NT_CREATE_THREAD: u64 = 55;
pub const SSN_NT_CREATE_EVENT: u64 = 37;
pub const SSN_NT_CREATE_SECTION: u64 = 52;
/// NtClose — no handle table modelled, so closing a (fake) handle is a no-op success.
pub const SSN_NT_CLOSE: u64 = 27;
/// Security-token SSNs SmpInit hits. NtOpenThreadToken → STATUS_NO_TOKEN (no impersonation token,
/// the normal case → caller falls back to the process token). NtOpenProcessToken → fake token
/// handle (out in R8). A real token/SID model is a later milestone.
pub const SSN_NT_OPEN_THREAD_TOKEN: u64 = 135;
pub const SSN_NT_OPEN_PROCESS_TOKEN: u64 = 129;
/// NtAdjustPrivilegesToken — smss enables privileges it needs (SeTcb/SeLoadDriver/…). We don't
/// model token privileges → no-op success (the enable "succeeds").
pub const SSN_NT_ADJUST_PRIV_TOKEN: u64 = 12;
/// A distinctive fake handle we hand back for objects we don't yet model (ports, events, …), so it
/// is recognisable in traces and never collides with a real (small) handle index.
pub const FAKE_HANDLE: u64 = 0x5A5A_0001;
/// ntdll's NtOpenDirectoryObject SSN (LdrpInitialize opens \KnownDlls; none → not-found).
pub const SSN_NT_OPEN_DIRECTORY_OBJECT: u64 = 119;
/// ntdll's NtOpenFile SSN (LdrpInitialize opens a DLL/manifest file; no FS → not-found).
pub const SSN_NT_OPEN_FILE: u64 = 122;
/// ntdll's NtQueryAttributesFile SSN (LdrpInitialize probes a file's existence; no FS → not-found).
pub const SSN_NT_QUERY_ATTRIBUTES_FILE: u64 = 145;
pub const PE_SCRATCH_VADDR: u64 = 0x0000_0100_0052_0000;
/// The loaded PE's Windows environment: TEB + PEB (in the PE's existing PT) and
/// KUSER_SHARED_DATA at its fixed low VA (its own PT chain). The thread's GS base is set to
/// TEB_VA so `GS:[0x30]` is the TEB self-pointer (NtCurrentTeb).
pub const TEB_VA: u64 = 0x0000_0100_0057_0000;
pub const PEB_VA: u64 = 0x0000_0100_0058_0000;
pub const KUSER_VA: u64 = 0x0000_0000_7FFE_0000;
/// The provided "ntdll" — a page of syscall stubs mapped RX in the PE VSpace; the PE's IAT is
/// resolved to point here, so the PE calls named ntdll functions like real Windows code.
pub const NTDLL_VA: u64 = 0x0000_0100_0059_0000;
/// Where the executive maps real device MMIO it claims (P1). HPET is exposed by the
/// kernel as a device untyped and isn't used by the kernel, so it's a safe first target.
pub const HPET_PADDR: u64 = 0xFED0_0000;
pub const HPET_VADDR: u64 = 0x0000_0100_005E_0000;
/// Where the executive maps a real PCI device's BAR (P1 capstone — the e1000e NIC).
pub const NIC_VADDR: u64 = 0x0000_0100_005F_0000;
/// P2: the AHCI controller ABAR (BAR5) MMIO, and a DMA frame for its command structures +
/// the sector data buffer (both just past the NIC's 4-page BAR, before IPCBUF).
pub const AHCI_VADDR: u64 = 0x0000_0100_005F_4000;
pub const AHCI_DMA_VADDR: u64 = 0x0000_0100_005F_5000;
/// Shared word between the executive (broker) and the isolated storage host: the AHCI's
/// device address (identity paddr, or a VT-d IOVA once confined) in @0; verdict (u32) @8,
/// INITRD cluster @0x10, size @0x14 out.
pub const STORAGE_SHARED_VADDR: u64 = 0x0000_0100_005F_6000;
/// A multi-frame file buffer shared between the executive and the storage host: the host reads
/// a real PE (ReactOS SMSS.EXE) off the disk into it, and the executive parses it there. 32
/// frames (128 KiB) at a fresh 2 MiB region, contiguous in both VSpaces (one shared PT).
pub const FILEBUF_VADDR: u64 = 0x0000_0100_0060_0000; // its own PT (0x40-0x60 is crowded)
pub const FILEBUF_FRAMES: u64 = 32;
/// A larger buffer for the ~975 KiB ReactOS ntdll.dll (its own 2 MiB PT), shared host<->exec.
pub const NTDLLBUF_VADDR: u64 = 0x0000_0100_00A0_0000;
pub const NTDLLBUF_FRAMES: u64 = 240; // 240*4K = 983040 > 975360
/// NLS code-page tables (c_1252.nls/c_437.nls/l_intl.nls), shared host<->exec. They live in the
/// NTDLLBUF page table's 2 MiB region (0xA0_0000-0xC0_0000, past NTDLLBUF's 0xA0-0xB0), so they
/// need no extra PT. spawn_sec_image later shares these frames into smss + points the PEB NLS
/// fields at them so RtlInitNlsTables/RtlUnicodeToMultiByteN work.
pub const NLS_ANSI_VADDR: u64 = 0x0000_0100_00B0_0000; // c_1252.nls (66082 B = 17 pages)
pub const NLS_ANSI_FRAMES: u64 = 20;
pub const NLS_OEM_VADDR: u64 = 0x0000_0100_00B2_0000; // c_437.nls (66594 B = 17 pages)
pub const NLS_OEM_FRAMES: u64 = 20;
pub const NLS_CASE_VADDR: u64 = 0x0000_0100_00B4_0000; // l_intl.nls (4870 B = 2 pages)
pub const NLS_CASE_FRAMES: u64 = 4;
/// The real ReactOS SYSTEM registry hive (::ROSSYS.HIV, ~204 KiB regf), read off the disk by the
/// isolated storage host into these shared frames; the executive parses it with nt-hive-regf so
/// the NT registry serves smss's real config. Shares the 0xA0-0xC0 page table (past the NLS bufs).
pub const HIVEBUF_VADDR: u64 = 0x0000_0100_00B5_0000;
pub const HIVEBUF_FRAMES: u64 = 64; // 256 KiB
/// The same NLS frames shared into smss (own PT at the 0xE0_0000 2 MiB region). The PEB's
/// AnsiCodePageData(@0x58)/OemCodePageData(@0x60)/UnicodeCaseTableData(@0x68) point here.
pub const NLS_SMSS_ANSI_VA: u64 = 0x0000_0100_00E0_0000;
pub const NLS_SMSS_OEM_VA: u64 = 0x0000_0100_00E2_0000;
pub const NLS_SMSS_CASE_VA: u64 = 0x0000_0100_00E4_0000;
/// The IOVA we grant the AHCI for its DMA frame. Once VT-d confinement is on, the HBA is
/// programmed with this address; VT-d maps it to the DMA frame and NOTHING else.
pub const AHCI_IOVA: u64 = 0x1000;
pub const IPCBUF_VADDR: u64 = 0x0000_0100_005F_B000;
/// A normal RAM frame the executive owns, used as a DMA buffer (TX descriptor ring +
/// packet buffer) for the e1000e. VT-d translation is off (identity) so the NIC DMAs
/// straight to this frame's physical address. Kept just past IPCBUF so it stays inside
/// the same 2 MiB page table as every other runtime mapping (0x40_0000..0x5F_FFFF) — a
/// vaddr in the next 2 MiB region would need a PT this vspace doesn't have.
pub const DMA_VADDR: u64 = 0x0000_0100_005F_C000;

pub const STACK_FRAMES: u64 = 4; // 16 KiB
pub const RING_LEN: usize = 4096;
pub const REP_DATA_LEN: usize = 4096;
const QLEN: u32 = 8;
/// Read/write, non-executable — data regions (heap, stack, rings, buffers).
const RW_NX: u64 = 3 | PAGE_EXECUTE_NEVER;

// A spawned component's own CNode cptrs.
pub const CT_PML4: u64 = 2;
pub const CT_N_SUB: u64 = 3;
pub const CT_N_COMP: u64 = 4;
pub const CT_FAULT: u64 = 6; // a user thread's own cap to its fault endpoint
pub const CT_WAIT_NTFN: u64 = 7; // a waiter thread's cap to the wait notification it parks on
pub const CT_IRQ_NTFN: u64 = 3; // the ISR host's cap to the IRQ notification
pub const CT_RESULT_NTFN: u64 = 4; // the ISR host's cap to the result notification
const CN_RADIX: u32 = 5;
const CN_GUARD_BADGE: u64 = 59;
/// Badge the isolated ISR host signals after it handles the interrupt.
const ISR_DONE_BADGE: u64 = 0x80;

// `SysReplyRecv` — reply to a pending fault + receive the next, in one syscall.
const SYS_REPLY_RECV: i64 = -2;
/// `SysNBRecv` — non-blocking poll of a notification (badge 0 if not signalled).
const SYS_NB_RECV: i64 = -8;
/// `X86IRQIssueIRQHandlerIOAPIC` invocation label — issues an IRQ-handler cap AND
/// programs the IOAPIC redirection-table entry for `pin` → vector+PIC1_VECTOR_BASE.
const LBL_X86_IRQ_ISSUE_IOAPIC: u64 = 64;
/// `X86IRQIssueIRQHandlerMSI` — issues an IRQ-handler cap for a message-signalled
/// interrupt (no IOAPIC pin; the device writes the vector to the LAPIC directly).
const LBL_X86_IRQ_ISSUE_MSI: u64 = 65;
/// Badge for the IRQ notification, so a delivered interrupt is distinguishable from
/// "not signalled" (badge 0) when we poll.
const IRQ_BADGE: u64 = 0x40;
/// The user-visible IRQ/vector (a legacy-range stub the kernel routes through
/// irq{V}_entry → handle_interrupt(V)); the HPET's IOAPIC pin is chosen separately.
const IRQ_VECTOR: u64 = 11;

// x86 I/O-port invocation labels + the IOPortControl cap slot (canonical slot 7).
const SLOT_IO_PORT_CONTROL: u64 = 7;
const LBL_IOPORT_CONTROL_ISSUE: u64 = 57;
const LBL_IOPORT_IN32: u64 = 60;
const LBL_IOPORT_OUT32: u64 = 63;
// PCI configuration-space access ports (0xCF8 address, 0xCFC data).
const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

// Intel e1000e interrupt registers (offsets from the NIC BAR base).
const E1000_ITR: u64 = 0xC4; // Interrupt Throttling (0 = deliver immediately, no postpone)
const E1000_ICR: u64 = 0xC0; // Interrupt Cause Read (reading clears)
const E1000_ICS: u64 = 0xC8; // Interrupt Cause Set (writing raises a cause → asserts INTx)
const E1000_IMS: u64 = 0xD0; // Interrupt Mask Set (enable causes)
// e1000e transmit-DMA registers (offsets from the NIC BAR base).
const E1000_TCTL: u64 = 0x0400; // Transmit Control (bit0 EN, bit1 PSP)
const E1000_TDBAL: u64 = 0x3800; // TX descriptor ring base, low 32 (a physical addr)
const E1000_TDBAH: u64 = 0x3804; // TX descriptor ring base, high 32
const E1000_TDLEN: u64 = 0x3808; // TX descriptor ring length in bytes (128-byte aligned)
const E1000_TDH: u64 = 0x3810; // TX descriptor head (NIC advances)
const E1000_TDT: u64 = 0x3818; // TX descriptor tail (we advance to hand off descriptors)
const E1000_TARC0: u64 = 0x3840; // TX arbitration counter, queue 0 (bit10 = engine ENABLE)

/// `X86Page::GetAddress` invocation label — returns a frame cap's physical address.
const LBL_X86_PAGE_GET_ADDRESS: u64 = 54;
// VT-d confined-DMA (Phase 2): map a driver's DMA frame into a device's IO address space
// so the device can only DMA into frames we granted.
const LBL_X86_IO_PAGE_TABLE_MAP: u64 = 49; // install a VT-d IO page table (builds context)
const LBL_X86_PAGE_MAP_IO: u64 = 53; // map a frame at an IOVA in a device's IO space
const OBJ_X86_IO_PAGE_TABLE: u64 = 13; // seL4_X86_IOPageTableObject
const SLOT_IO_SPACE: u64 = 8; // seL4_CapIOSpace — the master IO-space cap in the root CNode
/// IOVA we grant the NIC for its DMA frame. The NIC is programmed with this address; VT-d
/// translates it to the frame's real paddr. Any DMA outside the granted frame faults.
const NIC_IOVA: u64 = 0x1000;
/// Driver-host VSpace: where the executive maps the CM_RESOURCE_LIST + common-buffer
/// descriptor (also mapped at the same vaddr in the host, aliasing the frame).
pub const RESLIST_VADDR: u64 = 0x0000_0100_005F_D000;
/// The MSI vector we bind for the NIC interrupt (matches the NIC IRQ section).
const NIC_MSI_VECTOR: u64 = 5;
/// The IOAPIC pins PCI INTx routes to on q35 (GSI 16..23) — the NIC's exact pin is
/// chipset-routed, so we cover them all (edge-triggered, one delivery per assertion).

// HPET register offsets (from the mapped MMIO base).
const HPET_GEN_CONF: u64 = 0x10;
const HPET_MAIN_COUNTER: u64 = 0xF0;
const HPET_T0_CONFIG: u64 = 0x100;
const HPET_T0_COMPARATOR: u64 = 0x108;
/// The executive's own IPC buffer VA (from BootInfo) — stages reply message registers 4+.
static IPC_BUFFER: AtomicU64 = AtomicU64::new(0);

// Registry syscalls use the REAL ntdll SSN numbers (Windows 7 SP1 x64) + the real
// `NativeService` classification via `NativeServiceTable`; a real isolated ntdll
// process registers its own numbers the same way (from_numbers(ntdll.syscall_number)).
const NT_CREATE_KEY: u64 = 0x1D; // NtCreateKey(*OBJECT_ATTRIBUTES)
const NT_QUERY_VALUE_KEY: u64 = 0x18; // NtQueryValueKey(*OBJECT_ATTRIBUTES) → value in RAX
const NT_SET_VALUE_KEY: u64 = 0x5D; // NtSetValueKey(*OBJECT_ATTRIBUTES, value in RDX)
const NT_ALLOCATE_VM: u64 = 0x15; // NtAllocateVirtualMemory(size in R10) → base in RAX
const NT_QUERY_SYSTEM_TIME: u64 = 0x57; // NtQuerySystemTime() → HPET counter in RAX
const NT_CREATE_SECTION: u64 = 0x47; // NtCreateSection(size in R10) → section handle in RAX
const NT_MAP_VIEW: u64 = 0x25; // NtMapViewOfSection(section handle in R10) → view base VA in RAX
const NT_CREATE_THREAD: u64 = 0xA5; // NtCreateThreadEx(start routine in R10) → thread handle in RAX
/// Where the executive backs NtAllocateVirtualMemory for the user thread — inside its
/// existing 2 MiB image PT (image ends ~0x41_0000, stack at 0x5C_0000), so mapping needs no
/// new page table.
pub const USER_ALLOC_BASE: u64 = 0x0000_0100_0050_0000;

// The Object Manager namespace ops aren't in the `NativeService` enum (a niche
// syscall surface), so they keep synthetic numbers — but now carry a real
// OBJECT_ATTRIBUTES for the by-name variants.
const SSN_OB_CREATE_DIR: u64 = 0x0100; // arg1 = directory index → \Device\Syscall<n>
const SSN_OB_LOOKUP_DIR: u64 = 0x0101; // arg1 = directory index
const SSN_OB_CREATE_BYNAME: u64 = 0x0102; // arg1 = *OBJECT_ATTRIBUTES (a user-supplied path)
const SSN_OB_LOOKUP_BYNAME: u64 = 0x0103; // arg1 = *OBJECT_ATTRIBUTES
// P3 sync objects (custom SSNs; real KEVENT semantics via nt-kernel-exec EventStore).
const SSN_CREATE_EVENT: u64 = 0x0200; // arg1 = kind (0=Notification, 1=Synchronization), arg2 = initial
const SSN_SET_EVENT: u64 = 0x0201; // arg1 = event handle → previous state in RAX
const SSN_RESET_EVENT: u64 = 0x0202; // arg1 = event handle → previous state in RAX
const SSN_WAIT: u64 = 0x0203; // arg1 = handle → 0 (WAIT_OBJECT_0) or 0x102 (WAIT_TIMEOUT)
// P3 blocking wait dispatcher — a waiter thread parks on an event until a signaler wakes it.
const SSN_WAIT_BLOCK: u64 = 0x0210; // waiter: arg1 = event → 0 (signaled) or 0x102 (must block)
const SSN_SET_WAKE: u64 = 0x0211; // signaler: arg1 = event → set it + signal the wait notification
const SSN_DONE_A: u64 = 0x0212; // waiter reports done
const SSN_DONE_B: u64 = 0x0213; // signaler reports done
const BLOCK_EVENT_KEY: u64 = 0x9000; // the fixed event both threads reference
const SSN_DONE: u64 = 0x01FF; // arg1 = verdict (1 = all passed)

/// The fixed registry key the syscall front-end reads/writes for the Cm route.
const REG_KEY: &str = r"\Registry\Machine\System\CurrentControlSet\Services\FromSyscall";

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);
static IMAGE_FRAMES_START: AtomicU64 = AtomicU64::new(0);
static IMAGE_FRAMES_COUNT: AtomicU64 = AtomicU64::new(0);

fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}
unsafe fn alloc_frame() -> u64 {
    let s = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, s);
    s
}
unsafe fn copy_cap(src: u64) -> u64 {
    let d = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, d, src, 0);
    d
}
unsafe fn make_object(obj: u64) -> u64 {
    let s = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, obj, 0, 1, s);
    s
}
unsafe fn attach_sched_context(tcb: u64) {
    let sc = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS, 1, sc);
    let _ = sched_control_configure(SLOT_SCHED_CONTROL, sc, 10, 10);
    let _ = sched_context_bind(sc, tcb);
}

/// Map the executive's OWN heap (so its front-end can allocate). The root image's
/// `.bss` is fixed at boot; the allocator's arena lives at `HEAP_BASE` past it.
unsafe fn map_own_heap() {
    for i in 0..allocator::HEAP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(
            f,
            allocator::HEAP_BASE as u64 + i * 0x1000,
            RW_NX,
            CAP_INIT_THREAD_VSPACE,
        );
    }
}

/// Build a spawned service's VSpace: image RO+X, private heap, private stack, and
/// the four shared SURT frames at the shared vaddrs.
unsafe fn build_service_vspace(sub: u64, comp: u64, req: u64, rep: u64) -> u64 {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    for i in 0..allocator::HEAP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, allocator::HEAP_BASE as u64 + i * 0x1000, RW_NX, pml4);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let _ = page_map(sub, SUB_RING_VADDR, RW_NX, pml4);
    let _ = page_map(comp, COMP_RING_VADDR, RW_NX, pml4);
    let _ = page_map(req, REQ_DATA_VADDR, RW_NX, pml4);
    let _ = page_map(rep, REP_DATA_VADDR, RW_NX, pml4);
    pml4
}

/// Spawn one isolated service component at `entry`, seeded with `seeds`.
unsafe fn spawn_service(
    entry: unsafe extern "C" fn() -> !,
    seeds: &[(u64, u64)],
    sub: u64,
    comp: u64,
    req: u64,
    rep: u64,
) {
    let pml4 = build_service_vspace(sub, comp, req, rep);
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    for &(slot, src) in seeds {
        let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, slot, src, 0);
    }
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, 0, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, 100);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}

// --- The executive's front-end: an ObjectClient over the SURT ring to the
// isolated Object Manager service. -------------------------------------------

/// One request/reply SURT channel to an isolated service, parameterized by its data
/// frame vaddrs — so the executive can hold several (one per service).
struct RingChannel<'a> {
    sq: Producer<SurtSqe>,
    cq: Consumer<SurtCqe>,
    signal: Sel4Notify<'a, KernelEnv>,
    wait: Sel4Notify<'a, KernelEnv>,
    req_vaddr: u64,
    rep_vaddr: u64,
    next_id: u64,
}
impl RingChannel<'_> {
    /// One synchronous request/reply: stage `in_buf` in the request frame, push the
    /// SQE, wait for the matching completion, copy the reply payload out. Returns
    /// `(status, flags, information, detail0, detail1)`.
    fn raw(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> (i32, u32, u64, u64, u64) {
        // SAFETY: single request in flight; the ring push/pop orders these writes.
        unsafe {
            let dst = self.req_vaddr as *mut u8;
            for (i, b) in in_buf.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), *b);
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        let sqe = SurtSqe {
            opcode,
            len: in_buf.len() as u32,
            request_id: id,
            offset: 0,
            ..Default::default()
        };
        while self.sq.try_push(sqe).is_err() {
            yield_now();
        }
        let _ = self.sq.notify_consumer(&self.signal);
        let mut out = (0i32, 0u32, 0u64, 0u64, 0u64);
        let _ = drain_blocking(&mut self.cq, &self.wait, |cqe: &SurtCqe| {
            if cqe.request_id == id {
                out = (cqe.status, cqe.flags, cqe.information, cqe.detail0, cqe.detail1);
                false
            } else {
                true
            }
        });
        let n = (out.2 as usize).min(out_buf.len());
        // SAFETY: reply frame holds `n` result bytes.
        unsafe {
            let src = self.rep_vaddr as *const u8;
            for (i, slot) in out_buf.iter_mut().enumerate().take(n) {
                *slot = core::ptr::read_volatile(src.add(i));
            }
        }
        out
    }
}

/// The Object Manager transport wrapper.
struct ObChan<'a>(RingChannel<'a>);
impl nt_object_client::Backend for ObChan<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> ObReply {
        let (status, _flags, information, detail0, detail1) = self.0.raw(opcode, in_buf, out_buf);
        ObReply {
            status,
            information: information as u32,
            detail0,
            detail1,
        }
    }
}

/// The Configuration Manager transport wrapper.
struct CmChan<'a>(RingChannel<'a>);
impl nt_config_client::Backend for CmChan<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let (status, _flags, information, detail0, detail1) = self.0.raw(opcode, in_buf, out_buf);
        CmReply {
            status,
            information: information as u32,
            detail0,
            detail1,
        }
    }
}

/// The I/O Manager transport wrapper (carries the extra `flags` + a u64 `information`).
struct IoChan<'a>(RingChannel<'a>);
impl nt_io_client::Backend for IoChan<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> IoReply {
        let (status, flags, information, detail0, detail1) = self.0.raw(opcode, in_buf, out_buf);
        IoReply {
            status,
            flags,
            information,
            detail0,
            detail1,
        }
    }
}

// --- Native syscall trap front-end -----------------------------------------
// The executive catches a user thread's `syscall` (delivered as a seL4
// UnknownSyscall fault), routes it to the owning isolated service over SURT, and
// replies register-accurately so the user resumes past the syscall. (Trap/reply
// mechanics ported from driver-host-ntdll, which services real ntdll.)

/// Receive an UnknownSyscall fault: `(badge, msginfo, mr0..mr3)` = RAX(SSN), RBX,
/// RCX(=return IP), RDX. Saved regs 4+ land in this thread's IPC buffer.
/// Issue an MSI IRQ-handler cap for `vector` into `dest_slot` (no IOAPIC pin — the
/// device delivers by writing the vector to the LAPIC). Same 7-word + extra-cap ABI
/// as the IOAPIC issue, but label 65; the pin/level/polarity words are ignored.
unsafe fn msi_issue_irq_handler(dest_slot: u64, vector: u64) {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 5 * 8) as *mut u64, 0); // mr4 (ignored for MSI)
    core::ptr::write_volatile((ipc + 6 * 8) as *mut u64, 0); // mr5 (ignored)
    core::ptr::write_volatile((ipc + 7 * 8) as *mut u64, vector); // mr6 = vector
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, CAP_INIT_THREAD_CNODE);
    let msginfo = (LBL_X86_IRQ_ISSUE_MSI << 12) | (1 << 9) | (1 << 7) | 7;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") SLOT_IRQ_CONTROL,
        in("rsi") msginfo,
        in("r10") dest_slot, // mr0 = index (dest slot)
        in("r8") 64u64,      // mr1 = depth
        in("r9") 0u64,       // mr2 = ioapic id (ignored)
        in("r15") 0u64,      // mr3 = pin (ignored for MSI)
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// Non-blocking poll of a notification: returns the pending badge (0 if none).
unsafe fn nb_recv(ntfn: u64) -> u64 {
    let badge: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_NB_RECV as u64,
        inout("rdi") ntfn => badge,
        lateout("rsi") _, lateout("r10") _, lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    badge
}

unsafe fn ep_recv_full(ep: u64) -> (u64, u64, u64, u64, u64, u64) {
    let badge: u64;
    let msginfo: u64;
    let mr0: u64;
    let mr1: u64;
    let mr2: u64;
    let mr3: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_RECV as u64,
        inout("rdi") ep => badge,
        lateout("rsi") msginfo,
        lateout("r10") mr0,
        lateout("r8") mr1,
        lateout("r9") mr2,
        lateout("r15") mr3,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (badge, msginfo, mr0, mr1, mr2, mr3)
}

/// Reply to the pending fault (resume the faulter with the staged registers) + recv
/// the next fault. `r0..r3` → reply MRs 0..3 (RAX,RBX,RCX,RDX); MRs 4+ from `set_reply_mr`.
unsafe fn reply_recv_full(recv_ep: u64, reply_len: u64, r0: u64, r1: u64, r2: u64, r3: u64) -> (u64, u64, u64, u64, u64) {
    let msginfo: u64;
    let mr0: u64;
    let mr1: u64;
    let mr2: u64;
    let mr3: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_REPLY_RECV as u64,
        inout("rdi") recv_ep => _,
        inout("rsi") reply_len => msginfo,
        inout("r10") r0 => mr0,
        inout("r8") r1 => mr1,
        inout("r9") r2 => mr2,
        inout("r15") r3 => mr3,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (msginfo, mr0, mr1, mr2, mr3)
}

unsafe fn set_reply_mr(i: usize, v: u64) {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((base + 8 + (i as u64) * 8) as *mut u64, v);
}
unsafe fn get_recv_mr(i: usize) -> u64 {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::read_volatile((base + 8 + (i as u64) * 8) as *const u64)
}

/// Issue an IRQ-handler cap for a real IOAPIC `pin`, delivering `IRQ_VECTOR`, into
/// `dest_slot` of the executive's root CNode. This is `X86IRQIssueIRQHandlerIOAPIC`:
/// a 7-word message (msg_regs[0..6]) + one extra cap (the dest CNode root). mr0..2 go
/// in registers, mr3 (pin) in r15, mr4..6 in the IPC buffer, the extra cap at IPC
/// word 122. The kernel also programs IOAPIC RTE[pin] → pin fires vector+0x20.
unsafe fn ioapic_issue_irq_handler(dest_slot: u64, pin: u64, vector: u64, level: u64, polarity: u64) {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 5 * 8) as *mut u64, level); // mr4 = level (0=edge, 1=level)
    core::ptr::write_volatile((ipc + 6 * 8) as *mut u64, polarity); // mr5 = polarity (1=active-low)
    core::ptr::write_volatile((ipc + 7 * 8) as *mut u64, vector); // mr6 = vector (irq table index)
    // caps_or_badges[0] = the dest CNode root (resolved in the caller's cspace).
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, CAP_INIT_THREAD_CNODE);
    // msginfo: label=64, capsUnwrapped=1, extraCaps=1, length=7.
    let msginfo = (LBL_X86_IRQ_ISSUE_IOAPIC << 12) | (1 << 9) | (1 << 7) | 7;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") SLOT_IRQ_CONTROL,
        in("rsi") msginfo,
        in("r10") dest_slot, // mr0 = index (dest slot)
        in("r8") 64u64,      // mr1 = depth (init CNode: guard=0, so depth 64 resolves the slot)
        in("r9") 0u64,       // mr2 = ioapic id (ignored)
        in("r15") pin,       // mr3 = pin
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// The fixed object path for a syscall's directory index.
fn path_for(i: u64) -> &'static str {
    match i {
        0 => "\\Device\\Syscall0",
        1 => "\\Device\\Syscall1",
        _ => "\\Device\\SyscallX",
    }
}

/// The x64 `UNICODE_STRING` a user thread passes to a name-based syscall: a 16-byte
/// header (4 bytes of tail padding before the 8-byte `Buffer`) + UTF-16LE chars the
/// `Buffer` points at. Both live in the shared arg frame (same vaddr in both VSpaces).
#[repr(C)]
#[derive(Copy, Clone)]
struct NtUnicodeString {
    length: u16,         // bytes of the name (excluding NUL)
    maximum_length: u16, // capacity in bytes
    _pad: u32,
    buffer: u64, // vaddr of the UTF-16 chars (into the shared arg frame)
}

/// Copyin a user-supplied path from a `UNICODE_STRING` at `ptr`. Probes like a real
/// kernel: both the header and the `Buffer` range must lie inside the one shared arg
/// frame `[SYSARG_VADDR, SYSARG_VADDR + 4096)` — a hostile user can't steer the read
/// at executive memory. Returns the decoded path.
unsafe fn copyin_user_path(ptr: u64) -> Option<alloc::string::String> {
    let frame_lo = SYSARG_VADDR;
    let frame_hi = SYSARG_VADDR + 0x1000;
    let hdr = core::mem::size_of::<NtUnicodeString>() as u64;
    if ptr < frame_lo || ptr.checked_add(hdr)? > frame_hi {
        return None;
    }
    let us = core::ptr::read_unaligned(ptr as *const NtUnicodeString);
    let len = us.length as u64;
    if len % 2 != 0 || len > 1024 || us.buffer < frame_lo || us.buffer.checked_add(len)? > frame_hi {
        return None;
    }
    let mut units = Vec::with_capacity((len / 2) as usize);
    for i in 0..(len / 2) {
        units.push(core::ptr::read_unaligned((us.buffer + i * 2) as *const u16));
    }
    Some(alloc::string::String::from_utf16_lossy(&units))
}

/// The x64 `OBJECT_ATTRIBUTES` a create/open syscall carries (48 bytes): `Length`,
/// `RootDirectory`, `ObjectName` (→ `UNICODE_STRING`), `Attributes`, and two security
/// pointers we don't use yet. Built by the user in the shared arg frame.
#[repr(C)]
#[derive(Copy, Clone)]
struct RawObjectAttributes {
    length: u32,
    _pad0: u32,
    root_directory: u64,
    object_name: u64, // *UNICODE_STRING
    attributes: u32,
    _pad1: u32,
    security_descriptor: u64,
    security_qos: u64,
}

/// Copyin + decode a user `OBJECT_ATTRIBUTES` at `ptr` into the kernel-side
/// [`ObjectAttributes`]. Probes the header + follows `ObjectName` through the same
/// bounds-checked path copyin — exactly what a real `Nt*` create/open does with the
/// pointer a real ntdll passes.
unsafe fn copyin_object_attributes(ptr: u64) -> Option<ObjectAttributes> {
    let hdr = core::mem::size_of::<RawObjectAttributes>() as u64;
    if ptr < SYSARG_VADDR || ptr.checked_add(hdr)? > SYSARG_VADDR + 0x1000 {
        return None;
    }
    let raw = core::ptr::read_unaligned(ptr as *const RawObjectAttributes);
    let object_name = if raw.object_name == 0 {
        None
    } else {
        Some(UnicodeString::from_str(&copyin_user_path(raw.object_name)?))
    };
    Some(ObjectAttributes {
        root_directory: None,
        object_name,
        attributes: ObjAttrFlags::from_bits_truncate(raw.attributes),
    })
}

/// The absolute NT path an `OBJECT_ATTRIBUTES` names (this cut ignores RootDirectory).
fn oa_path(oa: &ObjectAttributes) -> Option<alloc::string::String> {
    oa.object_name
        .as_ref()
        .map(|n| alloc::string::String::from_utf16_lossy(n.as_units()))
}

/// A raw native syscall from the isolated user thread: SSN in RAX, arg1 in R10
/// (the Windows x64 convention — RCX is clobbered by `syscall`), result in RAX.
unsafe fn native_syscall(ssn: u64, arg1: u64) -> u64 {
    native_syscall2(ssn, arg1, 0)
}

/// Like [`native_syscall`] but with a 2nd arg in RDX (Windows x64 convention).
unsafe fn native_syscall2(ssn: u64, arg1: u64, arg2: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inout("rax") ssn => ret,
        // r10/rdx carry the args in, but the fault->reply path may leave them changed, so
        // declare them clobbered (=> _) rather than `in` (which implies preserved). Likewise
        // the other MR registers the reply may touch — else the compiler reuses stale values
        // (a wild write / #PF after a syscall that parks in between).
        inout("r10") arg1 => _,
        inout("rdx") arg2 => _,
        lateout("rcx") _, lateout("r11") _,
        lateout("r8") _, lateout("r9") _, lateout("r15") _,
        options(nostack),
    );
    ret
}

/// The isolated user thread: a separate VSpace/CSpace with no access to the Object
/// Manager — it reaches objects only by trapping `syscall`s the executive services.
#[no_mangle]
#[link_section = ".text.user_entry"]
/// Build a real x64 `OBJECT_ATTRIBUTES` naming `name` in the shared arg frame:
/// header @ 0 → `UNICODE_STRING` @ 48 → UTF-16 chars @ 64. Returns the OA pointer.
unsafe fn write_object_attributes(name: &[u8]) -> u64 {
    let oa_v = SYSARG_VADDR;
    let us_v = SYSARG_VADDR + 48;
    let buf_v = SYSARG_VADDR + 64;
    for (i, &ch) in name.iter().enumerate() {
        core::ptr::write_volatile((buf_v + (i as u64) * 2) as *mut u16, ch as u16);
    }
    core::ptr::write_unaligned(
        us_v as *mut NtUnicodeString,
        NtUnicodeString {
            length: (name.len() * 2) as u16,
            maximum_length: (name.len() * 2) as u16,
            _pad: 0,
            buffer: buf_v,
        },
    );
    core::ptr::write_unaligned(
        oa_v as *mut RawObjectAttributes,
        RawObjectAttributes {
            length: 48,
            _pad0: 0,
            root_directory: 0,
            object_name: us_v,
            attributes: 0,
            _pad1: 0,
            security_descriptor: 0,
            security_qos: 0,
        },
    );
    oa_v
}

/// A second thread the user process creates via NtCreateThreadEx. It runs in the PARENT's
/// VSpace (sharing its mappings), writes a marker the parent observes, then yields forever.
pub unsafe extern "C" fn thread2_entry() -> ! {
    core::ptr::write_volatile((SYSARG_VADDR + 0x468) as *mut u64, 0x7EAD2);
    loop {
        yield_now();
    }
}

/// A "loader" thread: maps a demand-paged, FILE-BACKED section whose backing is a REAL file
/// read off the disk (the SYSTEM.DAT hive), faults its first page IN, and reports the word it
/// read (the hive's `UNTHIVE1` magic) as its verdict — a section sourced from a real disk file.
pub unsafe extern "C" fn loader_entry() -> ! {
    let sec = native_syscall2(NT_CREATE_SECTION, 0x1000, 1); // file-backed = the disk hive frame
    let view = native_syscall(NT_MAP_VIEW, sec);
    let magic = if view != 0 {
        core::ptr::read_volatile(view as *const u64) // the page is demand-paged IN right here
    } else {
        0
    };
    let _ = native_syscall(SSN_DONE, magic);
    park()
}

pub unsafe extern "C" fn user_entry() -> ! {
    // Object Manager route (scalar args — fixed paths by index).
    let r0 = native_syscall(SSN_OB_CREATE_DIR, 0);
    let r0b = native_syscall(SSN_OB_LOOKUP_DIR, 0);
    let r1 = native_syscall(SSN_OB_CREATE_DIR, 1);

    // Object Manager route (pointer arg — a real OBJECT_ATTRIBUTES in the shared frame).
    let oa = write_object_attributes(b"\\Device\\FromUserString");
    let created = native_syscall(SSN_OB_CREATE_BYNAME, oa);
    let found = native_syscall(SSN_OB_LOOKUP_BYNAME, oa);

    // Registry route — REAL ntdll SSNs + a real OBJECT_ATTRIBUTES naming the key.
    let key_oa = write_object_attributes(REG_KEY.as_bytes());
    let ck = native_syscall(NT_CREATE_KEY, key_oa);
    let sk = native_syscall2(NT_SET_VALUE_KEY, key_oa, 42);
    let val = native_syscall(NT_QUERY_VALUE_KEY, key_oa);

    // P3: allocate virtual memory via a native syscall — the executive (Mm) maps a real
    // frame into this thread's VSpace — then prove it's usable by writing + reading it back.
    let vm = native_syscall(NT_ALLOCATE_VM, 0x1000);
    let pat = 0xDEAD_BEEF_CAFE_BABEu64;
    let readback = if vm != 0 {
        core::ptr::write_volatile(vm as *mut u64, pat);
        core::ptr::read_volatile(vm as *const u64) == pat
    } else {
        false
    };
    // P3: query the system clock twice — should be non-zero + monotonic.
    let t1 = native_syscall(NT_QUERY_SYSTEM_TIME, 0);
    let t2 = native_syscall(NT_QUERY_SYSTEM_TIME, 0);
    // Publish raw results to the shared sysarg frame for the executive to verify.
    core::ptr::write_volatile((SYSARG_VADDR + 0x400) as *mut u64, vm);
    core::ptr::write_volatile((SYSARG_VADDR + 0x408) as *mut u64, readback as u64);
    core::ptr::write_volatile((SYSARG_VADDR + 0x410) as *mut u64, t1);
    core::ptr::write_volatile((SYSARG_VADDR + 0x418) as *mut u64, t2);

    // P3 sync objects: a Synchronization (auto-reset) event — wait times out, a set satisfies
    // one wait, and the auto-reset then re-arms it (the next wait times out again).
    let ev = native_syscall2(SSN_CREATE_EVENT, 1, 0);
    let w1 = native_syscall(SSN_WAIT, ev); // not signaled → TIMEOUT (0x102)
    let _ = native_syscall(SSN_SET_EVENT, ev);
    let w2 = native_syscall(SSN_WAIT, ev); // signaled → OBJECT_0 (0), auto-reset consumes it
    let w3 = native_syscall(SSN_WAIT, ev); // consumed → TIMEOUT (0x102)
    // A Notification (manual-reset) event — a set stays signaled across waits until reset.
    let ev2 = native_syscall2(SSN_CREATE_EVENT, 0, 0);
    let _ = native_syscall(SSN_SET_EVENT, ev2);
    let m1 = native_syscall(SSN_WAIT, ev2); // OBJECT_0
    let m2 = native_syscall(SSN_WAIT, ev2); // still OBJECT_0 (manual-reset)
    let _ = native_syscall(SSN_RESET_EVENT, ev2);
    let m3 = native_syscall(SSN_WAIT, ev2); // TIMEOUT
    core::ptr::write_volatile((SYSARG_VADDR + 0x420) as *mut u64, w1);
    core::ptr::write_volatile((SYSARG_VADDR + 0x428) as *mut u64, w2);
    core::ptr::write_volatile((SYSARG_VADDR + 0x430) as *mut u64, w3);
    core::ptr::write_volatile((SYSARG_VADDR + 0x438) as *mut u64, m1);
    core::ptr::write_volatile((SYSARG_VADDR + 0x440) as *mut u64, m2);
    core::ptr::write_volatile((SYSARG_VADDR + 0x448) as *mut u64, m3);

    // P3 sections: create a section, map it as TWO views, write one + read the other — they
    // alias the same backing frame (the defining section property; the load vehicle for DLLs).
    let sec = native_syscall(NT_CREATE_SECTION, 0x1000);
    let sv1 = native_syscall(NT_MAP_VIEW, sec);
    let sv2 = native_syscall(NT_MAP_VIEW, sec);
    let smagic = 0x5EC7_10A5_ED00_1234u64;
    let sec_alias = if sv1 != 0 && sv2 != 0 {
        core::ptr::write_volatile(sv1 as *mut u64, smagic);
        core::ptr::read_volatile(sv2 as *const u64) == smagic
    } else {
        false
    };
    core::ptr::write_volatile((SYSARG_VADDR + 0x450) as *mut u64, sv1);
    core::ptr::write_volatile((SYSARG_VADDR + 0x458) as *mut u64, sv2);
    core::ptr::write_volatile((SYSARG_VADDR + 0x460) as *mut u64, sec_alias as u64);

    // P3 NtCreateThreadEx: create a SECOND thread in this process; it runs concurrently in our
    // VSpace and writes a marker we then observe (proving a real independent thread).
    core::ptr::write_volatile((SYSARG_VADDR + 0x468) as *mut u64, 0);
    let th = native_syscall(NT_CREATE_THREAD, thread2_entry as u64);
    let mut tmarker = 0u64;
    for _ in 0..2_000_000u64 {
        tmarker = core::ptr::read_volatile((SYSARG_VADDR + 0x468) as *const u64);
        if tmarker != 0 {
            break;
        }
        yield_now();
    }
    core::ptr::write_volatile((SYSARG_VADDR + 0x470) as *mut u64, th);
    core::ptr::write_volatile((SYSARG_VADDR + 0x478) as *mut u64, tmarker);

    // P3 demand paging: a FILE-BACKED section (arg2=1). NtMapViewOfSection RESERVES the view
    // VA without mapping the page; the first read below triggers a VMFault the executive
    // demand-pages in from the backing file — so the read returns the file's payload.
    let dsec = native_syscall2(NT_CREATE_SECTION, 0x1000, 1);
    let dview = native_syscall(NT_MAP_VIEW, dsec);
    let dpaged = if dview != 0 {
        core::ptr::read_volatile(dview as *const u64) // fault-in happens HERE
    } else {
        0
    };
    core::ptr::write_volatile((SYSARG_VADDR + 0x480) as *mut u64, dview);
    core::ptr::write_volatile((SYSARG_VADDR + 0x488) as *mut u64, dpaged);

    let ok = r0 == 1
        && r0b == 1
        && r1 == 1
        && created == 1
        && found == 1
        && ck == 1
        && sk == 1
        && val == 42
        && vm != 0
        && readback
        && t1 != 0
        && t2 >= t1
        && w1 == 0x102
        && w2 == 0
        && w3 == 0x102
        && m1 == 0
        && m2 == 0
        && m3 == 0x102
        && sv1 != 0
        && sv2 != 0
        && sec_alias
        && th != 0
        && tmarker == 0x7EAD2
        && dview != 0
        && dpaged == 0xDEAD_FACE_CAFE_F00D;
    let _ = native_syscall(SSN_DONE, ok as u64);
    park()
}

/// P3 blocking wait — the WAITER. Waits on a non-signaled event; the executive tells it to
/// block, so it PARKS on the wait notification (a real block) until the signaler wakes it,
/// then re-waits (now satisfied) and reads the signaler's handoff marker.
#[no_mangle]
#[link_section = ".text.waiter_entry"]
pub unsafe extern "C" fn waiter_entry() -> ! {
    let w_first = native_syscall(SSN_WAIT_BLOCK, BLOCK_EVENT_KEY);
    // Persist w_first to memory NOW — before the park below, which can clobber registers.
    core::ptr::write_volatile((SYSARG_VADDR + 0x510) as *mut u64, w_first);
    // Publish "the waiter has taken its first wait" so the signaler only sets the event AFTER
    // this (making the first wait deterministically observe a non-signaled event).
    core::ptr::write_volatile((SYSARG_VADDR + 0x528) as *mut u64, 1);
    if w_first != 0 {
        let _ = ep_recv(CT_WAIT_NTFN); // block until the signaler wakes us
    }
    let w_second = native_syscall(SSN_WAIT_BLOCK, BLOCK_EVENT_KEY);
    core::ptr::write_volatile((SYSARG_VADDR + 0x518) as *mut u64, w_second);
    // We could only observe the signaler's marker if we truly blocked until it ran.
    let handoff = core::ptr::read_volatile((SYSARG_VADDR + 0x500) as *const u64);
    core::ptr::write_volatile((SYSARG_VADDR + 0x520) as *mut u64, handoff);
    let _ = native_syscall(SSN_DONE_A, 0);
    park()
}

/// P3 blocking wait — the SIGNALER. Publishes a handoff marker, then sets + wakes the event.
/// Because the waiter is parked, it wakes only after this runs — and reads the marker.
#[no_mangle]
#[link_section = ".text.signaler_entry"]
pub unsafe extern "C" fn signaler_entry() -> ! {
    // Wait (yielding) until the waiter has taken its first, blocking wait — so our set lands
    // AFTER it, and the waiter genuinely parks rather than seeing a pre-signaled event.
    while core::ptr::read_volatile((SYSARG_VADDR + 0x528) as *const u64) == 0 {
        yield_now();
    }
    core::ptr::write_volatile((SYSARG_VADDR + 0x500) as *mut u64, 0xB0B);
    let _ = native_syscall(SSN_SET_WAKE, BLOCK_EVENT_KEY);
    let _ = native_syscall(SSN_DONE_B, 0);
    park()
}

/// The provided "ntdll" stub for NtQuerySystemTime: `mov rax,0x57; syscall; ret`. Mapped RX
/// at NTDLL_VA; the PE's IAT is resolved to point here, so the PE calls it like real code.
const NTDLL_STUB: &[u8] = &[
    0x48, 0xC7, 0xC0, 0x57, 0x00, 0x00, 0x00, // mov rax, 0x57  (NtQuerySystemTime)
    0x0F, 0x05, // syscall
    0xC3, // ret
];

/// Build a PE32+/x86_64 image. `sections` = (name8, va, chars, data); `dirs` = (index, rva,
/// size). Mirrors nt-pe-loader's own test builder (crates/nt-pe-loader/tests/parse.rs).
unsafe fn build_pe(
    image_base: u64,
    entry_rva: u32,
    size_of_image: u32,
    sections: &[(&[u8; 8], u32, u32, &[u8])],
    dirs: &[(usize, u32, u32)],
) -> alloc::vec::Vec<u8> {
    const NT_OFF: usize = 0x40;
    const OPT_OFF: usize = 0x58;
    const SECTION_TABLE: usize = 0x148;
    const FILE_ALIGN: usize = 0x200;
    let align = |n: usize, a: usize| (n + a - 1) & !(a - 1);
    let n = sections.len();
    let size_of_headers = align(SECTION_TABLE + n * 40, FILE_ALIGN);
    let mut raw_off = size_of_headers;
    let mut raws = alloc::vec::Vec::new();
    for s in sections {
        let sz = align(s.3.len().max(1), FILE_ALIGN);
        raws.push((raw_off, sz));
        raw_off += sz;
    }
    let mut b = alloc::vec![0u8; raw_off];
    let pu16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    let pu32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let pu64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    pu16(&mut b, 0, 0x5A4D); // MZ
    pu32(&mut b, 0x3C, NT_OFF as u32);
    pu32(&mut b, NT_OFF, 0x0000_4550); // PE\0\0
    pu16(&mut b, NT_OFF + 4, 0x8664); // machine AMD64
    pu16(&mut b, NT_OFF + 6, n as u16); // NumberOfSections
    pu16(&mut b, NT_OFF + 4 + 16, 240); // SizeOfOptionalHeader
    pu16(&mut b, NT_OFF + 4 + 18, 0x0002); // EXECUTABLE_IMAGE
    pu16(&mut b, OPT_OFF, 0x020b); // PE32+ magic
    pu32(&mut b, OPT_OFF + 16, entry_rva);
    pu64(&mut b, OPT_OFF + 24, image_base);
    pu32(&mut b, OPT_OFF + 32, 0x1000); // SectionAlignment
    pu32(&mut b, OPT_OFF + 36, FILE_ALIGN as u32);
    pu32(&mut b, OPT_OFF + 56, size_of_image);
    pu32(&mut b, OPT_OFF + 60, size_of_headers as u32);
    pu16(&mut b, OPT_OFF + 68, 1); // Subsystem: NATIVE
    pu32(&mut b, OPT_OFF + 108, 16); // NumberOfRvaAndSizes
    for &(idx, rva, size) in dirs {
        pu32(&mut b, OPT_OFF + 112 + idx * 8, rva);
        pu32(&mut b, OPT_OFF + 112 + idx * 8 + 4, size);
    }
    for (i, s) in sections.iter().enumerate() {
        let se = SECTION_TABLE + i * 40;
        b[se..se + 8].copy_from_slice(s.0);
        pu32(&mut b, se + 8, s.3.len() as u32); // VirtualSize
        pu32(&mut b, se + 12, s.1); // VirtualAddress
        pu32(&mut b, se + 16, raws[i].1 as u32); // SizeOfRawData
        pu32(&mut b, se + 20, raws[i].0 as u32); // PointerToRawData
        pu32(&mut b, se + 36, s.2); // Characteristics
        b[raws[i].0..raws[i].0 + s.3.len()].copy_from_slice(s.3);
    }
    b
}

/// The `.rdata` import table (section VA 0x2000): imports `ntdll.dll!NtQuerySystemTime`; the
/// IAT (FirstThunk) slot is at RVA 0x2038. Mirrors nt-pe-loader's `imports_are_listed` test.
unsafe fn build_import_table() -> alloc::vec::Vec<u8> {
    let base = 0x2000u32;
    let mut d = alloc::vec![0u8; 0x80];
    let p32 = |d: &mut [u8], o: usize, v: u32| d[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let p64 = |d: &mut [u8], o: usize, v: u64| d[o..o + 8].copy_from_slice(&v.to_le_bytes());
    // descriptor 0: OriginalFirstThunk@0, Name@0x0C, FirstThunk@0x10 (descriptor 1 = null).
    p32(&mut d, 0x00, base + 0x28); // ILT
    p32(&mut d, 0x0C, base + 0x48); // Name
    p32(&mut d, 0x10, base + 0x38); // IAT (FirstThunk) -> slot RVA 0x2038
    p64(&mut d, 0x28, (base + 0x58) as u64); // ILT thunk -> IMAGE_IMPORT_BY_NAME
    p64(&mut d, 0x38, (base + 0x58) as u64); // IAT thunk (patched at load)
    d[0x48..0x48 + 10].copy_from_slice(b"ntdll.dll\0");
    // IMAGE_IMPORT_BY_NAME: hint(0) + name.
    d[0x5A..0x5A + 18].copy_from_slice(b"NtQuerySystemTime\0");
    d
}

/// The PE `.text` code: `call [IAT:NtQuerySystemTime]` (the imported ntdll function), then
/// walk the Windows environment (GS:[0x30]->TEB->[+0x60]->PEB->[+0x10]->ImageBase), touch
/// KUSER, and report the image base via SSN_DONE. Uses the stack (the call) + GS-relative.
unsafe fn build_pe_text() -> alloc::vec::Vec<u8> {
    let iat_va = PE_LOAD_BASE + 0x2038;
    let mut t = alloc::vec::Vec::new();
    t.extend_from_slice(&[0x48, 0xB8]); // movabs rax, IAT_VA
    t.extend_from_slice(&iat_va.to_le_bytes());
    t.extend_from_slice(&[0xFF, 0x10]); // call [rax]  (NtQuerySystemTime via the IAT)
    t.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00]); // mov rax, gs:[0x30]
    t.extend_from_slice(&[0x48, 0x8B, 0x40, 0x60]); // mov rax, [rax+0x60]  (PEB)
    t.extend_from_slice(&[0x48, 0x8B, 0x40, 0x10]); // mov rax, [rax+0x10]  (ImageBase)
    t.extend_from_slice(&[0x49, 0x89, 0xC2]); // mov r10, rax
    t.extend_from_slice(&[0x48, 0xB9]); // movabs rcx, KUSER_VA
    t.extend_from_slice(&KUSER_VA.to_le_bytes());
    t.extend_from_slice(&[0x48, 0x8B, 0x09]); // mov rcx, [rcx]  (touch KUSER)
    t.extend_from_slice(&[0x48, 0xC7, 0xC0, 0xFF, 0x01, 0x00, 0x00]); // mov rax, 0x1FF (SSN_DONE)
    t.extend_from_slice(&[0x0F, 0x05]); // syscall
    t.extend_from_slice(&[0xEB, 0xFE]); // jmp $  (park)
    t
}

/// The `.text` for the SEC_IMAGE demo PE: read a magic from `.rdata` (RVA 0x2000 — a second
/// section faulted in on its own access) and report it via SSN_DONE. No stack/env use — proves
/// the process ran from a demand-paged `.text` AND its `.rdata` faulted in at the right offset.
unsafe fn build_sec_image_text() -> alloc::vec::Vec<u8> {
    let mut t = alloc::vec::Vec::new();
    t.extend_from_slice(&[0x48, 0xB8]); // movabs rax, .rdata VA
    t.extend_from_slice(&(PE_LOAD_BASE + 0x2000).to_le_bytes());
    t.extend_from_slice(&[0x48, 0x8B, 0x00]); // mov rax, [rax]  (read .rdata magic)
    t.extend_from_slice(&[0x49, 0x89, 0xC2]); // mov r10, rax    (arg1 = magic)
    t.extend_from_slice(&[0xB8, 0xFF, 0x01, 0x00, 0x00]); // mov eax, 0x1FF (SSN_DONE)
    t.extend_from_slice(&[0x0F, 0x05]); // syscall
    t.extend_from_slice(&[0xEB, 0xFE]); // jmp $  (park)
    t
}

/// Spawn an isolated user process running a real PE `mapped` (by nt-pe-loader): the PE image
/// is written into fresh frames (via an executive scratch mapping) and mapped RX at
/// PE_LOAD_BASE in the new VSpace; execution starts at the PE entry point. Returns the pml4.
unsafe fn spawn_pe_thread(mapped: &nt_pe_loader::MappedImage, fault_ep_c: u64, sysarg_c: u64) -> u64 {
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    // Map the PE image: write the bytes into fresh frames via an executive scratch mapping,
    // then map each frame RX (rights=2 — W^X) at PE_LOAD_BASE in the new VSpace.
    let pages = (mapped.bytes.len() + 0xFFF) / 0x1000;
    for i in 0..pages {
        let f = alloc_frame();
        let _ = page_map(f, PE_SCRATCH_VADDR + i as u64 * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        for j in 0..0x1000usize {
            let src = i * 0x1000 + j;
            let byte = if src < mapped.bytes.len() { mapped.bytes[src] } else { 0 };
            core::ptr::write_volatile((PE_SCRATCH_VADDR + src as u64) as *mut u8, byte);
        }
        let cp = copy_cap(f);
        let _ = page_map(cp, PE_LOAD_BASE + i as u64 * 0x1000, /* RX */ 2, pml4);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_frame();
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let ipcbuf = alloc_frame();
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    let _ = page_map(sysarg_c, SYSARG_VADDR, RW_NX, pml4);

    // --- Windows process environment: TEB + PEB (in the PE's PT) + KUSER_SHARED_DATA (its
    // own PT chain at the fixed low VA). Each frame is written via an executive scratch
    // mapping (past the PE code) then mapped into the PE VSpace at its VA.
    // Env/ntdll scratch pages sit PAST the PE image pages (which use scratch 0..pages) so
    // they never collide with them.
    let env_scratch = PE_SCRATCH_VADDR + pages as u64 * 0x1000;
    let teb = alloc_frame();
    let _ = page_map(teb, env_scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
    core::ptr::write_volatile((env_scratch + 0x30) as *mut u64, TEB_VA); // TEB self
    core::ptr::write_volatile((env_scratch + 0x60) as *mut u64, PEB_VA); // ProcessEnvironmentBlock
    let _ = page_map(copy_cap(teb), TEB_VA, RW_NX, pml4);
    let peb = alloc_frame();
    let _ = page_map(peb, env_scratch + 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    core::ptr::write_volatile((env_scratch + 0x1000 + 0x10) as *mut u64, PE_LOAD_BASE); // ImageBaseAddress
    let _ = page_map(copy_cap(peb), PEB_VA, RW_NX, pml4);
    // KUSER_SHARED_DATA at 0x7FFE0000 (PML4[0], vs the image at PML4[2]) — a fresh PT chain.
    let pdpt2 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt2);
    let pd2 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd2);
    let pt2 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt2);
    let _ = paging_struct_map(pdpt2, LBL_X86_PDPT_MAP, KUSER_VA, pml4);
    let _ = paging_struct_map(pd2, LBL_X86_PAGE_DIRECTORY_MAP, KUSER_VA, pml4);
    let _ = paging_struct_map(pt2, LBL_X86_PAGE_TABLE_MAP, KUSER_VA, pml4);
    let kuser = alloc_frame(); // zeroed; the stub only touches it (proves the fixed VA maps)
    let _ = page_map(kuser, KUSER_VA, RW_NX, pml4);
    // The provided "ntdll": a page of syscall stubs the PE's IAT resolves to, mapped RX.
    let ntdll = alloc_frame();
    let _ = page_map(ntdll, env_scratch + 0x2000, RW_NX, CAP_INIT_THREAD_VSPACE);
    for (j, &byte) in NTDLL_STUB.iter().enumerate() {
        core::ptr::write_volatile((env_scratch + 0x2000 + j as u64) as *mut u8, byte);
    }
    let _ = page_map(copy_cap(ntdll), NTDLL_VA, /* RX */ 2, pml4);

    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep_c, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, mapped.entry_point(), stack_top, 0);
    // The Windows TEB anchor: GS base = TEB_VA, so the PE's `GS:[0x30]` is the TEB self-pointer.
    let _ = tcb_set_gs_base(tcb, TEB_VA);
    let _ = tcb_set_priority(tcb, 100);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    pml4
}

/// Fill one page of a SEC_IMAGE view at `rva` from the PE FILE, translating RVA -> file offset
/// per the PE layout: the headers page comes from file offset 0; each section's pages come from
/// its `pointer_to_raw_data` (BSS beyond `size_of_raw_data` stays zero). Returns the page rights
/// (RX for executable sections, RW_NX otherwise). This is the memory-efficient image mapping:
/// only touched pages are ever materialized (vs pre-building the whole mapped image).
unsafe fn fill_image_page(pe: &nt_pe_loader::PeFile, rva: u32, dst: u64) -> u64 {
    for j in 0..0x1000u64 {
        core::ptr::write_volatile((dst + j) as *mut u8, 0);
    }
    let file = pe.bytes();
    let put = |off: u32, avail: u32| {
        for j in 0..avail.min(0x1000) as usize {
            let b = file.get(off as usize + j).copied().unwrap_or(0);
            core::ptr::write_volatile((dst + j as u64) as *mut u8, b);
        }
    };
    let soh = pe.headers().size_of_headers;
    let page_up = |n: u32| (n + 0xFFF) & !0xFFFu32;
    if rva < page_up(soh) {
        put(rva, soh.saturating_sub(rva)); // headers: file offset == rva
        return RW_NX;
    }
    for s in pe.sections() {
        if rva >= s.virtual_address && rva < s.virtual_address + page_up(s.virtual_size) {
            let in_sec = rva - s.virtual_address;
            if in_sec < s.size_of_raw_data {
                put(s.pointer_to_raw_data + in_sec, s.size_of_raw_data - in_sec);
            }
            return if s.is_executable() { 2 /* RX */ } else { RW_NX };
        }
    }
    RW_NX // gap between sections — a zero page
}

/// Demand-load a PE via SEC_IMAGE: build a fresh VSpace, RESERVE the image VA (page tables
/// present, image pages ABSENT), map a stack + IPC buffer, and start the entry point. The image
/// pages fault in on demand (service_sec_image fills each by RVA). Returns the pml4.
unsafe fn spawn_sec_image(
    pe: &nt_pe_loader::PeFile,
    fault_ep_c: u64,
    ntdll_base: u64,
    setup_env: bool,
) -> u64 {
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    // The image VA's page tables — but NOT the image pages. Touching the image faults in.
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    // A second demand-mapped image (ntdll) — reserve its VA's page table too (same pdpt/pd
    // as the image since both are within one 1 GiB / 512 GiB slot; only the PT differs).
    if ntdll_base != 0 {
        let npt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, npt);
        let _ = paging_struct_map(npt, LBL_X86_PAGE_TABLE_MAP, ntdll_base, pml4);
    }
    if setup_env {
        // Reserve a page table for the region the executive backs NtAllocateVirtualMemory in.
        let apt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, apt);
        let _ = paging_struct_map(apt, LBL_X86_PAGE_TABLE_MAP, SMSS_ALLOC_VA, pml4);
        // Reserve a PT in the EXECUTIVE's own VSpace for the heap copyin mirror window.
        let hpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, hpt);
        let _ = paging_struct_map(hpt, LBL_X86_PAGE_TABLE_MAP, SMSS_HEAP_MIRROR_VA, CAP_INIT_THREAD_VSPACE);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_frame();
        let _ = page_map(copy_cap(f), STACK_BASE + i * 0x1000, RW_NX, pml4);
        // Mirror the stack into the executive so it can read/write a syscall's stack-based
        // pointer args (copyin/copyout).
        if setup_env {
            let _ = page_map(copy_cap(f), SMSS_STACK_MIRROR_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
    }
    let ipcbuf = alloc_frame();
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    // A Windows process environment so the image's startup runs: a TEB (GS anchor), a PEB whose
    // ProcessParameters (+0x20) points at a zeroed RTL_USER_PROCESS_PARAMETERS, and a trampoline
    // that loads RCX=PEB then jumps to the entry (the entry expects RCX = PEB). Each page is
    // written via an executive scratch mapping, then mapped into the process VSpace.
    let entry = if setup_env {
        // A scratch region in the FILEBUF page table (0x60-0x80) to build the env pages. MUST be
        // past the service demand-fault scratch, which runs from 0x6C_0000 up by one page per
        // fault (0x6C_0000 + fault*0x1000). With up to 96 faults that reaches 0x72_0000, so the OLD
        // 0x6E_0000 collided at fault #32 (LdrpInitialize's deep page count) — page_map(f,0x6E_0000)
        // then failed because 0x6E_0000 was still mapped to the TEB frame, the fill wrote real
        // bytes into the TEB (not the fresh frame), and the fresh frame stayed zero → the ntdll
        // page mapped as zeros. 0x74_0000 is clear of the whole scratch span.
        let scr = 0x0000_0100_0074_0000u64;
        // TEB: self @0x30, PEB @0x60.
        let teb = alloc_frame();
        let _ = page_map(teb, scr, RW_NX, CAP_INIT_THREAD_VSPACE);
        core::ptr::write_volatile((scr + 0x30) as *mut u64, SMSS_TEB_VA); // NtTib.Self
        core::ptr::write_volatile((scr + 0x60) as *mut u64, SMSS_PEB_VA); // ProcessEnvironmentBlock
        // NtTib.StackBase(+0x08)/StackLimit(+0x10) — LdrpInitialize queries the memory region at
        // [TEB+0x10] (StackLimit) via NtQueryVirtualMemory; leaving it 0 would query address 0.
        core::ptr::write_volatile((scr + 0x08) as *mut u64, STACK_BASE + STACK_FRAMES * 0x1000);
        core::ptr::write_volatile((scr + 0x10) as *mut u64, STACK_BASE);
        // TEB->ActivationContextStackPointer (x64 TEB+0x2C8): the loader's actctx code
        // (RtlGetActiveActivationContext / RtlActivateActivationContextUnsafeFast, via fn
        // ntdll+0x10430 for the process default actctx) dereferences this. Point it at an EMPTY
        // ACTIVATION_CONTEXT_STACK laid out in the 2nd TEB page: ActiveFrame@0x00=NULL,
        // FrameListCache@0x08 = a self-referential empty LIST_ENTRY, Flags@0x18=0,
        // NextCookieSequenceNumber@0x1C=1, StackId@0x20=1.
        let acs_va = SMSS_TEB_VA + 0x1800; // in the 2nd TEB page
        core::ptr::write_volatile((scr + 0x2c8) as *mut u64, acs_va);
        let _ = page_map(copy_cap(teb), SMSS_TEB_VA, RW_NX, pml4);
        // The x64 TEB is ~0x1800 bytes (TLS slots etc.) — map a second page holding the
        // ACTIVATION_CONTEXT_STACK (written via scratch, then shared into smss).
        let teb2 = alloc_frame();
        let _ = page_map(teb2, scr + 0x5000, RW_NX, CAP_INIT_THREAD_VSPACE);
        let acs = scr + 0x5000 + 0x800; // matches acs_va's page offset (0x1800 & 0xFFF = 0x800)
        core::ptr::write_volatile((acs + 0x00) as *mut u64, 0); // ActiveFrame = NULL
        core::ptr::write_volatile((acs + 0x08) as *mut u64, acs_va + 0x08); // FrameListCache.Flink = self
        core::ptr::write_volatile((acs + 0x10) as *mut u64, acs_va + 0x08); // FrameListCache.Blink = self
        core::ptr::write_volatile((acs + 0x18) as *mut u32, 0); // Flags
        core::ptr::write_volatile((acs + 0x1c) as *mut u32, 1); // NextCookieSequenceNumber
        core::ptr::write_volatile((acs + 0x20) as *mut u32, 1); // StackId
        // TEB->StaticUnicodeString (x64 TEB+0x1258) + StaticUnicodeBuffer (TEB+0x1268, WCHAR[261];
        // ReactOS C_ASSERT_FIELD win2003_x64.c:158). The loader converts DLL/manifest names into
        // this fixed per-thread buffer via RtlAnsiStringToUnicodeString(&Teb->StaticUnicodeString,
        // ..., alloc=FALSE) (e.g. ntdll+0xf05e). With MaximumLength=0 that returns
        // STATUS_BUFFER_OVERFLOW (0x80000005), which propagates out of LdrpWalkImportDescriptor and
        // fails process init. Set MaximumLength = 261*sizeof(WCHAR) = 522 and point Buffer at the
        // in-TEB StaticUnicodeBuffer. Both live in the 2nd TEB page (offset 0x258/0x268).
        core::ptr::write_volatile((scr + 0x5000 + 0x25a) as *mut u16, 522); // MaximumLength
        core::ptr::write_volatile((scr + 0x5000 + 0x260) as *mut u64, SMSS_TEB_VA + 0x1268); // Buffer
        let _ = page_map(copy_cap(teb2), SMSS_TEB_VA + 0x1000, RW_NX, pml4);
        // PEB: ProcessParameters @0x20.
        let peb = alloc_frame();
        let _ = page_map(peb, scr + 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        core::ptr::write_volatile((scr + 0x1000 + 0x10) as *mut u64, PE_LOAD_BASE); // ImageBaseAddress
        core::ptr::write_volatile((scr + 0x1000 + 0x20) as *mut u64, SMSS_PARAMS_VA);
        // Heap process-list array (what LdrpInitializeProcess sets up before the first
        // RtlCreateHeap). Without it RtlpAddHeapToProcessList (heapuser.c:38) hits
        // `NumberOfHeaps == MaximumNumberOfHeaps` (0 == 0) → ASSERT(FALSE) and, since we answer
        // the debug prompt "Ignore", loops forever. Point ProcessHeaps at a small array in the
        // unused tail of the PEB page and cap at 16. x64 PEB: NumberOfHeaps@0xE8,
        // MaximumNumberOfHeaps@0xEC, ProcessHeaps@0xF0.
        core::ptr::write_volatile((scr + 0x1000 + 0xE8) as *mut u32, 0);
        core::ptr::write_volatile((scr + 0x1000 + 0xEC) as *mut u32, 16);
        core::ptr::write_volatile((scr + 0x1000 + 0xF0) as *mut u64, SMSS_PEB_VA + 0x800);
        // NLS code-page data pointers — LdrpInitializeProcess (ntdll+0x9e81) reads these and
        // passes them to RtlInitNlsTables, which builds the WideChar<->MultiByte tables
        // RtlUnicodeToMultiByteN needs (else it indexes a null table). x64 PEB (verified from the
        // disasm reading [PEB+0xa0/0xa8/0xb0]): AnsiCodePageData@0xA0, OemCodePageData@0xA8,
        // UnicodeCaseTableData@0xB0.
        core::ptr::write_volatile((scr + 0x1000 + 0xA0) as *mut u64, NLS_SMSS_ANSI_VA);
        core::ptr::write_volatile((scr + 0x1000 + 0xA8) as *mut u64, NLS_SMSS_OEM_VA);
        core::ptr::write_volatile((scr + 0x1000 + 0xB0) as *mut u64, NLS_SMSS_CASE_VA);
        let _ = page_map(copy_cap(peb), SMSS_PEB_VA, RW_NX, pml4);
        // Share the NLS tables (read off disk into the shared buffers at storage bring-up) into
        // smss at their own page table (the 0xE0_0000 2 MiB region covers all three).
        let nls_pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, nls_pt);
        let _ = paging_struct_map(nls_pt, LBL_X86_PAGE_TABLE_MAP, NLS_SMSS_ANSI_VA, pml4);
        for (start, va, frames) in [
            (NLS_ANSI_START.load(Ordering::Relaxed), NLS_SMSS_ANSI_VA, NLS_ANSI_FRAMES),
            (NLS_OEM_START.load(Ordering::Relaxed), NLS_SMSS_OEM_VA, NLS_OEM_FRAMES),
            (NLS_CASE_START.load(Ordering::Relaxed), NLS_SMSS_CASE_VA, NLS_CASE_FRAMES),
        ] {
            for i in 0..frames {
                let _ = page_map(copy_cap(start + i), va + i * 0x1000, RW_NX, pml4);
            }
        }
        // Process parameters: a real RTL_USER_PROCESS_PARAMETERS. LdrpInitializeProcess reads
        // DllPath (@0x50) and requires DllPath.Length > 0 (else "Error while retrieving buffer for
        // %wZ" → STATUS_INVALID_PARAMETER → APP_INIT_FAILURE). Build it in executive scratch
        // (scr+0x3000), populate the UNICODE_STRINGs (Buffers point at SMSS_PARAMS_VA tail), then
        // map into smss. x64 layout: MaximumLength@0x00, Length@0x04, CurrentDirectory.DosPath@0x38,
        // DllPath@0x50, ImagePathName@0x60, CommandLine@0x70 (each UNICODE_STRING = Len,MaxLen,_,Buf).
        let params = alloc_frame();
        let pp = scr + 0x3000;
        let _ = page_map(params, pp, RW_NX, CAP_INIT_THREAD_VSPACE);
        core::ptr::write_volatile((pp + 0x00) as *mut u32, 0x1000); // MaximumLength
        core::ptr::write_volatile((pp + 0x04) as *mut u32, 0x1000); // Length
        // Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED (0x1): our UNICODE_STRING Buffers are
        // absolute pointers, so RtlNormalizeProcessParams must NOT add the base to them (it would
        // otherwise double them → 2*SMSS_PARAMS_VA + off, a wild pointer).
        core::ptr::write_volatile((pp + 0x08) as *mut u32, 0x1);
        // write `s` as UTF-16LE at scratch VA `dst`; return byte length.
        let wstr = |dst: u64, s: &[u8]| -> u16 {
            for (i, &c) in s.iter().enumerate() {
                core::ptr::write_volatile((dst + i as u64 * 2) as *mut u8, c);
                core::ptr::write_volatile((dst + i as u64 * 2 + 1) as *mut u8, 0);
            }
            (s.len() * 2) as u16
        };
        // (unicode_string field offset, scratch buffer offset, smss buffer VA offset, text)
        let ustrs: [(u64, u64, &[u8]); 4] = [
            (0x38, 0x300, b"C:\\Windows"),                       // CurrentDirectory.DosPath
            (0x50, 0x340, b"C:\\Windows\\System32"),             // DllPath
            (0x60, 0x3A0, b"\\SystemRoot\\System32\\smss.exe"),  // ImagePathName
            (0x70, 0x420, b"smss.exe"),                          // CommandLine
        ];
        for (foff, boff, text) in ustrs {
            let len = wstr(pp + boff, text);
            core::ptr::write_volatile((pp + foff) as *mut u16, len); // Length
            core::ptr::write_volatile((pp + foff + 2) as *mut u16, len + 2); // MaximumLength
            core::ptr::write_volatile((pp + foff + 8) as *mut u64, SMSS_PARAMS_VA + boff); // Buffer
        }
        let _ = page_map(copy_cap(params), SMSS_PARAMS_VA, RW_NX, pml4);
        // KUSER_SHARED_DATA at 0x7FFE0000 (PML4[0] — a fresh PT chain; the image is PML4[2]).
        // LdrpInitialize reads it early (e.g. 0x7FFE0274); an unmapped read would #PF. A zeroed
        // page satisfies the early reads (a real cookie/NtGlobalFlag can be filled in later).
        let kpdpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, kpdpt);
        let kpd = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, kpd);
        let kpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, kpt);
        let _ = paging_struct_map(kpdpt, LBL_X86_PDPT_MAP, KUSER_VA, pml4);
        let _ = paging_struct_map(kpd, LBL_X86_PAGE_DIRECTORY_MAP, KUSER_VA, pml4);
        let _ = paging_struct_map(kpt, LBL_X86_PAGE_TABLE_MAP, KUSER_VA, pml4);
        let _ = page_map(alloc_frame(), KUSER_VA, RW_NX, pml4);
        // Trampoline: enter ntdll's REAL loader init, LdrpInitialize (ntdll+0x8e70, the target of
        // LdrInitializeThunk's `mov rcx,r9; jmp`). It does the whole process bring-up — reads
        // TEB/PEB/KUSER, NtQueryVirtualMemory, creates the process heap (RtlCreateHeap itself),
        // builds the loader module list, then NtContinue's to the image entry. RCX = a CONTEXT
        // record (which LdrpInitialize eventually resumes to reach smss's entry). We point it at a
        // zeroed slot in the PEB page tail for now; the Nt* cascade LdrpInitialize issues is
        // serviced by the executive (NtQueryVirtualMemory added; more to come). The entry runs
        // with RSP 16-aligned, so `call` gives LdrpInitialize a correctly-aligned frame.
        let _ = pe.entry_point_rva();
        let tramp = alloc_frame();
        let _ = page_map(tramp, scr + 0x2000, RW_NX, CAP_INIT_THREAD_VSPACE);
        let mut tb = alloc::vec::Vec::new();
        // Reserve 0x20 shadow space so LdrpInitialize's register-arg spills ([rsp+0x8..0x20]) land
        // WITHIN the stack, not above its top. RSP starts 16-aligned; sub 0x20 keeps it aligned so
        // the `call` gives LdrpInitialize the ABI-correct (rsp ≡ 8 mod 16) frame.
        tb.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20
        tb.extend_from_slice(&[0x48, 0xB9]);
        tb.extend_from_slice(&(SMSS_PEB_VA + 0x900).to_le_bytes()); // movabs rcx, Context (placeholder)
        // SystemArgument1 (RDX) = the ntdll base — LdrpInitializeProcess builds ntdll's
        // LDR_DATA_TABLE_ENTRY from it (the kernel passes it via the initial APC). RDX=0 left the
        // ntdll DllBase null → LdrpAllocateModuleEntry(RtlImageNtHeader(0)=0) returned null.
        tb.extend_from_slice(&[0x48, 0xBA]);
        tb.extend_from_slice(&NTDLL_BASE.to_le_bytes()); // movabs rdx, NTDLL_BASE
        tb.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d  (SystemArgument2)
        tb.extend_from_slice(&[0x48, 0xB8]);
        tb.extend_from_slice(&(NTDLL_BASE + 0x8e70).to_le_bytes()); // movabs rax, LdrpInitialize
        tb.extend_from_slice(&[0xFF, 0xD0]); // call rax  (runs the whole loader, then RETURNS here)
        // LdrpInitialize (== ReactOS LdrpInit) runs the entire process init and RETURNS — in real
        // Windows KiUserApcDispatcher would then NtContinue to the image entry; we have no APC
        // dispatcher, so chain straight to smss's native entry (NtProcessStartup) with RCX=PEB.
        // `call` (not jmp) gives the entry the ABI-correct rsp≡8(mod16); the entry never returns
        // (it ends in NtTerminateProcess), and the trailing jmp$ is a safety net if it does.
        tb.extend_from_slice(&[0x48, 0xB9]);
        tb.extend_from_slice(&SMSS_PEB_VA.to_le_bytes()); // movabs rcx, PEB
        tb.extend_from_slice(&[0x48, 0xB8]);
        tb.extend_from_slice(&(PE_LOAD_BASE + pe.entry_point_rva() as u64).to_le_bytes()); // movabs rax, entry
        tb.extend_from_slice(&[0xFF, 0xD0]); // call rax  (enter smss)
        tb.extend_from_slice(&[0xEB, 0xFE]); // jmp $
        for (j, &b) in tb.iter().enumerate() {
            core::ptr::write_volatile((scr + 0x2000 + j as u64) as *mut u8, b);
        }
        let _ = page_map(copy_cap(tramp), SMSS_TRAMP_VA, /* RX */ 2, pml4);
        SMSS_TRAMP_VA
    } else {
        PE_LOAD_BASE + pe.entry_point_rva() as u64
    };
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep_c, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry, stack_top, 0);
    if setup_env {
        let _ = tcb_set_gs_base(tcb, SMSS_TEB_VA);
    }
    let _ = tcb_set_priority(tcb, 100);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    pml4
}

/// Read a u64 from a SEC_IMAGE process's stack VA (a syscall's pointer arg) via the executive's
/// stack mirror. Returns 0 if the VA isn't in the mirrored stack range.
unsafe fn smss_stack_read(stack_va: u64) -> u64 {
    if stack_va >= STACK_BASE && stack_va + 8 <= STACK_BASE + STACK_FRAMES * 0x1000 {
        core::ptr::read_volatile((SMSS_STACK_MIRROR_VA + (stack_va - STACK_BASE)) as *const u64)
    } else {
        0
    }
}
/// Translate a SEC_IMAGE process VA to its executive mirror VA (stack or heap window), or None if
/// the range isn't covered by a mirror. The executive's copyin/copyout base: a userspace broker
/// can't walk smss's page tables, so it reaches smss memory through the same frames it mapped.
unsafe fn smss_mirror(va: u64, len: u64) -> Option<u64> {
    if va >= STACK_BASE && va + len <= STACK_BASE + STACK_FRAMES * 0x1000 {
        Some(SMSS_STACK_MIRROR_VA + (va - STACK_BASE))
    } else if va >= SMSS_ALLOC_VA && va + len <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
        Some(SMSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA))
    } else {
        None
    }
}
/// Copy `dst.len()` bytes IN from a SEC_IMAGE process VA (the executive's ProbeForRead+copyin).
/// Returns false if the range isn't mirror-backed.
unsafe fn smss_copyin(va: u64, dst: &mut [u8]) -> bool {
    match smss_mirror(va, dst.len() as u64) {
        Some(m) => {
            core::ptr::copy_nonoverlapping(m as *const u8, dst.as_mut_ptr(), dst.len());
            true
        }
        None => false,
    }
}
/// Copy `src.len()` bytes OUT to a SEC_IMAGE process VA (the executive's copyout).
/// Returns false if the range isn't mirror-backed.
unsafe fn smss_copyout(va: u64, src: &[u8]) -> bool {
    match smss_mirror(va, src.len() as u64) {
        Some(m) => {
            core::ptr::copy_nonoverlapping(src.as_ptr(), m as *mut u8, src.len());
            true
        }
        None => false,
    }
}
/// Read a UTF-16LE UNICODE_STRING (given its byte Length + Buffer VA) from smss into a UTF-16
/// code-unit Vec. Caps at 1024 code units. Empty on any copyin failure.
unsafe fn smss_read_unicode(buffer_va: u64, byte_len: u16) -> alloc::vec::Vec<u16> {
    let n = ((byte_len as usize) / 2).min(1024);
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let mut w = [0u8; 2];
        if !smss_copyin(buffer_va + (i as u64) * 2, &mut w) {
            break;
        }
        out.push(u16::from_le_bytes(w));
    }
    out
}
/// Copy in an OBJECT_ATTRIBUTES.ObjectName (x64: ObjectName PUNICODE_STRING @ +0x10; UNICODE_STRING
/// = {u16 Length, u16 MaximumLength, u32 pad, u64 Buffer}) and return the name as UTF-16 units.
unsafe fn smss_read_objattr_name(oa_va: u64) -> alloc::vec::Vec<u16> {
    let mut p = [0u8; 8];
    if !smss_copyin(oa_va + 0x10, &mut p) {
        return alloc::vec::Vec::new();
    }
    let objname = u64::from_le_bytes(p);
    if objname == 0 {
        return alloc::vec::Vec::new();
    }
    let mut lm = [0u8; 2];
    let mut bp = [0u8; 8];
    if !smss_copyin(objname, &mut lm) || !smss_copyin(objname + 8, &mut bp) {
        return alloc::vec::Vec::new();
    }
    smss_read_unicode(u64::from_le_bytes(bp), u16::from_le_bytes(lm))
}
/// Write a u64 to a SEC_IMAGE process's stack VA via the mirror (copyout).
unsafe fn smss_stack_write(stack_va: u64, v: u64) {
    if stack_va >= STACK_BASE && stack_va + 8 <= STACK_BASE + STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((SMSS_STACK_MIRROR_VA + (stack_va - STACK_BASE)) as *mut u64, v);
    }
}

/// Write a 32-bit value to a stack VA (via the mirror). Use for DWORD out-params (e.g. an
/// NtProtectVirtualMemory *OldProtect) — an 8-byte write would clobber the adjacent local.
unsafe fn smss_stack_write32(stack_va: u64, v: u32) {
    if stack_va >= STACK_BASE && stack_va + 4 <= STACK_BASE + STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((SMSS_STACK_MIRROR_VA + (stack_va - STACK_BASE)) as *mut u32, v);
    }
}

/// The file byte at image RVA `rva` (translated via the section table). For reading a faulting
/// instruction's opcode from the mapped PE.
unsafe fn pe_byte_at_rva(pe: &nt_pe_loader::PeFile, rva: u32) -> Option<u8> {
    for s in pe.sections() {
        if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
            let off = (s.pointer_to_raw_data + (rva - s.virtual_address)) as usize;
            return pe.bytes().get(off).copied();
        }
    }
    None
}

/// File offset of image RVA `rva`, via the section table.
unsafe fn rva_to_file(pe: &nt_pe_loader::PeFile, rva: u32) -> Option<u64> {
    for s in pe.sections() {
        let vend = s.virtual_address + s.virtual_size.max(s.size_of_raw_data);
        if rva >= s.virtual_address && rva < vend {
            return Some((s.pointer_to_raw_data + (rva - s.virtual_address)) as u64);
        }
    }
    None
}

/// Apply base relocations to a PE's RAW bytes in `buf` for a load at `load_base` (delta =
/// load_base - preferred image base). We SEC_IMAGE-load by copying raw section bytes, so ntdll's
/// absolute .data pointers (list heads etc.) must be fixed up here or they point at the
/// preferred base. Only IMAGE_REL_BASED_DIR64 (x64) is needed.
unsafe fn apply_relocations_to_buf(pe: &nt_pe_loader::PeFile, buf: u64, load_base: u64) {
    let e = core::ptr::read_volatile((buf + 0x3c) as *const u32) as u64;
    let image_base = core::ptr::read_volatile((buf + e + 24 + 24) as *const u64);
    let delta = load_base.wrapping_sub(image_base);
    if delta == 0 {
        return;
    }
    let reloc_rva = core::ptr::read_volatile((buf + e + 24 + 112 + 5 * 8) as *const u32);
    let reloc_size = core::ptr::read_volatile((buf + e + 24 + 112 + 5 * 8 + 4) as *const u32);
    if reloc_rva == 0 || reloc_size == 0 {
        return;
    }
    let base_off = match rva_to_file(pe, reloc_rva) {
        Some(o) => o,
        None => return,
    };
    let mut off = 0u64;
    while off + 8 <= reloc_size as u64 {
        let page_rva = core::ptr::read_volatile((buf + base_off + off) as *const u32);
        let block_size = core::ptr::read_volatile((buf + base_off + off + 4) as *const u32);
        if block_size < 8 {
            break;
        }
        let n = (block_size - 8) / 2;
        for i in 0..n as u64 {
            let entry = core::ptr::read_volatile((buf + base_off + off + 8 + i * 2) as *const u16);
            if (entry >> 12) == 10 {
                let target_rva = page_rva + (entry & 0xFFF) as u32;
                if let Some(tf) = rva_to_file(pe, target_rva) {
                    let v = core::ptr::read_volatile((buf + tf) as *const u64);
                    core::ptr::write_volatile((buf + tf) as *mut u64, v.wrapping_add(delta));
                }
            }
        }
        off += block_size as u64;
    }
}

/// The page-aligned virtual extent of a PE image (end of its highest section).
unsafe fn image_extent(pe: &nt_pe_loader::PeFile) -> u64 {
    let mut ext = 0u32;
    for s in pe.sections() {
        let e = s.virtual_address.wrapping_add(s.virtual_size);
        if e > ext {
            ext = e;
        }
    }
    ((ext + 0xFFF) & !0xFFF) as u64
}

/// The real NT syscall handler the dispatcher routes to (`nt_syscall::NativeSyscallHandler`).
/// This is the seam that replaces the ad-hoc broker: syscalls whose SSN is in the service table
/// are dispatched HERE (real subsystems), and everything else falls back to the broker match —
/// so syscalls migrate from fake to real one family at a time while the tree stays green. v0.1
/// covers only the trivial object calls; the registry family (real OBJECT_ATTRIBUTES copyin +
/// a real hive) lands next, then process/section/token/port against the smss trace.
/// Base for registry key handles the handler hands out (index into `key_handles`, offset so it
/// never looks like a small/null handle).
const KEY_HANDLE_BASE: u64 = 0x0000_0001_0000_0000;

struct ExecNtHandler {
    /// The REAL ReactOS SYSTEM hive (root = \Registry\Machine\System), parsed read-only by
    /// borrowing the regf bytes the storage host read off the disk into HIVEBUF (no 204 KiB copy —
    /// the executive heap is small). None if the hive wasn't staged on the disk.
    hive: Option<RegfHive<'static>>,
    key_handles: alloc::vec::Vec<KeyRef>,
}
impl ExecNtHandler {
    fn new() -> Self {
        // SAFETY: HIVEBUF is a fixed, executive-lifetime mapping the storage host filled from
        // ::ROSSYS.HIV; REAL_HIVE_SIZE is its reported byte length (0 if unstaged → None).
        let hive = unsafe {
            let n = REAL_HIVE_SIZE.load(Ordering::Relaxed) as usize;
            if n == 0 {
                None
            } else {
                let bytes: &'static [u8] =
                    core::slice::from_raw_parts(HIVEBUF_VADDR as *const u8, n);
                RegfHive::new(bytes)
            }
        };
        ExecNtHandler {
            hive,
            key_handles: alloc::vec::Vec::new(),
        }
    }
    /// Resolve a full NT key path (`\Registry\Machine\System\…`) to a key node in the SYSTEM hive:
    /// apply the CurrentControlSet alias (the hive has ControlSet001, not the kernel-synthesized
    /// CurrentControlSet symlink) + strip the hive's mount prefix.
    fn resolve_key(&self, full_path: &str) -> Option<KeyRef> {
        let hive = self.hive.as_ref()?;
        let aliased = apply_ccs_alias(full_path);
        let comps: alloc::vec::Vec<&str> =
            aliased.split('\\').filter(|c| !c.is_empty()).collect();
        if comps.len() >= 3
            && comps[0].eq_ignore_ascii_case("Registry")
            && comps[1].eq_ignore_ascii_case("Machine")
            && comps[2].eq_ignore_ascii_case("System")
        {
            hive.open_key(&comps[3..].join("\\"))
        } else {
            None
        }
    }
}
impl NativeSyscallHandler for ExecNtHandler {
    fn handle(&mut self, ctx: &NativeCallContext, args: &[u64], _out: &mut alloc::vec::Vec<u8>) -> u32 {
        match ctx.service {
            // No handle table modelled yet → closing a handle is a success (matches the broker).
            NativeService::NtClose => 0, // STATUS_SUCCESS
            // NtOpenKey(*KeyHandle[0], DesiredAccess[1], ObjectAttributes[2]). Copy in the object
            // name from smss, resolve it in the SYSTEM hive, hand back a handle (copyout to arg0).
            NativeService::NtOpenKey => unsafe {
                let name16 = smss_read_objattr_name(args[2]);
                let mut path = alloc::string::String::new();
                for &w in &name16 {
                    if let Some(c) = char::from_u32(w as u32) {
                        path.push(c);
                    }
                }
                match self.resolve_key(&path) {
                    Some(cell) => {
                        self.key_handles.push(cell);
                        let h = KEY_HANDLE_BASE + (self.key_handles.len() as u64 - 1);
                        smss_copyout(args[0], &h.to_le_bytes());
                        0 // STATUS_SUCCESS
                    }
                    None => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            _ => 0xC000_0002, // STATUS_NOT_IMPLEMENTED — never silently succeed
        }
    }
}

/// Build the service table mapping smss's ntdll SSNs -> NativeService, for ONLY the services the
/// real handler implements. `table.lookup(ssn).is_some()` is the routing switch: present -> real
/// dispatcher, absent -> broker fallback. Grows as each syscall family is implemented for real.
fn build_nt_table() -> NativeServiceTable {
    NativeServiceTable::from_numbers(
        UserlandAbiProfile::Windows7,
        &[
            (NativeService::NtClose, SSN_NT_CLOSE as u32),
            (NativeService::NtOpenKey, SSN_NT_OPEN_KEY as u32),
        ],
    )
}

/// Service a SEC_IMAGE process: on each VMFault, fault the faulting image page in BY RVA from
/// the PE file (scratch frames rotate from `scratch_base`); on SSN_DONE, capture the verdict.
/// Faults are routed to the main image (at PE_LOAD_BASE) or, if present, a second image `ntdll`
/// at `(base, pe)` — so smss's resolved ntdll calls fault ntdll's pages in and EXECUTE. SAFE
/// STOP: halt (don't loop) on a fault outside BOTH images (a null deref / bad address), a
/// non-VMFault (#GP), or a fault cap. Returns (verdict, faults, first, stop, ntdll_faults).
unsafe fn service_sec_image(
    fault_ep: u64,
    pml4: u64,
    pe: &nt_pe_loader::PeFile,
    scratch_base: u64,
    ntdll: Option<(u64, &nt_pe_loader::PeFile)>,
) -> (u64, u64, u64, u64, u64, u64) {
    let img_end = PE_LOAD_BASE + image_extent(pe);
    let (nt_base, nt_end) = match ntdll {
        Some((b, npe)) => (b, b + image_extent(npe)),
        None => (0, 0),
    };
    let mut verdict = 0u64;
    let mut faults = 0u64;
    let mut first = 0u64;
    let mut stop = 0u64;
    let mut ntfaults = 0u64;
    let mut stop_ssn = 0u64;
    let mut iters = 0u64;
    let mut dbgsvc = 0u64;
    // page VA filled at each fault index → its persistent executive scratch is
    // scratch_base + index*0x1000. Lets a syscall handler copy OUT to any already-mapped image
    // page (e.g. an ntdll .data global), not just the stack (which has its own mirror).
    let mut filled_pages = [0u64; 256];
    // DIAG ring buffer of the last serviced SSNs, to locate the silent 0x80000005.
    let mut ssn_ring = [0u16; 32];
    let mut ssn_ri = 0usize;
    // Distinct fake handles for objects we don't model yet (ports/threads/events/sections), so the
    // Session Manager's SmpInit keeps flowing. Each create hands out a fresh value.
    let mut next_handle = FAKE_HANDLE;
    // The real NT syscall path (seam): dispatch SSNs the handler implements; the rest fall back
    // to the broker match below.
    let nt_dispatcher = NativeSyscallDispatcher::new(build_nt_table());
    let mut nt_handler = ExecNtHandler::new();
    let (_z, mut mi, mut m0, mut m1, mut m2, mut m3) = ep_recv_full(fault_ep);
    loop {
        iters += 1;
        if iters > 3000 {
            stop = m1;
            break;
        }
        // A CPU exception (label 3). The DEBUG ntdll emits `int 0x2d` (DebugService/DPRINT),
        // which #GPs with no kernel debugger; emulate it as a no-op by skipping past the
        // `int 0x2d; int3` pair (echo the registers, advance the fault IP by 3, restart).
        if (mi >> 12) == 3 {
            // UserException delivery: m0=FaultIP, m1=SP, m2=FLAGS, m3=Number, mr4=Code. The
            // reply sets IP/SP/FLAGS (length 3); the general registers are preserved.
            let fip = m0;
            let mut skipped = false;
            if let Some((nb, npe)) = ntdll {
                if fip >= nb && fip < nb + image_extent(npe) {
                    if pe_byte_at_rva(npe, (fip - nb) as u32) == Some(0xCD) {
                        // Skip `int 0x2d; int3` (3 bytes) — the no-op DebugService.
                        let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(fault_ep, 3, fip + 3, m1, m2, 0);
                        mi = nmi;
                        m0 = nm0;
                        m1 = nm1;
                        m2 = nm2;
                        m3 = nm3;
                        skipped = true;
                        dbgsvc += 1;
                    }
                }
            }
            if skipped {
                continue;
            }
            stop = fip;
            break;
        }
        if (mi >> 12) == 6 {
            let addr = m1;
            if faults == 0 {
                first = addr;
            }
            let page = addr & !0xFFFu64;
            // Route to whichever image contains the faulting page.
            let (base, tpe) = if page >= PE_LOAD_BASE && page < img_end {
                (PE_LOAD_BASE, pe)
            } else if nt_base != 0 && page >= nt_base && page < nt_end {
                ntfaults += 1;
                (nt_base, ntdll.unwrap().1)
            } else {
                stop = addr; // outside both images (unresolved / null deref) — stop safely
                break;
            };
            if faults >= 256 {
                stop = addr;
                break;
            }
            let rva = (page - base) as u32;
            let scratch = scratch_base + faults * 0x1000;
            let f = alloc_frame();
            let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
            let rights = fill_image_page(tpe, rva, scratch);
            let _ = page_map(copy_cap(f), page, rights, pml4);
            if (faults as usize) < filled_pages.len() {
                filled_pages[faults as usize] = page;
            }
            faults += 1;
            let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(fault_ep, 0, 0, 0, 0, 0);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        if (mi >> 12) == 2 {
            // A native `syscall` from the process (via ntdll's Nt* stub). SSN_DONE is our test
            // sentinel; otherwise it's a REAL Nt* system call to service.
            if m0 == SSN_DONE {
                verdict = get_recv_mr(9); // R10 = arg1
                break;
            }
            ssn_ring[ssn_ri % 32] = m0 as u16;
            ssn_ri += 1;
            let resume_ip = m2; // RCX = syscall return address
            let sp = get_recv_mr(16);
            let flags = get_recv_mr(17);
            let mut result = 0u64; // STATUS_SUCCESS unless a handler overrides
            let mut handled = true;
            // SEAM: if this SSN is in the real service table, dispatch it through the NT syscall
            // dispatcher -> real handler; otherwise fall through to the broker match. The x64 native
            // ABI passes args in r10(=rcx),rdx,r8,r9 then the stack; here we forward the register
            // args (sized to the service's max) — pointer/stack args come with the copyin layer.
            if let Some(entry) = nt_dispatcher.table().lookup(m0 as u32) {
                let origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
                let regs = [get_recv_mr(2), m3, get_recv_mr(7), get_recv_mr(8)];
                let n = (entry.max_args as usize).min(4);
                let res = nt_dispatcher.dispatch(m0 as u32, &regs[..n], &origin, &mut nt_handler);
                result = res.status as u64;
            } else if m0 == SSN_NT_ALLOCATE_VM {
                // NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits, *RegionSize,
                // Type, Protect): R10=handle, RDX=&Base, R8=zerobits, R9=&Size, [sp+0x28]=Type.
                // RESERVE (base in==0) picks a bump base; COMMIT maps frames at the base.
                let base_ptr = m3; // RDX
                let size_ptr = get_recv_mr(8); // R9
                let alloc_type = smss_stack_read(sp + 0x28);
                let base_in = smss_stack_read(base_ptr);
                let want = smss_stack_read(size_ptr);
                let rounded = ((want + 0xFFF) & !0xFFFu64).max(0x1000);
                let base = if base_in != 0 {
                    base_in
                } else {
                    NEXT_SMSS_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                };
                if alloc_type & 0x1000 != 0 {
                    // MEM_COMMIT — back it with real frames.
                    let mut p = 0u64;
                    while p < rounded {
                        let f = alloc_frame();
                        let _ = page_map(f, base + p, RW_NX, pml4);
                        // Mirror the first heap window into the executive so smss_copyin can read
                        // heap-resident pointer args (registry key paths, etc.).
                        let va = base + p;
                        if va >= SMSS_ALLOC_VA && va < SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
                            let _ = page_map(copy_cap(f),
                                SMSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA), RW_NX, CAP_INIT_THREAD_VSPACE);
                        }
                        p += 0x1000;
                    }
                }
                smss_stack_write(base_ptr, base);
                smss_stack_write(size_ptr, rounded);
                NTALLOC_SERVICED.fetch_add(1, Ordering::Relaxed);
            } else if m0 == SSN_NT_QUERY_SYSTEM_INFO {
                // NtQuerySystemInformation(Class, Buffer, Len, *RetLen). RtlCreateHeap needs
                // SystemBasicInformation (class 0): PageSize, AllocationGranularity, and the
                // user-mode address range. Copyout the fields it reads.
                let class = get_recv_mr(9); // R10 = SystemInformationClass
                let buf = m3; // RDX = SystemInformation buffer
                let retlen_ptr = get_recv_mr(8); // R9 = *ReturnLength (4th arg, a register)
                if class == 0 {
                    smss_stack_write(buf + 0x08, 0x1000); // PageSize
                    smss_stack_write(buf + 0x18, 0x10000); // AllocationGranularity
                    smss_stack_write(buf + 0x20, 0x10000); // MinimumUserModeAddress
                    smss_stack_write(buf + 0x28, 0x0000_7FFF_FFFE_FFFF); // MaximumUserModeAddress
                    smss_stack_write(retlen_ptr, 0x40);
                }
            } else if m0 == SSN_NT_QUERY_VIRTUAL_MEM {
                // NtQueryVirtualMemory(Process, BaseAddress, Class, Buffer, Len, *RetLen).
                // LdrpInitialize queries MemoryBasicInformation (class 0) for [TEB+0x10]. Return a
                // plausible committed private region (buffer is a stack local → stack mirror).
                let base = m3; // RDX = BaseAddress
                let buf = get_recv_mr(8); // R9 = MemoryInformation buffer
                let retlen_ptr = smss_stack_read(sp + 0x30); // arg6 = *ReturnLength (stack slot)
                smss_stack_write(buf + 0x00, base & !0xFFFu64); // BaseAddress
                smss_stack_write(buf + 0x08, base & !0xFFFFu64); // AllocationBase
                smss_stack_write(buf + 0x10, 0x04); // AllocationProtect = PAGE_READWRITE
                smss_stack_write(buf + 0x18, 0x10000); // RegionSize
                smss_stack_write(buf + 0x20, 0x1000 | (0x04u64 << 32)); // State=MEM_COMMIT, Protect=RW
                smss_stack_write(buf + 0x28, 0x20000); // Type = MEM_PRIVATE
                if retlen_ptr != 0 {
                    smss_stack_write(retlen_ptr, 0x30);
                }
            } else if m0 == SSN_NT_QUERY_INFO_PROCESS {
                // NtQueryInformationProcess(Handle, Class, Buffer, Len, *RetLen). Class in RDX.
                let class = m3; // ProcessInformationClass
                let buf = get_recv_mr(7); // R8 = ProcessInformation buffer (a stack local)
                if class == 36 {
                    // ProcessCookie — a per-process value ntdll caches for RtlEncode/DecodePointer.
                    // A fixed nonzero cookie is fine as long as encode/decode round-trip with it.
                    smss_stack_write(buf, 0x1a2b_3c4d);
                } else {
                    handled = false;
                    result = 0xC0000002; // STATUS_NOT_IMPLEMENTED — surfaces the class via m3
                }
            } else if m0 == SSN_NT_CREATE_PORT
                || m0 == SSN_NT_CREATE_THREAD
                || m0 == SSN_NT_CREATE_EVENT
                || m0 == SSN_NT_CREATE_SECTION
            {
                // Object-creation calls SmpInit makes (\SmApiPort, the SM API-loop thread, events,
                // sections). Each takes the out handle in RCX (arg1). Hand back a fresh fake handle
                // so the Session Manager keeps initialising — real LPC / thread / section objects
                // are later milestones. NtCreateThread's new thread does NOT actually run yet.
                let out = get_recv_mr(2); // RCX = *Handle
                smss_stack_write(out, next_handle);
                next_handle += 1;
            } else if m0 == SSN_NT_OPEN_THREAD_TOKEN {
                // No impersonation token → STATUS_NO_TOKEN; the caller falls back to the process one.
                result = 0xC000007C;
            } else if m0 == SSN_NT_OPEN_PROCESS_TOKEN {
                // NtOpenProcessToken(ProcessHandle, DesiredAccess, *TokenHandle). R8 = out handle.
                let out = get_recv_mr(7); // R8
                smss_stack_write(out, next_handle);
                next_handle += 1;
            } else if m0 == SSN_NT_OPEN_DIRECTORY_OBJECT
                || m0 == SSN_NT_OPEN_FILE
                || m0 == SSN_NT_QUERY_ATTRIBUTES_FILE
            {
                // NtOpenDirectoryObject / NtOpenFile / NtQueryAttributesFile — no object namespace
                // or filesystem yet → STATUS_OBJECT_NAME_NOT_FOUND. (NtOpenKey now goes through the
                // real registry handler above.)
                result = 0xC0000034;
            } else if m0 == SSN_NT_QUERY_VALUE_KEY {
                // NtQueryValueKey — no registry → value not found; LdrpInitialize uses defaults.
                result = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
            } else if m0 == SSN_NT_PROTECT_VM {
                // NtProtectVirtualMemory(Process, *Base, *Size, NewProtect, *OldProtect). We don't
                // model per-page protection changes yet — report success and hand back a plausible
                // previous protection so LdrpInitialize's protect/restore pairs proceed.
                let oldprot_ptr = smss_stack_read(sp + 0x28); // arg5 = *OldAccessProtection
                if oldprot_ptr != 0 {
                    // DWORD write: OldProtect is a ULONG; an 8-byte write clobbers the caller's
                    // adjacent local (in LdrpSetProtection that is the section-header pointer).
                    smss_stack_write32(oldprot_ptr, 0x04); // PAGE_READWRITE
                }
            } else if m0 == SSN_NT_QUERY_DEFAULT_LOCALE {
                // NtQueryDefaultLocale(UserProfile, *DefaultLocaleId). Write en-US (0x409) to the
                // output, which ntdll points at one of its own .data GLOBALS (not the stack) — so
                // copy out through the target image page's persistent executive scratch mapping,
                // demand-filling the page first if LdrpInitialize hasn't touched it yet.
                let out = m3; // RDX = *DefaultLocaleId
                let pg = out & !0xFFFu64;
                let mut idx = usize::MAX;
                for i in 0..(faults as usize).min(filled_pages.len()) {
                    if filled_pages[i] == pg { idx = i; break; }
                }
                if idx == usize::MAX && (faults as usize) < filled_pages.len() {
                    let (base, tpe) = if pg >= PE_LOAD_BASE && pg < img_end {
                        (PE_LOAD_BASE, pe)
                    } else if nt_base != 0 && pg >= nt_base && pg < nt_end {
                        (nt_base, ntdll.unwrap().1)
                    } else { (0u64, pe) };
                    if base != 0 {
                        let scratch = scratch_base + faults * 0x1000;
                        let f = alloc_frame();
                        let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
                        let rights = fill_image_page(tpe, (pg - base) as u32, scratch);
                        let _ = page_map(copy_cap(f), pg, rights, pml4);
                        filled_pages[faults as usize] = pg;
                        idx = faults as usize;
                        faults += 1;
                    }
                }
                if idx != usize::MAX {
                    core::ptr::write_volatile(
                        (scratch_base + idx as u64 * 0x1000 + (out & 0xFFF)) as *mut u32, 0x409);
                }
            } else if m0 == SSN_NT_QUERY_DEBUG_FILTER_STATE {
                // Return TRUE so ntdll's DbgPrintEx does not filter out component traces
                // (rtl/debug.c:66 compares the result against (NTSTATUS)TRUE=1). Unmasks the
                // SXS/LDR loader diagnostics that pinpoint the failing internal step.
                result = 1;
            } else if m0 == SSN_NT_FREE_VM
                || m0 == SSN_NT_SET_INFO_THREAD
                || m0 == SSN_NT_SET_INFO_PROCESS
                || m0 == SSN_NT_TEST_ALERT
                || m0 == SSN_NT_FLUSH_INSTRUCTION_CACHE
                || m0 == SSN_NT_CREATE_KEYED_EVENT
                || m0 == SSN_NT_ADJUST_PRIV_TOKEN
            {
                // No-op → STATUS_SUCCESS (result stays 0). We never free (bump allocator), don't
                // model thread/process attribute sets, and don't model a handle table (NtClose of a
                // fake handle is a no-op).
            } else {
                handled = false;
                result = 0xC0000002; // STATUS_NOT_IMPLEMENTED
            }
            if !handled {
                stop_ssn = m0; // an Nt* syscall we don't service yet — stop
                break;
            }
            set_reply_mr(15, resume_ip);
            set_reply_mr(16, sp);
            set_reply_mr(17, flags);
            let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(fault_ep, 18, result, m1, 0, m3);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        stop = m1; // a non-VMFault, non-syscall (e.g. #GP) — stop
        break;
    }
    print_str(b"[sec-stop] label=");
    print_u64(mi >> 12);
    print_str(b" m0=0x");
    print_hex((m0 >> 32) as u32);
    print_hex(m0 as u32);
    print_str(b" m1=0x");
    print_hex((m1 >> 32) as u32);
    print_hex(m1 as u32);
    print_str(b" exc#=");
    print_u64(m3);
    print_str(b" code=0x");
    print_hex(get_recv_mr(4) as u32);
    print_str(b" iters=");
    print_u64(iters);
    print_str(b" dbgsvc=");
    print_u64(dbgsvc);
    print_str(b" stop_ssn=");
    print_u64(stop_ssn);
    // Dump the last serviced SSNs in chronological order (oldest first).
    print_str(b" ssns:");
    let ring_n = if ssn_ri < 32 { 0 } else { ssn_ri - 32 };
    for k in ring_n..ssn_ri {
        print_str(b" ");
        print_u64(ssn_ring[k % 32] as u64);
    }
    // NtRaiseHardError(190): decode the status (R10), Parameters[0], and the caller ([rsp]).
    // Guarded to this case — get_recv_mr(16)/(8) only hold a valid smss stack ptr here.
    if stop_ssn == 190 {
        print_str(b" r10=0x");
        print_hex((get_recv_mr(9) >> 32) as u32);
        print_hex(get_recv_mr(9) as u32);
        print_str(b" param0=0x");
        print_hex(smss_stack_read(get_recv_mr(8)) as u32);
        print_str(b" caller=0x");
        print_hex(smss_stack_read(get_recv_mr(16)) as u32);
        // Scan the stack for ntdll return addresses to reconstruct the call chain that produced
        // the failure status.
        let sp = get_recv_mr(16);
        print_str(b" chain:");
        let mut shown = 0;
        for i in 0..96u64 {
            let v = smss_stack_read(sp + i * 8);
            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                print_str(b" 0x");
                print_hex((v - NTDLL_BASE) as u32);
                shown += 1;
                if shown >= 12 {
                    break;
                }
            }
        }
    }
    print_str(b"\n");
    (verdict, faults, first, stop, ntfaults, stop_ssn)
}

/// Spawn the isolated user thread: its own VSpace (image RO + stack + IPC buffer),
/// its own CNode holding a cap to `fault_ep_c`, and its faults routed there (the
/// kernel's legacy TCBSetSpace resolves the fault cptr in the FAULTER's cspace).
unsafe fn spawn_user_thread(
    entry: unsafe extern "C" fn() -> !,
    fault_ep_c: u64,
    sysarg_c: u64,
    prio: u64,
    extra_ntfn: u64,
) -> u64 {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    // The shared syscall-arg frame, at the SAME vaddr as in the executive.
    let _ = page_map(sysarg_c, SYSARG_VADDR, RW_NX, pml4);
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep_c, 0);
    // A waiter thread gets a cap to the notification it parks on; others don't (least priv).
    if extra_ntfn != 0 {
        let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_WAIT_NTFN, extra_ntfn, 0);
    }
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    pml4 // the executive keeps this cap to map on-demand NtAllocateVirtualMemory frames
}

/// Create a NEW thread in an EXISTING VSpace `pml4` (NtCreateThreadEx): a fresh stack + IPC
/// buffer + CNode (fault ep) at bumped user vaddrs, starting at `entry`. The thread shares the
/// caller's address space (so it sees the caller's mappings). Returns the TCB cap.
unsafe fn spawn_thread_in(pml4: u64, entry: u64) -> u64 {
    let stack_base = NEXT_USER_VADDR.fetch_add(0x4000, Ordering::Relaxed);
    for i in 0..4u64 {
        let _ = page_map(alloc_frame(), stack_base + i * 0x1000, RW_NX, pml4);
    }
    let ipcbuf_va = NEXT_USER_VADDR.fetch_add(0x1000, Ordering::Relaxed);
    let ipcbuf = alloc_frame();
    let _ = page_map(ipcbuf, ipcbuf_va, RW_NX, pml4);
    let fault_ep = make_object(OBJ_ENDPOINT);
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, copy_cap(fault_ep), 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, ipcbuf_va, ipcbuf, 0);
    let _ = tcb_write_registers(tcb, entry, stack_base + 0x4000 - 16, 0);
    let _ = tcb_set_priority(tcb, 100);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    tcb
}

/// Spawn the isolated ISR "driver host" (P1): its own VSpace (image RO + stack + IPC
/// buffer) and a CNode holding ONLY a cap to the IRQ notification + the result
/// notification — least privilege. Its thread (`isr_entry`) blocks on the IRQ
/// notification and, when the real interrupt fires, signals the result notification.
unsafe fn spawn_isr(entry: unsafe extern "C" fn() -> !, irq_cap: u64, result_cap: u64, prio: u64) {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_IRQ_NTFN, irq_cap, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_RESULT_NTFN, result_cap, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, 0, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}

/// Spawn an isolated PnP driver host: a fresh VSpace/CSpace, plus — mapped into its
/// VSpace — the granted device resources: the NIC BAR (`bar_base`..+4 pages at
/// `NIC_VADDR`), a confined common DMA buffer (`dma_frame` at `DMA_VADDR`), and the
/// resource frame (`reslist_frame` at `RESLIST_VADDR`) holding the CM_RESOURCE_LIST. The
/// host gets caps only to the IRQ + result notifications. Device frames are aliased via
/// `copy_cap`, so the same physical pages are also mapped in the executive.
unsafe fn spawn_driver_host(
    entry: unsafe extern "C" fn() -> !,
    irq_cap: u64,
    result_cap: u64,
    fault_ep: u64,
    prio: u64,
    bar_base: u64,
    dma_frame: u64,
    reslist_frame: u64,
    pe_base: u64,
    arena_base: u64,
) {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    // Granted device resources, mapped into the host's VSpace (all within the image PT):
    //   the 4 NIC BAR pages at NIC_VADDR, the confined DMA buffer at DMA_VADDR, and the
    //   resource frame at RESLIST_VADDR. Each is a copy aliasing the executive's frame.
    for i in 0..4u64 {
        let cp = copy_cap(bar_base + i);
        let _ = page_map(cp, NIC_VADDR + i * 0x1000, RW_NX, pml4);
    }
    let dma_cp = copy_cap(dma_frame);
    let _ = page_map(dma_cp, DMA_VADDR, RW_NX, pml4);
    let res_cp = copy_cap(reslist_frame);
    let _ = page_map(res_cp, RESLIST_VADDR, RW_NX, pml4);
    // The pre-loaded real .sys image (R+W+X — W^X hardening deferred) + its RW arena.
    for i in 0..driver_pe::PE_FRAMES {
        let cp = copy_cap(pe_base + i);
        let _ = page_map(cp, driver_pe::CODE_VA + i * 0x1000, /* RWX */ 3, pml4);
    }
    for i in 0..driver_pe::ARENA_FRAMES {
        let cp = copy_cap(arena_base + i);
        let _ = page_map(cp, driver_pe::ARENA_VADDR + i * 0x1000, RW_NX, pml4);
    }

    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_IRQ_NTFN, irq_cap, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_RESULT_NTFN, result_cap, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}

/// Spawn an isolated KMDF driver host. Like `spawn_isr` but with what a real KMDF driver
/// + the WDF runtime need: the host image mapped RW (the 444-entry WDF function table +
/// globals live in `.bss`), a heap (WdfRuntime + every Wdf*Create allocate), the pre-loaded
/// KMDF PE image (RWX), and a shared word (DriverEntry rva in, verdict out). A bigger stack
/// for the deep driver→thunk→runtime call chains. Software-only — no device resources.
unsafe fn spawn_kmdf_host(
    entry: unsafe extern "C" fn() -> !,
    result_cap: u64,
    fault_ep: u64,
    prio: u64,
    kmdf_pe_base: u64,
    shared_frame: u64,
    nic_bar_base: u64,
) {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let stack_frames = 16u64; // 64 KiB — WDF call chains are deep
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    // Image mapped RW (rights=3 → RWX): the WDF function table + globals live in `.bss`
    // and this host must WRITE them. NOTE: these are the executive's SHARED image frames,
    // so — unlike the RO-image hosts — a buggy KMDF host could scribble on the executive's
    // code/data. Acceptable here (the host runs to completion before the executive resumes,
    // and a correct host writes only its own WDF statics); tightening to a private image
    // copy is a hardening follow-on.
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RWX */ 3, pml4);
    }
    // Heap for the WDF runtime; retype-zeroed frames give bump counter 0 (no init).
    for i in 0..allocator::HEAP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, allocator::HEAP_BASE as u64 + i * 0x1000, RW_NX, pml4);
    }
    for i in 0..stack_frames {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    // The pre-loaded KMDF PE image (RWX) + the shared word (RW, entry rva / verdict).
    for i in 0..kmdf_host::KMDF_PE_FRAMES {
        let cp = copy_cap(kmdf_pe_base + i);
        let _ = page_map(cp, kmdf_host::KMDF_CODE_VA + i * 0x1000, /* RWX */ 3, pml4);
    }
    let sh = copy_cap(shared_frame);
    let _ = page_map(sh, kmdf_host::KMDF_SHARED_VADDR, RW_NX, pml4);
    // The REAL e1000e NIC BAR (4 pages, aliased from the executive's caps) at NIC_VADDR —
    // the KMDF driver reaches real hardware via MmMapIoSpace → NIC_VADDR.
    if nic_bar_base != 0 {
        for i in 0..4u64 {
            let cp = copy_cap(nic_bar_base + i);
            let _ = page_map(cp, NIC_VADDR + i * 0x1000, RW_NX, pml4);
        }
    }

    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_RESULT_NTFN, result_cap, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + stack_frames * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}

/// Spawn an isolated **storage** host: an RO-image component granted ONLY the AHCI BAR + a
/// DMA frame + a shared word, so it drives the disk entirely from its own VSpace. The
/// executive (Tier-1 broker) has already enabled Bus Master; the host gets no PCI-config
/// access. `shared` carries `dma_paddr` in (@0) and the verdict + INITRD info out.
unsafe fn spawn_storage_host(
    entry: unsafe extern "C" fn() -> !,
    result_cap: u64,
    fault_ep: u64,
    prio: u64,
    ahci_bar_frame: u64,
    dma_frame: u64,
    shared_frame: u64,
    filebuf_start: u64,
    ntdllbuf_start: u64,
    nls_ansi_start: u64,
    nls_oem_start: u64,
    nls_case_start: u64,
    hivebuf_start: u64,
) {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    // Image mapped READ-ONLY (rights=2) — the storage path writes no statics, so the host
    // cannot scribble on the executive's shared code/data.
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    // Granted device resources (each a copy aliasing the executive's frame): the AHCI BAR
    // (1 page) at AHCI_VADDR, the DMA frame at AHCI_DMA_VADDR, the shared word.
    let bar_cp = copy_cap(ahci_bar_frame);
    let _ = page_map(bar_cp, AHCI_VADDR, RW_NX, pml4);
    let dma_cp = copy_cap(dma_frame);
    let _ = page_map(dma_cp, AHCI_DMA_VADDR, RW_NX, pml4);
    let sh_cp = copy_cap(shared_frame);
    let _ = page_map(sh_cp, STORAGE_SHARED_VADDR, RW_NX, pml4);
    // The shared file buffer (a run of FILEBUF_FRAMES consecutive frame caps), mapped
    // contiguously so the host can read a whole PE off disk into it for the executive to parse.
    // FILEBUF_VADDR is a fresh 2 MiB region in the host's VSpace too — give it its own PT.
    let fb_pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, fb_pt);
    let _ = paging_struct_map(fb_pt, LBL_X86_PAGE_TABLE_MAP, FILEBUF_VADDR, pml4);
    for i in 0..FILEBUF_FRAMES {
        let fb_cp = copy_cap(filebuf_start + i);
        let _ = page_map(fb_cp, FILEBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The ntdll buffer (its own PT), same pattern.
    let nb_pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, nb_pt);
    let _ = paging_struct_map(nb_pt, LBL_X86_PAGE_TABLE_MAP, NTDLLBUF_VADDR, pml4);
    for i in 0..NTDLLBUF_FRAMES {
        let nb_cp = copy_cap(ntdllbuf_start + i);
        let _ = page_map(nb_cp, NTDLLBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The NLS + SYSTEM-hive buffers share the NTDLLBUF page table (0xA0-0xC0 region) — no extra PT.
    for (start, vaddr, frames) in [
        (nls_ansi_start, NLS_ANSI_VADDR, NLS_ANSI_FRAMES),
        (nls_oem_start, NLS_OEM_VADDR, NLS_OEM_FRAMES),
        (nls_case_start, NLS_CASE_VADDR, NLS_CASE_FRAMES),
        (hivebuf_start, HIVEBUF_VADDR, HIVEBUF_FRAMES),
    ] {
        for i in 0..frames {
            let _ = page_map(copy_cap(start + i), vaddr + i * 0x1000, RW_NX, pml4);
        }
    }

    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_RESULT_NTFN, result_cap, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}

/// Next user vaddr the executive hands out for NtAllocateVirtualMemory (bump allocator).
static NEXT_USER_VADDR: AtomicU64 = AtomicU64::new(USER_ALLOC_BASE);
/// How many VMFaults (page faults) the service loop demand-paged in for the user thread.
static DEMAND_FAULTS: AtomicU64 = AtomicU64::new(0);
/// Bump allocator for NtAllocateVirtualMemory backing a SEC_IMAGE process.
static NEXT_SMSS_ALLOC: AtomicU64 = AtomicU64::new(SMSS_ALLOC_VA);
/// How many NtAllocateVirtualMemory calls the executive serviced for a SEC_IMAGE process.
static NTALLOC_SERVICED: AtomicU64 = AtomicU64::new(0);
/// NLS shared-buffer frame-cap bases + sizes (set at storage bring-up), so spawn_sec_image can
/// share the c_1252/c_437/l_intl frames into smss and point the PEB NLS fields at them.
static NLS_ANSI_START: AtomicU64 = AtomicU64::new(0);
static NLS_OEM_START: AtomicU64 = AtomicU64::new(0);
static NLS_CASE_START: AtomicU64 = AtomicU64::new(0);
static NLS_ANSI_SIZE: AtomicU64 = AtomicU64::new(0);
static NLS_OEM_SIZE: AtomicU64 = AtomicU64::new(0);
static NLS_CASE_SIZE: AtomicU64 = AtomicU64::new(0);
/// The frame-cap base + byte size of the real SYSTEM hive the storage host read into HIVEBUF.
static HIVEBUF_START: AtomicU64 = AtomicU64::new(0);
static REAL_HIVE_SIZE: AtomicU64 = AtomicU64::new(0);

/// Run the native-syscall service loop for the isolated user thread, routing each
/// Ob syscall to the isolated Object Manager service via `client`, backing
/// NtAllocateVirtualMemory with real frames mapped into `user_pml4`, and demand-paging
/// file-backed section views (backed by `file_frame`) on VMFault. Returns `(serviced, verdict)`.
unsafe fn service_user_syscalls<B, CB>(
    user_fault_ep: u64,
    client: &mut ObjectClient<B>,
    cm: &mut ConfigClient<CB>,
    user_pml4: u64,
    file_frame: u64,
) -> (u64, u64)
where
    B: nt_object_client::Backend,
    CB: nt_config_client::Backend,
{
    // The real NT service table: maps the trapped SSN → a `NativeService`. A real
    // ntdll process would register its own numbers here (from its syscall stubs).
    let table = NativeServiceTable::from_numbers(
        UserlandAbiProfile::Windows7,
        &[
            (NativeService::NtCreateKey, NT_CREATE_KEY as u32),
            (NativeService::NtSetValueKey, NT_SET_VALUE_KEY as u32),
            (NativeService::NtQueryValueKey, NT_QUERY_VALUE_KEY as u32),
            (NativeService::NtAllocateVirtualMemory, NT_ALLOCATE_VM as u32),
            (NativeService::NtQuerySystemTime, NT_QUERY_SYSTEM_TIME as u32),
            (NativeService::NtCreateSection, NT_CREATE_SECTION as u32),
            (NativeService::NtMapViewOfSection, NT_MAP_VIEW as u32),
            (NativeService::NtCreateThreadEx, NT_CREATE_THREAD as u32),
        ],
    );

    let mut created: [Option<ObjectId>; 2] = [None, None];
    // P3 sync objects: the real KEVENT state machine, plus a passive-level IRQL (waits are
    // allowed) and a bump handle allocator.
    let mut events = EventStore::new();
    let irql = IrqlState::new();
    let mut next_ev = 0x1000u64;
    // Section objects: each entry is the backing frame cap (a 1-page section). A handle is a
    // 1-based index. NtMapViewOfSection maps a COPY of the frame into the user VSpace, so two
    // views of one section alias the same backing (the defining section property).
    let mut sec_frames = [0u64; 8];
    let mut sec_demand = [false; 8]; // file-backed (demand-paged) vs anonymous (eager)
    let mut sec_count = 0usize;
    // Demand-paged views awaiting fault-in: (page-aligned view base, backing frame cap).
    let mut views = [(0u64, 0u64); 8];
    let mut view_count = 0usize;
    let mut serviced = 0u64;
    let mut verdict = 0u64;
    let (_z, mut mi, mut m0, mut m1, mut m2, mut m3) = ep_recv_full(user_fault_ep);
    loop {
        // A VMFault (page fault, label 6) from the user thread: demand-page the faulting page
        // of a file-backed section view. The fault address is in MR1; the reply RESTARTS the
        // faulting instruction (no register writeback), so re-run it once the page is present.
        if (mi >> 12) == 6 {
            let page = m1 & !0xFFFu64;
            for v in 0..view_count {
                if views[v].0 == page {
                    let _ = page_map(copy_cap(views[v].1), page, RW_NX, user_pml4);
                    DEMAND_FAULTS.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
            let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(user_fault_ep, 0, 0, 0, 0, 0);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        if (mi >> 12) != 2 {
            break; // not an UnknownSyscall — stop
        }
        let ssn = m0;
        let arg1 = get_recv_mr(9); // R10 = arg1
        let arg2 = m3; // RDX = arg2
        if ssn == SSN_DONE {
            verdict = arg1;
            break; // leave the faulter blocked; test is done
        }
        let resume_ip = m2; // RCX = return address saved by `syscall`
        let sp = get_recv_mr(16);
        let flags = get_recv_mr(17);
        // Registry syscalls go through the real service table + a real OBJECT_ATTRIBUTES.
        let result = if let Some(entry) = table.lookup(ssn as u32) {
            match entry.service {
                // Registry syscalls resolve a real OBJECT_ATTRIBUTES key.
                NativeService::NtCreateKey => copyin_object_attributes(arg1)
                    .as_ref()
                    .and_then(oa_path)
                    .and_then(|k| cm.create_key(&k).ok())
                    .map(|_| 1)
                    .unwrap_or(0),
                NativeService::NtSetValueKey => copyin_object_attributes(arg1)
                    .as_ref()
                    .and_then(oa_path)
                    .and_then(|k| cm.set_dword(&k, "Answer", arg2 as u32).ok())
                    .map(|_| 1)
                    .unwrap_or(0),
                NativeService::NtQueryValueKey => copyin_object_attributes(arg1)
                    .as_ref()
                    .and_then(oa_path)
                    .and_then(|k| cm.query_dword(&k, "Answer").ok())
                    .map(|v| v as u64)
                    .unwrap_or(0),
                // P3 VM: back the request with real frames mapped into the user's VSpace at
                // the next bump vaddr, and return the base (arg1 = size in bytes).
                NativeService::NtAllocateVirtualMemory => {
                    let size = if arg1 == 0 { 0x1000 } else { arg1 };
                    let pages = (size + 0xFFF) / 0x1000;
                    let base = NEXT_USER_VADDR.fetch_add(pages * 0x1000, Ordering::Relaxed);
                    for i in 0..pages {
                        let f = alloc_slot();
                        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
                        let _ = page_map(f, base + i * 0x1000, RW_NX, user_pml4);
                    }
                    base
                }
                // P3 clock: the CPU timestamp counter — a real monotonic time source that
                // needs no device mapping (the HPET isn't mapped yet at this point).
                NativeService::NtQuerySystemTime => core::arch::x86_64::_rdtsc(),
                // Create a section: allocate a backing frame (arg1 = size, 1 page here) and
                // return a 1-based handle. The load vehicle for images/DLLs.
                NativeService::NtCreateSection => {
                    // arg2 == 1 → a FILE-BACKED (demand-paged) section, backed by `file_frame`;
                    // else an anonymous section (a fresh frame, mapped eagerly).
                    if sec_count < sec_frames.len() {
                        if arg2 == 1 {
                            sec_frames[sec_count] = file_frame;
                            sec_demand[sec_count] = true;
                        } else {
                            let f = alloc_slot();
                            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
                            sec_frames[sec_count] = f;
                            sec_demand[sec_count] = false;
                        }
                        sec_count += 1;
                        sec_count as u64 // handle
                    } else {
                        0
                    }
                }
                // Map a view. Anonymous: map the section frame eagerly (two views alias the
                // same backing). File-backed: RESERVE the view VA (page tables present, page
                // absent) and record it — the page faults in on first access (demand paging).
                NativeService::NtMapViewOfSection => {
                    let h = arg1 as usize;
                    if h >= 1 && h <= sec_count {
                        let base = NEXT_USER_VADDR.fetch_add(0x1000, Ordering::Relaxed);
                        if sec_demand[h - 1] {
                            if view_count < views.len() {
                                views[view_count] = (base, sec_frames[h - 1]);
                                view_count += 1;
                            }
                            // deliberately NOT mapped — the page faults in on access.
                        } else {
                            let cp = copy_cap(sec_frames[h - 1]);
                            let _ = page_map(cp, base, RW_NX, user_pml4);
                        }
                        base
                    } else {
                        0
                    }
                }
                // Create a new thread in the CALLER's VSpace at start routine `arg1` (the way
                // RtlCreateUserProcess/smss launch a process's main thread). Returns a handle.
                NativeService::NtCreateThreadEx => {
                    let _tcb = spawn_thread_in(user_pml4, arg1);
                    1 // handle
                }
                _ => 0,
            }
        } else {
            match ssn {
                SSN_OB_CREATE_DIR => {
                    let i = arg1 as usize;
                    match client.create_directory(path_for(arg1), true) {
                        Ok(id) => {
                            if i < 2 {
                                created[i] = Some(id);
                            }
                            1
                        }
                        Err(_) => 0,
                    }
                }
                SSN_OB_LOOKUP_DIR => {
                    let i = arg1 as usize;
                    match client.lookup(path_for(arg1), true) {
                        Ok(id) if i < 2 && created[i] == Some(id) => 1,
                        _ => 0,
                    }
                }
                // Object create/open by a real OBJECT_ATTRIBUTES pointer.
                SSN_OB_CREATE_BYNAME => match copyin_object_attributes(arg1).as_ref().and_then(oa_path) {
                    Some(path) => client.create_directory(&path, true).map(|_| 1).unwrap_or(0),
                    None => 0,
                },
                SSN_OB_LOOKUP_BYNAME => match copyin_object_attributes(arg1).as_ref().and_then(oa_path) {
                    Some(path) if client.lookup(&path, true).is_ok() => 1,
                    _ => 0,
                },
                // P3 synchronization objects — real KEVENT semantics via the EventStore.
                SSN_CREATE_EVENT => {
                    let kind = if arg1 == 1 {
                        EventKind::Synchronization // auto-reset
                    } else {
                        EventKind::Notification // manual-reset
                    };
                    let h = next_ev;
                    next_ev += 8;
                    events.initialize(h, kind, arg2 != 0);
                    h
                }
                SSN_SET_EVENT => events.set(arg1) as u64, // returns previous state
                SSN_RESET_EVENT => events.reset(arg1) as u64,
                SSN_WAIT => match events.poll(arg1, &irql) {
                    WaitResult::Signaled => 0,      // WAIT_OBJECT_0
                    WaitResult::TimedOut => 0x102,  // STATUS_TIMEOUT / WAIT_TIMEOUT
                    WaitResult::BadIrql => 0xC000_0001, // STATUS_UNSUCCESSFUL
                },
                _ => 0,
            }
        };
        serviced += 1;
        // Reply: RAX = result, resume at the return IP, preserve SP/FLAGS.
        set_reply_mr(15, resume_ip);
        set_reply_mr(16, sp);
        set_reply_mr(17, flags);
        let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(user_fault_ep, 18, result, m1, 0, m3);
        mi = nmi;
        m0 = nm0;
        m1 = nm1;
        m2 = nm2;
        m3 = nm3;
    }
    (serviced, verdict)
}

/// Service the blocking-wait demo: two threads (waiter + signaler) fault here, dispatched by
/// SSN. A WAIT_BLOCK on a non-signaled event returns "block" (the waiter then parks on
/// `wait_ntfn`); a SET_WAKE sets the event AND signals `wait_ntfn` to wake the parked waiter.
/// Runs until both threads report done; returns (w_first, w_second, handoff) from the shared
/// frame. Every reply is immediate (paired with the next recv), so the single `reply_to`
/// slot is never asked to hold two — no cap-based reply needed.
unsafe fn service_blocking_wait(fault_ep: u64, wait_ntfn: u64) -> (u64, u64, u64) {
    let mut events = EventStore::new();
    let irql = IrqlState::new();
    events.initialize(BLOCK_EVENT_KEY, EventKind::Notification, false);
    let (mut a_done, mut b_done) = (false, false);
    // NB: MR1 maps to the faulter's RBX; it MUST be echoed back in every reply or the
    // faulter's RBX is zeroed (a callee-saved reg the compiler relies on → wild writes).
    let (_z, mut mi, mut m0, mut m1, mut m2, mut m3) = ep_recv_full(fault_ep);
    loop {
        if (mi >> 12) != 2 {
            break; // not an UnknownSyscall
        }
        let ssn = m0;
        let arg1 = get_recv_mr(9);
        if ssn == SSN_DONE_A || ssn == SSN_DONE_B {
            if ssn == SSN_DONE_A {
                a_done = true;
            } else {
                b_done = true;
            }
            if a_done && b_done {
                break; // leave both faulters blocked; the demo is done
            }
            // Don't reply to the done thread; just recv the next fault.
            let (_z2, nmi, nm0, nm1, nm2, nm3) = ep_recv_full(fault_ep);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        let resume_ip = m2;
        let sp = get_recv_mr(16);
        let flags = get_recv_mr(17);
        let result = match ssn {
            SSN_WAIT_BLOCK => match events.poll(arg1, &irql) {
                WaitResult::Signaled => 0, // WAIT_OBJECT_0
                _ => 0x102,                // not signaled → the waiter must block
            },
            SSN_SET_WAKE => {
                events.set(arg1);
                let _ = syscall5(SYS_SEND, wait_ntfn, 0, 0, 0, 0); // wake the parked waiter
                1
            }
            _ => 0,
        };
        set_reply_mr(15, resume_ip);
        set_reply_mr(16, sp);
        set_reply_mr(17, flags);
        let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(fault_ep, 18, result, m1, 0, m3);
        mi = nmi;
        m0 = nm0;
        m1 = nm1;
        m2 = nm2;
        m3 = nm3;
    }
    let w_first = core::ptr::read_volatile((SYSARG2_VADDR + 0x510) as *const u64);
    let w_second = core::ptr::read_volatile((SYSARG2_VADDR + 0x518) as *const u64);
    let handoff = core::ptr::read_volatile((SYSARG2_VADDR + 0x520) as *const u64);
    (w_first, w_second, handoff)
}

/// Print `0x` + 8 hex digits (for PCI IDs / BARs).
fn print_hex(v: u32) {
    print_str(b"0x");
    for i in (0..8).rev() {
        let nib = ((v >> (i * 4)) & 0xf) as u8;
        debug_put_char(if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) });
    }
}

fn check(name: &[u8], ok: bool, passed: &mut u64) {
    if ok {
        print_str(b"  PASS ");
        *passed += 1;
    } else {
        print_str(b"  FAIL ");
    }
    print_str(name);
    print_str(b"\n");
}

fn park() -> ! {
    loop {
        yield_now();
    }
}

/// Stand up one isolated service (the component-launch primitive): create its ring
/// set (2 notifications + 4 frames), map the frames in the executive's own VSpace at
/// `[sub_v, comp_v, req_v, rep_v]` + lay out both ring headers, spawn the service at
/// `entry` seeded with cap copies, and return the executive-side [`RingChannel`] to
/// drive it. Adding a service is now one call + wrapping the channel in its client.
unsafe fn stand_up_service(
    entry: unsafe extern "C" fn() -> !,
    sub_v: u64,
    comp_v: u64,
    req_v: u64,
    rep_v: u64,
) -> RingChannel<'static> {
    let n_sub = make_object(OBJ_NOTIFICATION);
    let n_comp = make_object(OBJ_NOTIFICATION);
    let f_sub = alloc_frame();
    let f_comp = alloc_frame();
    let f_req = alloc_frame();
    let f_rep = alloc_frame();
    // Map the four frames into the executive's own VSpace + lay out both ring headers
    // (broker-init, so the spawned service just attaches — no producer/consumer race).
    let _ = page_map(f_sub, sub_v, RW_NX, CAP_INIT_THREAD_VSPACE);
    let _ = page_map(f_comp, comp_v, RW_NX, CAP_INIT_THREAD_VSPACE);
    let _ = page_map(f_req, req_v, RW_NX, CAP_INIT_THREAD_VSPACE);
    let _ = page_map(f_rep, rep_v, RW_NX, CAP_INIT_THREAD_VSPACE);
    let cfg_sub = RingConfig {
        queue_len: QLEN,
        ring_id: 1,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    let cfg_comp = RingConfig {
        queue_len: QLEN,
        ring_id: 2,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    let _ = init_ring::<SurtSqe>(sub_v as *mut u8, RING_LEN, &cfg_sub);
    let _ = init_ring::<SurtCqe>(comp_v as *mut u8, RING_LEN, &cfg_comp);
    // The service maps its own cap copies at the shared vaddrs in its own VSpace.
    spawn_service(
        entry,
        &[(CT_N_SUB, copy_cap(n_sub)), (CT_N_COMP, copy_cap(n_comp))],
        copy_cap(f_sub),
        copy_cap(f_comp),
        copy_cap(f_req),
        copy_cap(f_rep),
    );
    let sq = match Producer::<SurtSqe>::attach(sub_v as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let cq = match Consumer::<SurtCqe>::attach(comp_v as *mut u8, RING_LEN) {
        Ok(q) => q,
        Err(_) => park(),
    };
    RingChannel {
        sq,
        cq,
        signal: Sel4Notify::new(&ENV, n_sub),
        wait: Sel4Notify::new(&ENV, n_comp),
        req_vaddr: req_v,
        rep_vaddr: rep_v,
        next_id: 1,
    }
}

/// Claim a real device MMIO page (P1): find the device untyped in BootInfo whose
/// paddr matches `paddr`, retype a device frame from it, and map it at `vaddr` in the
/// executive's VSpace (the kernel makes device frames uncacheable). Returns whether
/// the device untyped was found + mapped. This is how the executive, which owns the
/// hardware caps, hands real MMIO to itself (and later to isolated driver hosts).
unsafe fn claim_device_page(bi: &BootInfo, paddr: u64, vaddr: u64) -> bool {
    claim_device_pages(bi, paddr, vaddr, 1) != 0
}

/// Map the first `n` 4 KiB pages of the device MMIO region whose untyped base is
/// `paddr`, at consecutive vaddrs from `vaddr`. Consecutive retypes from one untyped
/// hand out consecutive physical frames, so page p lands at `paddr + p*0x1000` mapped
/// at `vaddr + p*0x1000` — i.e. an identity-offset window over the BAR. Needed for the
/// e1000e, whose TX descriptor registers sit at BAR offset 0x3800 (the 4th page).
/// Returns the cap slot of the FIRST mapped BAR frame (0 if not found). The `n` frames
/// occupy consecutive slots, so a caller can `copy_cap(base + p)` to alias a page (e.g.
/// to map the BAR into an isolated driver host's VSpace too).
unsafe fn claim_device_pages(bi: &BootInfo, paddr: u64, vaddr: u64, n: u64) -> u64 {
    let count = bi.untyped.end - bi.untyped.start;
    for i in 0..count {
        let d = bi.untyped_list[i as usize];
        if d.is_device == 1 && d.paddr == paddr {
            let mut base = 0u64;
            for p in 0..n {
                let frame = alloc_slot();
                if p == 0 {
                    base = frame;
                }
                let _ = untyped_retype(bi.untyped.start + i, OBJ_X86_4K_PAGE, PAGING_BITS, 1, frame);
                let _ = page_map(frame, vaddr + p * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            return base;
        }
    }
    0
}

/// Issue an x86 I/O-port cap for the inclusive window `[first, last]` into
/// `dest_slot` of the executive's root CNode (from the singleton IOPortControl cap).
/// ABI: mr0=first, mr1=last, mr2=dest_index, mr3=dest_depth, extra cap = dest CNode.
unsafe fn issue_ioport_cap(dest_slot: u64, first: u16, last: u16) {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, CAP_INIT_THREAD_CNODE);
    let msginfo = (LBL_IOPORT_CONTROL_ISSUE << 12) | (1 << 9) | (1 << 7) | 4;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") SLOT_IO_PORT_CONTROL,
        in("rsi") msginfo,
        in("r10") first as u64,     // mr0 = first_port
        in("r8") last as u64,       // mr1 = last_port
        in("r9") dest_slot,         // mr2 = dest_index
        in("r15") 64u64,            // mr3 = dest_depth (init CNode guard=0 → depth 64)
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// `out dx, eax` via an I/O-port cap (no reply).
unsafe fn io_out32(ioport: u64, port: u16, value: u32) {
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") ioport,
        in("rsi") (LBL_IOPORT_OUT32 << 12) | 2,
        in("r10") port as u64,      // mr0 = port
        in("r8") value as u64,      // mr1 = value
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// `in eax, dx` via an I/O-port cap — invoked with SysCall; the read value comes
/// back as the reply's mr0 (r10).
/// Invoke `X86Page::GetAddress` on a frame cap and return its physical address. The
/// kernel writes the paddr into reply msg_reg[0], which lands in r10 on return (same
/// reply-register convention `io_in32` relies on). No message args.
unsafe fn get_frame_paddr(frame_cap: u64) -> u64 {
    let paddr: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_CALL as u64,
        inout("rdi") frame_cap => _,
        inout("rsi") (LBL_X86_PAGE_GET_ADDRESS << 12) => _,
        out("r10") paddr, // reply mr0 = physical address
        lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    paddr
}

/// Bring up AHCI port 0 and READ one 512-byte sector (`sector`) into the DMA frame at
/// `dma_vaddr + 0x800` (paddr `dma_paddr + 0x800`) via ATA READ DMA EXT. All AHCI DMA
/// structures live in one 4 KiB frame: Command List @0 (1 KiB-aligned), FIS Rx @0x400
/// (256-aligned), Command Table @0x500 (128-aligned), data buffer @0x800. Returns the
/// port Task File Data low byte after completion (0 = success; 0xFF = timeout). READ ONLY.
unsafe fn ahci_read_sector(ahci_vaddr: u64, dma_vaddr: u64, dma_paddr: u64, sector: u64) -> u32 {
    let port = ahci_vaddr + 0x100; // port 0 register set
    let pr = |o: u64| core::ptr::read_volatile((port + o) as *const u32);
    let pw = |o: u64, v: u32| core::ptr::write_volatile((port + o) as *mut u32, v);
    // Enable AHCI mode (GHC.AE bit 31).
    let ghc = core::ptr::read_volatile((ahci_vaddr + 0x04) as *const u32);
    core::ptr::write_volatile((ahci_vaddr + 0x04) as *mut u32, ghc | (1 << 31));
    // Stop the port: clear ST (bit 0) + FRE (bit 4); wait CR (bit 15) + FR (bit 14) clear.
    pw(0x18, pr(0x18) & !((1 << 0) | (1 << 4)));
    for _ in 0..1_000_000u64 {
        if pr(0x18) & ((1 << 15) | (1 << 14)) == 0 {
            break;
        }
        yield_now();
    }
    // Zero the command list + FIS + command table region, then program the bases.
    for i in 0..(0x800u64 / 8) {
        core::ptr::write_volatile((dma_vaddr + i * 8) as *mut u64, 0);
    }
    pw(0x00, dma_paddr as u32); // PxCLB  (command list @ +0)
    pw(0x04, (dma_paddr >> 32) as u32); // PxCLBU
    pw(0x08, (dma_paddr + 0x400) as u32); // PxFB (FIS rx @ +0x400)
    pw(0x0C, (dma_paddr >> 32) as u32); // PxFBU
    // Start FRE, then ST.
    pw(0x18, pr(0x18) | (1 << 4));
    yield_now();
    pw(0x18, pr(0x18) | (1 << 0));
    pw(0x10, 0xFFFF_FFFF); // clear PxIS

    // Command Table @ dma+0x500: H2D Register FIS (READ DMA EXT) + PRDT[0].
    let ct = dma_vaddr + 0x500;
    let cb = |o: u64, v: u8| core::ptr::write_volatile((ct + o) as *mut u8, v);
    cb(0, 0x27); // FIS type = Register H2D
    cb(1, 0x80); // C = 1 (command), PMPort 0
    cb(2, 0x25); // command = READ DMA EXT
    cb(4, sector as u8); // LBA 7:0
    cb(5, (sector >> 8) as u8); // LBA 15:8
    cb(6, (sector >> 16) as u8); // LBA 23:16
    cb(7, 0x40); // device = LBA48
    cb(8, (sector >> 24) as u8); // LBA 31:24
    cb(9, (sector >> 32) as u8); // LBA 39:32
    cb(10, (sector >> 40) as u8); // LBA 47:40
    core::ptr::write_volatile((ct + 12) as *mut u16, 1); // count = 1 sector
    // PRDT[0] @ ct + 0x80.
    core::ptr::write_volatile((ct + 0x80) as *mut u32, (dma_paddr + 0x800) as u32); // DBA
    core::ptr::write_volatile((ct + 0x84) as *mut u32, (dma_paddr >> 32) as u32); // DBAU
    core::ptr::write_volatile((ct + 0x8C) as *mut u32, 511 | (1 << 31)); // DBC = 512 B | IOC

    // Command Header slot 0 @ dma+0. DW0 = CFL(5) | PRDTL(1)<<16; CTBA @ +8.
    core::ptr::write_volatile(dma_vaddr as *mut u32, 5 | (1u32 << 16));
    core::ptr::write_volatile((dma_vaddr + 8) as *mut u32, (dma_paddr + 0x500) as u32); // CTBA
    core::ptr::write_volatile((dma_vaddr + 12) as *mut u32, (dma_paddr >> 32) as u32); // CTBAU

    // Issue command slot 0 (PxCI bit 0) + poll for completion.
    pw(0x38, 1);
    for _ in 0..5_000_000u64 {
        if pr(0x38) & 1 == 0 {
            return pr(0x20) & 0xFF; // PxTFD low byte (0 = success)
        }
        yield_now();
    }
    0xFF // timeout
}

/// FAT32 filesystem geometry parsed from the volume's BPB (sector 0), plus the AHCI handles
/// needed to read further sectors. All reads go through `ahci_read_sector` into the shared
/// data buffer at `AHCI_DMA_VADDR + 0x800` — so a caller MUST consume one sector's bytes
/// before triggering the next read.
#[derive(Clone, Copy)]
struct Fat32 {
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    bps: u32,        // bytes per sector
    spc: u32,        // sectors per cluster
    fat_start: u32,  // first FAT sector
    data_start: u32, // first data sector (cluster 2)
    root_cl: u32,    // root directory cluster
}

/// Read `sector` off the disk (via AHCI) and return a pointer to its 512 bytes.
unsafe fn fat_read_sector(fs: &Fat32, sector: u32) -> *const u8 {
    ahci_read_sector(fs.ahci_vaddr, fs.dma_vaddr, fs.dma_paddr, sector as u64);
    (fs.dma_vaddr + 0x800) as *const u8
}

/// First disk sector of a cluster.
fn fat_cluster_sector(fs: &Fat32, cluster: u32) -> u32 {
    fs.data_start + (cluster - 2) * fs.spc
}

/// Follow the FAT: next cluster after `cluster` (>= 0x0FFF_FFF8 means end-of-chain).
unsafe fn fat_next(fs: &Fat32, cluster: u32) -> u32 {
    let byte = cluster * 4;
    let sec = fs.fat_start + byte / fs.bps;
    let off = (byte % fs.bps) as u64;
    let p = fat_read_sector(fs, sec);
    (core::ptr::read_unaligned(p.add(off as usize) as *const u32)) & 0x0FFF_FFFF
}

/// Scan directory `dir_cluster` (following its cluster chain) for the 8.3 name `name11`
/// (11 bytes, space-padded). Returns (first_cluster, size_bytes, attr). LFN / deleted /
/// volume-label / free entries are skipped. Extracts the entry before any further reads.
unsafe fn dir_find(fs: &Fat32, dir_cluster: u32, name11: &[u8; 11]) -> Option<(u32, u32, u8)> {
    let mut cl = dir_cluster;
    while cl >= 2 && cl < 0x0FFF_FFF8 {
        for s in 0..fs.spc {
            let p = fat_read_sector(fs, fat_cluster_sector(fs, cl) + s);
            for e in 0..(fs.bps as usize / 32) {
                let ent = p.add(e * 32);
                let first = *ent;
                if first == 0x00 {
                    return None; // end of directory
                }
                if first == 0xE5 {
                    continue; // deleted
                }
                let attr = *ent.add(0x0B);
                if attr == 0x0F || (attr & 0x08) != 0 {
                    continue; // LFN fragment or volume label
                }
                let mut matches = true;
                for i in 0..11 {
                    if *ent.add(i) != name11[i] {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    let hi = core::ptr::read_unaligned(ent.add(0x14) as *const u16) as u32;
                    let lo = core::ptr::read_unaligned(ent.add(0x1A) as *const u16) as u32;
                    let size = core::ptr::read_unaligned(ent.add(0x1C) as *const u32);
                    return Some(((hi << 16) | lo, size, attr));
                }
            }
        }
        cl = fat_next(fs, cl); // overwrites the buffer — fine, we're done with this cluster
    }
    None
}

/// Read a whole file (up to `size` bytes) from `first_cluster` into `dest_vaddr`, following
/// the FAT cluster chain. Each cluster is read via the AHCI into the shared data buffer, then
/// copied out to `dest_vaddr + offset` BEFORE the next read (which — incl. `fat_next` —
/// overwrites the buffer). Returns the number of bytes written.
unsafe fn fat_read_file(fs: &Fat32, first_cluster: u32, size: u32, dest_vaddr: u64) -> u32 {
    let mut cl = first_cluster;
    let mut written = 0u32;
    while cl >= 2 && cl < 0x0FFF_FFF8 && written < size {
        for s in 0..fs.spc {
            if written >= size {
                break;
            }
            let p = fat_read_sector(fs, fat_cluster_sector(fs, cl) + s);
            let n = core::cmp::min(fs.bps, size - written);
            for i in 0..n as u64 {
                core::ptr::write_volatile((dest_vaddr + written as u64 + i) as *mut u8, *p.add(i as usize));
            }
            written += n;
        }
        cl = fat_next(fs, cl);
    }
    written
}

/// The whole P2 storage stack, callable from an isolated host: bring up AHCI port 0, read
/// sector 0 (MBR), parse the FAT32 volume, list the root directory, read BOOTBOOT/INITRD, and
/// read the registry hive `SYSTEM.DAT` into `hive_dest`. Returns (verdict, initrd_cluster,
/// initrd_size, hive_size). Verdict bits: 1 = port present + MBR (0xAA55), 2 = FAT32 BPB ok,
/// 4 = root lists EFI+BOOTBOOT, 8 = INITRD read, 0x10 = SYSTEM.DAT read. READ ONLY. AHCI BAR
/// @ `ahci_vaddr`, DMA @ `dma_vaddr` (device addr `dma_paddr`) — all in the caller's VSpace.
unsafe fn storage_probe(
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    hive_dest: u64,
    smss_dest: u64,
    imports_dest: u64,
    ntdll_dest: u64,
    nls_ansi_dest: u64,
    nls_oem_dest: u64,
    nls_case_dest: u64,
) -> (u32, u32, u32, u32, u32, u32, u32, u32, u32, u32) {
    let mut verdict = 0u32;
    let (mut nls_ansi_size, mut nls_oem_size, mut nls_case_size) = (0u32, 0u32, 0u32);
    // Port 0 present? PxSSTS DET [11:8] != 0.
    let ssts = core::ptr::read_volatile((ahci_vaddr + 0x100 + 0x28) as *const u32);
    let det = (ssts >> 8) & 0xF;
    // Read sector 0 (the MBR / VBR) via a real READ DMA EXT.
    let tfd = ahci_read_sector(ahci_vaddr, dma_vaddr, dma_paddr, 0);
    let db = |i: u64| core::ptr::read_volatile((dma_vaddr + 0x800 + i) as *const u8);
    let sig = (db(510) as u16) | ((db(511) as u16) << 8);
    print_str(b"[storage-host] AHCI DET=");
    print_u64(det as u64);
    print_str(b" TFD=0x");
    print_hex(tfd);
    print_str(b" sig=0x");
    print_hex(sig as u32);
    print_str(b"\n");
    if det != 0 && (tfd & 0x89) == 0 && sig == 0xAA55 {
        verdict |= 1;
    }
    // Parse the BPB (sector 0 is still in the buffer).
    let bp = |o: u64| core::ptr::read_volatile((dma_vaddr + 0x800 + o) as *const u8);
    let bp16 = |o: u64| (bp(o) as u32) | ((bp(o + 1) as u32) << 8);
    let bp32 = |o: u64| bp16(o) | (bp16(o + 2) << 16);
    let bps = bp16(0x0B);
    let spc = bp(0x0D) as u32;
    let reserved = bp16(0x0E);
    let nfats = bp(0x10) as u32;
    let spf32 = bp32(0x24);
    let root_cl = bp32(0x2C);
    let is_fat32 = bp(0x52) == b'F' && bp(0x53) == b'A' && bp(0x54) == b'T';
    print_str(b"[storage-host] FAT32 bps=");
    print_u64(bps as u64);
    print_str(b" spc=");
    print_u64(spc as u64);
    print_str(b" reserved=");
    print_u64(reserved as u64);
    print_str(b" nfats=");
    print_u64(nfats as u64);
    print_str(b" spf=");
    print_u64(spf32 as u64);
    print_str(b"\n");
    let (mut cluster, mut size, mut hive_size, mut smss_size, mut imports_size, mut ntdll_size) =
        (0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    if bps == 512 && spc >= 1 && is_fat32 {
        verdict |= 2;
        let fs = Fat32 {
            ahci_vaddr,
            dma_vaddr,
            dma_paddr,
            bps,
            spc,
            fat_start: reserved,
            data_start: reserved + nfats * spf32,
            root_cl,
        };
        // List the root directory (a real directory read).
        print_str(b"[storage-host] root dir:");
        let rp = fat_read_sector(&fs, fat_cluster_sector(&fs, fs.root_cl));
        for e in 0..(fs.bps as usize / 32) {
            let ent = rp.add(e * 32);
            if *ent == 0x00 {
                break;
            }
            let attr = *ent.add(0x0B);
            if *ent == 0xE5 || attr == 0x0F || (attr & 0x08) != 0 {
                continue;
            }
            debug_put_char(b' ');
            for i in 0..11 {
                let c = *ent.add(i);
                if c != b' ' {
                    debug_put_char(c);
                }
            }
        }
        print_str(b"\n");
        let have_efi = dir_find(&fs, fs.root_cl, b"EFI        ").is_some();
        let bootboot = dir_find(&fs, fs.root_cl, b"BOOTBOOT   ");
        if have_efi && bootboot.is_some() {
            verdict |= 4;
        }
        // Navigate BOOTBOOT/ → INITRD, then read the file's first cluster.
        if let Some((bb_cl, _, _)) = bootboot {
            if let Some((initrd_cl, initrd_size, _)) = dir_find(&fs, bb_cl, b"INITRD     ") {
                let fp = fat_read_sector(&fs, fat_cluster_sector(&fs, initrd_cl));
                let mut nz = false;
                for i in 0..512usize {
                    if *fp.add(i) != 0 {
                        nz = true;
                        break;
                    }
                }
                print_str(b"[storage-host] BOOTBOOT/INITRD cluster=");
                print_u64(initrd_cl as u64);
                print_str(b" size=");
                print_u64(initrd_size as u64);
                print_str(b" first8=0x");
                print_hex(core::ptr::read_unaligned(fp as *const u32));
                print_hex(core::ptr::read_unaligned(fp.add(4) as *const u32));
                print_str(b"\n");
                cluster = initrd_cl;
                size = initrd_size;
                if initrd_size > 0 && nz {
                    verdict |= 8;
                }
            }
        }
        // Read the registry hive SYSTEM.DAT off the root into `hive_dest` (a real file read
        // through the FS, feeding the Config Manager).
        if let Some((hive_cl, hsize, _)) = dir_find(&fs, fs.root_cl, b"SYSTEM  DAT") {
            let got = fat_read_file(&fs, hive_cl, hsize, hive_dest);
            print_str(b"[storage-host] SYSTEM.DAT cluster=");
            print_u64(hive_cl as u64);
            print_str(b" size=");
            print_u64(hsize as u64);
            print_str(b" read=");
            print_u64(got as u64);
            print_str(b"\n");
            if got == hsize && hsize > 0 {
                hive_size = hsize;
                verdict |= 0x10;
            }
        }
        // Read the real ReactOS SMSS.EXE off the root into `smss_dest` (up to the file buffer's
        // capacity) — a real x64 PE for the executive to load via SEC_IMAGE.
        if let Some((smss_cl, ssize, _)) = dir_find(&fs, fs.root_cl, b"SMSS    EXE") {
            let cap = (FILEBUF_FRAMES * 0x1000) as u32;
            let want = if ssize < cap { ssize } else { cap };
            let got = fat_read_file(&fs, smss_cl, want, smss_dest);
            print_str(b"[storage-host] SMSS.EXE cluster=");
            print_u64(smss_cl as u64);
            print_str(b" size=");
            print_u64(ssize as u64);
            print_str(b" read=");
            print_u64(got as u64);
            print_str(b"\n");
            if got == want && ssize > 0 {
                smss_size = ssize;
                verdict |= 0x20;
            }
        }
        // The build-time import-resolution table (imports.bin), read into `imports_dest`.
        if let Some((ic, isz, _)) = dir_find(&fs, fs.root_cl, b"IMPORTS BIN") {
            let got = fat_read_file(&fs, ic, isz, imports_dest);
            if got == isz && isz > 0 {
                imports_size = isz;
                verdict |= 0x40;
            }
        }
        // The real ReactOS ntdll.dll (~975 KiB) into `ntdll_dest` — smss's imports resolve here.
        if let Some((nc, nsz, _)) = dir_find(&fs, fs.root_cl, b"NTDLL   DLL") {
            let cap = (NTDLLBUF_FRAMES * 0x1000) as u32;
            let want = if nsz < cap { nsz } else { cap };
            let got = fat_read_file(&fs, nc, want, ntdll_dest);
            print_str(b"[storage-host] NTDLL.DLL size=");
            print_u64(nsz as u64);
            print_str(b" read=");
            print_u64(got as u64);
            print_str(b"\n");
            if got == want && nsz > 0 {
                ntdll_size = nsz;
                verdict |= 0x80;
            }
        }
        // NLS code-page tables — c_1252 (ANSI), c_437 (OEM), l_intl (Unicode case).
        for (name, dest, frames, out) in [
            (b"C_1252  NLS", nls_ansi_dest, NLS_ANSI_FRAMES, &mut nls_ansi_size),
            (b"C_437   NLS", nls_oem_dest, NLS_OEM_FRAMES, &mut nls_oem_size),
            (b"L_INTL  NLS", nls_case_dest, NLS_CASE_FRAMES, &mut nls_case_size),
        ] {
            if let Some((c, sz, _)) = dir_find(&fs, fs.root_cl, name) {
                let cap = (frames * 0x1000) as u32;
                let want = if sz < cap { sz } else { cap };
                let got = fat_read_file(&fs, c, want, dest);
                print_str(b"[storage-host] NLS ");
                for &ch in name { debug_put_char(ch); }
                print_str(b" size=");
                print_u64(sz as u64);
                print_str(b" read=");
                print_u64(got as u64);
                print_str(b"\n");
                if got == want && sz > 0 {
                    *out = sz;
                }
            }
        }
        // The real ReactOS SYSTEM registry hive (::ROSSYS.HIV, regf) into HIVEBUF; report its
        // size at STORAGE_SHARED+0x38 so the executive can nt-hive-regf-parse it for smss.
        if let Some((c, sz, _)) = dir_find(&fs, fs.root_cl, b"ROSSYS  HIV") {
            let cap = (HIVEBUF_FRAMES * 0x1000) as u32;
            let want = if sz < cap { sz } else { cap };
            let got = fat_read_file(&fs, c, want, HIVEBUF_VADDR);
            print_str(b"[storage-host] ROSSYS.HIV size=");
            print_u64(sz as u64);
            print_str(b" read=");
            print_u64(got as u64);
            print_str(b"\n");
            if got == want && sz > 0 {
                core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x38) as *mut u32, sz);
            }
        }
    }
    (
        verdict, cluster, size, hive_size, smss_size, imports_size, ntdll_size,
        nls_ansi_size, nls_oem_size, nls_case_size,
    )
}

/// Install a VT-d IO page table `iopt_cap` into device IO space `io_space_cap`, walking
/// toward `io_address`. Returns the invocation error label (0 = success). The first call
/// for a device installs the context root (and lazily enables VT-d translation).
unsafe fn iopt_map(iopt_cap: u64, io_space_cap: u64, io_address: u64) -> u64 {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, io_space_cap); // extraCaps[0] = IOSpace
    let msginfo = (LBL_X86_IO_PAGE_TABLE_MAP << 12) | (1 << 9) | (1 << 7) | 1;
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") iopt_cap => _,
        inout("rsi") msginfo => reply,
        inout("r10") io_address => _, // mr0 = io_address (args.a2)
        lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply >> 12
}

/// Map frame `frame_cap` into device IO space `io_space_cap` at `io_address` with `rights`
/// (bit0 = write, bit1 = read). Returns the error label (0 = success). The frame cap must
/// be UNMAPPED — pass a copy if the original is mapped in a VSpace.
unsafe fn map_io(frame_cap: u64, io_space_cap: u64, rights: u64, io_address: u64) -> u64 {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, io_space_cap); // extraCaps[0] = IOSpace
    let msginfo = (LBL_X86_PAGE_MAP_IO << 12) | (1 << 9) | (1 << 7) | 2;
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") frame_cap => _,
        inout("rsi") msginfo => reply,
        inout("r10") rights => _,    // mr0 = rights (args.a2)
        inout("r8") io_address => _, // mr1 = io_address (args.a3)
        lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply >> 12
}

unsafe fn io_in32(ioport: u64, port: u16) -> u32 {
    let value: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_CALL as u64,
        inout("rdi") ioport => _,
        inout("rsi") ((LBL_IOPORT_IN32 << 12) | 1) => _,
        inout("r10") port as u64 => value, // mr0 in = port; reply mr0 = value
        lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    value as u32
}

/// Read a 32-bit PCI configuration register (mechanism #1: 0xCF8 address / 0xCFC data).
unsafe fn pci_read32(ioport: u64, bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((reg as u32) & 0xFC);
    io_out32(ioport, PCI_CONFIG_ADDR, addr);
    io_in32(ioport, PCI_CONFIG_DATA)
}

/// Write a 32-bit PCI configuration register.
unsafe fn pci_write32(ioport: u64, bus: u8, dev: u8, func: u8, reg: u8, value: u32) {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((reg as u32) & 0xFC);
    io_out32(ioport, PCI_CONFIG_ADDR, addr);
    io_out32(ioport, PCI_CONFIG_DATA, value);
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);
    IPC_BUFFER.store(bi.ipc_buffer as u64, Ordering::Relaxed);
    let img = bi.user_image_frames;
    IMAGE_FRAMES_START.store(img.start, Ordering::Relaxed);
    IMAGE_FRAMES_COUNT.store(img.end - img.start, Ordering::Relaxed);

    print_str(b"[ntos-exec] NT executive core: spawning the Object Manager as an isolated service\n");

    // The executive front-end allocates (ObjectClient etc.), so give it its own heap.
    map_own_heap();

    // Object Manager: stand it up as an isolated service + drive it as the front-end.
    let mut c = ObjectClient::new(ObChan(stand_up_service(
        server::server_entry,
        SUB_RING_VADDR,
        COMP_RING_VADDR,
        REQ_DATA_VADDR,
        REP_DATA_VADDR,
    )));

    let mut passed = 0u64;
    check(b"exec_ob_ping", c.ping().is_success(), &mut passed);
    let created = c.create_directory("\\Device\\Test0", true);
    check(b"exec_ob_create_directory", created.is_ok(), &mut passed);
    let id = created.unwrap_or(ObjectId::NULL);
    check(b"exec_ob_lookup", c.lookup("\\Device\\Test0", true) == Ok(id), &mut passed);
    let handle = c.open("\\Device\\Test0", AccessMask::GENERIC_READ, None, true);
    check(b"exec_ob_open", handle.is_ok(), &mut passed);
    check(
        b"exec_ob_create_symbolic_link",
        c.create_symbolic_link("\\??\\Link", "\\Device\\Test0", true).is_ok(),
        &mut passed,
    );
    check(
        b"exec_ob_lookup_via_symlink",
        c.lookup("\\??\\Link", true) == Ok(id),
        &mut passed,
    );
    let expected: Vec<u16> = "\\Device\\Test0".encode_utf16().collect();
    let target = c.query_symbolic_link("\\??\\Link", true);
    check(
        b"exec_ob_query_symbolic_link",
        matches!(&target, Ok(t) if t.as_slice() == expected.as_slice()),
        &mut passed,
    );
    match handle {
        Ok(h) => check(b"exec_ob_close_handle", c.close_handle(h).is_ok(), &mut passed),
        Err(_) => check(b"exec_ob_close_handle", false, &mut passed),
    }

    // --- Second isolated service: the Configuration Manager (registry) over SURT.
    print_str(b"[ntos-exec] spawning the Configuration Manager as a second isolated service\n");
    let mut cm = ConfigClient::new(CmChan(stand_up_service(
        cm_server::cm_server_entry,
        CM_SUB_VADDR,
        CM_COMP_VADDR,
        CM_REQ_VADDR,
        CM_REP_VADDR,
    )));
    let svc_key = r"\Registry\Machine\System\CurrentControlSet\Services\Demo";
    check(b"exec_cm_ping", cm.ping(), &mut passed);
    check(b"exec_cm_create_key", cm.create_key(svc_key).is_ok(), &mut passed);
    check(b"exec_cm_open_key", cm.open_key(svc_key), &mut passed);
    check(b"exec_cm_set_dword", cm.set_dword(svc_key, "Start", 3).is_ok(), &mut passed);
    check(
        b"exec_cm_query_dword",
        cm.query_dword(svc_key, "Start") == Ok(3),
        &mut passed,
    );

    // --- Third isolated service: the I/O Manager over SURT (open/read/write/close a
    // device backed by a mock driver + an embedded Object Manager, in its own VSpace).
    print_str(b"[ntos-exec] spawning the I/O Manager as a third isolated service\n");
    let mut io = IoClient::new(IoChan(stand_up_service(
        io_server::io_server_entry,
        IO_SUB_VADDR,
        IO_COMP_VADDR,
        IO_REQ_VADDR,
        IO_REP_VADDR,
    )));
    check(b"exec_io_ping", io.ping().is_success(), &mut passed);
    let io_handle = io.open(
        "\\??\\Test0",
        AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
        0,
        0,
        0,
    );
    check(b"exec_io_open", io_handle.is_ok(), &mut passed);
    let ih = io_handle.unwrap_or(HandleValue::NULL);
    check(b"exec_io_write", io.write(ih, 0, b"hello") == Ok(5), &mut passed);
    let mut io_out = [0u8; 8];
    check(
        b"exec_io_read",
        matches!(io.read(ih, 0, &mut io_out), Ok(5)) && &io_out[..5] == b"hello",
        &mut passed,
    );
    check(b"exec_io_close", io.close(ih).is_ok(), &mut passed);

    // --- Native syscall front-end: an isolated USER thread traps `syscall`s; the
    // executive routes each to the isolated Ob service over SURT and replies so the
    // user resumes. User -> executive front-end -> isolated service -> reply.
    print_str(b"[ntos-exec] spawning an isolated user thread; routing its native syscalls to Ob\n");
    let user_fault_ep = make_object(OBJ_ENDPOINT);
    let user_fault_ep_c = copy_cap(user_fault_ep);
    // The shared syscall-arg frame: mapped at SYSARG_VADDR in the executive AND (via
    // the cap copy) at the same vaddr in the user thread — so a user UNICODE_STRING's
    // Buffer pointer resolves in both address spaces.
    let sysarg = alloc_frame();
    let _ = page_map(sysarg, SYSARG_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
    // A "file" frame backing a demand-paged section: fill it (via an executive scratch mapping)
    // with a recognizable payload. (Sourcing this frame from a real disk file via the P2
    // storage host is the next composition — the demand-paging mechanism is identical.)
    let ff = alloc_frame();
    let _ = page_map(ff, STORAGE_SHARED_VADDR + 0x2000, RW_NX, CAP_INIT_THREAD_VSPACE);
    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x2000) as *mut u64, 0xDEAD_FACE_CAFE_F00D);
    let user_pml4 = spawn_user_thread(user_entry, user_fault_ep_c, copy_cap(sysarg), 100, 0);
    let (serviced, verdict) = service_user_syscalls(user_fault_ep, &mut c, &mut cm, user_pml4, ff);
    check(b"exec_syscall_frontend_serviced", serviced >= 10, &mut passed);
    check(b"exec_syscall_user_verdict_passed", verdict == 1, &mut passed);
    // The directory the user created via a syscall is visible in the isolated Ob service.
    check(
        b"exec_syscall_created_dir_visible",
        c.lookup(path_for(0), true).is_ok(),
        &mut passed,
    );
    // The user-supplied UNICODE_STRING path (copyin'd from the shared frame) created a
    // real object visible in the isolated Ob service.
    check(
        b"exec_syscall_byname_path_visible",
        c.lookup("\\Device\\FromUserString", true).is_ok(),
        &mut passed,
    );
    // The DWORD the user set via a registry syscall is visible in the isolated Cm service.
    check(
        b"exec_syscall_registry_value_visible",
        cm.query_dword(REG_KEY, "Answer") == Ok(42),
        &mut passed,
    );

    // --- P3: the user thread's first REAL memory + clock syscalls. It called
    // NtAllocateVirtualMemory (the executive mapped a real frame into its VSpace), wrote +
    // read back a pattern, and queried NtQuerySystemTime twice. Verify the published results.
    let vm_base = core::ptr::read_volatile((SYSARG_VADDR + 0x400) as *const u64);
    let vm_readback = core::ptr::read_volatile((SYSARG_VADDR + 0x408) as *const u64);
    let ut1 = core::ptr::read_volatile((SYSARG_VADDR + 0x410) as *const u64);
    let ut2 = core::ptr::read_volatile((SYSARG_VADDR + 0x418) as *const u64);
    print_str(b"[ntos-exec] user NtAllocateVirtualMemory base=0x");
    print_hex((vm_base >> 32) as u32);
    print_hex(vm_base as u32);
    print_str(b" readback=");
    print_u64(vm_readback);
    print_str(b" NtQuerySystemTime t1=0x");
    print_hex(ut1 as u32);
    print_str(b" t2=0x");
    print_hex(ut2 as u32);
    print_str(b"\n");
    check(
        b"exec_nt_alloc_vm_base",
        vm_base >= USER_ALLOC_BASE && vm_base < USER_ALLOC_BASE + 0x0020_0000,
        &mut passed,
    );
    check(b"exec_nt_alloc_vm_readback", vm_readback == 1, &mut passed);
    check(b"exec_nt_query_time_monotonic", ut1 != 0 && ut2 >= ut1, &mut passed);

    // P3 sync objects: the user thread exercised a Synchronization (auto-reset) + a
    // Notification (manual-reset) event through NtWaitForSingleObject.
    let ew1 = core::ptr::read_volatile((SYSARG_VADDR + 0x420) as *const u64);
    let ew2 = core::ptr::read_volatile((SYSARG_VADDR + 0x428) as *const u64);
    let ew3 = core::ptr::read_volatile((SYSARG_VADDR + 0x430) as *const u64);
    let em1 = core::ptr::read_volatile((SYSARG_VADDR + 0x438) as *const u64);
    let em2 = core::ptr::read_volatile((SYSARG_VADDR + 0x440) as *const u64);
    let em3 = core::ptr::read_volatile((SYSARG_VADDR + 0x448) as *const u64);
    print_str(b"[ntos-exec] user event waits: sync[");
    print_u64(ew1);
    print_str(b",");
    print_u64(ew2);
    print_str(b",");
    print_u64(ew3);
    print_str(b"] manual[");
    print_u64(em1);
    print_str(b",");
    print_u64(em2);
    print_str(b",");
    print_u64(em3);
    print_str(b"] (0=OBJECT_0, 258=TIMEOUT)\n");
    check(
        b"exec_nt_event_sync_autoreset",
        ew1 == 0x102 && ew2 == 0 && ew3 == 0x102,
        &mut passed,
    );
    check(
        b"exec_nt_event_manual_reset",
        em1 == 0 && em2 == 0 && em3 == 0x102,
        &mut passed,
    );

    // --- P3 sections: the user thread created a section + mapped it as two views, and wrote
    // one view + read the other. Two views of one section alias the same backing frame — the
    // real section property, and the load vehicle for image/DLL mapping (toward smss).
    let sv1 = core::ptr::read_volatile((SYSARG_VADDR + 0x450) as *const u64);
    let sv2 = core::ptr::read_volatile((SYSARG_VADDR + 0x458) as *const u64);
    let sec_alias = core::ptr::read_volatile((SYSARG_VADDR + 0x460) as *const u64);
    print_str(b"[ntos-exec] section views v1=0x");
    print_hex(sv1 as u32);
    print_str(b" v2=0x");
    print_hex(sv2 as u32);
    print_str(b" aliased=");
    print_u64(sec_alias);
    print_str(b"\n");
    check(
        b"exec_nt_section_views",
        sv1 != 0 && sv2 != 0 && sv1 != sv2,
        &mut passed,
    );
    check(b"exec_nt_section_aliased", sec_alias == 1, &mut passed);

    // --- P3 NtCreateThreadEx: the user process created a SECOND thread in its own VSpace; that
    // thread ran concurrently and wrote its marker (proving a real independent thread — the way
    // a process launches its main thread / smss launches csrss).
    let th = core::ptr::read_volatile((SYSARG_VADDR + 0x470) as *const u64);
    let t2 = core::ptr::read_volatile((SYSARG_VADDR + 0x478) as *const u64);
    print_str(b"[ntos-exec] NtCreateThreadEx handle=");
    print_u64(th);
    print_str(b" second-thread marker=0x");
    print_hex(t2 as u32);
    print_str(b"\n");
    check(b"exec_nt_create_thread", th != 0, &mut passed);
    check(b"exec_nt_second_thread_ran", t2 == 0x7EAD2, &mut passed);

    // --- P3 demand paging: the user thread mapped a file-backed section view (VA reserved, page
    // NOT mapped) and read it; the read #PF'd, the executive faulted the page in from the
    // backing file, and the read returned the file's payload (0xDEADFACECAFEF00D).
    let dview = core::ptr::read_volatile((SYSARG_VADDR + 0x480) as *const u64);
    let dpaged = core::ptr::read_volatile((SYSARG_VADDR + 0x488) as *const u64);
    let dfaults = DEMAND_FAULTS.load(Ordering::Relaxed);
    print_str(b"[ntos-exec] demand-paged view=0x");
    print_hex(dview as u32);
    print_str(b" read=0x");
    print_hex((dpaged >> 32) as u32);
    print_hex(dpaged as u32);
    print_str(b" VMFaults serviced=");
    print_u64(dfaults);
    print_str(b"\n");
    check(b"exec_demand_page_faulted", dfaults >= 1, &mut passed);
    check(
        b"exec_demand_page_content",
        dpaged == 0xDEAD_FACE_CAFE_F00D,
        &mut passed,
    );

    // --- P3 blocking wait dispatcher: a WAITER thread PARKS on an event until a separate
    // SIGNALER thread wakes it — a real cross-thread block, not a poll. The waiter (prio 150)
    // runs + parks first; the signaler (100) publishes a handoff marker then sets+wakes the
    // event; the waiter could only observe the marker by having blocked until the signaler ran.
    print_str(b"[ntos-exec] P3: blocking wait - waiter parks on an event, signaler wakes it\n");
    let bw_fault = make_object(OBJ_ENDPOINT);
    let wait_ntfn = make_object(OBJ_NOTIFICATION);
    let sysarg2 = alloc_frame();
    let _ = page_map(sysarg2, SYSARG2_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
    core::ptr::write_volatile((SYSARG2_VADDR + 0x500) as *mut u64, 0);
    core::ptr::write_volatile((SYSARG2_VADDR + 0x528) as *mut u64, 0); // parking flag
    let _ = spawn_user_thread(waiter_entry, copy_cap(bw_fault), copy_cap(sysarg2), 150, wait_ntfn);
    let _ = spawn_user_thread(signaler_entry, copy_cap(bw_fault), copy_cap(sysarg2), 100, 0);
    let (bw_first, bw_second, bw_handoff) = service_blocking_wait(bw_fault, wait_ntfn);
    print_str(b"[ntos-exec] blocking wait: w_first=");
    print_u64(bw_first);
    print_str(b" w_second=");
    print_u64(bw_second);
    print_str(b" handoff=0x");
    print_hex(bw_handoff as u32);
    print_str(b"\n");
    check(b"exec_blocking_wait_parked", bw_first == 0x102, &mut passed);
    check(b"exec_blocking_wait_woken", bw_second == 0, &mut passed);
    check(b"exec_blocking_wait_ordered", bw_handoff == 0xB0B, &mut passed);

    // --- P3 REAL PE: construct a minimal real PE (a native-syscall stub as .text), load it
    // via nt-pe-loader (parse + map), and run it in an isolated process — the real PE-load
    // path, not hand-written code in the executive image. The stub does NtQuerySystemTime +
    // reports the result via SSN_DONE, so we see a real syscall come back through a loaded PE.
    print_str(b"[ntos-exec] P3: loading a real PE that imports ntdll.dll!NtQuerySystemTime\n");
    let text = build_pe_text();
    let idata = build_import_table();
    let pe_bytes = build_pe(
        PE_LOAD_BASE,
        0x1000,
        0x3000,
        &[
            (b".text\0\0\0", 0x1000, 0x6000_0020, &text),
            (b".rdata\0\0", 0x2000, 0x4000_0040, &idata),
        ],
        &[(1, 0x2000, 40)],
    );
    let (mut pe_loaded, mut pe_serviced, mut pe_verdict, mut imports_ok) = (false, 0u64, 0u64, false);
    if let Ok(pe) = nt_pe_loader::PeFile::parse(&pe_bytes) {
        // Resolve the import table: find ntdll.dll!NtQuerySystemTime + its IAT slot RVA.
        let mut slot = 0u32;
        if let Ok(imps) = pe.imports() {
            for dll in &imps {
                for f in &dll.functions {
                    if let nt_pe_loader::ImportRef::ByName { name, iat_slot_rva, .. } = f {
                        if name == "NtQuerySystemTime" && dll.name.eq_ignore_ascii_case("ntdll.dll") {
                            slot = *iat_slot_rva;
                        }
                    }
                }
            }
        }
        if let Ok(mut mapped) = pe.map(PE_LOAD_BASE) {
            pe_loaded = mapped.entry_point() == PE_LOAD_BASE + 0x1000;
            if slot != 0 {
                let _ = mapped.patch_iat(slot, NTDLL_VA);
                let mut sb = [0u8; 8];
                sb.copy_from_slice(&mapped.bytes[slot as usize..slot as usize + 8]);
                imports_ok = slot == 0x2038 && u64::from_le_bytes(sb) == NTDLL_VA;
            }
            print_str(b"[ntos-exec] PE imports ntdll.dll!NtQuerySystemTime -> IAT slot 0x");
            print_hex(slot);
            print_str(b" patched=");
            print_u64(imports_ok as u64);
            print_str(b"\n");
            let pe_fault = make_object(OBJ_ENDPOINT);
            let pe_fault_c = copy_cap(pe_fault);
            let pe_sysarg = alloc_frame();
            let pe_pml4 = spawn_pe_thread(&mapped, pe_fault_c, pe_sysarg);
            let (srv, verdict) = service_user_syscalls(pe_fault, &mut c, &mut cm, pe_pml4, 0);
            pe_serviced = srv;
            pe_verdict = verdict;
        }
    }
    print_str(b"[ntos-exec] real PE: loaded=");
    print_u64(pe_loaded as u64);
    print_str(b" serviced=");
    print_u64(pe_serviced);
    print_str(b" walked GS->TEB->PEB->ImageBase=0x");
    print_hex((pe_verdict >> 32) as u32);
    print_hex(pe_verdict as u32);
    print_str(b"\n");
    check(b"exec_real_pe_loaded", pe_loaded, &mut passed);
    check(b"exec_real_pe_ran", pe_serviced >= 1, &mut passed);
    check(b"exec_real_pe_syscall", pe_verdict != 0, &mut passed);
    // GS->TEB->PEB->ImageBase resolved AND (before it) the IAT call to the ntdll stub ran.
    check(b"exec_pe_env_imagebase", pe_verdict == PE_LOAD_BASE, &mut passed);
    // The PE's import table was parsed + the IAT slot resolved to the provided ntdll stub.
    check(b"exec_pe_imports_resolved", imports_ok, &mut passed);

    // --- P3 SEC_IMAGE: demand-load a PE via image sections. Unlike the eager load above, the
    // image VA is only RESERVED — each page faults in BY RVA from the PE file (headers @ file 0,
    // .text from raw 0x200, .rdata from raw 0x400; RVA != raw). The .text reads a magic from
    // .rdata (a second section, faulted in on its own access) and reports it — a real PE runs
    // with pages arriving only as touched, from their correct file offsets. This is how a real
    // ntdll/smss will load: memory-efficient, only touched pages materialized.
    print_str(b"[ntos-exec] P3: demand-loading a PE via SEC_IMAGE (pages fault in by RVA)\n");
    let sec_magic = 0x5EC1_1A6E_D15C_0DE5u64;
    let si_text = build_sec_image_text();
    let si_rdata = sec_magic.to_le_bytes();
    let si_bytes = build_pe(
        PE_LOAD_BASE,
        0x1000,
        0x3000,
        &[
            (b".text\0\0\0", 0x1000, 0x6000_0020, &si_text),
            (b".rdata\0\0", 0x2000, 0x4000_0040, &si_rdata),
        ],
        &[],
    );
    let (mut si_verdict, mut si_faults) = (0u64, 0u64);
    if let Ok(pe) = nt_pe_loader::PeFile::parse(&si_bytes) {
        let si_fault = make_object(OBJ_ENDPOINT);
        let si_fault_c = copy_cap(si_fault);
        let pml4 = spawn_sec_image(&pe, si_fault_c, 0, false);
        let (v, f, _, _, _, _) = service_sec_image(si_fault, pml4, &pe, STORAGE_SHARED_VADDR + 0x4000, None);
        si_verdict = v;
        si_faults = f;
    }
    print_str(b"[ntos-exec] SEC_IMAGE: PE ran demand-paged, read .rdata magic=0x");
    print_hex((si_verdict >> 32) as u32);
    print_hex(si_verdict as u32);
    print_str(b" pages-faulted-in=");
    print_u64(si_faults);
    print_str(b"\n");
    // The PE executed from a demand-paged .text (RVA 0x1000 <- raw 0x200) AND read a magic from
    // a demand-paged .rdata (RVA 0x2000 <- raw 0x400): RVA->file translation on fault works.
    check(b"exec_sec_image_demand_loaded", si_verdict == sec_magic, &mut passed);
    check(b"exec_sec_image_two_sections", si_faults >= 2, &mut passed);

    // --- P1: real MMIO. Claim the HPET's device memory (a real device untyped from
    // BootInfo) as a frame cap, map it, and read a real hardware register — proving
    // the mapping hits real device memory, not RAM.
    print_str(b"[ntos-exec] P1: claiming real HPET MMIO (0xFED00000) as a device frame\n");
    let mmio_mapped = claim_device_page(bi, HPET_PADDR, HPET_VADDR);
    check(b"exec_hpet_device_untyped_mapped", mmio_mapped, &mut passed);
    if mmio_mapped {
        // HPET General Capabilities + ID (offset 0): bits [31:16] = VENDOR_ID.
        let gcap = core::ptr::read_volatile(HPET_VADDR as *const u32);
        print_str(b"[ntos-exec] HPET GCAP_ID low dword = ");
        print_u64(gcap as u64);
        print_str(b" (vendor ");
        print_u64((gcap >> 16) as u64);
        print_str(b")\n");
        // QEMU's HPET reports the Intel vendor id 0x8086 (= 32902).
        check(b"exec_hpet_mmio_vendor_intel", (gcap >> 16) == 0x8086, &mut passed);
    }

    // --- P1: a real hardware interrupt. Program HPET timer 0 for a one-shot, route
    // it to an IOAPIC pin, get an IRQ-handler cap for that pin (which programs the
    // IOAPIC RTE), bind a badged notification, arm the timer, and confirm the real
    // interrupt is delivered. Poll non-blocking so a misfire fails, never hangs.
    if mmio_mapped {
        print_str(b"[ntos-exec] P1: arming HPET timer 0 -> IOAPIC IRQ-handler cap -> notification\n");
        // Timer 0's INT_ROUTE_CAP (config bits [63:32]) = the IOAPIC pins it may drive.
        let t0cfg = core::ptr::read_volatile((HPET_VADDR + HPET_T0_CONFIG) as *const u64);
        let route_cap = (t0cfg >> 32) as u32;
        check(b"exec_hpet_irq_route_cap_nonzero", route_cap != 0, &mut passed);
        if route_cap != 0 {
            let pin = (31 - route_cap.leading_zeros()) as u64; // highest allowed pin
            print_str(b"[ntos-exec] HPET timer0 IOAPIC pin = ");
            print_u64(pin);
            print_str(b", vector = ");
            print_u64(IRQ_VECTOR);
            print_str(b"\n");

            // The IRQ notification (bound to the handler; the ISR host waits on it) +
            // the result notification (the ISR host signals it). Badged so signals are
            // unambiguous when polled.
            let irq_ntfn = make_object(OBJ_NOTIFICATION);
            let irq_ntfn_badged = alloc_slot();
            let _ = syscall5(
                SYS_SEND,
                CAP_INIT_THREAD_CNODE,
                LBL_CNODE_MINT << 12,
                irq_ntfn_badged,
                irq_ntfn,
                IRQ_BADGE,
            );
            let irq_ntfn_isr = copy_cap(irq_ntfn); // the isolated ISR host waits on this
            let result_ntfn = make_object(OBJ_NOTIFICATION);
            let result_ntfn_badged = alloc_slot();
            let _ = syscall5(
                SYS_SEND,
                CAP_INIT_THREAD_CNODE,
                LBL_CNODE_MINT << 12,
                result_ntfn_badged,
                result_ntfn,
                ISR_DONE_BADGE,
            );
            // Issue the IOAPIC IRQ-handler cap LEVEL-triggered: this exercises the
            // kernel's mask-on-deliver fix — a level line held asserted (the HPET holds
            // it until its status is cleared) would storm without it. With the fix it
            // delivers once, the kernel masks the line, and the host wakes cleanly.
            let handler = alloc_slot();
            ioapic_issue_irq_handler(handler, pin, IRQ_VECTOR, /*level*/ 1, /*polarity*/ 0);
            let _ = irq_handler_set_notification(handler, irq_ntfn_badged);
            // Hand the isolated ISR "driver host" ONLY the IRQ + result notifications;
            // its ISR thread blocks on the IRQ and reports via the result notification.
            spawn_isr(isr::isr_entry, irq_ntfn_isr, result_ntfn_badged, 100);

            // Program timer 0: interrupt enable + route to `pin`, LEVEL-triggered, one-shot.
            let newcfg = (1u64 << 1) | (1u64 << 2) | (pin << 9);
            core::ptr::write_volatile((HPET_VADDR + HPET_T0_CONFIG) as *mut u64, newcfg);
            // Comparator = now + a small delta so it fires within our poll window.
            let now = core::ptr::read_volatile((HPET_VADDR + HPET_MAIN_COUNTER) as *const u64);
            core::ptr::write_volatile(
                (HPET_VADDR + HPET_T0_COMPARATOR) as *mut u64,
                now.wrapping_add(0x20000),
            );
            // Enable the HPET main counter (GEN_CONF bit 0).
            let gc = core::ptr::read_volatile((HPET_VADDR + HPET_GEN_CONF) as *const u64);
            core::ptr::write_volatile((HPET_VADDR + HPET_GEN_CONF) as *mut u64, gc | 1);

            // Block on the RESULT notification. The executive is priority 255, so it
            // must BLOCK (not spin) to yield the CPU to the priority-100 ISR host —
            // which then waits on the IRQ and, when the real interrupt fires, signals
            // us back. (Same pattern as the SURT service waits; the timer delivery is
            // proven, so this returns rather than hangs.)
            let (_z, got, _s, _m) = ep_recv(result_ntfn);
            print_str(b"[ntos-exec] isolated ISR host reported badge = ");
            print_u64(got);
            print_str(b"\n");
            check(
                b"exec_hpet_irq_reached_isolated_isr",
                got == ISR_DONE_BADGE,
                &mut passed,
            );
        }
    }

    // --- P1: PCI enumeration via real x86 port I/O. Get an I/O-port cap for the PCI
    // config ports, walk bus 0, and read each device's vendor/device/class/BAR0/IRQ —
    // the discovery step that finds a real device (its BAR + IRQ) to hand to a host.
    print_str(b"[ntos-exec] P1: enumerating PCI bus 0 via port I/O (0xCF8/0xCFC)\n");
    let pci_io = alloc_slot();
    issue_ioport_cap(pci_io, PCI_CONFIG_ADDR, PCI_CONFIG_DATA + 3); // 0xCF8..=0xCFF
    // Host bridge 00:00.0 — reading its vendor id proves port I/O + config access work.
    let hb = pci_read32(pci_io, 0, 0, 0, 0x00);
    let hb_vendor = (hb & 0xFFFF) as u16;
    check(b"exec_pci_portio_reads_config", hb_vendor != 0xFFFF, &mut passed);
    check(b"exec_pci_host_bridge_intel", hb_vendor == 0x8086, &mut passed);

    let mut count = 0u64;
    let mut found_storage = false;
    let (mut storage_bar5, mut storage_irq) = (0u32, 0u32);
    let (mut storage_dev, mut storage_func) = (0u8, 0u8);
    let (mut nic_bar0, mut nic_irq, mut found_nic) = (0u32, 0u32, false);
    let (mut nic_dev, mut nic_func) = (0u8, 0u8);
    for dev in 0..32u8 {
        for func in 0..8u8 {
            let vd = pci_read32(pci_io, 0, dev, func, 0x00);
            let vendor = (vd & 0xFFFF) as u16;
            if vendor == 0xFFFF {
                if func == 0 {
                    break; // no function 0 → device absent
                }
                continue;
            }
            count += 1;
            let device = (vd >> 16) as u16;
            let class = pci_read32(pci_io, 0, dev, func, 0x08); // [class][sub][progif][rev]
            let bar0 = pci_read32(pci_io, 0, dev, func, 0x10);
            let irq = pci_read32(pci_io, 0, dev, func, 0x3C) & 0xFF;
            print_str(b"  pci 0:");
            print_u64(dev as u64);
            print_str(b".");
            print_u64(func as u64);
            print_str(b" id=");
            print_hex(((device as u32) << 16) | vendor as u32);
            print_str(b" class=");
            print_hex(class >> 8);
            print_str(b" bar0=");
            print_hex(bar0);
            print_str(b" irq=");
            print_u64(irq as u64);
            print_str(b"\n");
            // First AHCI SATA controller (class 0x0106). On q35 the boot disk is on the
            // add-in `-device ahci` at a low slot (00:3.0); the built-in ICH9 SATA (00:31.2)
            // is empty — so first-wins picks the one with the disk. ABAR = BAR5.
            if (class >> 8) == 0x01_0601 && !found_storage {
                found_storage = true;
                storage_bar5 = pci_read32(pci_io, 0, dev, func, 0x24);
                storage_irq = irq;
                storage_dev = dev;
                storage_func = func;
            }
            // A network controller (class 0x02) — the e1000e NIC we drive as the
            // P1 capstone (its MMIO BAR0 + interrupt line).
            if (class >> 24) == 0x02 {
                found_nic = true;
                nic_bar0 = bar0;
                nic_irq = irq;
                nic_dev = dev;
                nic_func = func;
            }
        }
    }
    print_str(b"[ntos-exec] PCI devices on bus 0 = ");
    print_u64(count);
    print_str(b"\n");
    check(b"exec_pci_found_multiple_devices", count >= 2, &mut passed);
    check(b"exec_pci_found_storage_controller", found_storage, &mut passed);
    if found_storage {
        print_str(b"[ntos-exec] storage controller ABAR(BAR5)=");
        print_hex(storage_bar5);
        print_str(b" irq=");
        print_u64(storage_irq as u64);
        print_str(b" (a real device to hand an isolated driver host)\n");
    }


    // --- P1 CAPSTONE: drive the real e1000e NIC. Map its enumerated BAR0 as a
    // device frame and read a live device register — a real driver path touching
    // real (QEMU-emulated) network hardware, not a mock.
    let mut kmdf_nic_bar_base = 0u64; // the real NIC BAR caps, handed to the KMDF host below
    if found_nic {
        let nic_mmio = (nic_bar0 & 0xFFFF_FFF0) as u64; // mask the BAR flag bits
        print_str(b"[ntos-exec] P1 CAPSTONE: mapping e1000e NIC BAR0 ");
        print_hex(nic_mmio as u32);
        print_str(b" (irq ");
        print_u64(nic_irq as u64);
        print_str(b")\n");
        // Map the first 4 pages (16 KiB) of the BAR: page 0 has CTRL/STATUS/interrupt
        // regs, page 3 (offset 0x3000) has the TX descriptor registers (0x3800..0x3828).
        let nic_bar_base = claim_device_pages(bi, nic_mmio, NIC_VADDR, 4);
        check(b"exec_nic_bar_mapped", nic_bar_base != 0, &mut passed);
        kmdf_nic_bar_base = nic_bar_base; // hand the real BAR to the KMDF host later
        if nic_bar_base != 0 {
            // Intel e1000e register file: CTRL @ 0x00, STATUS @ 0x08.
            let ctrl = core::ptr::read_volatile((NIC_VADDR + 0x00) as *const u32);
            let status = core::ptr::read_volatile((NIC_VADDR + 0x08) as *const u32);
            print_str(b"[ntos-exec] e1000e CTRL=");
            print_hex(ctrl);
            print_str(b" STATUS=");
            print_hex(status);
            print_str(b"\n");
            // A live NIC returns a real value — not 0xFFFFFFFF (unmapped MMIO) or 0.
            check(
                b"exec_nic_mmio_status_live",
                status != 0xFFFF_FFFF && status != 0,
                &mut passed,
            );

            // --- FULL-DEVICE LOOP: a real NIC interrupt delivered into an isolated
            // driver host. Issue IOAPIC handlers for the PCI GSIs (the NIC's exact
            // pin is chipset-routed) bound to a notification, spawn an isolated ISR
            // host, then trigger a real NIC interrupt via the e1000e ICS register.
            print_str(b"[ntos-exec] FULL LOOP: real NIC interrupt -> isolated ISR host\n");
            // Diagnostic: PCI Interrupt Pin (config 0x3D) — 1=INTA .. 4=INTD, 0=no INTx
            // (MSI-only). Tells us whether INTx routing is even the right mechanism.
            let int_pin = (pci_read32(pci_io, 0, nic_dev, nic_func, 0x3C) >> 8) & 0xFF;
            print_str(b"[ntos-exec] NIC Interrupt Pin = ");
            print_u64(int_pin as u64);
            print_str(b"\n");
            let nic_irq_ntfn = make_object(OBJ_NOTIFICATION);
            let nic_irq_badged = alloc_slot();
            let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, nic_irq_badged, nic_irq_ntfn, IRQ_BADGE);
            let result_ntfn = make_object(OBJ_NOTIFICATION);
            let result_badged = alloc_slot();
            let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, result_badged, result_ntfn, ISR_DONE_BADGE);
            let _ = int_pin;
            // The isolated ISR host waits on the NIC notification (reuses spawn_isr).
            let nic_irq_isr = copy_cap(nic_irq_ntfn);
            spawn_isr(isr::isr_entry, nic_irq_isr, result_badged, 255);

            // Deliver the NIC interrupt via MSI (its INTx isn't routed to the IOAPIC in
            // this QEMU q35 config; MSI is a memory write to the LAPIC that bypasses the
            // IOAPIC + chipset entirely). Walk the PCI capability list for the MSI cap
            // (ID 0x05), program it to deliver our vector to the LAPIC, then enable it.
            let mut cap = (pci_read32(pci_io, 0, nic_dev, nic_func, 0x34) & 0xFC) as u8;
            let mut msi_off = 0u8;
            let mut msix_off = 0u8;
            for _ in 0..16 {
                if cap == 0 {
                    break;
                }
                let hdr = pci_read32(pci_io, 0, nic_dev, nic_func, cap);
                let id = (hdr & 0xFF) as u8;
                print_str(b"[ntos-exec]   pci cap id=0x");
                print_hex(id as u32);
                print_str(b" @ 0x");
                print_hex(cap as u32);
                print_str(b"\n");
                if id == 0x05 {
                    msi_off = cap;
                }
                if id == 0x11 {
                    msix_off = cap;
                }
                cap = ((hdr >> 8) & 0xFC) as u8;
            }
            let _ = msix_off;
            print_str(b"[ntos-exec] NIC MSI capability @ config 0x");
            print_hex(msi_off as u32);
            print_str(b"\n");
            check(b"exec_nic_has_msi_capability", msi_off != 0, &mut passed);
            let msi_vector = 5u64; // irq index → LAPIC vector 0x25
            if msi_off != 0 {
                let msg_ctrl = (pci_read32(pci_io, 0, nic_dev, nic_func, msi_off) >> 16) as u16;
                let data_off = if (msg_ctrl & 0x80) != 0 { msi_off + 0xC } else { msi_off + 8 };
                // Message Address = LAPIC (0xFEE00000, physical dest APIC 0); Message
                // Data = the CPU vector (irq index + PIC1_VECTOR_BASE → IDT irq stub).
                pci_write32(pci_io, 0, nic_dev, nic_func, msi_off + 4, 0xFEE0_0000);
                if (msg_ctrl & 0x80) != 0 {
                    pci_write32(pci_io, 0, nic_dev, nic_func, msi_off + 8, 0);
                }
                pci_write32(pci_io, 0, nic_dev, nic_func, data_off, (msi_vector + 0x20) as u32);
                // Issue the MSI IRQ-handler cap + bind the NIC notification.
                let handler = alloc_slot();
                msi_issue_irq_handler(handler, msi_vector);
                let _ = irq_handler_set_notification(handler, nic_irq_badged);
                // Bus Master (Command bit 2) so the NIC can DMA the MSI write; then set
                // the MSI Enable bit (Message Control bit 0 = dword bit 16).
                let cmd = pci_read32(pci_io, 0, nic_dev, nic_func, 0x04);
                pci_write32(pci_io, 0, nic_dev, nic_func, 0x04, cmd | (1 << 2));
                let ctrl = pci_read32(pci_io, 0, nic_dev, nic_func, msi_off);
                pci_write32(pci_io, 0, nic_dev, nic_func, msi_off, ctrl | (1 << 16));
            }
            // ITR=0 so QEMU's e1000e doesn't postpone the interrupt (throttling).
            core::ptr::write_volatile((NIC_VADDR + E1000_ITR) as *mut u32, 0);
            // Enable + raise a real NIC interrupt (e1000e): unmask a cause, then set it.
            core::ptr::write_volatile((NIC_VADDR + E1000_IMS) as *mut u32, 0x1);
            core::ptr::write_volatile((NIC_VADDR + E1000_ICS) as *mut u32, 0x1);
            // Poll the result (bounded, non-blocking so a misroute fails not hangs).
            // The ISR host is priority 255 (== executive), so yield_now round-robins
            // to it when the real interrupt makes it runnable.
            let mut got = 0u64;
            for _ in 0..2_000_000u64 {
                let b = nb_recv(result_ntfn);
                if b != 0 {
                    got = b;
                    break;
                }
                yield_now();
            }
            // Diagnostic: read ICR from the executive. Nonzero ⇒ ICS asserted a real
            // cause (so the trigger works even if the IOAPIC route missed).
            let icr = core::ptr::read_volatile((NIC_VADDR + E1000_ICR) as *const u32);
            print_str(b"[ntos-exec] NIC ISR host badge=");
            print_u64(got);
            print_str(b" e1000e ICR=");
            print_hex(icr);
            print_str(b"\n");
            // The NIC raises a REAL interrupt: ICR bit 31 (INT asserted) + our cause.
            check(b"exec_nic_raised_real_interrupt", (icr & 0x8000_0000) != 0, &mut passed);
            // ...and it is delivered via MSI all the way into the isolated ISR host — a
            // real driver on real hardware taking a real device interrupt, crash-
            // contained. QEMU's e1000e delivers plain MSI on a legacy cause; the kernel
            // LAPIC-EOIs so this isn't blocked by the earlier HPET interrupt's ISR bit.
            check(b"exec_nic_irq_reached_isolated_host", got == ISR_DONE_BADGE, &mut passed);

            // ---- DMA: prove the NIC does REAL DMA to memory the executive allocates.
            // Build a TX descriptor ring + packet buffer in a normal RAM frame, learn its
            // physical address (VT-d translation is off → identity), point the e1000e TX
            // engine at it, kick the tail, and watch the NIC DMA-write the descriptor-DONE
            // bit back. DD=1 ⇒ the NIC DMA-read the ring + buffer and DMA-wrote the status.
            print_str(b"[ntos-exec] DMA: real e1000e TX DMA to an executive-owned frame\n");
            // Bus Master (Command bit 2) + Memory Space (bit 1) — DMA needs BME (idempotent
            // with the MSI setup above, but assert it so DMA doesn't depend on that path).
            let cmd = pci_read32(pci_io, 0, nic_dev, nic_func, 0x04);
            pci_write32(pci_io, 0, nic_dev, nic_func, 0x04, cmd | (1 << 2) | (1 << 1));

            let dma_frame = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, dma_frame);
            let _ = page_map(dma_frame, DMA_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
            let dma_paddr = get_frame_paddr(dma_frame);
            print_str(b"[ntos-exec] DMA frame paddr=");
            print_hex((dma_paddr >> 32) as u32);
            print_hex(dma_paddr as u32);
            print_str(b"\n");
            check(
                b"exec_frame_get_paddr",
                dma_paddr != 0 && (dma_paddr & 0xFFF) == 0,
                &mut passed,
            );

            // Frame layout: TX ring at offset 0 (8 legacy descriptors = 128 bytes, meeting
            // the TDLEN 128-byte-alignment rule; we use descriptor 0), packet at 0x200.
            const RING_OFF: u64 = 0x0;
            const PKT_OFF: u64 = 0x200;
            const PKT_LEN: u16 = 64;
            for i in 0..PKT_LEN as u64 {
                core::ptr::write_volatile((DMA_VADDR + PKT_OFF + i) as *mut u8, 0xA5);
            }
            // Legacy TX descriptor 0 (16 bytes): buffer_addr[0..7], length[8..9], CSO[10],
            // CMD[11]=EOP|RS, STA[12] (NIC writes DD here), CSS[13], special[14..15].
            core::ptr::write_volatile((DMA_VADDR + RING_OFF) as *mut u64, dma_paddr + PKT_OFF);
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 8) as *mut u16, PKT_LEN);
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 10) as *mut u8, 0); // CSO
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 11) as *mut u8, 0x09); // CMD = EOP | RS
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 12) as *mut u8, 0); // STA (NIC writes DD)
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 13) as *mut u8, 0); // CSS
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 14) as *mut u16, 0); // special

            // Point the TX engine at the ring's PHYSICAL address, enable TX, arm queue 0,
            // then kick. QEMU's e1000e gates TX on TARC0 bit 10 (E1000_TARC_ENABLE) — not
            // TXDCTL — so without it a TDT write silently does nothing.
            let ring_paddr = dma_paddr + RING_OFF;
            core::ptr::write_volatile((NIC_VADDR + E1000_TDBAL) as *mut u32, ring_paddr as u32);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDBAH) as *mut u32, (ring_paddr >> 32) as u32);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDLEN) as *mut u32, 128);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDH) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDT) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TCTL) as *mut u32, 0x0004_00F3); // EN|PSP|CT|COLD
            let tarc0 = core::ptr::read_volatile((NIC_VADDR + E1000_TARC0) as *const u32);
            core::ptr::write_volatile((NIC_VADDR + E1000_TARC0) as *mut u32, tarc0 | (1 << 10));
            core::ptr::write_volatile((NIC_VADDR + E1000_TDT) as *mut u32, 1); // hand off descriptor 0

            // Poll the descriptor's STA byte (offset +12) for DD (bit 0) — set by the NIC
            // via DMA once it has processed the descriptor.
            let mut dd = 0u8;
            for _ in 0..2_000_000u64 {
                dd = core::ptr::read_volatile((DMA_VADDR + RING_OFF + 12) as *const u8);
                if dd & 0x1 != 0 {
                    break;
                }
                yield_now();
            }
            print_str(b"[ntos-exec] TX descriptor STA=0x");
            print_hex(dd as u32);
            print_str(b" (DD=1 => NIC DMA-read the ring+buffer and DMA-wrote status)\n");
            check(b"exec_nic_tx_dma_writeback", dd & 0x1 != 0, &mut passed);

            // ---- DMA Phase 2: CONFINE the NIC's DMA via the VT-d IOMMU. Grant the NIC an
            // IO address space containing ONLY this frame, reprogram it to address memory
            // by IOVA (not raw paddr), and prove the DMA still lands — now translated +
            // confined, so a DMA anywhere else would fault. Building the NIC's first IO
            // context lazily turns on VT-d translation (kernel side).
            print_str(b"[ntos-exec] DMA Phase 2: confine NIC DMA via the VT-d IOMMU\n");
            // Mint a device IO-space cap stamped with the NIC's PCI request-id + a domain.
            let nic_rid = ((nic_dev as u64) << 3) | (nic_func as u64);
            let nic_io_badge = (1u64 << 16) | nic_rid;
            let nic_io_space = alloc_slot();
            let _ = syscall5(
                SYS_SEND,
                CAP_INIT_THREAD_CNODE,
                LBL_CNODE_MINT << 12,
                nic_io_space,
                SLOT_IO_SPACE,
                nic_io_badge,
            );
            // Build the 4-level IO page-table hierarchy toward NIC_IOVA: 4 tables (context
            // root + 3 intermediate — the walk starts at levels_remaining=3 so MapIO reaches
            // level 0 only after 4 tables). The first install creates the context + TE.
            let mut iopt_err = 0u64;
            for _ in 0..4 {
                let iopt = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_IO_PAGE_TABLE, PAGING_BITS, 1, iopt);
                let e = iopt_map(iopt, nic_io_space, NIC_IOVA);
                if e != 0 {
                    iopt_err = e;
                }
            }
            print_str(b"[ntos-exec] IO page-table build err=");
            print_u64(iopt_err);
            print_str(b"\n");
            check(b"exec_nic_iopt_hierarchy_built", iopt_err == 0, &mut passed);
            // Map the DMA frame (a COPY — the original stays VSpace-mapped for CPU access)
            // into the NIC's IO space at NIC_IOVA, read+write.
            let dma_frame_io = copy_cap(dma_frame);
            let map_err = map_io(dma_frame_io, nic_io_space, 0x3, NIC_IOVA);
            print_str(b"[ntos-exec] map_io err=");
            print_u64(map_err);
            print_str(b"\n");
            check(b"exec_nic_dma_frame_io_mapped", map_err == 0, &mut passed);

            // Re-arm a transmit, but now the NIC addresses memory via the IOVA: ring base =
            // NIC_IOVA, buffer = NIC_IOVA + PKT_OFF. The CPU still reads/writes the
            // descriptor through the VSpace mapping (DMA_VADDR) — VT-d only gates the device.
            core::ptr::write_volatile((DMA_VADDR + RING_OFF) as *mut u64, NIC_IOVA + PKT_OFF);
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 12) as *mut u8, 0); // clear STA/DD
            core::ptr::write_volatile((NIC_VADDR + E1000_TDBAL) as *mut u32, NIC_IOVA as u32);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDBAH) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDH) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDT) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDT) as *mut u32, 1);
            let mut dd2 = 0u8;
            for _ in 0..2_000_000u64 {
                dd2 = core::ptr::read_volatile((DMA_VADDR + RING_OFF + 12) as *const u8);
                if dd2 & 0x1 != 0 {
                    break;
                }
                yield_now();
            }
            print_str(b"[ntos-exec] confined TX descriptor STA=0x");
            print_hex(dd2 as u32);
            print_str(b" (DD=1 => NIC DMA went through VT-d: IOVA -> frame)\n");
            check(b"exec_nic_confined_dma", dd2 & 0x1 != 0, &mut passed);

            // ---- DRIVER HOST AT START: the executive, acting as the PnP manager + HAL,
            // hands an ISOLATED driver host a real NT CM_RESOURCE_LIST (MMIO + interrupt)
            // and a VT-d-confined common DMA buffer, then lets it drive the NIC (MMIO +
            // confined DMA) entirely from its own CSpace/VSpace — the seL4 analogue of a
            // KMDF driver's START_DEVICE. A fault or rogue DMA is contained in the host.
            print_str(b"[ntos-exec] driver host: START with CM_RESOURCE_LIST + confined DMA buffer\n");
            // Resource frame: mapped here (to fill it) and, via a copy, in the host.
            let reslist_frame = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, reslist_frame);
            let _ = page_map(reslist_frame, RESLIST_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
            {
                use nt_cm_resources::*;
                let buf =
                    core::slice::from_raw_parts_mut(RESLIST_VADDR as *mut u8, MEMORY_INTERRUPT_LIST_SIZE);
                let _ = build_memory_interrupt_list(
                    buf,
                    0, // bus 0
                    MemoryDescriptor {
                        start: NIC_VADDR, // the host's MMIO window (already mapped for it)
                        length: 0x4000,
                        flags: CM_RESOURCE_MEMORY_READ_WRITE,
                        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
                    },
                    InterruptDescriptor {
                        level: NIC_MSI_VECTOR as u32,
                        vector: NIC_MSI_VECTOR as u32,
                        affinity: 1,
                        flags: CM_RESOURCE_INTERRUPT_LATCHED,
                        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
                    },
                );
            }
            // Common-buffer descriptor (the DMA adapter's AllocateCommonBuffer result):
            // CPU virtual address, device logical address (IOVA), length.
            core::ptr::write_volatile((RESLIST_VADDR + 0x100) as *mut u64, DMA_VADDR);
            core::ptr::write_volatile((RESLIST_VADDR + 0x108) as *mut u64, NIC_IOVA);
            core::ptr::write_volatile((RESLIST_VADDR + 0x110) as *mut u64, 0x1000u64);
            core::ptr::write_volatile((RESLIST_VADDR + 0x200) as *mut u8, 0); // clear verdict
            core::ptr::write_volatile((RESLIST_VADDR + 0x210) as *mut u8, 0); // clear .sys verdict
            // Pre-load the REAL .sys driver (the executive owns the heap): map its image
            // frames RW here, parse/map/relocate/patch-IAT to our stubs, then hand the same
            // frames to the host R+X. Also a RW arena for the driver's host-side state.
            let mut pe_base = 0u64;
            for i in 0..driver_pe::PE_FRAMES {
                let f = alloc_slot();
                if i == 0 {
                    pe_base = f;
                }
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
                let _ = page_map(f, driver_pe::CODE_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            let sys_entry = driver_pe::load_into().unwrap_or(0);
            let mut arena_base = 0u64;
            for i in 0..driver_pe::ARENA_FRAMES {
                let f = alloc_slot();
                if i == 0 {
                    arena_base = f;
                }
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
                let _ = page_map(f, driver_pe::ARENA_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            core::ptr::write_volatile((RESLIST_VADDR + 0x300) as *mut u64, sys_entry as u64);
            core::ptr::write_volatile((RESLIST_VADDR + 0x308) as *mut u64, nic_mmio);
            print_str(b"[ntos-exec] pre-loaded real PnpMmioInterruptTest.sys; DriverEntry rva=");
            print_hex(sys_entry);
            print_str(b"\n");
            // A fresh badged result notification the host signals when it's done.
            let dh_result = make_object(OBJ_NOTIFICATION);
            let dh_result_badged = alloc_slot();
            let _ = syscall5(
                SYS_SEND,
                CAP_INIT_THREAD_CNODE,
                LBL_CNODE_MINT << 12,
                dh_result_badged,
                dh_result,
                ISR_DONE_BADGE,
            );
            // Hand the host a cap to the NIC's IRQ notification too (full resource grant).
            let dh_irq = copy_cap(nic_irq_ntfn);
            let dh_fault = make_object(OBJ_ENDPOINT);
            spawn_driver_host(
                driver_host::driver_host_entry,
                dh_irq,
                dh_result_badged,
                dh_fault,
                100,
                nic_bar_base,
                dma_frame,
                reslist_frame,
                pe_base,
                arena_base,
            );
            let _ = dh_fault; // a fault EP so a host fault is contained cleanly, not silent
            // The host always signals when done; read back its verdict from the shared frame.
            let (_z, dhb, _s, _m) = ep_recv(dh_result);
            let dh_verdict = core::ptr::read_volatile((RESLIST_VADDR + 0x200) as *const u8);
            print_str(b"[ntos-exec] driver host signalled badge=");
            print_u64(dhb);
            print_str(b" verdict=");
            print_u64(dh_verdict as u64);
            print_str(b"\n");
            check(b"exec_driver_host_drove_nic", dh_verdict == 1, &mut passed);
            // ...and a REAL Windows .sys driver binary ran in that same isolated host,
            // driven through DriverEntry → AddDevice → IRP_MN_START_DEVICE with our real
            // CM_RESOURCE_LIST, reaching the real NIC via MmMapIoSpace.
            let sys_v = core::ptr::read_volatile((RESLIST_VADDR + 0x210) as *const u8);
            print_str(b"[ntos-exec] hosted real .sys verdict bits=0x");
            print_hex(sys_v as u32);
            print_str(b"\n");
            check(b"exec_sys_driver_entry_ok", (sys_v & 1) != 0, &mut passed);
            check(b"exec_sys_adddevice_built_fdo", (sys_v & 2) != 0, &mut passed);
            check(b"exec_sys_start_reached_real_nic", (sys_v & 8) != 0, &mut passed);
            if (sys_v & 4) == 0 {
                print_str(b"[ntos-exec]   note: the driver's START handler ran + did real MMIO,\n");
                print_str(b"[ntos-exec]   then returned a device-specific status (the real device\n");
                print_str(b"[ntos-exec]   is an e1000e NIC, not this driver's own test device).\n");
            }
        }
    }

    // ---- KMDF DRIVER HOST: host a real KMDF driver (KmdfBasicTest.sys) through the FULL
    // WDF lifecycle (DriverEntry → WdfDriverCreate → AddDevice → EvtDevicePrepareHardware
    // → D0Entry → IOCTLs → REMOVE) in a SEPARATE isolated host — the MODERN Windows driver
    // framework, crash-contained on the microkernel. Software-only (simulated MMIO).
    {
        print_str(b"[ntos-exec] KMDF host: loading real KmdfBasicTest.sys\n");
        let mut kmdf_pe_base = 0u64;
        for i in 0..kmdf_host::KMDF_PE_FRAMES {
            let f = alloc_slot();
            if i == 0 {
                kmdf_pe_base = f;
            }
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
            let _ = page_map(f, kmdf_host::KMDF_CODE_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
        let kmdf_entry = kmdf_host::load_into().unwrap_or(0);
        let kmdf_shared = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, kmdf_shared);
        let _ = page_map(kmdf_shared, kmdf_host::KMDF_SHARED_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
        core::ptr::write_volatile(kmdf_host::KMDF_SHARED_VADDR as *mut u64, kmdf_entry as u64);
        core::ptr::write_volatile((kmdf_host::KMDF_SHARED_VADDR + 8) as *mut u32, 0);
        core::ptr::write_volatile((kmdf_host::KMDF_SHARED_VADDR + 0x10) as *mut u32, 0);
        print_str(b"[ntos-exec] pre-loaded KmdfBasicTest.sys; FxDriverEntry rva=");
        print_hex(kmdf_entry);
        print_str(b"\n");
        let kmdf_result = make_object(OBJ_NOTIFICATION);
        let kmdf_result_badged = alloc_slot();
        let _ = syscall5(
            SYS_SEND,
            CAP_INIT_THREAD_CNODE,
            LBL_CNODE_MINT << 12,
            kmdf_result_badged,
            kmdf_result,
            ISR_DONE_BADGE,
        );
        let kmdf_fault = make_object(OBJ_ENDPOINT);
        spawn_kmdf_host(
            kmdf_host::kmdf_host_entry,
            kmdf_result_badged,
            kmdf_fault,
            100,
            kmdf_pe_base,
            kmdf_shared,
            kmdf_nic_bar_base,
        );
        let _ = kmdf_fault;
        let (_z, _b, _s, _m) = ep_recv(kmdf_result);
        let kv = core::ptr::read_volatile((kmdf_host::KMDF_SHARED_VADDR + 8) as *const u32);
        print_str(b"[ntos-exec] KMDF host lifecycle verdict bits=0x");
        print_hex(kv);
        print_str(b"\n");
        check(b"exec_kmdf_driver_create", (kv & 1) != 0, &mut passed);
        check(b"exec_kmdf_adddevice_queue", (kv & 2) != 0, &mut passed);
        // bit 4 now = the driver's PrepareHardware mapped the REAL NIC BAR + read + rejected
        // a real register (not its 'KMDF' test HW) — a real KMDF driver reaching real HW.
        check(b"exec_kmdf_prepare_hw_read_real_nic", (kv & 4) != 0, &mut passed);
        check(b"exec_kmdf_ioctl", (kv & 8) != 0, &mut passed);
        check(b"exec_kmdf_remove", (kv & 16) != 0, &mut passed);
        // The KMDF driver, in EvtDevicePrepareHardware, mapped the REAL e1000e BAR
        // (MmMapIoSpace → NIC_VADDR) and its READ_REG32 IOCTL returned register 0 (CTRL).
        // Verify it matches a direct read of the same live register — a real KMDF driver
        // reaching real hardware through the WDF stack.
        let kmdf_ctrl = core::ptr::read_volatile((kmdf_host::KMDF_SHARED_VADDR + 0x10) as *const u32);
        let direct_ctrl = if kmdf_nic_bar_base != 0 {
            core::ptr::read_volatile(NIC_VADDR as *const u32)
        } else {
            0
        };
        print_str(b"[ntos-exec] KMDF driver read real NIC CTRL=0x");
        print_hex(kmdf_ctrl);
        print_str(b" (direct read=0x");
        print_hex(direct_ctrl);
        print_str(b")\n");
        check(
            b"exec_kmdf_read_real_nic",
            kmdf_ctrl != 0 && kmdf_ctrl != 0xFFFF_FFFF && kmdf_ctrl == direct_ctrl,
            &mut passed,
        );
    }

    // --- P2: real block I/O in an ISOLATED host with VT-d-CONFINED DMA. The executive is the
    // Tier-1 broker: it enables Bus Master, claims the AHCI BAR + a DMA frame, gives the AHCI
    // its OWN VT-d IO context (the DMA frame mapped at an IOVA — the device can reach NOTHING
    // else), and hands the isolated storage host only those caps. The host drives the disk
    // from its own VSpace, addressing memory by IOVA. Runs AFTER the NIC block so VT-d
    // translation is already ON (the NIC's Phase-2 turned it on); the AHCI just adds its
    // own context. READ ONLY.
    if found_storage {
        let ahci_bar = (storage_bar5 & 0xFFFF_FFF0) as u64;
        print_str(b"[ntos-exec] P2: AHCI ABAR=");
        print_hex(ahci_bar as u32);
        print_str(b" dev=");
        print_u64(storage_dev as u64);
        print_str(b" -> isolated storage host (VT-d confined)\n");
        // Enable Bus Master (Command bit 2) + Memory Space (bit 1) so the HBA can DMA.
        let cmd = pci_read32(pci_io, 0, storage_dev, storage_func, 0x04);
        pci_write32(pci_io, 0, storage_dev, storage_func, 0x04, cmd | (1 << 2) | (1 << 1));
        let ahci_frame = claim_device_pages(bi, ahci_bar, AHCI_VADDR, 1);
        check(b"exec_ahci_abar_claimed", ahci_frame != 0, &mut passed);
        if ahci_frame != 0 {
            // The DMA frame: AHCI command list + FIS + command table + the data buffer.
            let dma_frame = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, dma_frame);
            // ---- CONFINE the AHCI's DMA via the VT-d IOMMU. Mint an IO-space cap stamped
            // with the AHCI's PCI request-id (00:3.0 -> rid 0x18) + its own domain, build the
            // 4-level IO page-table hierarchy toward AHCI_IOVA, and map the DMA frame there.
            // The AHCI can then DMA to AHCI_IOVA only — VT-d faults anything else.
            let ahci_rid = ((storage_dev as u64) << 3) | (storage_func as u64);
            let ahci_io_badge = (2u64 << 16) | ahci_rid; // domain 2 (the NIC uses domain 1)
            let ahci_io_space = alloc_slot();
            let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, ahci_io_space, SLOT_IO_SPACE, ahci_io_badge);
            let mut iopt_err = 0u64;
            for _ in 0..4 {
                let iopt = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_IO_PAGE_TABLE, PAGING_BITS, 1, iopt);
                let e = iopt_map(iopt, ahci_io_space, AHCI_IOVA);
                if e != 0 {
                    iopt_err = e;
                }
            }
            print_str(b"[ntos-exec] AHCI IO page-table build err=");
            print_u64(iopt_err);
            print_str(b"\n");
            check(b"exec_ahci_iopt_hierarchy_built", iopt_err == 0, &mut passed);
            let dma_frame_io = copy_cap(dma_frame);
            let map_err = map_io(dma_frame_io, ahci_io_space, 0x3, AHCI_IOVA);
            print_str(b"[ntos-exec] AHCI map_io err=");
            print_u64(map_err);
            print_str(b"\n");
            check(b"exec_ahci_dma_frame_io_mapped", map_err == 0, &mut passed);
            // Shared word: the AHCI's DEVICE address — now the IOVA (VT-d maps it to the
            // frame) — in @0; verdict + INITRD info out.
            let shared = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, shared);
            let sh_exec = copy_cap(shared);
            let _ = page_map(sh_exec, STORAGE_SHARED_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
            core::ptr::write_volatile(STORAGE_SHARED_VADDR as *mut u64, AHCI_IOVA);
            core::ptr::write_volatile((STORAGE_SHARED_VADDR + 8) as *mut u32, 0);
            // The shared file buffer: FILEBUF_FRAMES consecutive frames, mapped contiguously in
            // the executive (to parse the PE) and in the host (to read it off disk into).
            // FILEBUF_VADDR is a fresh 2 MiB region — give it its own page table.
            let fb_pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, fb_pt);
            let _ = paging_struct_map(fb_pt, LBL_X86_PAGE_TABLE_MAP, FILEBUF_VADDR, CAP_INIT_THREAD_VSPACE);
            let fb_start = alloc_frame();
            for _ in 1..FILEBUF_FRAMES {
                let _ = alloc_frame();
            }
            for i in 0..FILEBUF_FRAMES {
                let _ = page_map(copy_cap(fb_start + i), FILEBUF_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            // The ntdll buffer (240 frames, its own PT), mapped in the executive too.
            let nb_pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, nb_pt);
            let _ = paging_struct_map(nb_pt, LBL_X86_PAGE_TABLE_MAP, NTDLLBUF_VADDR, CAP_INIT_THREAD_VSPACE);
            let nb_start = alloc_frame();
            for _ in 1..NTDLLBUF_FRAMES {
                let _ = alloc_frame();
            }
            for i in 0..NTDLLBUF_FRAMES {
                let _ = page_map(copy_cap(nb_start + i), NTDLLBUF_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            // The NLS buffers share the NTDLLBUF page table (0xA0-0xC0) — map contiguous frame runs
            // in the executive too, and remember their cap bases for spawn_sec_image to share into
            // smss.
            let mut nls_starts = [0u64; 3];
            for (k, (vaddr, frames)) in [
                (NLS_ANSI_VADDR, NLS_ANSI_FRAMES),
                (NLS_OEM_VADDR, NLS_OEM_FRAMES),
                (NLS_CASE_VADDR, NLS_CASE_FRAMES),
            ]
            .into_iter()
            .enumerate()
            {
                let start = alloc_frame();
                for _ in 1..frames {
                    let _ = alloc_frame();
                }
                for i in 0..frames {
                    let _ = page_map(copy_cap(start + i), vaddr + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
                }
                nls_starts[k] = start;
            }
            NLS_ANSI_START.store(nls_starts[0], Ordering::Relaxed);
            NLS_OEM_START.store(nls_starts[1], Ordering::Relaxed);
            NLS_CASE_START.store(nls_starts[2], Ordering::Relaxed);
            // The real SYSTEM hive buffer (64 frames, shares the 0xA0-0xC0 PT), mapped in the
            // executive; the same frames are granted to the storage host in spawn_storage_host.
            let hivebuf_start = alloc_frame();
            for _ in 1..HIVEBUF_FRAMES {
                let _ = alloc_frame();
            }
            for i in 0..HIVEBUF_FRAMES {
                let _ = page_map(copy_cap(hivebuf_start + i), HIVEBUF_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            HIVEBUF_START.store(hivebuf_start, Ordering::Relaxed);
            // Spawn the isolated storage host (prio 100; the executive is 255 and BLOCKS on
            // the result, yielding the CPU to it) and wait for its report.
            let sresult = make_object(OBJ_NOTIFICATION);
            let sresult_badged = alloc_slot();
            let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, sresult_badged, sresult, ISR_DONE_BADGE);
            let sfault = make_object(OBJ_ENDPOINT);
            spawn_storage_host(
                storage_host::storage_host_entry,
                sresult_badged,
                sfault,
                100,
                ahci_frame,
                dma_frame,
                shared,
                fb_start,
                nb_start,
                nls_starts[0],
                nls_starts[1],
                nls_starts[2],
                hivebuf_start,
            );
            let _ = sfault;
            let (_z, _b, _s, _m) = ep_recv(sresult);
            let verdict = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 8) as *const u32);
            // Capture the NLS table sizes the host reported.
            NLS_ANSI_SIZE.store(
                core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x2c) as *const u32) as u64,
                Ordering::Relaxed,
            );
            NLS_OEM_SIZE.store(
                core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x30) as *const u32) as u64,
                Ordering::Relaxed,
            );
            NLS_CASE_SIZE.store(
                core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x34) as *const u32) as u64,
                Ordering::Relaxed,
            );
            // The real SYSTEM hive size the storage host read into HIVEBUF (reported @+0x38).
            REAL_HIVE_SIZE.store(
                core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x38) as *const u32) as u64,
                Ordering::Relaxed,
            );
            let cluster = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x10) as *const u32);
            let size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x14) as *const u32);
            print_str(b"[ntos-exec] isolated storage host reported verdict=0x");
            print_hex(verdict);
            print_str(b" INITRD cluster=");
            print_u64(cluster as u64);
            print_str(b" size=");
            print_u64(size as u64);
            print_str(b"\n");
            // The host reached the disk through granted caps only, and EVERY AHCI DMA went
            // through VT-d (IOVA -> frame). Verdict bits: 1=MBR, 2=FAT32, 4=root, 8=file.
            check(b"exec_storage_host_reported", verdict != 0, &mut passed);
            check(b"exec_storage_host_mbr", (verdict & 1) != 0, &mut passed);
            check(b"exec_storage_host_fat32", (verdict & 2) != 0, &mut passed);
            check(b"exec_storage_host_root_dir", (verdict & 4) != 0, &mut passed);
            check(b"exec_storage_host_confined_read_file", (verdict & 8) != 0, &mut passed);
            check(b"exec_storage_host_read_hive", (verdict & 0x10) != 0, &mut passed);

            // --- P2 finale: the Config Manager parses the registry hive the isolated storage
            // host read off the FS (an nt-hive-core image at STORAGE_SHARED_VADDR+0x100) and
            // reads a known value back — disk -> volume -> FS -> REGISTRY, end to end.
            let hive_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x18) as *const u32);
            let hive_bytes = core::slice::from_raw_parts(
                (STORAGE_SHARED_VADDR + 0x100) as *const u8,
                hive_size as usize,
            );
            match nt_hive_core::decode_image(hive_bytes) {
                Ok(hive) => {
                    print_str(b"[ntos-exec] Config Manager decoded hive (");
                    print_u64(hive_size as u64);
                    print_str(b" bytes)\n");
                    check(b"exec_cm_hive_decoded", true, &mut passed);
                    let answer = hive
                        .open_key("ControlSet001\\Services\\NtosTest")
                        .and_then(|k| hive.query_dword(k, "Answer"));
                    print_str(b"[ntos-exec] hive ControlSet001\\Services\\NtosTest\\Answer = ");
                    print_u64(answer.unwrap_or(0) as u64);
                    print_str(b"\n");
                    check(b"exec_cm_hive_answer_42", answer == Some(42), &mut passed);
                }
                Err(_) => {
                    print_str(b"[ntos-exec] hive decode FAILED\n");
                    check(b"exec_cm_hive_decoded", false, &mut passed);
                    check(b"exec_cm_hive_answer_42", false, &mut passed);
                }
            }
        }
    }

    // --- P3: source a demand-paged section from a REAL disk file. The storage host read
    // SYSTEM.DAT (the hive) off the FAT32 disk into the shared frame; copy it into a file
    // frame, then a loader thread maps it as a demand-paged file-backed section and faults its
    // first page IN — so a page of a real on-disk file arrives in the process only when touched.
    let hive_len = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x18) as *const u32);
    if found_storage && hive_len > 0 {
        // Copy the disk hive (shared frame @+0x100) into a dedicated file frame. The hive is
        // only `hive_len` bytes — don't read off the end of the 1-page shared frame. ldff is
        // retype-zeroed, so the rest stays 0.
        let ldff = alloc_frame();
        let _ = page_map(ldff, STORAGE_SHARED_VADDR + 0x3000, RW_NX, CAP_INIT_THREAD_VSPACE);
        let n = (hive_len as u64).min(0xF00);
        for i in 0..n {
            let b = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x100 + i) as *const u8);
            core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x3000 + i) as *mut u8, b);
        }
        let ld_fault = make_object(OBJ_ENDPOINT);
        let ld_fault_c = copy_cap(ld_fault);
        let ld_sysarg = alloc_frame();
        let faults_before = DEMAND_FAULTS.load(Ordering::Relaxed);
        let ld_pml4 = spawn_user_thread(loader_entry, ld_fault_c, copy_cap(ld_sysarg), 100, 0);
        let (_srv, ld_magic) = service_user_syscalls(ld_fault, &mut c, &mut cm, ld_pml4, ldff);
        let ld_faults = DEMAND_FAULTS.load(Ordering::Relaxed) - faults_before;
        print_str(b"[ntos-exec] loader demand-paged the disk hive: magic=0x");
        print_hex((ld_magic >> 32) as u32);
        print_hex(ld_magic as u32);
        print_str(b" (UNTHIVE1) faults=");
        print_u64(ld_faults);
        print_str(b"\n");
        // The loader read the hive's UNTHIVE1 magic via a page fault from a section backed by
        // the real on-disk SYSTEM.DAT.
        check(
            b"exec_disk_section_demand_paged",
            ld_magic == 0x3145_5649_4854_4E55 && ld_faults >= 1,
            &mut passed,
        );
    }

    // --- P3 ReactOS-binary pipeline: the storage host read a REAL, redistributable (GPL)
    // ReactOS x64 smss.exe off the disk into the file buffer. Parse it through the REAL
    // PE-load path (nt-pe-loader) and validate our SEC_IMAGE page-fill against it — a genuine
    // Windows-family binary flowing through the machinery we built.
    let smss_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x20) as *const u32);
    if found_storage && smss_size > 0 {
        let smss = core::slice::from_raw_parts(FILEBUF_VADDR as *const u8, smss_size as usize);
        match nt_pe_loader::PeFile::parse(smss) {
            Ok(pe) => {
                // Fix up smss's absolute pointers for its load at PE_LOAD_BASE (before the IAT
                // patch, which overwrites the import thunks anyway).
                apply_relocations_to_buf(&pe, FILEBUF_VADDR, PE_LOAD_BASE);
                // Now that the code is relocated to PE_LOAD_BASE, PATCH the header's
                // OptionalHeader.ImageBase to PE_LOAD_BASE too. smss's preferred base is
                // 0x140000000; without this, ntdll sees ImageBaseAddress(PE_LOAD_BASE) != the
                // header's preferred base and tries to RELOCATE THE EXE — but ReactOS's EXE-reloc
                // path (ldrinit.c:2409) is UNIMPLEMENTED and returns STATUS_INVALID_IMAGE_FORMAT.
                // Setting the header field = load base makes ntdll treat it as already-at-preferred
                // (no relocation). OptionalHeader.ImageBase @ NtHeaders(FILEBUF+e_lfanew)+0x30.
                let e_lfanew = core::ptr::read_volatile((FILEBUF_VADDR + 0x3c) as *const u32) as u64;
                core::ptr::write_volatile(
                    (FILEBUF_VADDR + e_lfanew + 0x30) as *mut u64, PE_LOAD_BASE);
                let nsec = pe.sections().len();
                let entry = pe.entry_point_rva();
                let mut imports_ntdll = false;
                if let Ok(imps) = pe.imports() {
                    for dll in &imps {
                        if dll.name.eq_ignore_ascii_case("ntdll.dll") {
                            imports_ntdll = true;
                        }
                    }
                }
                // SEC_IMAGE fill validation: fill the .text page (RVA 0x1000) via our RVA->file
                // translation and compare to the file's .text raw bytes. Match => our loader
                // maps a real 6-section x64 binary correctly.
                let scratch = STORAGE_SHARED_VADDR + 0x5000;
                let _ = page_map(alloc_frame(), scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
                let _ = fill_image_page(&pe, 0x1000, scratch);
                let mut fill_ok = false;
                if let Some(t) = pe.sections().iter().find(|s| s.virtual_address == 0x1000) {
                    let raw = t.pointer_to_raw_data as u64;
                    fill_ok = true;
                    for j in 0..64u64 {
                        let a = core::ptr::read_volatile((scratch + j) as *const u8);
                        let b = core::ptr::read_volatile((FILEBUF_VADDR + raw + j) as *const u8);
                        if a != b {
                            fill_ok = false;
                            break;
                        }
                    }
                }
                print_str(b"[ntos-exec] REAL ReactOS smss.exe loaded: PE32+ x64, sections=");
                print_u64(nsec as u64);
                print_str(b" entry=0x");
                print_hex(entry);
                print_str(b" imports_ntdll=");
                print_u64(imports_ntdll as u64);
                print_str(b" sec_image_fill_ok=");
                print_u64(fill_ok as u64);
                print_str(b"\n");
                check(b"exec_reactos_smss_parsed", nsec == 6 && entry == 0x12ee0, &mut passed);
                check(b"exec_reactos_smss_imports_ntdll", imports_ntdll, &mut passed);
                check(b"exec_reactos_sec_image_fill", fill_ok, &mut passed);

                // Resolve smss's ntdll imports: apply the build-time patch table (imports.bin,
                // read off disk into STORAGE_SHARED+0x800) to smss's IAT in the file buffer —
                // each slot := NTDLL_BASE + the import's real ntdll export RVA. So smss's ntdll
                // calls now target real ntdll addresses instead of unresolved file thunks.
                let imports_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x24) as *const u32);
                let mut resolved = 0u32;
                if imports_size >= 4 {
                    let count = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x800) as *const u32);
                    for i in 0..count as u64 {
                        let ent = STORAGE_SHARED_VADDR + 0x804 + i * 8;
                        let off = core::ptr::read_volatile(ent as *const u32) as u64;
                        let rva = core::ptr::read_volatile((ent + 4) as *const u32) as u64;
                        core::ptr::write_volatile((FILEBUF_VADDR + off) as *mut u64, NTDLL_BASE + rva);
                        resolved += 1;
                    }
                }
                let rnpp = core::ptr::read_volatile((FILEBUF_VADDR + 0x13330) as *const u64);
                print_str(b"[ntos-exec] resolved ");
                print_u64(resolved as u64);
                print_str(b" smss ntdll imports; IAT[RtlNormalizeProcessParams]=0x");
                print_hex((rnpp >> 32) as u32);
                print_hex(rnpp as u32);
                print_str(b"\n");
                check(b"exec_reactos_imports_resolved", resolved == 103, &mut passed);

                // LIVE SEC_IMAGE LOAD with ntdll MAPPED: spawn smss (image VA reserved) AND
                // demand-map the disk-read ntdll.dll at NTDLL_BASE. smss executes its entry, its
                // .text faults in live, then it calls RtlNormalizeProcessParams via the resolved
                // IAT -> NTDLL_BASE+0x48f00 -> ntdll's .text page faults in and REAL NTDLL CODE
                // EXECUTES. It runs until it derefs the (null) process params -> a safe stop.
                let ntdll_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x28) as *const u32);
                let ntdll_bytes = core::slice::from_raw_parts(NTDLLBUF_VADDR as *const u8, ntdll_size as usize);
                let si_fault = make_object(OBJ_ENDPOINT);
                let si_fault_c = copy_cap(si_fault);
                if let Ok(ntdll_pe) = nt_pe_loader::PeFile::parse(ntdll_bytes) {
                    // Relocate ntdll for its load at NTDLL_BASE — its .data list heads etc. hold
                    // absolute self-pointers at the preferred base otherwise.
                    apply_relocations_to_buf(&ntdll_pe, NTDLLBUF_VADDR, NTDLL_BASE);
                    // setup_env=true: a PEB + process params + trampoline so smss's entry gets a
                    // non-null PEB in RCX and runs its real startup (past the RtlAssert/null-deref).
                    let pml4 = spawn_sec_image(&pe, si_fault_c, NTDLL_BASE, true);
                    // Scratch at 0x6C — past FILEBUF (0x60), the stack mirror (0x68), in the
                    // FILEBUF PT; up to the 96-fault cap fits before 0x80.
                    let (heap_verdict, sfaults, sfirst, sstop, ntfaults, sssn) = service_sec_image(
                        si_fault,
                        pml4,
                        &pe,
                        0x0000_0100_006C_0000,
                        Some((NTDLL_BASE, &ntdll_pe)),
                    );
                    print_str(b"[ntos-exec] LIVE ReactOS smss+env: faulted ");
                    print_u64(sfaults);
                    print_str(b" page(s) (");
                    print_u64(ntfaults);
                    print_str(b" in ntdll), first=0x");
                    print_hex((sfirst >> 32) as u32);
                    print_hex(sfirst as u32);
                    print_str(b" stop=0x");
                    print_hex((sstop >> 32) as u32);
                    print_hex(sstop as u32);
                    print_str(b" ntalloc_serviced=");
                    print_u64(NTALLOC_SERVICED.load(Ordering::Relaxed));
                    print_str(b" rtlcreateheap=0x");
                    print_hex((heap_verdict >> 32) as u32);
                    print_hex(heap_verdict as u32);
                    print_str(b"\n");
                    let _ = (sfirst, sssn, heap_verdict);
                    // The trampoline now enters ntdll's REAL loader init, LdrpInitialize
                    // (ntdll+0x8e70). It runs deep into process bring-up — reads TEB/PEB/KUSER,
                    // NtQueryVirtualMemory, NtQueryInformationProcess(ProcessCookie), NtOpenKey +
                    // NtQueryValueKey (IFEO/options → not-found), NtProtectVirtualMemory,
                    // RtlImageNtHeader on smss's own image (checking Subsystem==NATIVE) — all
                    // serviced by the executive, demand-loading ~33 ntdll pages. It currently stops
                    // in a CRT/locale-style string routine (ntdll+0x63dc0) called with a bad context
                    // pointer — the next blocker on the way to LdrpInitializeProcess's RtlCreateHeap
                    // and the image entry hand-off.
                    check(b"exec_reactos_smss_live_paged", sfaults >= 1, &mut passed);
                    check(b"exec_reactos_smss_calls_into_ntdll", ntfaults >= 1, &mut passed);
                    // LdrpInitialize executes deep loader init (demand-loading many ntdll pages),
                    // not merely entering — proves the real loader-init path is running.
                    check(b"exec_reactos_ldrinit_runs_deep", sfaults >= 25, &mut passed);
                    // LdrpInitializeProcess reached RtlCreateHeap and created the process heap —
                    // both its NtAllocateVirtualMemory reserve+commit serviced by the executive.
                    check(
                        b"exec_reactos_ldrinit_creates_heap",
                        NTALLOC_SERVICED.load(Ordering::Relaxed) >= 2,
                        &mut passed,
                    );
                    // RtlImageNtHeader (in LdrpInitializeProcess) demand-faulted smss's OWN image
                    // header — at least one fault outside ntdll — proving loader init inspects the
                    // real ReactOS binary (PEB->ImageBaseAddress) and read past the null derefs.
                    check(
                        b"exec_reactos_ldrinit_reads_image",
                        sfaults > ntfaults && sstop != 0x0000_0100_24bc_8350,
                        &mut passed,
                    );
                } else {
                    check(b"exec_reactos_smss_live_paged", false, &mut passed);
                    check(b"exec_reactos_smss_calls_into_ntdll", false, &mut passed);
                    check(b"exec_reactos_ldrinit_runs_deep", false, &mut passed);
                    check(b"exec_reactos_ldrinit_creates_heap", false, &mut passed);
                    check(b"exec_reactos_ldrinit_reads_image", false, &mut passed);
                }
            }
            Err(_) => {
                print_str(b"[ntos-exec] ReactOS smss.exe PARSE FAILED\n");
                check(b"exec_reactos_smss_parsed", false, &mut passed);
                check(b"exec_reactos_smss_imports_ntdll", false, &mut passed);
                check(b"exec_reactos_sec_image_fill", false, &mut passed);
            }
        }
    }

    print_str(b"[ntos-exec summary: ");
    print_u64(passed);
    print_str(b"/93 executive->isolated-service checks passed]\n");
    print_str(b"[microtest done]\n");
    park()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_put_char(b'!');
    park()
}
