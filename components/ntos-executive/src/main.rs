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
mod alpc_selftest;
mod cm_server;
mod io_server;
mod lpc_server;
mod driver_host;
mod driver_pe;
mod isr;
mod kmdf_host;
mod server;
mod win32k_pe;
mod win32k_host;
mod storage_host;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;

use nt_config_abi::CmReply;
use nt_config_client::ConfigClient;
use nt_io_abi::wire::IoReply;
use nt_io_client::IoClient;
use nt_kernel_exec::{EventKind, EventStore, IrqlState, WaitResult};
use nt_lpc_abi::LpcReply;
use nt_lpc_client::LpcClient;
use nt_object_abi::ObReply;
use nt_object_client::ObjectClient;
use nt_hive_core::apply_ccs_alias;
use nt_fs::{FileSystem, MemFs};
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

// Relocated "cluster" vaddr layout — all inside ONE 2 MiB page table at WORK_CLUSTER_BASE
// (0x1040_0000, 256 MiB past IMAGE_BASE), well clear of the 64 MiB ELF reserve. These vaddrs are
// used in BOTH the executive's own VSpace (front-end side) and each spawned service's VSpace (they
// map their own copies of the same frames). Low 21 bits preserve the old intra-2 MiB offsets, so
// every "same 2 MiB PT" relationship is unchanged — only the PT moved out from under the ELF.
pub const IMAGE_BASE: u64 = 0x0000_0100_0040_0000;
/// Base of the relocated shared working-VA cluster (rings, stack, IPC buffer, sysarg, device MMIO,
/// driver code/arena). One 2 MiB page table covers [WORK_CLUSTER_BASE, +0x20_0000); every
/// executive-image VSpace (and the executive's own) builds it via `map_cluster_pt`.
pub const WORK_CLUSTER_BASE: u64 = 0x0000_0100_1040_0000;
pub const SUB_RING_VADDR: u64 = 0x0000_0100_1050_0000;
pub const COMP_RING_VADDR: u64 = 0x0000_0100_1051_0000;
pub const REQ_DATA_VADDR: u64 = 0x0000_0100_1052_0000;
pub const REP_DATA_VADDR: u64 = 0x0000_0100_1053_0000;
// A SECOND ring set — the executive's side of the Configuration Manager service.
// (Each spawned service maps ITS frames at the shared SUB/COMP/REQ/REP vaddrs above
// in its own VSpace; the executive maps each service's frames at distinct vaddrs.)
pub const CM_SUB_VADDR: u64 = 0x0000_0100_1054_0000;
pub const CM_COMP_VADDR: u64 = 0x0000_0100_1055_0000;
pub const CM_REQ_VADDR: u64 = 0x0000_0100_1056_0000;
pub const CM_REP_VADDR: u64 = 0x0000_0100_1057_0000;
// A THIRD ring set — the executive's side of the I/O Manager service.
pub const IO_SUB_VADDR: u64 = 0x0000_0100_1058_0000;
pub const IO_COMP_VADDR: u64 = 0x0000_0100_1059_0000;
pub const IO_REQ_VADDR: u64 = 0x0000_0100_105A_0000;
pub const IO_REP_VADDR: u64 = 0x0000_0100_105B_0000;
// A FOURTH ring set — the executive's side of the LPC connection broker. Placed in the FREE low
// half of the WORK_CLUSTER 2 MiB PT (0x1040..0x104F, all covered by map_cluster_pt, unused by the
// ring/stack/sysarg region at 0x1050+), so no new page table is needed.
pub const LPC_SUB_VADDR: u64 = 0x0000_0100_1040_0000;
pub const LPC_COMP_VADDR: u64 = 0x0000_0100_1041_0000;
pub const LPC_REQ_VADDR: u64 = 0x0000_0100_1042_0000;
pub const LPC_REP_VADDR: u64 = 0x0000_0100_1043_0000;
pub const STACK_BASE: u64 = 0x0000_0100_105C_0000;
/// Floor for on-demand stack growth: a fault in [STACK_GROWTH_FLOOR, STACK_BASE) commits a fresh
/// page and restarts (Windows guard-page style), so smss's stack grows past the 16 KiB initial
/// commit instead of crashing. Bounded above IO_REP_VADDR (…5B_0000) so growth never collides
/// with the env mappings below. ~60 KiB of growth room; ~76 KiB total stack.
pub const STACK_GROWTH_FLOOR: u64 = 0x0000_0100_105B_1000;
/// A per-user-thread syscall argument frame, mapped at the SAME vaddr in both the
/// executive and the user thread — so a `UNICODE_STRING` whose `Buffer` points into
/// it is valid in both address spaces (the copyin path for pointer-based `Nt*` args).
pub const SYSARG_VADDR: u64 = 0x0000_0100_105D_0000;
/// A second shared frame, for the blocking-wait demo's two threads (mapped at SYSARG_VADDR in
/// each of them) — read by the executive at this vaddr (its own view of the same frame).
pub const SYSARG2_VADDR: u64 = 0x0000_0100_105D_1000;
/// Where a loaded real PE's image is mapped in its user VSpace (inside the one 2 MiB PT with
/// the stack/sysarg/ipcbuf), and the executive's scratch region to write the code first.
pub const PE_LOAD_BASE: u64 = 0x0000_0100_0056_0000;
/// Where ntdll.dll is (to be) mapped in a loaded process's VSpace — smss's IAT is resolved to
/// NTDLL_BASE + each import's export RVA.
pub const NTDLL_BASE: u64 = 0x0000_0100_0080_0000;
/// A hosted process's environment pages (TEB/PEB/params/trampoline). These live in the SAME 2 MiB
/// image page table (the reserved IMAGE_BASE PT spans [0x40_0000, 0x60_0000)) but must sit BELOW
/// PE_LOAD_BASE (0x56_0000) so they never collide with the hosted EXE's own image, which loads at
/// PE_LOAD_BASE and grows UP. The OLD placement at 0x58/0x59/0x5A_0000 (= PE_LOAD_BASE + 0x20/0x30/
/// 0x40 KiB) worked only because smss/csrss are tiny (<128 KiB); winlogon.exe is 245 KiB (image
/// ends 0x59d000), so its .rdata (the TLS directory @ rva 0x20940 → 0x58_0940) was SHADOWED by the
/// PEB page → LdrpInitializeTls read a zero AddressOfIndex and #PF'd writing through NULL. Placing
/// the env block in [0x51_0000, 0x54_0000) keeps it clear of every hosted EXE (all load at
/// 0x56_0000). Same VA in each VSpace (independent page tables), so one set of constants suffices.
/// Layout (below PE_LOAD_BASE, distinct pages, in the reserved image PT): TEB @0x51 (2 pages),
/// params+env @0x52 (2 pages), PEB @0x53 (1 page), trampoline @0x55 (1 page).
pub const SMSS_TRAMP_VA: u64 = 0x0000_0100_0055_0000;
pub const SMSS_PEB_VA: u64 = 0x0000_0100_0053_0000;
pub const SMSS_PARAMS_VA: u64 = 0x0000_0100_0052_0000;
pub const SMSS_TEB_VA: u64 = 0x0000_0100_0051_0000;
/// The executive's mirror of smss's stack (same frames), for reading/writing a syscall's
/// stack-based pointer args (copyin/copyout). In the FILEBUF PT (0x60-0x80), present.
pub const SMSS_STACK_MIRROR_VA: u64 = 0x0000_0100_1068_0000;
/// The 2nd hosted process (csrss) needs its OWN executive stack mirror: its syscall out-params
/// (e.g. NtAllocateVirtualMemory's base for RtlCreateHeap) must be written to ITS stack, not smss's.
/// Adjacent to smss's mirror, in the same FILEBUF page table. ACTIVE_STACK_MIRROR selects between
/// them by the current fault badge.
pub const CSRSS_STACK_MIRROR_VA: u64 = 0x0000_0100_1069_0000;
/// Where the executive backs NtAllocateVirtualMemory for the process (its own PT).
pub const SMSS_ALLOC_VA: u64 = 0x0000_0100_00C0_0000;
/// The executive's mirror of the first window of smss's heap (SMSS_ALLOC_VA). A userspace broker
/// can't walk smss's page tables, so `smss_copyin` reads syscall pointer args (e.g. a loader-built
/// registry key path) from the same frames it mapped, through this parallel mapping. Own PT.
pub const SMSS_HEAP_MIRROR_VA: u64 = 0x0000_0100_1090_0000;
pub const SMSS_HEAP_MIRROR_WINDOW: u64 = 0x0020_0000; // 2 MiB (one PT) of early heap
/// csrss's own heap mirror — its loader builds DLL search paths ("…\csrsrv.dll") on its heap, which
/// the executive must read from CSRSS's heap, not smss's. 2 MiB at 0x200_0000 (past the fill-scratch
/// region 0x100-0x200, its own PT). ACTIVE_HEAP_MIRROR selects by the current badge.
pub const CSRSS_HEAP_MIRROR_VA: u64 = 0x0000_0100_1200_0000;
/// The executive's mirror of smss's demand-filled IMAGE pages, so smss_copyin can read static
/// pointer args (registry value/subkey names in .rdata, etc.) from the process image. Sits just
/// below the heap mirror and SHARES its 0x80-0xA0 page table (no extra PT).
pub const IMAGE_MIRROR_VA: u64 = 0x0000_0100_1080_0000;
pub const IMAGE_MIRROR_WINDOW: u64 = 0x0010_0000; // 1 MiB (smss image is ~110 KiB)
/// csrss's own image mirror — its loader reads import-descriptor DLL names ("csrsrv.dll") from its
/// image .idata, which the executive must read from CSRSS's image, not smss's. 1 MiB at 0xB0_0000
/// (inside the NTDLLBUF page table, 0xA0-0xC0). ACTIVE_IMAGE_MIRROR selects by the current badge.
pub const CSRSS_IMAGE_MIRROR_VA: u64 = 0x0000_0100_10B0_0000;
/// winlogon's per-process executive mirrors (3rd hosted process). Stack mirror sits beside the
/// smss/csrss/SM mirrors in the FILEBUF PT (0x1068/0x1069/0x106A used → 0x106B free). Heap + image
/// mirrors get their OWN page tables (created in spawn_sec_image, past CSRSS_HEAP_MIRROR 0x1200) so
/// they can't collide with smss's/csrss's mirrors. ACTIVE_*_MIRROR selects them for pi==2.
pub const WINLOGON_STACK_MIRROR_VA: u64 = 0x0000_0100_106B_0000; // FILEBUF PT, present
pub const WINLOGON_HEAP_MIRROR_VA: u64 = 0x0000_0100_1220_0000; // own PT (spawn_sec_image creates it)
pub const WINLOGON_IMAGE_MIRROR_VA: u64 = 0x0000_0100_1240_0000; // own PT (spawn_sec_image creates it)
/// winlogon's CSR client-connect regions (mapped into winlogon's OWN VSpace by the NtSecureConnectPort
/// handler, lazily). One 2 MiB PT holds both: the LpcWrite heap VIEW (16 pages / 64 KiB — kernel32
/// RtlCreateHeaps over it as CsrPortHeap; ViewBase in the returned PORT_VIEW) and the CSR shared
/// STATIC server data (4 pages — ConnectionInfo.SharedStaticServerData → an array of per-ServerDll
/// pointers; [BASESRV=1] → a BASE_STATIC_SERVER_DATA whose WindowsDirectory/WindowsSystemDirectory
/// kernel32's BaseDllInitialize dereferences). Free in winlogon (DLLs at 0x8000_0000+, image/ntdll/
/// stack/heap elsewhere). Executive-side fill via a dedicated scratch PT.
pub const WINLOGON_CSR_HEAP_VA: u64 = 0x0000_0100_0400_0000; // 64 KiB LpcWrite view (ViewBase)
pub const WINLOGON_CSR_STATIC_VA: u64 = 0x0000_0100_0401_0000; // 16 KiB shared static server data
pub const WINLOGON_CSR_FILL_SCRATCH: u64 = 0x0000_0100_1320_0000; // exec-side fill alias (own PT)
// --- Authentic SM-loop thread (path B): a REAL 2nd thread in smss's VSpace running SmpApiLoop. ---
// Its per-thread env (stack/IPC/TEB/trampoline) lives at free VAs in smss's cluster PT (0x1040-0x105B;
// smss itself only uses 0x105C stack + 0x105F ipc there, and the LPC rings 0x1040-43 are
// executive-side, so 0x1044-0x104B are free in smss's VSpace).
pub const SM_STACK_BASE: u64 = 0x0000_0100_1044_0000; // 4 frames (16 KiB)
pub const SM_STACK_FRAMES: u64 = 4;
pub const SM_IPCBUF_VA: u64 = 0x0000_0100_1048_0000;
pub const SM_TEB_VA: u64 = 0x0000_0100_1049_0000; // 2 pages (TEB + ACS/StaticUnicode)
pub const SM_TRAMP_VA: u64 = 0x0000_0100_104B_0000;
/// The executive's mirror of the SM-loop thread's stack (same frames), so the rendezvous can write
/// its syscall out-params (the received PORT_MESSAGE, PROCESS_BASIC_INFORMATION, the accepted port
/// handle) onto its stack. In the FILEBUF PT (0x60-0x80), beside the smss/csrss stack mirrors.
pub const SM_STACK_MIRROR_VA: u64 = 0x0000_0100_106A_0000;
/// Executive scratch (3 pages) to populate the SM-loop thread's TEB/trampoline frames before they
/// are copy_cap'd into smss. In the FILEBUF PT, clear of the smss (0x74) / csrss (0x78) env scratch.
pub const SM_ENV_SCRATCH_VA: u64 = 0x0000_0100_1070_0000;
/// Isolated executive scratch (its own PT) for demand-filling the SM-loop thread's code pages
/// (SmpApiLoop/SmpHandleConnectionRequest in smss's .text + ntdll stubs) during the rendezvous.
pub const SM_FILL_SCRATCH_BASE: u64 = 0x0000_0100_1300_0000;
// --- Authentic CSR accept: the REAL CsrApiRequestThread runs in CSRSS's VSpace (a 2nd csrss thread),
// mirroring the SM-loop thread. The csrss-VSpace VAs (stack/ipc/teb/tramp) REUSE the SM numeric
// values — safe because they land in csrss's OWN pml4 (isolated from smss's, where the SM thread
// uses the same VAs); both fall in the STACK_BASE 2 MiB PT (0x1040_0000) that csrss's spawn already
// created. Only the EXECUTIVE-side aliases (mirror/env/fill, in CAP_INIT_THREAD_VSPACE) must be
// DISTINCT from the SM ones.
pub const CSR_STACK_BASE: u64 = SM_STACK_BASE; // csrss VSpace (4 frames)
pub const CSR_IPCBUF_VA: u64 = SM_IPCBUF_VA; // csrss VSpace
pub const CSR_TEB_VA: u64 = SM_TEB_VA; // csrss VSpace (2 pages)
pub const CSR_TRAMP_VA: u64 = SM_TRAMP_VA; // csrss VSpace
/// Executive mirror of the CSR thread's stack (same frames) for syscall out-params. FILEBUF PT,
/// beside SM (0x106A) / winlogon (0x106B) stack mirrors.
pub const CSR_STACK_MIRROR_VA: u64 = 0x0000_0100_106C_0000;
/// Executive scratch (3 pages) to populate the CSR thread's TEB/trampoline before copy_cap into
/// csrss. FILEBUF PT, clear of the SM (0x1070) / smss (0x1074) / csrss (0x1078) env scratch.
pub const CSR_ENV_SCRATCH_VA: u64 = 0x0000_0100_1071_0000;
/// Isolated executive scratch (its own PT) for demand-filling the CSR thread's code pages
/// (CsrApiRequestThread/CsrApiHandleConnectionRequest in csrsrv + ntdll/csrss) during the rendezvous.
pub const CSR_FILL_SCRATCH_BASE: u64 = 0x0000_0100_1310_0000;
/// ntdll's NtAllocateVirtualMemory system-service number (from its export stub).
pub const SSN_NT_ALLOCATE_VM: u64 = 0x12;
/// ntdll's NtQuerySystemInformation SSN (RtlCreateHeap needs SystemBasicInformation).
pub const SSN_NT_QUERY_SYSTEM_INFO: u64 = 0xb5;
/// ntdll's NtQueryVirtualMemory SSN (LdrpInitialize queries the region at [TEB+0x10] early).
pub const SSN_NT_QUERY_VIRTUAL_MEM: u64 = 186;
/// ntdll's NtQuerySystemTime SSN (csrss init reads the clock during CsrServerInitialization).
pub const SSN_NT_QUERY_SYSTEM_TIME_SVC: u64 = 182;
/// ntdll's NtQueryPerformanceCounter SSN (csrss init seeds timing / RNG from the perf counter).
pub const SSN_NT_QUERY_PERF_COUNTER: u64 = 173;
/// ntdll's NtQueryInformationProcess SSN (LdrpInitialize queries ProcessCookie et al.).
pub const SSN_NT_QUERY_INFO_PROCESS: u64 = 161;
/// ntdll's NtOpenKey SSN (LdrpInitialize opens IFEO/options; we have no registry → not-found).
pub const SSN_NT_OPEN_KEY: u64 = 125;
/// ntdll's NtQueryValueKey SSN (registry value lookups; not-found → LdrpInitialize uses defaults).
pub const SSN_NT_QUERY_VALUE_KEY: u64 = 185;
/// ntdll's NtEnumerateValueKey SSN (SmpInit enumerates Environment/DOS-Devices values by index).
pub const SSN_NT_ENUM_VALUE_KEY: u64 = 77;
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
/// NtInitializeRegistry — smss tells the Config Manager it's safe to enable registry writes
/// (sminit.c:2429, CM_BOOT_FLAG_SMSS). We don't model CM write-enable → no-op success.
pub const SSN_NT_INITIALIZE_REGISTRY: u64 = 96;
/// NtSetValueKey — smss writes registry values after CM write-enable. Our regf hive is read-only
/// and we don't persist, so → no-op success (the write "succeeds" but isn't recorded).
pub const SSN_NT_SET_VALUE_KEY: u64 = 256;
/// NtSetSystemInformation — smss sets system-wide config in SmpInit (priority separation, etc.).
/// We don't model system-info classes → no-op success so bring-up proceeds.
pub const SSN_NT_SET_SYSTEM_INFORMATION: u64 = 249;
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
pub const SSN_NT_CREATE_SEMAPHORE: u64 = 53;
// NT LPC connection-rendezvous SSNs (ReactOS ntdll — the one smss/csrss run).
pub const SSN_NT_ACCEPT_CONNECT_PORT: u64 = 0;
pub const SSN_NT_COMPLETE_CONNECT_PORT: u64 = 31;
pub const SSN_NT_CONNECT_PORT: u64 = 33;
pub const SSN_NT_SECURE_CONNECT_PORT: u64 = 218;
/// NtRequestWaitReplyPort — the LPC message data plane (CSR API calls: kernel32's CsrClientCallServer
/// → \Windows\ApiPort). Serviced by the executive's DIRECT cross-badge message plane.
pub const SSN_NT_REQUEST_WAIT_REPLY_PORT: u64 = 208;
pub const SSN_NT_CREATE_SECTION: u64 = 52;
/// NtOpenSection — CsrServerInitialization opens named sections (NLS, \KnownDlls\*, CSR shared mem).
pub const SSN_NT_OPEN_SECTION: u64 = 131;
/// NtCreateProcess — smss spawns csrss from the SEC_IMAGE section (SmpExecuteImage). Not serviced
/// yet (the real spawn is the next step) — a diagnostic verifies the file→section→process chain.
pub const SSN_NT_CREATE_PROCESS: u64 = 49;
/// NtQuerySection — RtlCreateUserProcess reads SectionImageInformation (entry/stack/subsystem)
/// from the csrss image section between NtCreateProcess and creating the initial thread.
pub const SSN_NT_QUERY_SECTION: u64 = 175;
/// NtCreateDirectoryObject — SmpInit creates object-namespace directories (\Windows, \KnownDlls,
/// \??/DosDevices, …). Out handle in RCX; faked until the object manager lands.
pub const SSN_NT_CREATE_DIRECTORY_OBJECT: u64 = 36;
/// NtClose — no handle table modelled, so closing a (fake) handle is a no-op success.
pub const SSN_NT_CLOSE: u64 = 27;
/// NtDeleteValueKey — smss deletes SAFEBOOT_OPTION from \Session Manager\Environment (sminit.c:2321).
/// Registry writes aren't modelled (the regf hive is read-only) → best-effort no-op success.
pub const SSN_NT_DELETE_VALUE_KEY: u64 = 68;
/// Security-token SSNs SmpInit hits. NtOpenThreadToken → STATUS_NO_TOKEN (no impersonation token,
/// the normal case → caller falls back to the process token). NtOpenProcessToken → fake token
/// handle (out in R8). A real token/SID model is a later milestone.
pub const SSN_NT_OPEN_THREAD_TOKEN: u64 = 135;
pub const SSN_NT_OPEN_PROCESS_TOKEN: u64 = 129;
/// NtQueryInformationToken — csrss's CsrServerInitialization queries its process token (identity,
/// session, statistics) after opening it. Class in RDX; TOKEN_* struct copied out to R8.
pub const SSN_NT_QUERY_INFO_TOKEN: u64 = 163;
/// NtAdjustPrivilegesToken — smss enables privileges it needs (SeTcb/SeLoadDriver/…). We don't
/// model token privileges → no-op success (the enable "succeeds").
pub const SSN_NT_ADJUST_PRIV_TOKEN: u64 = 12;
/// Process/thread lifecycle SSNs (ReactOS numbering = sysfuncs.lst line − 1, cross-checked against
/// NtClose=27/NtCreateProcess=49/NtCreateThread=55). NOT issued during the current boot (no hosted
/// process self-terminates) — registering them is additive; the teardown POLICY is proven by the
/// post-loop self-test. NtOpenProcess (128) stays a handler METHOD until a live caller appears.
pub const SSN_NT_TERMINATE_PROCESS: u64 = 266;
pub const SSN_NT_TERMINATE_THREAD: u64 = 267;
/// A distinctive fake handle we hand back for objects we don't yet model (ports, events, …), so it
/// is recognisable in traces and never collides with a real (small) handle index.
pub const FAKE_HANDLE: u64 = 0x5A5A_0001;
/// ntdll's NtOpenDirectoryObject SSN (SmpInit opens \?? for DosDevices; served by the object ns).
pub const SSN_NT_OPEN_DIRECTORY_OBJECT: u64 = 119;
/// NtCreateSymbolicLinkObject SSN (SmpInit creates the drive-letter links in \??). SSN = sysfuncs
/// line 55 − 1.
pub const SSN_NT_CREATE_SYMBOLIC_LINK_OBJECT: u64 = 54;
/// NtMakeTemporaryObject SSN (SmpInit clears OBJ_PERMANENT on a colliding link). sysfuncs 111 − 1.
pub const SSN_NT_MAKE_TEMPORARY_OBJECT: u64 = 110;
/// NtOpenSymbolicLinkObject SSN (SmpInit opens a link after DosDevices). sysfuncs 134 − 1.
pub const SSN_NT_OPEN_SYMBOLIC_LINK_OBJECT: u64 = 133;
/// NtDisplayString SSN (smss prints a boot/status string). sysfuncs 71 − 1. Routed to serial.
pub const SSN_NT_DISPLAY_STRING: u64 = 70;
/// ntdll's NtOpenFile SSN (LdrpInitialize opens a DLL/manifest file; no FS → not-found).
pub const SSN_NT_OPEN_FILE: u64 = 122;
/// ntdll's NtQueryAttributesFile SSN (LdrpInitialize probes a file's existence; no FS → not-found).
pub const SSN_NT_QUERY_ATTRIBUTES_FILE: u64 = 145;
/// NtQueryVolumeInformationFile — CsrServerInitialization queries volume info for a file handle.
pub const SSN_NT_QUERY_VOLUME_INFO_FILE: u64 = 187;
pub const PE_SCRATCH_VADDR: u64 = 0x0000_0100_1052_0000;
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
pub const HPET_VADDR: u64 = 0x0000_0100_105E_0000;
/// Where the executive maps a real PCI device's BAR (P1 capstone — the e1000e NIC).
pub const NIC_VADDR: u64 = 0x0000_0100_105F_0000;
/// P2: the AHCI controller ABAR (BAR5) MMIO, and a DMA frame for its command structures +
/// the sector data buffer (both just past the NIC's 4-page BAR, before IPCBUF).
pub const AHCI_VADDR: u64 = 0x0000_0100_105F_4000;
pub const AHCI_DMA_VADDR: u64 = 0x0000_0100_105F_5000;
/// Shared word between the executive (broker) and the isolated storage host: the AHCI's
/// device address (identity paddr, or a VT-d IOVA once confined) in @0; verdict (u32) @8,
/// INITRD cluster @0x10, size @0x14 out.
pub const STORAGE_SHARED_VADDR: u64 = 0x0000_0100_105F_6000;
/// A multi-frame file buffer shared between the executive and the storage host: the host reads
/// a real PE (ReactOS SMSS.EXE) off the disk into it, and the executive parses it there. 32
/// frames (128 KiB) at a fresh 2 MiB region, contiguous in both VSpaces (one shared PT).
pub const FILEBUF_VADDR: u64 = 0x0000_0100_1060_0000; // its own PT, just past the cluster region
pub const FILEBUF_FRAMES: u64 = 64; // 256 KiB — holds smss + csrss + csrsrv, still one 2 MiB PT
/// csrss.exe (~7 KiB) is staged into the FILEBUF tail, past smss.exe (~99 KiB) but well within the
/// buffer — no separate buffer needed. The storage host reads it here and writes its size
/// to STORAGE_SHARED+0x3c; the executive parses the PE from FILEBUF_VADDR+CSRSS_FILEBUF_OFFSET.
pub const CSRSS_FILEBUF_OFFSET: u64 = 0x1A000; // 104 KiB in — clear of a ~99 KiB smss
/// csrsrv.dll (~65 KiB) — csrss.exe's static-import Server DLL — is staged further into the FILEBUF
/// (past smss+csrss), size reported at STORAGE_SHARED+0x40. The loader needs it or DLL_NOT_FOUND.
pub const CSRSRV_FILEBUF_OFFSET: u64 = 0x20000; // 128 KiB in — clear of csrss (ends ~111 KiB)
/// basesrv.dll (~50 KiB) + winsrv.dll (~400 KiB) — csrss's dynamically-loaded ServerDlls — don't fit
/// in FILEBUF, so they get their own 512 KiB buffer (its own 2 MiB PT), dual-mapped host<->exec like
/// NTDLLBUF. basesrv at offset 0, winsrv at +0x10000; sizes reported at STORAGE_SHARED +0x44 / +0x48.
pub const SRVBUF_VADDR: u64 = 0x0000_0100_1400_0000;
pub const SRVBUF_FRAMES: u64 = 128; // 512 KiB
pub const BASESRV_SRVBUF_OFFSET: u64 = 0x0;
pub const WINSRV_SRVBUF_OFFSET: u64 = 0x10000; // 64 KiB in — clear of basesrv (~50 KiB)
/// winlogon.exe (~225 KiB, PE32+) — smss's SmpExecuteInitialCommand initial command. The FILEBUF
/// tail is full (smss+csrss+csrsrv), so it gets its OWN 256 KiB buffer (its own 2 MiB PT past
/// SRVBUF), dual-mapped host<->exec like SRVBUF. Size reported at STORAGE_SHARED+0x94; the executive
/// parses it PE32+ and spawns it as the 3rd hosted process when smss's RtlCreateUserProcess creates it.
pub const WINLOGONBUF_VADDR: u64 = 0x0000_0100_1420_0000; // own PT, past SRVBUF (0x1400)
pub const WINLOGONBUF_FRAMES: u64 = 64; // 256 KiB — holds the 229888 B winlogon.exe
/// The Win32 client stack (kernel32 ~2.66 MiB + user32 ~1.12 MiB + gdi32 ~326 KiB) that winsrv.dll
/// statically imports. These are too large for the SRVBUF, so they get their own fresh 6 MiB region
/// (3 PTs), dual-mapped host<->exec like SRVBUF. Sizes reported at STORAGE_SHARED +0x4c/+0x50/+0x54.
pub const WIN32BUF_VADDR: u64 = 0x0000_0100_0500_0000; // fresh 8 MiB region (4 PTs), past SRVBUF
pub const WIN32BUF_FRAMES: u64 = 2048; // 8 MiB — kernel32+user32+gdi32 + Win32 deps
pub const KERNEL32_WIN32BUF_OFFSET: u64 = 0x0;       // kernel32 ~2.66 MiB
pub const USER32_WIN32BUF_OFFSET: u64 = 0x2C0000;    // user32 ~1.12 MiB (clear of kernel32)
pub const GDI32_WIN32BUF_OFFSET: u64 = 0x400000;     // gdi32 ~326 KiB (clear of user32)
// winsrv's transitive import closure (7 DLLs, ~1.77 MiB) — sizes at STORAGE_SHARED +0x58..+0x70.
pub const RPCRT4_WIN32BUF_OFFSET: u64 = 0x460000;         // rpcrt4 ~617 KiB
pub const MSVCRT_WIN32BUF_OFFSET: u64 = 0x500000;         // msvcrt ~581 KiB
pub const ADVAPI32_WIN32BUF_OFFSET: u64 = 0x5A0000;       // advapi32 ~455 KiB
pub const WS2_32_WIN32BUF_OFFSET: u64 = 0x620000;         // ws2_32 ~93 KiB
pub const KERNEL32_VISTA_WIN32BUF_OFFSET: u64 = 0x640000; // kernel32_vista ~32 KiB
pub const ADVAPI32_VISTA_WIN32BUF_OFFSET: u64 = 0x650000; // advapi32_vista ~23 KiB
pub const WS2HELP_WIN32BUF_OFFSET: u64 = 0x660000;        // ws2help ~14 KiB
pub const NTDLL_VISTA_WIN32BUF_OFFSET: u64 = 0x670000;    // ntdll_vista ~56 KiB (ends 0x67E000)
// winlogon.exe's two extra static imports (the rest of its Win32 stack is shared with csrss above).
pub const USERENV_WIN32BUF_OFFSET: u64 = 0x680000;        // userenv ~166 KiB (file 0x297C0)
pub const MPR_WIN32BUF_OFFSET: u64 = 0x6C0000;            // mpr ~107 KiB (ends ~0x6DAC00)
/// Raw win32k.sys staging buffer (2,208,192 B). Its own 2 MiB-aligned window past WIN32BUF, with
/// 2 page tables (544 frames = 0x220000 spans two 2 MiB PTs). The storage host reads win32k.sys
/// off disk into here; the executive parses+loads it into the win32k-service component.
pub const WIN32KBUF_VADDR: u64 = 0x0000_0100_0600_0000;
pub const WIN32KBUF_FRAMES: u64 = 544; // 0x220 — matches win32k.sys size_of_image
/// Raw dxg.sys / dxgthk.sys staging buffers (DirectX kernel driver + thunk table). Own 2 MiB PTs
/// past WIN32KBUF (0x0600..0x0622) and clear of WIN32K_CODE_VA (0x0680, mapped in the executive too).
/// dxg.sys=33,728 B (16 frames), dxgthk.sys=11,200 B (8 frames); one PT each.
pub const DXGBUF_VADDR: u64 = 0x0000_0100_0630_0000;
pub const DXGBUF_FRAMES: u64 = 16;
pub const DXGTHKBUF_VADDR: u64 = 0x0000_0100_0650_0000;
pub const DXGTHKBUF_FRAMES: u64 = 8;
/// Raw ftfd.dll staging buffer (FreeType font driver, ~977 KiB). Own 2 MiB PT window [0x0660..0x0680)
/// (245 frames span 0x0670_0000..0x067f_5000, clear of WIN32K_CODE_VA at 0x0680). ftfd size=1,000,960 B.
pub const FTFDBUF_VADDR: u64 = 0x0000_0100_0670_0000;
pub const FTFDBUF_FRAMES: u64 = 245;
/// Raw framebuf.dll staging buffer (display driver, 12 KiB / size_of_image 0x8000). Own PT window at
/// 0x06C0 — free between the win32k image (0x0680..0x06A2) and the aux window (0x0700).
pub const FRAMEBUFBUF_VADDR: u64 = 0x0000_0100_06C0_0000;
pub const FRAMEBUFBUF_FRAMES: u64 = 8;
/// Fault-endpoint badge for the second hosted process (csrss). smss's fault cap is an unbadged
/// copy (badge 0); csrss's is minted at this badge so the single service loop can tell them apart.
pub const CSRSS_BADGE: u64 = 2;
/// csrss's demand-fault scratch region in the executive's VSpace — a non-overlapping window inside
/// smss's already-mapped 8-PT scratch range (smss uses [0x1_1100_0000 .. +256 pages]; PT k=4 backs
/// this), so no extra page tables are needed.
pub const CSRSS_SCRATCH_BASE: u64 = 0x0000_0100_1180_0000;
/// Fault-endpoint badge for the THIRD hosted process (winlogon). Distinct from smss (0) + csrss (2).
pub const WINLOGON_BADGE: u64 = 4;
/// winlogon's demand-fault scratch — PT 6 of smss's already-mapped 8-PT scratch range
/// (0x1100..0x1200); smss uses PT 0 (0x1100), csrss PT 4 (0x1180). PT 6 (0x11C0) is clear of both
/// (csrss realistically uses < 0x40 PTs of headroom), so no extra page tables are needed.
pub const WINLOGON_SCRATCH_BASE: u64 = 0x0000_0100_11C0_0000;
/// A larger buffer for the ~975 KiB ReactOS ntdll.dll (its own 2 MiB PT), shared host<->exec.
pub const NTDLLBUF_VADDR: u64 = 0x0000_0100_10A0_0000;
pub const NTDLLBUF_FRAMES: u64 = 240; // 240*4K = 983040 > 975360
/// NLS code-page tables (c_1252.nls/c_437.nls/l_intl.nls), shared host<->exec. They live in the
/// NTDLLBUF page table's 2 MiB region (0xA0_0000-0xC0_0000, past NTDLLBUF's 0xA0-0xB0), so they
/// need no extra PT. spawn_sec_image later shares these frames into smss + points the PEB NLS
/// fields at them so RtlInitNlsTables/RtlUnicodeToMultiByteN work.
pub const NLS_ANSI_VADDR: u64 = 0x0000_0100_10B0_0000; // c_1252.nls (66082 B = 17 pages)
pub const NLS_ANSI_FRAMES: u64 = 20;
pub const NLS_OEM_VADDR: u64 = 0x0000_0100_10B2_0000; // c_437.nls (66594 B = 17 pages)
pub const NLS_OEM_FRAMES: u64 = 20;
pub const NLS_CASE_VADDR: u64 = 0x0000_0100_10B4_0000; // l_intl.nls (4870 B = 2 pages)
pub const NLS_CASE_FRAMES: u64 = 4;
/// c_20127.nls (US-ASCII, CP20127; 66082 B = 17 pages) — csrss's Win32 client stack maps the named
/// section \Nls\NlsSectionCP20127 during a DllMain. Shares the NTDLLBUF 0xA0-0xC0 page table so it
/// needs no extra PT. Placed at 0xB9_0000 — PAST HIVEBUF (0xB5_0000 + 64 frames = 0xB9_0000); the
/// task's suggested 0xB6_0000 collides with the SYSTEM-hive buffer. Runs to 0xBD_0000, clear of
/// the 0xC0_0000 region end.
pub const NLS_20127_VADDR: u64 = 0x0000_0100_10B9_0000;
pub const NLS_20127_FRAMES: u64 = 20;
/// The real ReactOS SYSTEM registry hive (::ROSSYS.HIV, ~204 KiB regf), read off the disk by the
/// isolated storage host into these shared frames; the executive parses it with nt-hive-regf so
/// the NT registry serves smss's real config. Shares the 0xA0-0xC0 page table (past the NLS bufs).
pub const HIVEBUF_VADDR: u64 = 0x0000_0100_10B5_0000;
pub const HIVEBUF_FRAMES: u64 = 64; // 256 KiB
/// The same NLS frames shared into smss (own PT at the 0xE0_0000 2 MiB region). The PEB's
/// AnsiCodePageData(@0x58)/OemCodePageData(@0x60)/UnicodeCaseTableData(@0x68) point here.
pub const NLS_SMSS_ANSI_VA: u64 = 0x0000_0100_00E0_0000;
pub const NLS_SMSS_OEM_VA: u64 = 0x0000_0100_00E2_0000;
pub const NLS_SMSS_CASE_VA: u64 = 0x0000_0100_00E4_0000;
/// The IOVA we grant the AHCI for its DMA frame. Once VT-d confinement is on, the HBA is
/// programmed with this address; VT-d maps it to the DMA frame and NOTHING else.
pub const AHCI_IOVA: u64 = 0x1000;
pub const IPCBUF_VADDR: u64 = 0x0000_0100_105F_B000;
/// A normal RAM frame the executive owns, used as a DMA buffer (TX descriptor ring +
/// packet buffer) for the e1000e. VT-d translation is off (identity) so the NIC DMAs
/// straight to this frame's physical address. Kept just past IPCBUF so it stays inside
/// the same 2 MiB page table as every other runtime mapping (0x40_0000..0x5F_FFFF) — a
/// vaddr in the next 2 MiB region would need a PT this vspace doesn't have.
pub const DMA_VADDR: u64 = 0x0000_0100_105F_C000;

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
pub const RESLIST_VADDR: u64 = 0x0000_0100_105F_D000;
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
/// The executive stack-mirror base for the process whose fault/syscall is currently being serviced.
/// The 2-process service loop sets this at the top of each iteration (smss vs csrss) so the shared
/// smss_stack_read/write helpers read+write the RIGHT process's stack.
static ACTIVE_STACK_MIRROR: AtomicU64 = AtomicU64::new(SMSS_STACK_MIRROR_VA);
/// Executive image-mirror base for the process currently being serviced (smss vs csrss), so the
/// shared copyin path reads import-descriptor DLL names etc. from the RIGHT process's image.
static ACTIVE_IMAGE_MIRROR: AtomicU64 = AtomicU64::new(IMAGE_MIRROR_VA);
/// Executive heap-mirror base for the process currently being serviced, so the copyin path reads
/// heap-resident syscall args (the loader's built-up DLL search paths) from the RIGHT process's heap.
static ACTIVE_HEAP_MIRROR: AtomicU64 = AtomicU64::new(SMSS_HEAP_MIRROR_VA);

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
/// Where the executive backs NtAllocateVirtualMemory for the user thread — inside the relocated
/// cluster PT (WORK_CLUSTER_BASE), which spawn_user_thread builds; the 2 MiB alloc window
/// [USER_ALLOC_BASE, +0x20_0000) stays within it, so mapping needs no new page table.
pub const USER_ALLOC_BASE: u64 = 0x0000_0100_1050_0000;

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

/// Fix (B) — per-caller MCS reply objects so the executive's dispatch composes with nested service.
/// The kernel has a SINGLE per-TCB `reply_to` stash; `finish_call` (endpoint.rs) UNCONDITIONALLY
/// overwrites it with the latest caller. When a win32k SSN handler FAULTS while the executive is
/// mid-servicing a csrss syscall, the fault Call clobbers `reply_to` from csrss -> win32k and
/// csrss's pending reply is orphaned. Binding each channel's caller to its OWN `Cap::Reply`
/// (recv-with-r12 + Send-on-reply-cap / decode_reply) resumes exactly that caller regardless of
/// `reply_to`. REPLY_MAIN backs the main service loop (csrss/smss); REPLY_W32 backs win32k's
/// demand-page faults during a dispatch. cptr 0 = "not yet retyped" (legacy reply_to fallback).
static REPLY_MAIN_SLOT: AtomicU64 = AtomicU64::new(0);
static REPLY_W32_SLOT: AtomicU64 = AtomicU64::new(0);
/// Path B (authentic SM accept): the SM-loop thread's dedicated fault endpoint (the executive recvs
/// its real NtReplyWaitReceivePort/NtAcceptConnectPort/NtCompleteConnectPort faults here during the
/// nested `sm_rendezvous`; no standing receiver otherwise, so the thread parks) + its own MCS reply
/// object (REPLY_SMLOOP), mirroring REPLY_W32. 0 = not yet retyped.
static SM_FAULT_EP: AtomicU64 = AtomicU64::new(0);
static REPLY_SMLOOP_SLOT: AtomicU64 = AtomicU64::new(0);
/// The SM-loop thread's TCB (0 until smss's first NtCreateThread spawns it; one real SmpApiLoop
/// thread is enough — subsequent NtCreateThread stays a fake handle).
static SM_LOOP_TCB: AtomicU64 = AtomicU64::new(0);
/// Set once the SM_FILL_SCRATCH_BASE page table is created (lazily, in the first rendezvous).
static SM_FILL_PT_DONE: AtomicU64 = AtomicU64::new(0);
/// Authentic CSR accept (mirrors the SM triad): the REAL CsrApiRequestThread's dedicated fault EP
/// (the executive recvs its NtSetEvent/NtReplyWaitReceivePort/NtAcceptConnectPort/NtCompleteConnectPort
/// faults here during `csr_rendezvous`; no standing receiver otherwise → the thread parks) + its own
/// MCS reply object (REPLY_CSRLOOP). 0 = not yet retyped.
static CSR_FAULT_EP: AtomicU64 = AtomicU64::new(0);
static REPLY_CSRLOOP_SLOT: AtomicU64 = AtomicU64::new(0);
/// The CSR API thread's TCB (0 until csrss's first NtCreateThread spawns it; one real thread suffices
/// for one connection accept — CsrpCheckRequestThreads does NOT fire on the connection path).
static CSR_LOOP_TCB: AtomicU64 = AtomicU64::new(0);
/// Set once the CSR_FILL_SCRATCH_BASE page table is created (lazily, in the first rendezvous).
static CSR_FILL_PT_DONE: AtomicU64 = AtomicU64::new(0);
/// Set once the CSR API thread has been resumed (lazily, at the first `csr_rendezvous`).
static CSR_RESUMED: AtomicU64 = AtomicU64::new(0);
/// Count of csrss's NtCreatePort calls (its port names are unreadable csrsrv .data globals, so they
/// are assigned canonical names by creation order: 0 = \Windows\ApiPort, 1 = \Windows\SbApiPort).
static CSR_CREATEPORT_N: AtomicU64 = AtomicU64::new(0);
/// The self-connect ClientId (FLAGGED simplification, like SM's PID_SMSS): written to the faked
/// CsrApiRequestThread's *ClientId out-param (so csrss's CsrAddStaticServerThread registers a
/// CSR_THREAD with this CID) AND marshaled into the connection-request PORT_MESSAGE, so csrss's real
/// CsrLocateThreadByClientId finds it → CsrProcess=CsrRootProcess → AllowConnection=TRUE → accept.
const CSR_STATIC_CID_PROC: u64 = 0x0000_0000_0000_0244; // csrss's CSR pid (arbitrary, must be consistent)
const CSR_STATIC_CID_THREAD: u64 = 0x0000_0000_0000_0248;

/// Per-hosted-process demand-fill bookkeeping (page VA per fault index), one row per process
/// (0 = smss, 1 = csrss, 2 = winlogon). Kept off the 16 KiB rootserver stack — a [[u64;256];3]
/// local (6 KiB) plus service_sec_image's other arrays would risk the guard page. Zeroed at
/// service_sec_image entry; only that single loop touches it.
static mut PFILLED: [[u64; 256]; 3] = [[0u64; 256]; 3];

fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}

// --- Shared executable-page cache (generic DLL loader) --------------------------------------------
// A DLL's RX (text) page is identical across processes — each DLL is loaded at a fixed system-wide
// base and (for the ServerDlls) pre-relocated, so no per-process relocation touches its code. So we
// fill each such page ONCE into a frame and map THAT frame read-only into every process that faults
// it — real Windows image sharing (fewer frames, one fill). Keyed by page VA (base+rva). Frames
// persist for the run (no process teardown yet). Accessed via raw pointers to avoid the
// static_mut_refs lint; single-threaded executive, so no races.
const DLL_CACHE_CAP: usize = 4096;
static mut DLL_CACHE_VA: [u64; DLL_CACHE_CAP] = [0; DLL_CACHE_CAP];
static mut DLL_CACHE_FR: [u64; DLL_CACHE_CAP] = [0; DLL_CACHE_CAP];
static mut DLL_CACHE_N: usize = 0;
static DLL_SHARED_HITS: AtomicU64 = AtomicU64::new(0);
/// The shared frame cap for page VA `va`, or 0 if not yet cached.
unsafe fn dll_cache_get(va: u64) -> u64 {
    let n = core::ptr::read(core::ptr::addr_of!(DLL_CACHE_N));
    let vas = core::ptr::addr_of!(DLL_CACHE_VA) as *const u64;
    let frs = core::ptr::addr_of!(DLL_CACHE_FR) as *const u64;
    for i in 0..n {
        if core::ptr::read(vas.add(i)) == va {
            return core::ptr::read(frs.add(i));
        }
    }
    0
}
/// Record the shared frame `fr` for page VA `va` (once, on first fill).
unsafe fn dll_cache_put(va: u64, fr: u64) {
    let n = core::ptr::read(core::ptr::addr_of!(DLL_CACHE_N));
    if n < DLL_CACHE_CAP {
        let vas = core::ptr::addr_of_mut!(DLL_CACHE_VA) as *mut u64;
        let frs = core::ptr::addr_of_mut!(DLL_CACHE_FR) as *mut u64;
        core::ptr::write(vas.add(n), va);
        core::ptr::write(frs.add(n), fr);
        core::ptr::write(core::ptr::addr_of_mut!(DLL_CACHE_N), n + 1);
    }
}

// --- csrss client-page frame tracking (win32k cross-AS client-memory sharing) --------------------
// win32k runs in its own component VSpace, but its NtUser/NtGdi handlers dereference the CALLING
// process's (the GUI client's) user pointers DIRECTLY — the authentic Windows model where win32k
// shares the caller's user address space. To emulate that we map the CURRENT dispatch client's OWN
// frame for a faulting page into win32k at the SAME VA (identity), so win32k reads/writes that
// caller's live memory (no per-SSN marshaling). This table is PER-CLIENT (pi-keyed): csrss (pi 1)
// and winlogon (pi 2) load an OVERLAPPING set of DLLs/stacks at IDENTICAL VAs but into DISTINCT
// frames, so the SAME VA resolves to a DIFFERENT frame per client. The win32k `attach` (see
// `w32_client_attach`) re-points win32k's client window to the current dispatch's client, mapping
// THIS pi's frame at each colliding VA (the KeStackAttachProcess model). It records the frame cap
// the fault-fill path allocated for each PER-PROCESS client page ((pi,page) -> frame cptr); the
// shared-DLL-text cache (`dll_cache`) covers RX pages (byte-identical across clients). The
// executive's scratch alias already shares these frames, so the client's runtime writes are visible.
const CSRSS_FRAME_CAP: usize = 8192;
static mut CSRSS_FRAME_PI: [u8; CSRSS_FRAME_CAP] = [0; CSRSS_FRAME_CAP];
static mut CSRSS_FRAME_VA: [u64; CSRSS_FRAME_CAP] = [0; CSRSS_FRAME_CAP];
static mut CSRSS_FRAME_FR: [u64; CSRSS_FRAME_CAP] = [0; CSRSS_FRAME_CAP];
static mut CSRSS_FRAME_N: usize = 0;
/// Record GUI client `pi`'s frame cap `fr` for page VA `page` (once per (pi,page)).
unsafe fn csrss_frame_put(pi: u64, page: u64, fr: u64) {
    let n = core::ptr::read(core::ptr::addr_of!(CSRSS_FRAME_N));
    let vas = core::ptr::addr_of!(CSRSS_FRAME_VA) as *const u64;
    let pis = core::ptr::addr_of!(CSRSS_FRAME_PI) as *const u8;
    for i in 0..n {
        if core::ptr::read(vas.add(i)) == page && core::ptr::read(pis.add(i)) as u64 == pi {
            return;
        }
    }
    if n < CSRSS_FRAME_CAP {
        core::ptr::write((core::ptr::addr_of_mut!(CSRSS_FRAME_PI) as *mut u8).add(n), pi as u8);
        core::ptr::write((core::ptr::addr_of_mut!(CSRSS_FRAME_VA) as *mut u64).add(n), page);
        core::ptr::write((core::ptr::addr_of_mut!(CSRSS_FRAME_FR) as *mut u64).add(n), fr);
        core::ptr::write(core::ptr::addr_of_mut!(CSRSS_FRAME_N), n + 1);
    }
}
/// GUI client `pi`'s frame cap for page VA `page`, or 0 if not backed by a recorded per-process
/// frame (falls back to the shared-DLL-text cache, which backs every client's RX pages identically).
unsafe fn csrss_frame_get(pi: u64, page: u64) -> u64 {
    let n = core::ptr::read(core::ptr::addr_of!(CSRSS_FRAME_N));
    let vas = core::ptr::addr_of!(CSRSS_FRAME_VA) as *const u64;
    let frs = core::ptr::addr_of!(CSRSS_FRAME_FR) as *const u64;
    let pis = core::ptr::addr_of!(CSRSS_FRAME_PI) as *const u8;
    for i in 0..n {
        if core::ptr::read(vas.add(i)) == page && core::ptr::read(pis.add(i)) as u64 == pi {
            return core::ptr::read(frs.add(i));
        }
    }
    dll_cache_get(page)
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
/// Mint a copy of `src` carrying `badge`. For an endpoint cap, the badge is delivered to the
/// receiver on every message/fault sent through it — the 2-process service loop mints each hosted
/// thread's fault cap with a distinct badge so it can tell whose fault this is.
unsafe fn mint_badged(src: u64, badge: u64) -> u64 {
    let d = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, d, src, badge);
    d
}

// --- SYS_CALL variants that RETURN the invocation error label (0 = success) ---
// The SYS_SEND helpers above are fire-and-forget: a failed retype/copy/map is invisible, so a
// resource exhaustion (or a bad precondition) silently leaves a page unmapped/zero. These mirror
// the same register layout via seL4_Call and hand back the reply's error label so callers can
// detect and react. The reply's message-info comes back in rsi; its label is `reply >> 12`.
unsafe fn untyped_retype_r(untyped: u64, obj: u64, bits: u32, num: u32, dest: u64) -> u64 {
    let size_num = ((bits as u64) << 32) | (num as u64);
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") untyped => _,
        inout("rsi") LBL_UNTYPED_RETYPE << 12 => reply,
        inout("r10") obj => _,
        inout("r8") size_num => _,
        inout("r9") dest => _,
        lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply >> 12
}
unsafe fn copy_cap_r(src: u64) -> (u64, u64) {
    let d = alloc_slot();
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") CAP_INIT_THREAD_CNODE => _,
        inout("rsi") LBL_CNODE_COPY << 12 => reply,
        inout("r10") d => _,
        inout("r8") src => _,
        inout("r9") 0u64 => _,
        lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (d, reply >> 12)
}
unsafe fn page_map_r(frame: u64, vaddr: u64, rights: u64, vspace: u64) -> u64 {
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") frame => _,
        inout("rsi") LBL_X86_PAGE_MAP << 12 => reply,
        inout("r10") vaddr => _,
        inout("r8") rights => _,
        inout("r9") vspace => _,
        lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply >> 12
}
/// Allocate a fresh 4 KiB frame, returning (slot, retype-error-label).
unsafe fn alloc_frame_r() -> (u64, u64) {
    let s = alloc_slot();
    let e = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, s);
    (s, e)
}
unsafe fn make_object(obj: u64) -> u64 {
    let s = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, obj, 0, 1, s);
    s
}
// --- ITEM 2b: seL4 MECHANISM teardown (reclamation) invocations, SYS_CALL so they RETURN the error
// label (0 = success). `TCBSuspend`=12 / `CNodeDelete`=23 (kernel InvocationLabel). CNodeDelete on a
// slot under the ROOT CNode is the FULL reclamation primitive — the kernel (src/invocation.rs
// cnode_delete) does, in one call: (1) suspend the TCB on a Thread-cap delete; (2) unmap a mapped
// Frame's PTE + TLB-shootdown; (3) release the object's pool slot when it was the last reference;
// (4) `reclaim_untyped_chain_at_tail` = roll the parent Untyped's `free_index` back so the bytes
// become allocatable again (return-to-Untyped). So full Untyped-return needs NO new kernel primitive.
const LBL_TCB_SUSPEND: u64 = 12;
const LBL_CNODE_DELETE: u64 = 23;
unsafe fn tcb_suspend_r(tcb: u64) -> u64 {
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") LBL_TCB_SUSPEND << 12 => reply,
        inout("r10") 0u64 => _,
        inout("r8") 0u64 => _,
        inout("r9") 0u64 => _,
        lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply >> 12
}
/// `CNodeDelete` slot `idx` under the caller's ROOT CNode. Same legacy invocation shape as
/// `copy_cap_r`/`cnode_copy` (index in a2=r10, msginfo length 0 → the kernel defaults depth to
/// WORD_BITS, which resolves a direct root-CNode slot). Returns the error label (0 = success).
unsafe fn cnode_delete_r(idx: u64) -> u64 {
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") CAP_INIT_THREAD_CNODE => _,
        inout("rsi") LBL_CNODE_DELETE << 12 => reply,
        inout("r10") idx => _, // a2 = slot index under the root CNode
        inout("r8") 0u64 => _, // a3 = depth (ignored; msginfo length 0 → WORD_BITS)
        inout("r9") 0u64 => _,
        lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply >> 12
}
/// Retype `num` objects of `obj` (size `bits`) from an ARBITRARY untyped cap `untyped` into `dest`.
/// (`untyped_retype_r` hardcodes `CAP_INIT_UNTYPED`; the reclamation self-test carves + fills a
/// throwaway CHILD untyped.) Returns the error label (0 = success; non-zero once the untyped is
/// exhausted).
unsafe fn untyped_retype_from_r(untyped: u64, obj: u64, bits: u32, num: u32, dest: u64) -> u64 {
    let size_num = ((bits as u64) << 32) | (num as u64);
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") untyped => _,
        inout("rsi") LBL_UNTYPED_RETYPE << 12 => reply,
        inout("r10") obj => _,
        inout("r8") size_num => _,
        inout("r9") dest => _,
        lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply >> 12
}

/// ITEM 2b — prove the seL4 MECHANISM-teardown (reclamation) end-to-end on a THROWAWAY untyped, with
/// ZERO risk to the live boot: runs POST-LOOP (all spawns done), touches only freshly-retyped
/// throwaway caps + an UNUSED offset of smss's (already-torn-down) demand-fill scratch region, and
/// deletes everything it makes → the 3 hosted processes' TCB/VSpace/CSpace/frames are NEVER touched.
/// Returns a bitmask of proven properties (all set = 0b11_1111 = the mechanism works). This is the
/// reclamation MECHANISM the coordinator asked to prove before (optionally) applying it live.
///
/// `RECLAIM_VA`: an unused page of smss's 8-PT demand-fill scratch span (0x…1100_0000..0x…1200_0000,
/// mapped into the executive's OWN VSpace); smss faulted ~136 pages (offsets < 0x9_0000), so page
/// 3000 (offset 0xBB8_000) is free + its PT exists → a safe, isolated frame-map/unmap target.
unsafe fn reclaim_mechanism_selftest() -> u64 {
    const RECLAIM_VA: u64 = 0x0000_0100_1100_0000 + 3000 * 0x1000;
    let mut ok = 0u64;

    // (bit0) Carve a THROWAWAY child untyped — 2^16 = 64 KiB (room for ~16 x 4 KiB frames) — out of
    // the boot untyped. Deleting it at the end returns those 64 KiB to CAP_INIT_UNTYPED.
    let child = alloc_slot();
    if untyped_retype_from_r(CAP_INIT_UNTYPED, OBJ_UNTYPED, 16, 1, child) == 0 {
        ok |= 1 << 0;
    }

    // (bit1) FRAME RECLAMATION via Untyped-return. Allocate 4 KiB frames from the child until it is
    // EXHAUSTED (round 1, count K); CNodeDelete every one (kernel rolls the child's free_index back);
    // then allocate again INTO THE SAME SLOTS (round 2). round2 == round1 (and K >= 8) proves the
    // deletes returned the full capacity to the untyped — the hard "return-to-Untyped" reclamation.
    let mut fslots = [0u64; 20];
    let mut round1 = 0usize;
    while round1 < fslots.len() {
        let s = alloc_slot();
        if untyped_retype_from_r(child, OBJ_X86_4K_PAGE, PAGING_BITS, 1, s) != 0 {
            break; // child untyped exhausted
        }
        fslots[round1] = s;
        round1 += 1;
    }
    let mut deleted_all = round1 > 0;
    for i in 0..round1 {
        if cnode_delete_r(fslots[i]) != 0 {
            deleted_all = false;
        }
    }
    let mut round2 = 0usize;
    while round2 < round1 {
        // Reuse the round-1 slot (now Null after delete): proves the slot AND the untyped bytes
        // are both reclaimed. A fresh retype into a freed slot must succeed.
        if untyped_retype_from_r(child, OBJ_X86_4K_PAGE, PAGING_BITS, 1, fslots[round2]) != 0 {
            break;
        }
        round2 += 1;
    }
    if deleted_all && round1 >= 8 && round2 == round1 {
        ok |= 1 << 1;
    }
    // Clean up round-2 frames before the child is deleted.
    for i in 0..round2 {
        let _ = cnode_delete_r(fslots[i]);
    }

    // (bit2) TCB (thread) reclamation: retype a throwaway TCB, SUSPEND it (TCBSuspend), then delete
    // it (CNodeDelete also suspends on a Thread-cap delete + releases the TCB pool slot).
    let tcb = alloc_slot();
    let tcb_made = untyped_retype_from_r(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb) == 0;
    let tcb_suspended = tcb_suspend_r(tcb) == 0;
    let tcb_deleted = cnode_delete_r(tcb) == 0;
    if tcb_made && tcb_suspended && tcb_deleted {
        ok |= 1 << 2;
    }

    // (bit3) VSpace (PML4) + CSpace (CNode) reclamation: retype a throwaway PML4 + a CNode, delete
    // both. This is the per-process CREATE mechanism's root caps (the same kinds spawn_sec_image
    // makes for each hosted process), proven reclaimable.
    let pml4 = alloc_slot();
    let cnode = alloc_slot();
    let pml4_made = untyped_retype_from_r(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4) == 0;
    let cnode_made = untyped_retype_from_r(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, cnode) == 0;
    if pml4_made && cnode_made && cnode_delete_r(pml4) == 0 && cnode_delete_r(cnode) == 0 {
        ok |= 1 << 3;
    }

    // (bit4) FRAME-UNMAP-on-delete. Map throwaway frame A at RECLAIM_VA (executive's own VSpace),
    // write a sentinel, read it back (mapped + writable); CNodeDelete A (the kernel unmaps its PTE +
    // TLB-shootdown); map a FRESH zeroed frame B at the SAME VA — B mapping SUCCEEDS only if the PTE
    // was cleared, and reads back 0 (B's zero fill, not A's sentinel) — proving A was truly unmapped.
    let fa = alloc_slot();
    let fb = alloc_slot();
    let a_made = untyped_retype_from_r(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, fa) == 0;
    let a_mapped = page_map_r(fa, RECLAIM_VA, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
    let mut unmap_ok = false;
    if a_made && a_mapped {
        core::ptr::write_volatile(RECLAIM_VA as *mut u32, 0xABCD_1234);
        let a_val = core::ptr::read_volatile(RECLAIM_VA as *const u32);
        let a_deleted = cnode_delete_r(fa) == 0; // kernel unmaps A's PTE
        let b_made = untyped_retype_from_r(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, fb) == 0;
        let b_mapped = page_map_r(fb, RECLAIM_VA, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
        let b_val = if b_mapped {
            core::ptr::read_volatile(RECLAIM_VA as *const u32)
        } else {
            0xFFFF_FFFF
        };
        // A was mapped+writable, A deleted, B re-mapped at the same VA (PTE was free), B reads its
        // own zero fill (A's sentinel is gone) → frame-unmap-on-delete confirmed.
        unmap_ok = a_val == 0xABCD_1234 && a_deleted && b_made && b_mapped && b_val == 0;
        let _ = cnode_delete_r(fb); // tear down B (unmaps + reclaims)
    }
    if unmap_ok {
        ok |= 1 << 4;
    }

    // (bit5) Return the throwaway child untyped's 64 KiB to the boot untyped (delete rolls
    // CAP_INIT_UNTYPED's free_index back through the parent chain).
    if cnode_delete_r(child) == 0 {
        ok |= 1 << 5;
    }

    print_str(b"[ntos-exec] item2b reclaim self-test: ok=0x");
    print_hex(ok as u32);
    print_str(b" round1=");
    print_u64(round1 as u64);
    print_str(b" round2=");
    print_u64(round2 as u64);
    print_str(b"\n");
    ok
}

// ===================== ALPC last-mile item (b): the PHYSICAL two-VSpace port-section view =========
// Prove a REAL cross-address-space ALPC section view — the WOW64 / big-data path. Two SEPARATE
// throwaway endpoint VSpaces map the SAME port-section backing frames at the SAME view VA (via
// copy_cap + page_map — the identical CSRSS_ANON_BASE machinery). A hosted thread in endpoint A
// WRITES big data through its mapped view; a hosted thread in endpoint B READS it back through ITS
// OWN mapping at its view VA — proving genuine cross-VSpace shared memory (not a copy, not a single-
// VSpace backing store). Both throwaway VSpaces + the section frames are CNodeDelete-reclaimed after.
// Runs POST-LOOP (all live spawns done): touches ONLY freshly-retyped throwaway caps + an unused
// executive scratch page; the 3 live hosted processes are NEVER touched → boot byte-identical.

/// Writer trampoline (endpoint A): `movabs rcx,view; movabs rax,PATTERN; mov [rcx],rax;
/// mov [rcx+0x1000],rax; movabs rax,0xA; syscall; jmp $`. With the hosted-syscalls flag every
/// `syscall` faults as UnknownSyscall, delivering the register file — RAX (=0xA done-marker) in m0.
fn xview_writer_code(view: u64, pattern: u64) -> alloc::vec::Vec<u8> {
    let mut t = alloc::vec::Vec::new();
    t.extend_from_slice(&[0x48, 0xB9]);
    t.extend_from_slice(&view.to_le_bytes()); // movabs rcx, view
    t.extend_from_slice(&[0x48, 0xB8]);
    t.extend_from_slice(&pattern.to_le_bytes()); // movabs rax, PATTERN
    t.extend_from_slice(&[0x48, 0x89, 0x01]); // mov [rcx], rax        (page 0)
    t.extend_from_slice(&[0x48, 0x89, 0x81, 0x00, 0x10, 0x00, 0x00]); // mov [rcx+0x1000], rax (page 1)
    t.extend_from_slice(&[0x48, 0xB8]);
    t.extend_from_slice(&0x0Au64.to_le_bytes()); // movabs rax, 0xA (done marker)
    t.extend_from_slice(&[0x0F, 0x05]); // syscall  → UnknownSyscall fault (m0 = RAX)
    t.extend_from_slice(&[0xEB, 0xFE]); // jmp $
    t
}

/// Reader trampoline (endpoint B): `movabs rcx,view; mov rax,[rcx]; mov rdx,[rcx+0x1000]; syscall;
/// jmp $`. The fault delivers RAX (=page 0) in m0 and RDX (=page 1) in m3.
fn xview_reader_code(view: u64) -> alloc::vec::Vec<u8> {
    let mut t = alloc::vec::Vec::new();
    t.extend_from_slice(&[0x48, 0xB9]);
    t.extend_from_slice(&view.to_le_bytes()); // movabs rcx, view
    t.extend_from_slice(&[0x48, 0x8B, 0x01]); // mov rax, [rcx]         (page 0)
    t.extend_from_slice(&[0x48, 0x8B, 0x91, 0x00, 0x10, 0x00, 0x00]); // mov rdx, [rcx+0x1000] (page 1)
    t.extend_from_slice(&[0x0F, 0x05]); // syscall  → fault (m0 = RAX, m3 = RDX)
    t.extend_from_slice(&[0xEB, 0xFE]); // jmp $
    t
}

/// Stand up ONE throwaway endpoint VSpace running `code`, with the two port-section frames (`f0`,
/// `f1` — pass copies for the 2nd endpoint) mapped RW at the view VA + a code page (RX) + stack +
/// IPC buffer, a fault EP, a hosted-syscalls TCB, an SC — resumed. Every new cap slot is appended to
/// `slots`. Returns (pml4, tcb, fault_ep). VAs live in the fresh VSpace so any layout is free.
#[allow(clippy::too_many_arguments)]
unsafe fn xview_spawn(
    code: &[u8],
    f0: u64,
    f1: u64,
    write_scratch: u64,
    slots: &mut [u64; 96],
    n: &mut usize,
) -> (u64, u64, u64) {
    const VIEW: u64 = 0x0000_0000_4000_0000; // 1 GiB — the section-view VA in the endpoint VSpace
    const CODE: u64 = VIEW + 0x10000;
    const STK: u64 = VIEW + 0x20000;
    const IPC: u64 = VIEW + 0x30000;
    let mut push = |s: u64| {
        slots[*n] = s;
        *n += 1;
        s
    };
    let pml4 = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, VIEW, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, VIEW, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, VIEW, pml4);
    // The port-section backing frames mapped RW at the view VA — the shared region.
    let _ = page_map(f0, VIEW, RW_NX, pml4);
    let _ = page_map(f1, VIEW + 0x1000, RW_NX, pml4);
    // Code page: write the trampoline via an executive scratch mapping, then map a COPY RX (W^X).
    let codef = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, codef);
    let _ = page_map(codef, write_scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
    for (i, b) in code.iter().enumerate() {
        core::ptr::write_volatile((write_scratch + i as u64) as *mut u8, *b);
    }
    let codecopy = push(copy_cap(codef));
    let _ = page_map(codecopy, CODE, /* RX */ 2, pml4);
    let stk = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, stk);
    let _ = page_map(stk, STK, RW_NX, pml4);
    let ipc = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipc);
    let _ = page_map(ipc, IPC, RW_NX, pml4);
    let fault_ep = push(make_object(OBJ_ENDPOINT));
    let raw = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = push(alloc_slot());
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let fault_copy = push(copy_cap(fault_ep));
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_copy, 0);
    let tcb = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPC, ipc, 0);
    let _ = tcb_write_registers(tcb, CODE, STK + 0x1000 - 16, 0);
    let _ = tcb_set_priority(tcb, 100);
    let sc = push(alloc_slot());
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS, 1, sc);
    let _ = sched_control_configure(SLOT_SCHED_CONTROL, sc, 1000, 1000);
    let _ = sched_context_bind(sc, tcb);
    // Hosted-syscalls flag: `syscall` faults as UnknownSyscall (delivering the register file to our
    // fault EP) instead of trapping natively — the same mechanism the live smss/csrss threads use.
    const LBL_TCB_SET_HOSTED_SYSCALLS: u64 = 66;
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_HOSTED_SYSCALLS << 12, 0, 0, 0);
    let _ = tcb_resume(tcb);
    (pml4, tcb, fault_ep)
}

/// ALPC last-mile item (b): the physical two-VSpace section-view proof. Returns a bitmask (0x3F =
/// all 6 sub-proofs). See the block comment above. Post-loop, throwaway-only, byte-identical boot.
unsafe fn alpc_cross_vspace_selftest() -> u64 {
    const PATTERN: u64 = 0xCAFE_BABE_DEAD_BEEF;
    // Executive-VSpace scratch pages to write each endpoint's code frame + one window onto the
    // section frame for an independent read. These sit in smss's (already-torn-down) demand-fill
    // scratch span, in the SAME 2 MiB page table as the reclaim self-test's proven-mapped RECLAIM_VA
    // (base + 3000*0x1000, PT index 5) — offsets 3001..3003 share that resident PT, so mapping a
    // fresh frame there succeeds (a page_map to an absent PT would silently fail → the executive
    // would then fault writing the trampoline; staying in the proven PT avoids that).
    const SCRATCH_BASE: u64 = 0x0000_0100_1100_0000;
    let write_scratch_a = SCRATCH_BASE + 3001 * 0x1000;
    let write_scratch_b = SCRATCH_BASE + 3002 * 0x1000;
    let win_va = SCRATCH_BASE + 3003 * 0x1000;

    let mut ok = 0u64;
    let mut slots = [0u64; 96];
    let mut n = 0usize;

    // The ALPC port section's REAL backing: two fresh 4 KiB frames (8 KiB — a multi-page big-data
    // view). These frames ARE the shared section; they map into BOTH endpoint VSpaces at the view VA.
    let f0 = {
        let s = alloc_slot();
        slots[n] = s;
        n += 1;
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, s);
        s
    };
    let f1 = {
        let s = alloc_slot();
        slots[n] = s;
        n += 1;
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, s);
        s
    };
    // One MCS Reply object per endpoint (a fault recv binds the faulting thread to its reply cap).
    let reply_a = {
        let s = alloc_slot();
        slots[n] = s;
        n += 1;
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, s);
        s
    };
    let reply_b = {
        let s = alloc_slot();
        slots[n] = s;
        n += 1;
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, s);
        s
    };

    // Endpoint A: a fresh VSpace mapping the ORIGINAL section frames + running the writer. Receive
    // its fault FIRST so the section carries A's write before endpoint B reads it (serialized).
    let writer = xview_writer_code(0x0000_0000_4000_0000, PATTERN);
    let (pml4_a, tcb_a, ep_a) = xview_spawn(&writer, f0, f1, write_scratch_a, &mut slots, &mut n);
    let (_ba, mia, m0a, _1a, _2a, _3a) = recv_full_r12(ep_a, reply_a);
    if (mia >> 12) == 2 && m0a == 0x0A {
        ok |= 1 << 1; // the writer ran in VSpace A + wrote its big data, then fault-reported done
    }

    // Endpoint B: a SEPARATE VSpace mapping COPIES of the SAME section frames (copy_cap + page_map =
    // the CSRSS_ANON_BASE machinery) + running the reader. It reads the section back through ITS OWN
    // mapping at its view VA.
    let cf0 = {
        let s = copy_cap(f0);
        slots[n] = s;
        n += 1;
        s
    };
    let cf1 = {
        let s = copy_cap(f1);
        slots[n] = s;
        n += 1;
        s
    };
    let reader = xview_reader_code(0x0000_0000_4000_0000);
    let (pml4_b, tcb_b, ep_b) = xview_spawn(&reader, cf0, cf1, write_scratch_b, &mut slots, &mut n);
    let (_bb, mib, m0b, _1b, _2b, m3b) = recv_full_r12(ep_b, reply_b);

    if pml4_a != 0 && pml4_b != 0 && pml4_a != pml4_b {
        ok |= 1 << 0; // two SEPARATE endpoint VSpaces stood up
    }
    if (mib >> 12) == 2 && m0b == PATTERN {
        ok |= 1 << 2; // VSpace B read page 0 written by VSpace A — genuine cross-VSpace shared memory
    }
    if (mib >> 12) == 2 && m3b == PATTERN {
        ok |= 1 << 3; // VSpace B also read page 1 — a real MULTI-PAGE big-data view (WOW64 path)
    }
    // Independent confirmation the two VSpaces mapped the SAME physical frame (not a copy): read the
    // section through a THIRD copy_cap window in the executive's own VSpace — it shows A's write too.
    let win = {
        let s = copy_cap(f0);
        slots[n] = s;
        n += 1;
        s
    };
    if page_map_r(win, win_va, RW_NX, CAP_INIT_THREAD_VSPACE) == 0
        && core::ptr::read_volatile(win_va as *const u64) == PATTERN
    {
        ok |= 1 << 4; // the physical section frame carries A's write — shared, not copied
    }

    // Reclaim: suspend both throwaway threads, then CNodeDelete every throwaway slot (return-to-
    // Untyped — the mechanism proven by reclaim_mechanism_selftest). Delete the section frames FIRST
    // (they are mapped in BOTH endpoints' PTs), then the rest child-first (reverse push order), then
    // the essential TCBs + PML4s (whose child paging structs are already gone) — the gated proof.
    let _ = tcb_suspend_r(tcb_a);
    let _ = tcb_suspend_r(tcb_b);
    let sec_ok = cnode_delete_r(f0) == 0
        && cnode_delete_r(f1) == 0
        && cnode_delete_r(cf0) == 0
        && cnode_delete_r(cf1) == 0;
    for i in (0..n).rev() {
        let s = slots[i];
        if s == 0 || s == f0 || s == f1 || s == cf0 || s == cf1 || s == tcb_a || s == tcb_b
            || s == pml4_a || s == pml4_b
        {
            continue;
        }
        let _ = cnode_delete_r(s);
    }
    let vs_ok = cnode_delete_r(tcb_a) == 0
        && cnode_delete_r(tcb_b) == 0
        && cnode_delete_r(pml4_a) == 0
        && cnode_delete_r(pml4_b) == 0;
    if sec_ok && vs_ok {
        ok |= 1 << 5; // throwaway VSpaces + section frames reclaimed
    }

    print_str(b"[ntos-exec] ALPC cross-vspace section-view self-test: ok=0x");
    print_hex(ok as u32);
    print_str(b" writer=0x");
    print_hex(m0a as u32);
    print_str(b" readerA=0x");
    print_hex((m0b >> 32) as u32);
    print_hex(m0b as u32);
    print_str(b" readerB=0x");
    print_hex((m3b >> 32) as u32);
    print_hex(m3b as u32);
    print_str(b"\n");
    ok
}

unsafe fn attach_sched_context(tcb: u64) {
    let sc = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS, 1, sc);
    let _ = sched_control_configure(SLOT_SCHED_CONTROL, sc, 10, 10);
    let _ = sched_context_bind(sc, tcb);
}

/// Build the page table for the relocated shared "cluster" region (rings, stack, IPC buffer,
/// sysarg, device MMIO, driver code/arena) at `WORK_CLUSTER_BASE` in `pml4`. The cluster used to
/// piggyback the image's 2 MiB PT; now that the working VAs moved high (out of the 64 MiB ELF
/// reserve) it needs its own PT in every executive-image VSpace and in the executive's own.
unsafe fn map_cluster_pt(pml4: u64) {
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, WORK_CLUSTER_BASE, pml4);
}

/// Build the page table for the relocated heap region (`HEAP_BASE`) in `pml4`. The generous heap
/// is 512 frames = exactly one 2 MiB PT.
unsafe fn map_heap_pt(pml4: u64) {
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, allocator::HEAP_BASE as u64, pml4);
}

/// Build the standard executive-image paging skeleton in `pml4`: pdpt + pd for the image's 1 GiB
/// slot, one PT per 2 MiB of image (so the ELF can grow into its 64 MiB reserve), and the
/// relocated cluster PT. Callers then map the image frames + any region-specific buffer PTs. The
/// pd is 1 GiB-granular, so it also covers the cluster / heap / buffer PTs (all < 512 MiB).
unsafe fn map_image_skeleton(pml4: u64, img_count: u64) {
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    // One PT per 2 MiB of image (512 4 KiB pages each). `.max(1)` keeps at least one even for a
    // trivially small image.
    let npt = ((img_count + 511) / 512).max(1);
    for k in 0..npt {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE + k * 0x20_0000, pml4);
    }
    map_cluster_pt(pml4);
}

/// Map the executive's OWN heap (so its front-end can allocate). Builds the heap PT first (the
/// heap is relocated far above the image, so — unlike before — the kernel's ELF PTs don't cover
/// it), then maps all HEAP_FRAMES at the relocated `HEAP_BASE`.
unsafe fn map_own_heap() {
    map_heap_pt(CAP_INIT_THREAD_VSPACE);
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
    map_image_skeleton(pml4, img_count);
    map_heap_pt(pml4);
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    for i in 0..allocator::SERVICE_HEAP_FRAMES {
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

/// The LPC connection-broker transport wrapper (control plane over SURT).
struct LpcChan<'a>(RingChannel<'a>);
impl nt_lpc_client::Backend for LpcChan<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> LpcReply {
        let (status, _flags, information, detail0, detail1) = self.0.raw(opcode, in_buf, out_buf);
        LpcReply {
            status,
            information: information as u32,
            detail0,
            detail1,
        }
    }
}

/// The executive's client to the isolated `lpc-server` component. Set once in
/// `_start` after `stand_up_service`; the LPC syscall handlers reach it via
/// [`lpc_client`] (single-threaded executive → the `static mut` is race-free).
static mut LPC_CLIENT: Option<LpcClient<LpcChan<'static>>> = None;

/// Borrow the LPC client (None until the service is stood up).
///
/// # Safety
/// Single-threaded executive; no aliasing across the one service loop.
unsafe fn lpc_client() -> Option<&'static mut LpcClient<LpcChan<'static>>> {
    (*core::ptr::addr_of_mut!(LPC_CLIENT)).as_mut()
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

/// A plain, blocking `seL4_Send(ep, label)` with a length-0 message — used to wake the win32k
/// dispatch component (fix A: Send/Recv handshake, no reply cap → the kernel's single `reply_to`
/// slot is untouched, so a csrss syscall reply in flight on the same executive thread survives).
unsafe fn ep_send(ep: u64, label: u64) {
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") ep,
        in("rsi") label << 12,
        in("r10") 0u64, in("r8") 0u64, in("r9") 0u64, in("r15") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
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

/// Like [`reply_recv_full`] but also returns the RECEIVED cap's badge (rdi on return). The
/// 2-process service loop mints each hosted thread's fault-endpoint cap with a distinct badge
/// (smss=0, csrss=CSRSS_BADGE) so it can tell whose fault/syscall this is and select that
/// process's VSpace/image/scratch state.
unsafe fn reply_recv_badge(recv_ep: u64, reply_len: u64, r0: u64, r1: u64, r2: u64, r3: u64) -> (u64, u64, u64, u64, u64, u64) {
    let badge: u64;
    let msginfo: u64;
    let mr0: u64;
    let mr1: u64;
    let mr2: u64;
    let mr3: u64;
    // Fix (B): the RECV half registers REPLY_MAIN in the MCS reply register (r12) so the kernel
    // binds the next caller's Call to REPLY_MAIN (finish_call -> replies[idx].bound_tcb = caller).
    // The REPLY half still targets the legacy `reply_to` (unchanged behavior); only the win32k-
    // routed syscall arm reads back through Send-on-REPLY_MAIN so its reply survives a nested
    // win32k-fault `reply_to` clobber. cptr 0 (pre-retype) = no cap, legacy path only.
    let reply_cptr = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_REPLY_RECV as u64,
        inout("rdi") recv_ep => badge,
        inout("rsi") reply_len => msginfo,
        inout("r10") r0 => mr0,
        inout("r8") r1 => mr1,
        inout("r9") r2 => mr2,
        inout("r15") r3 => mr3,
        in("r12") reply_cptr,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (badge, msginfo, mr0, mr1, mr2, mr3)
}

/// `seL4_Recv(ep)` that ALSO registers a reply capability via the MCS `replyRegister` (r12): the
/// kernel binds `reply_cptr`'s Reply object to whichever thread's Call pairs with this recv
/// (finish_call -> replies[idx].bound_tcb = caller). A later Send on `reply_cptr` (decode_reply)
/// then resumes exactly that caller regardless of the single per-TCB `reply_to` slot — so a nested
/// faulting dispatch can't orphan an outer caller's pending reply. The kernel preserves the user's
/// r12 across the syscall (it reads it, never writes it), so `in` is sufficient.
unsafe fn recv_full_r12(ep: u64, reply_cptr: u64) -> (u64, u64, u64, u64, u64, u64) {
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
        in("r12") reply_cptr,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (badge, msginfo, mr0, mr1, mr2, mr3)
}

/// Reply to a Call/fault via a `seL4_Send` on a `Cap::Reply` (kernel `decode_reply`): resume the
/// reply object's bound caller, applying `apply_fault_reply` when the caller is blocked on a fault
/// (the win32k/csrss demand-page + syscall replies are all fault replies). MR0..3 ride in
/// r10/r8/r9/r15; MR4+ come from the IPC buffer (`set_reply_mr`). Used instead of SYS_REPLY_RECV so
/// the reply targets the bound caller, NOT the (possibly clobbered) legacy `reply_to`.
unsafe fn send_on_reply(reply_cptr: u64, msginfo: u64, r0: u64, r1: u64, r2: u64, r3: u64) {
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") reply_cptr,
        in("rsi") msginfo,
        in("r10") r0, in("r8") r1, in("r9") r2, in("r15") r3,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
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
    // The stack / IPC buffer / sysarg frame live in the relocated cluster region.
    map_cluster_pt(pml4);
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
/// The mapping rights `fill_image_page` WOULD return for `rva`, WITHOUT filling — RX (2) for an
/// executable section, RW_NX otherwise (headers/rdata/data/gaps). Lets the fault router classify a
/// page before deciding whether it's a shareable text page (RX) or a per-process page.
unsafe fn page_rights(pe: &nt_pe_loader::PeFile, rva: u32) -> u64 {
    let soh = pe.headers().size_of_headers;
    let page_up = |n: u32| (n + 0xFFF) & !0xFFFu32;
    if rva < page_up(soh) {
        return RW_NX; // headers
    }
    for s in pe.sections() {
        if rva >= s.virtual_address && rva < s.virtual_address + page_up(s.virtual_size) {
            return if s.is_executable() { 2 /* RX */ } else { RW_NX };
        }
    }
    RW_NX // gap
}
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
    pi: u64,
    pe: &nt_pe_loader::PeFile,
    fault_ep_c: u64,
    ntdll_base: u64,
    setup_env: bool,
    prio: u64,
    scr_base: u64,
    stack_mirror: u64,
    heap_mirror: u64,
    image_mirror: u64,
    image_path: &[u8],
    cmd_line: &[u8],
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
    // The stack + IPC buffer live in the relocated cluster region (out of the ELF reserve).
    map_cluster_pt(pml4);
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
        let _ = paging_struct_map(hpt, LBL_X86_PAGE_TABLE_MAP, heap_mirror, CAP_INIT_THREAD_VSPACE);
        // A dedicated PT for the IMAGE copyin mirror, when the process needs its own (winlogon: its
        // image mirror is a fresh VA with no pre-existing PT, unlike smss's IMAGE_MIRROR (FILEBUF PT)
        // and csrss's CSRSS_IMAGE_MIRROR (NTDLLBUF PT), which pass image_mirror=0 to reuse those).
        if image_mirror != 0 {
            let ipt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, ipt);
            let _ = paging_struct_map(ipt, LBL_X86_PAGE_TABLE_MAP, image_mirror, CAP_INIT_THREAD_VSPACE);
        }
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_frame();
        let _ = page_map(copy_cap(f), STACK_BASE + i * 0x1000, RW_NX, pml4);
        // Mirror the stack into the executive so it can read/write a syscall's stack-based
        // pointer args (copyin/copyout).
        if setup_env {
            let _ = page_map(copy_cap(f), stack_mirror + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
        // Record the INITIAL committed stack frames for a GUI client (csrss pi 1 / winlogon pi 2) so
        // win32k can share them per-client. Unlike demand-grown stack pages (fault site), these are
        // mapped at spawn, so they'd otherwise be absent from the client-frame table — and a client's
        // stack-built OBJECT_ATTRIBUTES (e.g. winlogon's NtUserCreateWindowStation) lives here.
        if pi >= 1 {
            csrss_frame_put(pi, STACK_BASE + i * 0x1000, f);
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
        //
        // These executive scratch mappings (scr+0x0/0x1000/0x2000/0x3000/0x5000) are NEVER unmapped
        // — they only exist to populate the frames before copy_cap'ing them into the process. So a
        // SECOND spawn (csrss) MUST use a distinct scr_base (both fit in the FILEBUF PT 0x60-0x80),
        // or its env writes would land in the first process's still-mapped frames and leave csrss's
        // env pages zero → a null-deref in its trampoline.
        let scr = scr_base;
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
        // (unicode_string field offset, scratch buffer offset, smss buffer VA offset, text).
        // ImagePathName + CommandLine are per-process (smss vs csrss) — the loader derives the DLL
        // search + the ".local" SxS probe from ImagePathName, and the image's entry parses CommandLine.
        let ustrs: [(u64, u64, &[u8]); 4] = [
            (0x38, 0x300, b"C:\\Windows"),           // CurrentDirectory.DosPath
            (0x50, 0x340, b"C:\\Windows\\System32"), // DllPath
            (0x60, 0x3A0, image_path),               // ImagePathName
            (0x70, 0x480, cmd_line),                 // CommandLine
        ];
        for (foff, boff, text) in ustrs {
            let len = wstr(pp + boff, text);
            core::ptr::write_volatile((pp + foff) as *mut u16, len); // Length
            core::ptr::write_volatile((pp + foff + 2) as *mut u16, len + 2); // MaximumLength
            core::ptr::write_volatile((pp + foff + 8) as *mut u64, SMSS_PARAMS_VA + boff); // Buffer
        }
        // Environment block (RTL_USER_PROCESS_PARAMETERS+0x80). kernel32's init walks this as a
        // list of UTF-16LE `NAME=VALUE` strings, each wide-NUL-terminated, the block ended by an
        // empty entry (a lone wide NUL). A NULL Environment makes kernel32 wcslen(NULL) and #PF at
        // addr 2 (verified: kernel32+0x93c4 `movzx eax,[rax]`). Real Windows always supplies one.
        // The csrss command line is long (~200+ chars at pp+0x480), so put the environment in its
        // OWN page (SMSS_PARAMS_VA+0x1000 — the next page in the same 2 MiB PT, no new PT needed).
        let env_frame = alloc_frame();
        let env_scr = scr + 0x4000;
        let _ = page_map(env_frame, env_scr, RW_NX, CAP_INIT_THREAD_VSPACE);
        {
            let mut off: u64 = 0;
            for var in [
                b"SystemRoot=C:\\Windows".as_slice(),
                b"SystemDrive=C:".as_slice(),
                b"windir=C:\\Windows".as_slice(),
                b"Path=C:\\Windows\\System32;C:\\Windows".as_slice(),
            ] {
                let len = wstr(env_scr + off, var);
                off += len as u64;
                core::ptr::write_volatile((env_scr + off) as *mut u16, 0); // wide NUL terminator
                off += 2;
            }
            core::ptr::write_volatile((env_scr + off) as *mut u16, 0); // final empty entry
            off += 2;
            // EnvironmentSize (RTL_USER_PROCESS_PARAMETERS+0x3F0, SIZE_T on x64). ntdll's
            // param/env duplication (RtlCreateProcessParametersEx) copies EnvironmentSize bytes
            // via memmove (ntdll+0x5e420); if it is 0 the copy loop overruns past the env page and
            // #PFs (kernel32/ntdll env walk). Set it to the full block length incl. terminator.
            core::ptr::write_volatile((pp + 0x3F0) as *mut u64, off);
        }
        core::ptr::write_volatile((pp + 0x80) as *mut u64, SMSS_PARAMS_VA + 0x1000); // Environment
        let _ = page_map(copy_cap(params), SMSS_PARAMS_VA, RW_NX, pml4);
        let _ = page_map(copy_cap(env_frame), SMSS_PARAMS_VA + 0x1000, RW_NX, pml4);
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
    let _ = tcb_set_priority(tcb, prio);
    // Mark this a HOSTED thread: the kernel turns EVERY `syscall` it issues into an UnknownSyscall
    // fault to the executive, never a native seL4 dispatch. Without this, NT syscalls whose arg2
    // (RDX) collides with a seL4 syscall number are misdispatched by the kernel and never reach us —
    // e.g. NtMapViewOfSection passes ProcessHandle = NtCurrentProcess() = -1 in RDX, and the kernel
    // reads RDX as the syscall number where -1 == SysCall, so the map silently never faults here.
    const LBL_TCB_SET_HOSTED_SYSCALLS: u64 = 66;
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_HOSTED_SYSCALLS << 12, 0, 0, 0);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    pml4
}

/// Read a u64 from a SEC_IMAGE process's stack VA (a syscall's pointer arg) via the executive's
/// stack mirror. Returns 0 if the VA isn't in the mirrored stack range.
unsafe fn smss_stack_read(stack_va: u64) -> u64 {
    if stack_va >= STACK_BASE && stack_va + 8 <= STACK_BASE + STACK_FRAMES * 0x1000 {
        let mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
        core::ptr::read_volatile((mirror + (stack_va - STACK_BASE)) as *const u64)
    } else {
        0
    }
}
/// Translate a SEC_IMAGE process VA to its executive mirror VA (stack or heap window), or None if
/// the range isn't covered by a mirror. The executive's copyin/copyout base: a userspace broker
/// can't walk smss's page tables, so it reaches smss memory through the same frames it mapped.
unsafe fn smss_mirror(va: u64, len: u64) -> Option<u64> {
    if va >= STACK_BASE && va + len <= STACK_BASE + STACK_FRAMES * 0x1000 {
        Some(ACTIVE_STACK_MIRROR.load(Ordering::Relaxed) + (va - STACK_BASE))
    } else if va >= SMSS_ALLOC_VA && va + len <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
        Some(ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed) + (va - SMSS_ALLOC_VA))
    } else if va >= PE_LOAD_BASE && va + len <= PE_LOAD_BASE + IMAGE_MIRROR_WINDOW {
        // Image .rdata/.idata/.data — only valid once the page has been demand-faulted (the process
        // reads a static string, faulting+mirroring its page, before passing it to a syscall). Uses
        // the ACTIVE process's image mirror so csrss's import-descriptor names read from ITS image.
        Some(ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed) + (va - PE_LOAD_BASE))
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
/// The executive's writable scratch mirror of an already demand-paged csrss page (any region:
/// image, ntdll, csrsrv .data, …), so a syscall handler can copy OUT an out-param that doesn't live
/// in the stack/heap/image mirrors. Returns the executive VA aliasing `va`, or None if `va`'s page
/// hasn't been faulted in (so isn't in `filled_pages`).
unsafe fn scratch_for(va: u64, filled_pages: &[u64], nfilled: usize, scratch_base: u64) -> Option<u64> {
    let page = va & !0xFFFu64;
    for i in 0..nfilled.min(filled_pages.len()) {
        if filled_pages[i] == page {
            return Some(scratch_base + i as u64 * 0x1000 + (va & 0xFFF));
        }
    }
    None
}
/// Write a u64 OUT-param to a csrss VA that may live ANYWHERE in its VSpace — not just the
/// stack/heap/image mirrors, but also a csrsrv .data global (~0x8001xxxx). Tries the mirrors
/// (smss_copyout), then an already-faulted page's scratch alias, then — for a not-yet-faulted csrsrv
/// page — demand-fills it and writes. csrss stores load-bearing handles/bases here (the CSR section
/// handle, CsrSrvSharedSectionBase), so a silent miss leaves them NULL and later NULL-derefs.
unsafe fn csrss_out_write(
    va: u64,
    val: u64,
    filled_pages: &mut [u64; 256],
    faults: &mut u64,
    scratch_base: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
    pml4: u64,
) {
    if smss_copyout(va, &val.to_le_bytes()) {
        return;
    }
    let page = va & !0xFFFu64;
    let mut sva = scratch_for(va, filled_pages, *faults as usize, scratch_base);
    // A not-yet-faulted page that belongs to a mapped registry DLL (e.g. a csrsrv/basesrv .data
    // global): demand-fill it from that DLL's PE so the write lands (a silent miss leaves a
    // load-bearing handle/base NULL → later NULL-deref).
    if sva.is_none() && (*faults as usize) < filled_pages.len() {
        if let Some((i, rva)) = reg.dll_for_page(page) {
            if let Some(pe) = dll_pes[i].as_ref() {
                let scratch = scratch_base + *faults * 0x1000;
                let f = alloc_frame();
                let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
                let rights = fill_image_page(pe, rva, scratch);
                let _ = page_map(copy_cap(f), page, rights, pml4);
                filled_pages[*faults as usize] = page;
                sva = Some(scratch + (va & 0xFFF));
                *faults += 1;
            }
        }
    }
    if let Some(m) = sva {
        core::ptr::write_volatile(m as *mut u64, val);
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
/// Copy in a UNICODE_STRING at `ustr_va` (x64 {u16 Length, u16 MaximumLength, u32 pad, u64 Buffer})
/// and return its UTF-16 code units. (For NtQueryValueKey's ValueName — used once IMAGE copyin
/// lets us reach the .rdata name buffers.)
#[allow(dead_code)]
unsafe fn smss_read_ustr(ustr_va: u64) -> alloc::vec::Vec<u16> {
    if ustr_va == 0 {
        return alloc::vec::Vec::new();
    }
    let mut lm = [0u8; 2];
    let mut bp = [0u8; 8];
    if !smss_copyin(ustr_va, &mut lm) || !smss_copyin(ustr_va + 8, &mut bp) {
        return alloc::vec::Vec::new();
    }
    smss_read_unicode(u64::from_le_bytes(bp), u16::from_le_bytes(lm))
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
        let mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
        core::ptr::write_volatile((mirror + (stack_va - STACK_BASE)) as *mut u64, v);
    }
}

/// Write a 32-bit value to a stack VA (via the mirror). Use for DWORD out-params (e.g. an
/// NtProtectVirtualMemory *OldProtect) — an 8-byte write would clobber the adjacent local.
unsafe fn smss_stack_write32(stack_va: u64, v: u32) {
    if stack_va >= STACK_BASE && stack_va + 4 <= STACK_BASE + STACK_FRAMES * 0x1000 {
        let mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
        core::ptr::write_volatile((mirror + (stack_va - STACK_BASE)) as *mut u32, v);
    }
}

/// Write a 16-bit value to a stack VA (via the mirror). Use for the PORT_MESSAGE u2.s2.Type field
/// (a CSHORT) when modeling an LPC reply in place — a wider write would clobber the adjacent
/// DataInfoOffset / u1 length fields.
unsafe fn smss_stack_write16(stack_va: u64, v: u16) {
    if stack_va >= STACK_BASE && stack_va + 2 <= STACK_BASE + STACK_FRAMES * 0x1000 {
        let mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
        core::ptr::write_volatile((mirror + (stack_va - STACK_BASE)) as *mut u16, v);
    }
}

/// Write an ASCII string as a NUL-terminated UTF-16LE buffer at an executive scratch VA (for building
/// the CSR shared static server data's WCHAR name buffers before they are mapped into winlogon).
unsafe fn write_wstr(exec_va: u64, s: &str) {
    let mut off = 0u64;
    for u in s.encode_utf16() {
        core::ptr::write_volatile((exec_va + off) as *mut u16, u);
        off += 2;
    }
    core::ptr::write_volatile((exec_va + off) as *mut u16, 0);
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
/// Sentinel `KeyRef` for the synthesized `\Registry\Machine\Hardware\…\CentralProcessor\0` key
/// (the kernel's volatile HARDWARE hive, which we don't have on disk). Far above any real regf
/// cell offset, so it never collides with a hive key.
const SYNTH_CPU_KEY: KeyRef = 0xFFFF_FF00;

/// The real filenames of the boot-path binaries staged under `\SystemRoot\System32` (the names the
/// ntdll/csrss loader probes). The executive's nt-fs namespace is seeded with these so nt-fs is the
/// single authority for "does this System32 file exist + attributes." Mirrors the nt-dll-registry
/// `dll_seed` set (which keeps the SEC_IMAGE base/geometry role for CONTENT) + csrss.exe. Adding a
/// served binary is a seed entry here, not a handler edit.
const SYSTEM32_FILES: &[&str] = &[
    "csrss.exe",
    "winlogon.exe",
    "csrsrv.dll",
    "basesrv.dll",
    "winsrv.dll",
    "kernel32.dll",
    "user32.dll",
    "gdi32.dll",
    "rpcrt4.dll",
    "msvcrt.dll",
    "advapi32.dll",
    "ws2_32.dll",
    "kernel32_vista.dll",
    "advapi32_vista.dll",
    "ws2help.dll",
    "ntdll_vista.dll",
    "userenv.dll",
    "mpr.dll",
];

/// The (Type, UTF-16 data) for a value name under the synthesized CentralProcessor\0 key. Enough
/// for SmpInit's PROCESSOR_IDENTIFIER build (Identifier + VendorIdentifier, both REG_SZ).
fn synth_cpu_value(name_lc: &str) -> Option<(u32, alloc::vec::Vec<u16>)> {
    const REG_SZ: u32 = 1;
    let s: &str = match name_lc {
        "identifier" => "Intel64 Family 6 Model 60 Stepping 3",
        "vendoridentifier" => "GenuineIntel",
        _ => return None,
    };
    let mut d: alloc::vec::Vec<u16> = s.encode_utf16().collect();
    d.push(0); // REG_SZ is NUL-terminated
    Some((REG_SZ, d))
}
/// UTF-16 code units → little-endian bytes (registry value data is stored/copied as bytes).
fn utf16_bytes(d16: &[u16]) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec::Vec::with_capacity(d16.len() * 2);
    for &w in d16 {
        b.extend_from_slice(&w.to_le_bytes());
    }
    b
}
/// Base for object-manager handles (index into `obj_ns`, distinct from key handles).
const OBJ_HANDLE_BASE: u64 = 0x0000_0002_0000_0000;

/// One node in the executive's minimal object-manager namespace. Inline, `Copy`, no nested heap
/// allocation, so the backing `Vec` (pre-reserved below the per-syscall heap mark) never
/// reallocates and survives the bump-heap reset. Enough for SmpInit's DosDevices bring-up:
/// directories (`\`, `\??`, …) and the drive-letter symbolic links it creates in `\??`.
#[derive(Clone, Copy)]
struct ObjEntry {
    name: [u8; 40],   // leaf name, lowercased ASCII (len in name_len)
    name_len: u8,
    parent: u8,       // index of the parent directory; 0xFF = the root itself
    kind: u8,         // 0 = directory, 1 = symbolic link
    target: [u8; 40], // symbolic-link target (kind == 1)
    target_len: u8,
}
impl ObjEntry {
    fn dir(name: &[u8], parent: u8) -> Self {
        let mut e = ObjEntry {
            name: [0; 40],
            name_len: 0,
            parent,
            kind: 0,
            target: [0; 40],
            target_len: 0,
        };
        let n = name.len().min(40);
        e.name[..n].copy_from_slice(&name[..n]);
        e.name_len = n as u8;
        e
    }
    fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Build a KEY_VALUE_*_INFORMATION structure (NtQueryValueKey/NtEnumerateValueKey out buffer) for
/// the given class: 0 = Basic {TitleIndex,Type,NameLength,Name}, 2 = Partial
/// {TitleIndex,Type,DataLength,Data}, 1/other = Full {TitleIndex,Type,DataOffset,DataLength,
/// NameLength,Name,[pad],Data}. Name is UTF-16LE.
fn build_key_value_info(class: u64, name: &str, ty: u32, data: &[u8]) -> alloc::vec::Vec<u8> {
    let name16: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let nb = name16.len() * 2;
    let mut b = alloc::vec::Vec::new();
    match class {
        0 => {
            // KeyValueBasicInformation
            b.extend_from_slice(&0u32.to_le_bytes()); // TitleIndex
            b.extend_from_slice(&ty.to_le_bytes()); // Type
            b.extend_from_slice(&(nb as u32).to_le_bytes()); // NameLength
            for &w in &name16 {
                b.extend_from_slice(&w.to_le_bytes());
            }
        }
        2 => {
            // KeyValuePartialInformation
            b.extend_from_slice(&0u32.to_le_bytes()); // TitleIndex
            b.extend_from_slice(&ty.to_le_bytes()); // Type
            b.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataLength
            b.extend_from_slice(data);
        }
        _ => {
            // KeyValueFullInformation
            let data_off = ((0x14 + nb) + 7) & !7; // 8-align the data
            b.extend_from_slice(&0u32.to_le_bytes()); // TitleIndex
            b.extend_from_slice(&ty.to_le_bytes()); // Type
            b.extend_from_slice(&(data_off as u32).to_le_bytes()); // DataOffset
            b.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataLength
            b.extend_from_slice(&(nb as u32).to_le_bytes()); // NameLength
            for &w in &name16 {
                b.extend_from_slice(&w.to_le_bytes());
            }
            while b.len() < data_off {
                b.push(0);
            }
            b.extend_from_slice(data);
        }
    }
    b
}

/// Raw references to the fault/syscall loop's per-iteration state, handed to the group-C handlers
/// (Workstream A) so they can reach the section/registry/demand-fill state that genuinely lives on
/// the loop (`service_sec_image`), not on the handler. The Tier-1 dispatch arm rebuilds this each
/// iteration pointing at the current loop locals.
///
/// SAFETY: every pointer targets a `service_sec_image` local that outlives each `dispatch` call;
/// the executive is single-threaded and the loop does not touch these between building the ctx and
/// draining the handler's signals, so there is no aliasing in practice. Extended as more group-C
/// cases migrate (reg / dll_pes / csrss handle-tracking / image PEs / demand-fill state).
#[derive(Clone, Copy)]
struct ExecLoopCtx {
    /// The faulting process's PML4 (page_map target for COMMIT frames / demand-filled pages).
    pml4: u64,
    /// The named NLS section handle (\Nls\NlsSectionCP20127) NtOpenSection records so
    /// NtMapViewOfSection can back it. Points at the loop-local `nls_section_handle`.
    nls_section_handle: *mut u64,
    /// The DLL registry (csrsrv/basesrv/winsrv + the Win32 client stack): name→index resolution,
    /// per-DLL file/section-handle tracking, and image-info synthesis for the file/section fakes.
    reg: *mut nt_dll_registry::Registry,
    /// The file handle smss/csrss opened for csrss.exe (NtOpenFile records it; NtCreateSection reads
    /// it to recognise the SEC_IMAGE for the subsystem process). Points at the loop-local.
    csrss_file_handle: *mut u64,
    /// The SEC_IMAGE section handle for csrss.exe (NtCreateSection records; NtQuerySection/
    /// NtCreateProcess read). Points at the loop-local.
    csrss_section_handle: *mut u64,
    /// The parsed csrss.exe PE (`None` on the earlier demo path). NtQuerySection synthesises its
    /// SECTION_IMAGE_INFORMATION; NtCreateProcess spawns from it. Lifetime-erased raw ptr.
    csrss_pe: *const Option<nt_pe_loader::PeFile<'static>>,
    /// winlogon.exe (the 3rd hosted process) — the file/section handles smss opens+creates for it
    /// (NtOpenFile/NtCreateSection track them) so NtCreateProcess recognises its SEC_IMAGE and asks
    /// the loop to spawn it; the parsed PE the loop spawns from. Same roles as the csrss_* trio.
    winlogon_file_handle: *mut u64,
    winlogon_section_handle: *mut u64,
    winlogon_pe: *const Option<nt_pe_loader::PeFile<'static>>,
    /// The active process's demand-fill bookkeeping (page VA per fault index) + fault count — the
    /// same locals `csrss_out_write` mutates. NtQueryDefaultLocale demand-fills an image .data page.
    filled_pages: *mut [u64; 256],
    faults: *mut u64,
    /// The faulting image's persistent executive scratch base (smss's), and the two images
    /// NtQueryDefaultLocale may demand-fill from (the main image `pe` at PE_LOAD_BASE up to
    /// `img_end`, and `ntdll_pe` in [`nt_base`,`nt_end`); `ntdll_pe` is null if absent).
    scratch_base: u64,
    pe: *const nt_pe_loader::PeFile<'static>,
    ntdll_pe: *const nt_pe_loader::PeFile<'static>,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    /// The 14 loadable DLL PEs (csrsrv/basesrv/winsrv + the Win32 client stack), for
    /// `csrss_out_write`'s demand-fill of a not-yet-faulted DLL .data page. Lifetime-erased.
    dll_pes: *const [&'static Option<nt_pe_loader::PeFile<'static>>; 16],
    /// csrss's ANONYMOUS (no-file) section — its CSR SharedSection shared memory: the handle
    /// NtCreateSection records + the requested size NtMapViewOfSection backs. Point at the locals.
    csrss_anon_section_handle: *mut u64,
    csrss_anon_size: *mut u64,
    /// The base NtMapViewOfSection assigned the anonymous CSR section (0 until first mapped) + the
    /// PER-PROCESS once-only flag for the shared 0x8000_0000 DLL page-directory (indexed by pi:
    /// each hosted process's VSpace needs its OWN PD covering the DLL PDPT range). Point at the
    /// loop-locals.
    csrss_anon_base: *mut u64,
    dll_pd_created: *mut [bool; 3],
    /// PER-PROCESS bitmask of which registry DLLs have had their VA-range page table reserved in
    /// THIS process's VSpace (bit i = DLL i mapped in process pi). csrss (pi==1) and winlogon
    /// (pi==2) each load an overlapping DLL set at the SAME fixed bases but into DISTINCT VSpaces,
    /// so the PT reservation must be tracked per-process (the registry's global `mapped` flag stays
    /// for `dll_for_page` VA-range resolution, which is base-identical across processes).
    dll_mapped_bits: *mut [u32; 3],
}

struct ExecNtHandler {
    /// The REAL ReactOS SYSTEM hive (root = \Registry\Machine\System), parsed read-only by
    /// borrowing the regf bytes the storage host read off the disk into HIVEBUF (no 204 KiB copy —
    /// the executive heap is small). None if the hive wasn't staged on the disk.
    hive: Option<RegfHive<'static>>,
    key_handles: alloc::vec::Vec<KeyRef>,
    /// The minimal object-manager namespace (index 0 = root `\`). Pre-reserved below the heap mark
    /// like `key_handles`; entries are inline (no nested heap) so pushes never reallocate.
    obj_ns: alloc::vec::Vec<ObjEntry>,
    /// Per-call context the dispatch loop refreshes before each `dispatch` (Workstream A: the
    /// converged table-driven path carries executive context on the handler rather than a parallel
    /// mechanism). `pi` = process index (0 = smss, 1 = csrss); `stop` = a side-signal a handler
    /// sets when it can't service the call, so the loop stops the process (the ladder's
    /// `handled = false; break`).
    pi: usize,
    stop: bool,
    /// Monotonic fake-handle allocator for objects the executive doesn't model yet (ports, threads,
    /// events, sections, tokens, files). Persistent across smss + csrss (single source of truth —
    /// the remaining ladder cases reference `nt_handler.next_handle`). Migrated off the loop-local
    /// `next_handle` when the create-handle group moved onto the table (Workstream A, group A).
    next_handle: u64,
    /// Queued out-param writes (Workstream A group B2): out-writing query handlers (NtQuerySystemTime
    /// /PerformanceCounter/VolumeInformationFile) push `(ptr, value)` here instead of writing
    /// directly, because a csrss out-ptr can be an arbitrary VA that needs the loop's demand-fill
    /// bookkeeping (filled_pages/faults/scratch/reg/dll_pes/pml4). The dispatch loop drains this
    /// after `dispatch`, writing each via `csrss_out_write` (csrss) or `smss_stack_write` (smss).
    out_writes: [(u64, u64); 8],
    out_writes_n: usize,
    /// Raw refs to the loop's per-iteration state for group-C handlers (see [`ExecLoopCtx`]). Set
    /// by the Tier-1 dispatch arm before each `dispatch`; `None` outside the loop.
    loop_ctx: Option<ExecLoopCtx>,
    /// Control-flow signal-back (Workstream A group C): NtCreateProcess validates the csrss section
    /// then sets this so the LOOP performs the actual spawn (mint_badged(CSRSS_BADGE) +
    /// spawn_sec_image + per-badge state + *ProcessHandle out) after dispatch — the spawn needs
    /// fault_ep + the per-process arrays which stay loop-resident. Mirrors `stop`/the write queue.
    spawn_request: bool,
    /// Like `spawn_request` but for the 3rd hosted process: NtCreateProcess recognised winlogon's
    /// SEC_IMAGE section, so the loop spawns winlogon (badge WINLOGON_BADGE) after dispatch.
    winlogon_spawn_request: bool,
    /// Path B (authentic SM accept): set by the FIRST smss `NtCreateThread` (an `SmpApiLoop` worker)
    /// so the LOOP spawns the REAL SM-loop thread (`spawn_sm_loop_thread` — it needs smss's PML4 +
    /// the caller's SP to read the CONTEXT/PortHandle, which stay loop-resident). Mirrors `spawn_request`.
    sm_spawn_request: bool,
    /// Path B: when csrss's `NtConnectPort` leaves the connection Pending (Manual policy), the handler
    /// records the broker connection id + the caller's `*PortHandle` VA (arg0) here; the loop then
    /// drives `sm_rendezvous`, writes the completed client comm-port handle, and replies csrss. 0 = none.
    lpc_rendezvous_conn: u64,
    lpc_rendezvous_out: u64,
    /// Authentic CSR accept (mirrors the SM path): set by csrss's FIRST `NtCreateThread` (its
    /// `CsrApiRequestThread`) so the LOOP spawns the REAL CSR API thread (`spawn_csr_loop_thread`,
    /// which needs csrss's PML4 + the caller's SP — loop-resident). Parks on `CSR_FAULT_EP`.
    csr_spawn_request: bool,
    /// Authentic CSR accept: when winlogon's `NtSecureConnectPort(\Windows\ApiPort)` leaves the broker
    /// connection Pending (Manual), the handler records the broker connection id + the caller's
    /// `*PortHandle` VA here; the loop then drives `csr_rendezvous` (the REAL CsrApiRequestThread
    /// accept), writes the completed client comm-port handle, and replies winlogon. 0 = none.
    csr_rendezvous_conn: u64,
    csr_rendezvous_out: u64,
    /// The two most-recent csrss `NtCreateEvent` handles, in creation order (winsrv's power + media
    /// request events). NtUserInitialize's SSN>=0x1000 forward substitutes these for its NULL event
    /// args (our csrss demand-fill window can't write the handle back to winsrv's late .bss global),
    /// so win32k receives + models the REAL Event objects. See the `NtCreateEvent` handler.
    csrss_event_handles: [u64; 2],
    csrss_event_n: usize,
    /// A REAL in-memory NT filesystem (nt-fs MemFs + mount manager) seeded with the boot-path system
    /// binaries the loader probes. NtQueryAttributesFile resolves file EXISTENCE + attributes through
    /// this real namespace instead of a hardcoded name substring — adding a served binary is a seed
    /// call, not a handler edit. Content delivery (SEC_IMAGE demand-fault) is unchanged and still
    /// flows through nt-dll-registry + the PE loader; this only owns the exists/attributes answer.
    /// Allocated in `new()` (before the per-syscall heap mark) so it persists across the bump resets;
    /// `query_attributes` is `&self` (no handle allocation) so it never reallocates during a syscall.
    fs: FileSystem,
    /// The DATA-plane cache of established LPC connections (control/data-plane split): the isolated
    /// nt-lpc-server owns the namespace + rendezvous, but is NOT on the message path. When a CONNECT
    /// completes through the server, the executive records the connection here so the future message
    /// bulk (NtRequestWaitReplyPort/NtReplyWaitReceivePort/NtReplyPort) is served by DIRECT cross-
    /// badge delivery against this cache — never a per-message round-trip to the server. Pre-reserved
    /// below the heap mark (like `key_handles`) so pushes never reallocate across the per-syscall
    /// bump reset. Records are `Copy` (inline name, no nested heap).
    lpc_connections: alloc::vec::Vec<LpcConnRecord>,
    /// winlogon's CSR client-connect LpcWrite heap-view base (0 = the CSR regions haven't been mapped
    /// yet). Set the first time NtSecureConnectPort services winlogon's kernel32 → \Windows\ApiPort
    /// connect; guards the one-time region mapping (heap view + static server data) in that handler.
    winlogon_csr_view: u64,
    /// The real NT Process Manager (nt-process): EPROCESS/ETHREAD, per-process handle tables, and the
    /// process/thread lifecycle. FIRST convergence increment — each hosted process (smss/csrss/
    /// winlogon) is backed by a real EPROCESS created in `new()` (below the per-syscall heap mark, so
    /// its BTreeMap allocations survive the bump reset). This increment only CREATES + LOOKS UP the
    /// EPROCESSes (read-only during the loop, so no runtime realloc); the ad-hoc identity arrays +
    /// `next_handle` fakes stay live and are migrated onto this in the sequenced bulk. Policy lives
    /// here; the seL4 VSpace/CSpace/TCB caps + mirror/scratch VAs (the create MECHANISM) stay in the
    /// executive (only the trusted root task holds those caps), linked to an EPROCESS by `PM_PIDS[pi]`.
    pm: nt_process::ProcessManager,
}

/// One established LPC connection cached executive-side (the data-plane record — see
/// `ExecNtHandler::lpc_connections`). Identity + peer refs only; the message queues will live here
/// when the data plane lands. `Copy`/inline (no nested heap) so it survives the per-syscall bump reset.
// Fields are populated now (control plane) and consumed when the direct message data plane lands
// (path B / bulk) — write-only until then.
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct LpcConnRecord {
    /// The broker's connection id (ties back to the nt-lpc-server connection).
    connection_id: u64,
    /// The client comm-port handle handed to the connector.
    client_handle: u64,
    /// Which hosted process connected (0 = smss, 1 = csrss) — the connector badge for direct delivery.
    connector_pi: u8,
    /// Folded port name (inline; `\SmApiPort` etc. fit in 32 units).
    name: [u16; 32],
    name_len: u8,
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
            // Reserve up front so the backing buffer is allocated BELOW the heap
            // mark taken in service_sec_image and never reallocates during the
            // smss loop — its address stays stable across the per-syscall bump
            // reset. Opens are deduped (below), so a bounded set of distinct keys
            // never exceeds this.
            key_handles: alloc::vec::Vec::with_capacity(256),
            obj_ns: {
                let mut v = alloc::vec::Vec::with_capacity(48);
                v.push(ObjEntry::dir(b"", 0xFF)); // 0 = root "\"
                // The standard top-level directories the object manager pre-creates. SmpInit opens
                // \?? (DosDevices) + creates drive-letter symlinks in it; the rest exist so later
                // opens (\KnownDlls, \Device, \BaseNamedObjects, …) resolve rather than miss.
                // Names are stored folded (lowercase), matching obj lookups.
                for d in [
                    b"??".as_slice(),
                    b"device",
                    b"global??",
                    b"knowndlls",
                    b"basenamedobjects",
                    b"sessions",
                    b"dosdevices",
                    b"windows",
                    b"objecttypes",
                    b"driver",
                    b"filesystem",
                    b"security",
                ] {
                    v.push(ObjEntry::dir(d, 0));
                }
                v
            },
            pi: 0,
            stop: false,
            next_handle: FAKE_HANDLE,
            out_writes: [(0, 0); 8],
            out_writes_n: 0,
            loop_ctx: None,
            spawn_request: false,
            winlogon_spawn_request: false,
            sm_spawn_request: false,
            lpc_rendezvous_conn: 0,
            lpc_rendezvous_out: 0,
            csr_spawn_request: false,
            csr_rendezvous_conn: 0,
            csr_rendezvous_out: 0,
            csrss_event_handles: [0; 2],
            csrss_event_n: 0,
            fs: {
                // MemFs::with_fixture() gives the \Windows\System32\Config\* tree (so
                // \Windows\System32 exists as a directory). Seed the full boot-path binary set
                // (SYSTEM32_FILES) under System32 so nt-fs is the single authority for System32 file
                // existence. FILE_CREATE allocates a handle below the heap mark (persistent) — the
                // query path (`&self` query_attributes) never allocates one.
                let mut fs = FileSystem::new(MemFs::with_fixture());
                for name in SYSTEM32_FILES {
                    let path = alloc::format!(r"\SystemRoot\System32\{name}");
                    let r = fs.zw_create_file(&path, 0, 0, 0, nt_fs::FILE_CREATE, 0);
                    let _ = fs.zw_close(r.handle);
                }
                fs
            },
            // Reserve up front (below the per-syscall heap mark) so pushes never reallocate: a
            // bounded set of LPC connections (csrss→\SmApiPort + smss's ports) never exceeds this.
            lpc_connections: alloc::vec::Vec::with_capacity(16),
            winlogon_csr_view: 0,
            // The real Process Manager. Pre-create an EPROCESS for each hosted process (identity is
            // fixed + known ahead of the actual seL4 spawn — real NT likewise has PspCreateProcess
            // build the EPROCESS before its threads run). Creating all three here (before the
            // service_sec_image heap mark) keeps every EPROCESS allocation persistent + avoids any
            // runtime realloc under the per-syscall bump reset. `PM_PIDS[pi]` records the badge↔pid
            // link (pi 0=smss / 1=csrss / 2=winlogon); the specs verify the objects back the badges.
            pm: {
                let mut pm = nt_process::ProcessManager::new();
                // Path 1b: append-only handle values. The executive hands each hosted process its
                // OWN dense per-process handle VALUES (real NT), then indexes external state (the
                // per-pi DLL registry, EXE section scalars) by those values. NT-style slot reuse
                // would recycle a value while stale bindings to the old value still exist →
                // mis-routing the next open; append-only keeps every value monotonic for the run.
                pm.set_handle_no_reuse(true);
                let smss_pid = pm.create_process("smss.exe", None, None);
                let csrss_pid = pm.create_process("csrss.exe", Some(smss_pid), None);
                let winlogon_pid = pm.create_process("winlogon.exe", Some(smss_pid), None);
                PM_PIDS[0].store(smss_pid as u64, Ordering::Relaxed);
                PM_PIDS[1].store(csrss_pid as u64, Ordering::Relaxed);
                PM_PIDS[2].store(winlogon_pid as u64, Ordering::Relaxed);
                PM_PROC_COUNT.store(pm.process_count() as u64, Ordering::Relaxed);
                // Identity check: each EPROCESS exists, names its hosted binary, and has a distinct pid.
                let mut ok = 0u64;
                let expect: [(usize, u32, &str); 3] = [
                    (0, smss_pid, "smss.exe"),
                    (1, csrss_pid, "csrss.exe"),
                    (2, winlogon_pid, "winlogon.exe"),
                ];
                for (i, pid, name) in expect {
                    let distinct = expect.iter().filter(|e| e.1 == pid).count() == 1;
                    if distinct
                        && pm
                            .process(pid)
                            .is_some_and(|p| p.image_file_name.eq_ignore_ascii_case(name))
                    {
                        ok |= 1 << i;
                    }
                }
                PM_IDENTITY_OK.store(ok, Ordering::Relaxed);
                // Path 2 — create each hosted process's MAIN THREAD as a real ETHREAD (identity)
                // NOW, at boot, below the service_sec_image heap mark: pm.create_thread's BTreeMap/
                // BTreeSet inserts are durable but happen before the mark, so the per-syscall bump
                // reset never rewinds them (same non-leaking pattern as the EPROCESSes). This moves
                // each EPROCESS Created→Running + sets its main_thread. The real image ENTRY is bound
                // later, alloc-free, at the actual seL4 spawn (set_thread_start_address). Entry starts
                // 0 = "not yet bound".
                let mut mt_ok = 0u64;
                let pids = [smss_pid, csrss_pid, winlogon_pid];
                for (i, &pid) in pids.iter().enumerate() {
                    if let Ok(tid) = pm.create_thread(pid, 0, 0, false) {
                        PM_TIDS[i].store(tid as u64, Ordering::Relaxed);
                        let running = pm
                            .process(pid)
                            .is_some_and(|p| p.state == nt_process::ProcessState::Running);
                        let cid_ok = pm.client_id(tid) == Some(nt_process::ClientId {
                            unique_process: pid,
                            unique_thread: tid,
                        });
                        if pm.main_thread(pid) == Some(tid) && running && cid_ok {
                            mt_ok |= 1 << i;
                        }
                    }
                }
                PM_MAIN_THREADS_OK.store(mt_ok, Ordering::Relaxed);
                // Pre-reserve each EPROCESS's handle table NOW (below the service_sec_image heap
                // mark) so per-syscall `insert_handle` writes into pre-allocated storage and NEVER
                // reallocates under the per-call bump reset — the NON-LEAKING heap-reset solution.
                // Measured peak is < ~100 handles per process over a full boot; 256 is ~3× headroom.
                for pid in [smss_pid, csrss_pid, winlogon_pid] {
                    pm.reserve_handles(pid, PM_HANDLE_RESERVE);
                }
                // Record the reserved capacity (min across the 3) so the run can prove it never
                // grows — i.e. `insert_handle` never reallocates under the per-syscall reset.
                let cap = pm
                    .handle_capacity(smss_pid)
                    .min(pm.handle_capacity(csrss_pid))
                    .min(pm.handle_capacity(winlogon_pid));
                PM_HANDLE_CAP_BOOT.store(cap as u64, Ordering::Relaxed);
                pm
            },
        }
    }
    /// Resolve a fault BADGE's process index (pi) to its EPROCESS pid (the badge↔pid convergence
    /// link). Returns `None` before the ProcessManager has created that hosted process.
    fn pm_pid_for_pi(&self, pi: usize) -> Option<nt_process::ProcessId> {
        let pid = PM_PIDS.get(pi)?.load(Ordering::Relaxed);
        (pid != 0).then_some(pid as nt_process::ProcessId)
    }
    /// Mint an executive handle for the CURRENT process (`self.pi`) and record it in that process's
    /// real EPROCESS handle table (path 1 of the nt-process convergence). Behaviour-preserving: the
    /// returned VALUE is still the global monotonic `next_handle` (so the reg/LPC/win32k consumers
    /// that match on handle values are unchanged), but the durable per-process table now OWNS the
    /// handle — tagged with the value in a `HandleObject::Opaque` so `NtClose` can free it. The
    /// pre-reserved capacity guarantees the `insert_handle` never reallocates under the reset.
    fn mint_handle(&mut self) -> u64 {
        // Path 1b: return the process-LOCAL dense value the EPROCESS handle table allocates
        // (real NT `(slot+1)*4`), not a global monotonic value. Two processes each get their own
        // 0x4, 0x8, … namespace; cross-process collisions are resolved by the per-pi-keyed
        // consumers (DLL registry) + pi-scoped scalar comparisons. Append-only (no_reuse) keeps
        // each value monotonic for the run so external bindings never see a recycled value.
        if let Some(pid) = self.pm_pid_for_pi(self.pi) {
            if let Ok(h) = self.pm.insert_handle(pid, nt_process::HandleObject::Opaque(0), 0) {
                let c = self.pm.handle_count(pid) as u64;
                if c > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
                    PM_HANDLE_PEAK.store(c, Ordering::Relaxed);
                }
                PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                return h as u64;
            }
        }
        // Fallback (no EPROCESS for this pi — not the 3 hosted processes): global monotonic value.
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }
    /// Bind a hosted process's MAIN THREAD to its real image entry at the actual seL4 spawn — the
    /// "route NtCreateThread through pm at real spawn time" step (the thread object was pre-created
    /// at boot for the non-leaking heap solution; this alloc-free field write completes it).
    fn bind_main_thread_entry(&mut self, pi: usize, entry: u64) {
        if let Some(tid) = PM_TIDS.get(pi).map(|t| t.load(Ordering::Relaxed)) {
            if tid != 0 && self.pm.set_thread_start_address(tid as nt_process::ThreadId, entry) {
                PM_THREAD_BINDS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    /// `NtOpenProcess` (spec §9): open a handle to the process identified by `target_pid` in the
    /// CURRENT process's (`self.pi`) EPROCESS handle table, returning the handle VALUE (the global
    /// scheme, like every other mint) or `None` if the target/opener is unknown. The table entry is
    /// a typed `Process(target_pid)` so a later lookup/terminate resolves the real EPROCESS.
    fn nt_open_process(&mut self, target_pid: nt_process::ProcessId) -> Option<u64> {
        let opener = self.pm_pid_for_pi(self.pi)?;
        self.pm.process(target_pid)?; // target must exist
        // Path 1b: the returned VALUE is the opener's process-local dense handle for the typed
        // Process(target_pid) object — so a later value→object lookup resolves the real EPROCESS.
        let h = self
            .pm
            .insert_handle(opener, nt_process::HandleObject::Process(target_pid), 0)
            .ok()?;
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        Some(h as u64)
    }
    /// Resolve a `NtTerminateProcess`/`NtOpenProcess`-style ProcessHandle to the target EPROCESS pid.
    /// `NtCurrentProcess()` (`-1`) → the caller (self-terminate). A real child ProcessHandle is now
    /// resolved via path 1b's value→object index: process handles are dense typed `Process(pid)`
    /// entries in the CALLER's EPROCESS handle table, so `lookup_handle(caller, handle)` returns the
    /// target pid. Returns `None` for an unknown/untyped handle (→ the caller falls back to a benign
    /// no-op, never terminating the wrong process).
    fn resolve_process_handle(&self, handle: u64) -> Option<nt_process::ProcessId> {
        let caller = self.pm_pid_for_pi(self.pi)?;
        if handle == 0xFFFF_FFFF_FFFF_FFFF {
            return Some(caller); // NtCurrentProcess()
        }
        // Path 1b: dense process-local handle VALUE → typed Process(pid) object in the caller's table.
        match self.pm.lookup_handle(caller, handle as nt_process::Handle) {
            Some(nt_process::HandleObject::Process(pid)) => Some(pid),
            _ => None,
        }
    }
    /// Queue an 8-byte out-param write for the loop to perform after dispatch (group B2). Silently
    /// drops if the fixed queue is full (bounded per-syscall — no handler queues more than 6).
    fn queue_write(&mut self, ptr: u64, val: u64) {
        if self.out_writes_n < self.out_writes.len() {
            self.out_writes[self.out_writes_n] = (ptr, val);
            self.out_writes_n += 1;
        }
    }
    /// Read a UNICODE_STRING's UTF-16 buffer from the faulting process for an LPC syscall, handling
    /// a buffer that lives OUTSIDE the stack/heap/image mirrors — e.g. csrss's `NtConnectPort`
    /// PortName `L"\\SmApiPort"` is a static string in csrsrv's `.rdata` (~0x8000_xxxx). The
    /// UNICODE_STRING struct itself is a stack local (mirror-readable); its Buffer is read via the
    /// per-fault scratch alias of the already-demand-faulted `.rdata` page (`scratch_for`). Empty on
    /// failure (→ the caller's connect misses by name, a clean error, not a crash).
    /// Read an OBJECT_ATTRIBUTES.ObjectName (OA+0x10 → PUNICODE_STRING) with the SAME .rdata-capable
    /// fallback as `read_lpc_name`. The free `smss_read_objattr_name` is mirror-only, so csrss's
    /// `NtCreatePort(\Windows\ApiPort)` (name in csrsrv .rdata) registered under an EMPTY name → the
    /// broker couldn't match winlogon's connect. Use this so the port registers under its real name.
    unsafe fn read_objattr_name(&self, oa_va: u64) -> alloc::vec::Vec<u16> {
        let mut p = [0u8; 8];
        if !smss_copyin(oa_va + 0x10, &mut p) {
            return alloc::vec::Vec::new();
        }
        let objname = u64::from_le_bytes(p);
        if objname == 0 {
            return alloc::vec::Vec::new();
        }
        self.read_lpc_name(objname)
    }
    unsafe fn read_lpc_name(&self, ustr_va: u64) -> alloc::vec::Vec<u16> {
        if ustr_va == 0 {
            return alloc::vec::Vec::new();
        }
        let mut lm = [0u8; 2];
        let mut bp = [0u8; 8];
        if !smss_copyin(ustr_va, &mut lm) || !smss_copyin(ustr_va + 8, &mut bp) {
            return alloc::vec::Vec::new();
        }
        let buffer_va = u64::from_le_bytes(bp);
        let n = ((u16::from_le_bytes(lm) as usize) / 2).min(1024);
        let mut out = alloc::vec::Vec::with_capacity(n);
        for i in 0..n {
            let va = buffer_va + (i as u64) * 2;
            let mut w = [0u8; 2];
            if smss_copyin(va, &mut w) {
                out.push(u16::from_le_bytes(w));
                continue;
            }
            // Not in a mirror → try the scratch alias of an already-faulted page (csrsrv .rdata).
            if let Some(ctx) = self.loop_ctx.as_ref() {
                let fp = &*ctx.filled_pages;
                let nf = *ctx.faults as usize;
                if let Some(m) = scratch_for(va, fp, nf, ctx.scratch_base) {
                    let p = m as *const u8;
                    w[0] = *p;
                    w[1] = *p.add(1);
                    out.push(u16::from_le_bytes(w));
                    continue;
                }
            }
            break;
        }
        out
    }
    /// Cache an established LPC connection (the data-plane record). Bounded by the pre-reserved
    /// capacity so the push never reallocates across the per-syscall bump reset. `connector_pi` =
    /// the current process (0=smss, 1=csrss).
    fn cache_lpc_connection(&mut self, connection_id: u64, client_handle: u64, name: &[u16]) {
        if self.lpc_connections.len() >= self.lpc_connections.capacity() {
            return;
        }
        let mut buf = [0u16; 32];
        let n = name.len().min(32);
        buf[..n].copy_from_slice(&name[..n]);
        self.lpc_connections.push(LpcConnRecord {
            connection_id,
            client_handle,
            connector_pi: self.pi as u8,
            name: buf,
            name_len: n as u8,
        });
    }
    /// Service winlogon's kernel32 CSR client connect (NtSecureConnectPort → \Windows\ApiPort).
    ///
    /// csrss owns \Windows\ApiPort but its real CsrApiRequestThread doesn't run yet, so the executive
    /// MODELS the CSR acceptor (interim, mirroring SM path A): auto-accept through the broker + fill the
    /// reply the client reads back. kernel32's BaseDllInitialize is FATAL on a failed connect and then
    /// dereferences the shared static server data (`Peb->ReadOnlyStaticServerData[BASESRV]->
    /// WindowsDirectory`), so this must hand back real, mapped memory:
    ///  - `ClientView` (PORT_VIEW LpcWrite) ViewBase = a 64 KiB RW region kernel32 RtlCreateHeaps over.
    ///  - `ConnectionInfo` (CSR_API_CONNECTINFO) SharedSectionBase/Heap, SharedStaticServerData (→ an
    ///    array whose [BASESRV=1] slot points at a BASE_STATIC_SERVER_DATA with valid Windows dirs),
    ///    and ServerProcessId.
    /// All out-params are winlogon STACK locals (ConnectionInfo/LpcWrite) reached via the mirror; the
    /// backing regions are mapped into winlogon's own VSpace (lazily, once). Returns STATUS_SUCCESS.
    unsafe fn csr_client_connect(
        &mut self,
        name16: &[u16],
        porthandle_ptr: u64,
        clientview_ptr: u64,
        conninfo_ptr: u64,
    ) -> u32 {
        let ctx = match self.loop_ctx {
            Some(c) => c,
            None => return 0xC000_0001,
        };
        let pml4 = ctx.pml4;
        // (1) Connect through the broker (Pending under Manual). ★ AUTHENTIC accept (mirrors SM path
        // B): rather than modeling the acceptor here, RECORD the pending connection id + the caller's
        // *PortHandle so the LOOP drives `csr_rendezvous` — csrss's REAL CsrApiRequestThread issues the
        // NtReplyWaitReceivePort → CsrApiHandleConnectionRequest → NtAcceptConnectPort →
        // NtCompleteConnectPort. The loop overrides the client handle + writes *PortHandle after the
        // rendezvous. Only if the broker connect is NOT pending (no live named port) do we fall back to
        // a modeled handle + write it here. IMAGE_SUBSYSTEM_WINDOWS_GUI(2) = a Win32 GUI client.
        let mut client_handle = 0u64;
        let mut pending = false;
        if let Some(c) = lpc_client() {
            if let Ok(r) = c.connect_port(name16, 2, &[]) {
                if r.pending && r.connection_id != 0 {
                    self.csr_rendezvous_conn = r.connection_id;
                    self.csr_rendezvous_out = porthandle_ptr;
                    pending = true;
                } else if r.handle != 0 {
                    client_handle = r.handle;
                    self.cache_lpc_connection(r.connection_id, r.handle, name16);
                }
            }
        }
        if !pending && client_handle == 0 {
            client_handle = self.mint_handle();
        }
        // (2) Map winlogon's CSR regions once (heap view + static server data).
        if self.winlogon_csr_view == 0 {
            // One 2 MiB PT in winlogon covers both regions; a second PT in the executive VSpace is
            // the fill-scratch alias for populating the static data before copy_cap'ing it in.
            let wpt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wpt);
            let _ = paging_struct_map(wpt, LBL_X86_PAGE_TABLE_MAP, WINLOGON_CSR_HEAP_VA, pml4);
            let spt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
            let _ = paging_struct_map(
                spt,
                LBL_X86_PAGE_TABLE_MAP,
                WINLOGON_CSR_FILL_SCRATCH,
                CAP_INIT_THREAD_VSPACE,
            );
            // LpcWrite heap view: 16 committed RW frames (kernel32 RtlCreateHeaps over ViewBase).
            for i in 0..16u64 {
                let f = alloc_frame();
                let _ = page_map(copy_cap(f), WINLOGON_CSR_HEAP_VA + i * 0x1000, RW_NX, pml4);
            }
            // Static server data (4 frames): fill via the exec scratch alias, then map into winlogon.
            //   page0 +0x0000: ReadOnlyStaticServerData[4]; [1] -> BASE_STATIC_SERVER_DATA
            //   page0 +0x0100: BASE_STATIC_SERVER_DATA (WindowsDirectory@0, WindowsSystemDirectory@0x10,
            //                  NamedObjectDirectory@0x20 — all x64 UNICODE_STRINGs)
            //   page3 (+0x3000 in-region): the WCHAR name buffers
            for i in 0..4u64 {
                let f = alloc_frame();
                let sc = WINLOGON_CSR_FILL_SCRATCH + i * 0x1000;
                let _ = page_map(f, sc, RW_NX, CAP_INIT_THREAD_VSPACE);
                if i == 0 {
                    core::ptr::write_volatile((sc + 0x08) as *mut u64, WINLOGON_CSR_STATIC_VA + 0x0100);
                    let bssd = sc + 0x0100;
                    // WindowsDirectory = L"C:\Windows" (9 wchars)
                    core::ptr::write_volatile((bssd + 0x00) as *mut u16, 9 * 2);
                    core::ptr::write_volatile((bssd + 0x02) as *mut u16, 10 * 2);
                    core::ptr::write_volatile((bssd + 0x08) as *mut u64, WINLOGON_CSR_STATIC_VA + 0x3000);
                    // WindowsSystemDirectory = L"C:\Windows\System32" (18 wchars)
                    core::ptr::write_volatile((bssd + 0x10) as *mut u16, 18 * 2);
                    core::ptr::write_volatile((bssd + 0x12) as *mut u16, 19 * 2);
                    core::ptr::write_volatile((bssd + 0x18) as *mut u64, WINLOGON_CSR_STATIC_VA + 0x3020);
                    // NamedObjectDirectory = L"\BaseNamedObjects" (17 wchars)
                    core::ptr::write_volatile((bssd + 0x20) as *mut u16, 17 * 2);
                    core::ptr::write_volatile((bssd + 0x22) as *mut u16, 18 * 2);
                    core::ptr::write_volatile((bssd + 0x28) as *mut u64, WINLOGON_CSR_STATIC_VA + 0x3060);
                } else if i == 3 {
                    write_wstr(sc + 0x000, "C:\\Windows");
                    write_wstr(sc + 0x020, "C:\\Windows\\System32");
                    write_wstr(sc + 0x060, "\\BaseNamedObjects");
                }
                let _ = page_map(copy_cap(f), WINLOGON_CSR_STATIC_VA + i * 0x1000, RW_NX, pml4);
            }
            self.winlogon_csr_view = WINLOGON_CSR_HEAP_VA;
        }
        // (3) Fill the client PORT_VIEW (LpcWrite): ViewBase/ViewRemoteBase (delta 0 → capture pointers
        // are client pointers, which the direct message plane reads via the mirror) + ViewSize.
        if clientview_ptr != 0 {
            smss_stack_write(clientview_ptr + 0x18, 0x1_0000); // ViewSize = 64 KiB
            smss_stack_write(clientview_ptr + 0x20, WINLOGON_CSR_HEAP_VA); // ViewBase
            smss_stack_write(clientview_ptr + 0x28, WINLOGON_CSR_HEAP_VA); // ViewRemoteBase
        }
        // (4) Fill CSR_API_CONNECTINFO: kernel32 copies these into the PEB (ReadOnlySharedMemoryBase/
        // Heap, ReadOnlyStaticServerData) + records ServerProcessId.
        if conninfo_ptr != 0 {
            smss_stack_write(conninfo_ptr + 0x08, WINLOGON_CSR_HEAP_VA); // SharedSectionBase
            smss_stack_write(conninfo_ptr + 0x10, WINLOGON_CSR_STATIC_VA); // SharedStaticServerData
            smss_stack_write(conninfo_ptr + 0x18, WINLOGON_CSR_HEAP_VA); // SharedSectionHeap
            smss_stack_write(conninfo_ptr + 0x30, 8); // ServerProcessId (csrss — plausible)
        }
        // (5) *PortHandle = &CsrApiPort (an ntdll .data global) — best-effort. On the AUTHENTIC path
        // the loop writes it after `csr_rendezvous` produces the real client comm-port handle; here we
        // write only the fallback (non-pending) handle. (The modeled message plane doesn't dispatch by
        // this handle, so a silent miss is harmless.)
        if !pending && porthandle_ptr != 0 {
            csrss_out_write(
                porthandle_ptr,
                client_handle,
                &mut *ctx.filled_pages,
                &mut *ctx.faults,
                ctx.scratch_base,
                &*ctx.reg,
                &*ctx.dll_pes,
                pml4,
            );
        }
        WINLOGON_CSR_CONNECTED.store(1, Ordering::Relaxed);
        print_str(if pending {
            b"[csr] winlogon NtSecureConnectPort(\\Windows\\ApiPort) -> driving REAL CsrApiRequestThread accept; client(fallback)=0x".as_slice()
        } else {
            b"[csr] winlogon NtSecureConnectPort(\\Windows\\ApiPort) -> modeled accept; client=0x".as_slice()
        });
        print_hex((client_handle >> 32) as u32);
        print_hex(client_handle as u32);
        print_str(b" ViewBase=0x");
        print_hex((WINLOGON_CSR_HEAP_VA >> 32) as u32);
        print_hex(WINLOGON_CSR_HEAP_VA as u32);
        print_str(b" StaticData=0x");
        print_hex((WINLOGON_CSR_STATIC_VA >> 32) as u32);
        print_hex(WINLOGON_CSR_STATIC_VA as u32);
        print_str(b"\n");
        0
    }
    /// Lowercase-ASCII a UTF-16 name into a fixed buffer (object names are case-insensitive);
    /// returns the filled length. Non-ASCII code units are truncated to their low byte.
    fn fold_name(name16: &[u16], out: &mut [u8]) -> usize {
        let mut n = 0;
        for &w in name16 {
            if n >= out.len() {
                break;
            }
            out[n] = (w as u8).to_ascii_lowercase();
            n += 1;
        }
        n
    }
    /// Resolve an object path to an `obj_ns` index. A path starting with `\` walks from the root;
    /// otherwise it is relative to `root_idx` (an already-open directory, e.g. an OA RootDirectory).
    /// Empty leading components (from the leading `\`) are skipped.
    fn obj_resolve(&self, path: &[u8], root_idx: usize) -> Option<usize> {
        let mut cur = if path.first() == Some(&b'\\') {
            0
        } else {
            root_idx
        };
        for comp in path.split(|&c| c == b'\\') {
            if comp.is_empty() {
                continue;
            }
            cur = self.obj_child(cur, comp)?;
        }
        Some(cur)
    }
    /// Find a direct child of directory `parent` whose (folded) name matches `leaf`.
    fn obj_child(&self, parent: usize, leaf: &[u8]) -> Option<usize> {
        self.obj_ns
            .iter()
            .position(|e| e.parent as usize == parent && e.name() == leaf)
    }
    /// Insert a child (dir or symlink) under `parent`, or return the existing one (OPENIF/name
    /// collision → reuse). Returns the index, or None if the table is at capacity.
    fn obj_insert(&mut self, parent: usize, leaf: &[u8], kind: u8, target: &[u8]) -> Option<usize> {
        if let Some(i) = self.obj_child(parent, leaf) {
            return Some(i);
        }
        if self.obj_ns.len() >= self.obj_ns.capacity() {
            return None;
        }
        let mut e = ObjEntry::dir(leaf, parent as u8);
        e.kind = kind;
        if kind == 1 {
            let t = target.len().min(40);
            e.target[..t].copy_from_slice(&target[..t]);
            e.target_len = t as u8;
        }
        self.obj_ns.push(e);
        Some(self.obj_ns.len() - 1)
    }
    /// Create a dir/symlink named by `path` (which may be `\`-qualified or relative to `root_idx`):
    /// resolve the parent from all but the last component, then insert the leaf. Existing → reused.
    fn obj_create(&mut self, path: &[u8], root_idx: usize, kind: u8, target: &[u8]) -> Option<usize> {
        let (parent_path, leaf) = match path.iter().rposition(|&c| c == b'\\') {
            Some(p) => (&path[..p], &path[p + 1..]),
            None => (&[][..], path),
        };
        let parent = if parent_path.iter().all(|&c| c == b'\\') {
            // No real parent component: root if the path was absolute, else the supplied root.
            if path.first() == Some(&b'\\') {
                0
            } else {
                root_idx
            }
        } else {
            self.obj_resolve(parent_path, root_idx)?
        };
        if leaf.is_empty() {
            return Some(parent);
        }
        self.obj_insert(parent, leaf, kind, target)
    }
    /// Resolve a full NT key path (`\Registry\Machine\System\…`) to a key node in the SYSTEM hive:
    /// apply the CurrentControlSet alias (the hive has ControlSet001, not the kernel-synthesized
    /// CurrentControlSet symlink) + strip the hive's mount prefix.
    fn resolve_key(&self, full_path: &str) -> Option<KeyRef> {
        let aliased = apply_ccs_alias(full_path);
        let comps: alloc::vec::Vec<&str> =
            aliased.split('\\').filter(|c| !c.is_empty()).collect();
        if comps.len() < 3
            || !comps[0].eq_ignore_ascii_case("Registry")
            || !comps[1].eq_ignore_ascii_case("Machine")
        {
            return None;
        }
        if comps[2].eq_ignore_ascii_case("System") {
            return self.hive.as_ref()?.open_key(&comps[3..].join("\\"));
        }
        // The kernel's volatile HARDWARE hive isn't on disk. Synthesize the one key smss's SmpInit
        // reads: \Registry\Machine\Hardware\Description\System\CentralProcessor\0 (CPU identifier).
        let ci = |i: usize, s: &str| comps.get(i).map_or(false, |c| c.eq_ignore_ascii_case(s));
        if comps.len() == 7
            && ci(2, "Hardware")
            && ci(3, "Description")
            && ci(4, "System")
            && ci(5, "CentralProcessor")
            && ci(6, "0")
        {
            return Some(SYNTH_CPU_KEY);
        }
        None
    }
    /// Does a `\SystemRoot\System32` file with this probe's leaf name exist in the real nt-fs
    /// namespace? Extracts the leaf (last `\`-component) of the folded probe path and looks it up
    /// under System32 — path-form independent (the loader probes many directory prefixes for the
    /// same DLL). nt-fs is the single existence authority; nt-dll-registry keeps SEC_IMAGE geometry.
    fn fs_system32_has(&self, folded: &[u8]) -> bool {
        let leaf = match folded.iter().rposition(|&c| c == b'\\') {
            Some(p) => &folded[p + 1..],
            None => folded,
        };
        if leaf.is_empty() {
            return false;
        }
        let Ok(leaf_str) = core::str::from_utf8(leaf) else {
            return false;
        };
        let mut path = alloc::string::String::from(r"\SystemRoot\System32\");
        path.push_str(leaf_str);
        self.fs.query_attributes(&path).is_some()
    }
}
impl NativeSyscallHandler for ExecNtHandler {
    fn handle(&mut self, ctx: &NativeCallContext, args: &[u64], _out: &mut alloc::vec::Vec<u8>) -> u32 {
        match ctx.service {
            // NtClose(Handle[R10]=args[0]): free the handle in the caller's REAL EPROCESS handle
            // table by its SLOT (path 1b — the value IS the dense per-process table handle now, so
            // close by value directly; no value-tag scan). Append-only allocation means the freed
            // slot is NOT recycled, so a later open never reuses a closed value (keeping external
            // bindings — the per-pi DLL registry — consistent). We still return SUCCESS
            // unconditionally (matching the prior no-op) so a close of a handle the executive
            // doesn't own — a win32k/Ob handle, a pseudo-handle, or a fallback global value — stays
            // benign. Purely additive: the returned status is unchanged.
            NativeService::NtClose => {
                if let Some(pid) = self.pm_pid_for_pi(self.pi) {
                    if self.pm.close_handle(pid, args[0] as nt_process::Handle).is_ok() {
                        PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
                    }
                }
                0 // STATUS_SUCCESS
            }
            // NtOpenKey(*KeyHandle[0], DesiredAccess[1], ObjectAttributes[2]). Copy in the object
            // name from smss, resolve it in the SYSTEM hive, hand back a handle (copyout to arg0).
            NativeService::NtOpenKey => unsafe {
                // OBJECT_ATTRIBUTES: RootDirectory @+8, ObjectName @+0x10. RtlQueryRegistryValues
                // opens subkeys RELATIVE to an already-open key (RootDirectory = its handle,
                // ObjectName = a leaf like "Environment"), so honour RootDirectory.
                let oa = args[2];
                let mut rd = [0u8; 8];
                let _ = smss_copyin(oa + 8, &mut rd);
                let root_dir = u64::from_le_bytes(rd);
                let name16 = smss_read_objattr_name(oa);
                let mut path = alloc::string::String::new();
                for &w in &name16 {
                    if let Some(c) = char::from_u32(w as u32) {
                        path.push(c);
                    }
                }
                let cell = if root_dir >= KEY_HANDLE_BASE {
                    let idx = (root_dir - KEY_HANDLE_BASE) as usize;
                    match (self.hive.as_ref(), self.key_handles.get(idx).copied()) {
                        (Some(h), Some(parent)) => h.open_key_from(parent, &path),
                        _ => None,
                    }
                } else {
                    self.resolve_key(&path)
                };
                match cell {
                    Some(cell) => {
                        // Dedup: smss reopens the same keys in a loop and NtClose is a no-op, so
                        // return the existing handle for a known cell instead of growing the table
                        // unboundedly (which would reallocate its buffer above the heap mark and
                        // get clobbered by the per-syscall bump reset).
                        let idx = match self.key_handles.iter().position(|&c| c == cell) {
                            Some(i) => i,
                            None => {
                                self.key_handles.push(cell);
                                self.key_handles.len() - 1
                            }
                        };
                        let h = KEY_HANDLE_BASE + idx as u64;
                        smss_copyout(args[0], &h.to_le_bytes());
                        0 // STATUS_SUCCESS
                    }
                    None => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            // NtEnumerateValueKey(KeyHandle[0], Index[1], InfoClass[2], KeyValueInfo[3], Length[4],
            // *ResultLength[5]). Enumerate the value at Index from the real hive + copy the
            // KEY_VALUE_*_INFORMATION out; SmpInit reads the Environment/DOS-Devices/etc. values.
            NativeService::NtEnumerateValueKey => unsafe {
                let hive = match self.hive.as_ref() {
                    Some(h) => h,
                    None => return 0xC000_0008, // STATUS_INVALID_HANDLE
                };
                let key = match self
                    .key_handles
                    .get(args[0].wrapping_sub(KEY_HANDLE_BASE) as usize)
                    .copied()
                {
                    Some(k) => k,
                    None => return 0xC000_0008, // STATUS_INVALID_HANDLE
                };
                let byname: Option<(alloc::string::String, u32, alloc::vec::Vec<u8>)> =
                    if key == SYNTH_CPU_KEY {
                        // The synthetic CPU key has 2 values (Identifier, VendorIdentifier).
                        let entry = match args[1] {
                            0 => Some(("Identifier", "identifier")),
                            1 => Some(("VendorIdentifier", "vendoridentifier")),
                            _ => None,
                        };
                        entry.and_then(|(nm, lc)| {
                            synth_cpu_value(lc)
                                .map(|(ty, d16)| (alloc::string::String::from(nm), ty, utf16_bytes(&d16)))
                        })
                    } else {
                        hive.value_by_index(key, args[1] as usize)
                    };
                match byname {
                    None => 0x8000_001A, // STATUS_NO_MORE_ENTRIES
                    Some((name, ty, data)) => {
                        let info = build_key_value_info(args[2], &name, ty, &data);
                        smss_copyout(args[5], &(info.len() as u32).to_le_bytes()); // *ResultLength
                        if info.len() > args[4] as usize {
                            0x8000_0005 // STATUS_BUFFER_OVERFLOW
                        } else {
                            smss_copyout(args[3], &info);
                            0 // STATUS_SUCCESS
                        }
                    }
                }
            },
            // NtQueryValueKey(KeyHandle[0], *ValueName[1], InfoClass[2], KeyValueInfo[3], Length[4],
            // *ResultLength[5]). SmpInit reads Identifier/VendorIdentifier from the synthetic CPU
            // key to build PROCESSOR_IDENTIFIER. Real-hive values by name → not-found (smss defaults).
            NativeService::NtQueryValueKey => unsafe {
                let key = match self
                    .key_handles
                    .get(args[0].wrapping_sub(KEY_HANDLE_BASE) as usize)
                    .copied()
                {
                    Some(k) => k,
                    None => return 0xC000_0008, // STATUS_INVALID_HANDLE
                };
                let name16 = smss_read_ustr(args[1]);
                let mut name_lc = alloc::string::String::new();
                for &w in &name16 {
                    if let Some(c) = char::from_u32(w as u32) {
                        name_lc.push(c.to_ascii_lowercase());
                    }
                }
                let val: Option<(u32, alloc::vec::Vec<u8>)> = if key == SYNTH_CPU_KEY {
                    synth_cpu_value(&name_lc).map(|(ty, d16)| (ty, utf16_bytes(&d16)))
                } else {
                    None // real-hive value-by-name not modelled yet
                };
                match val {
                    None => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND — smss uses defaults
                    Some((ty, data)) => {
                        // KeyValuePartialInformation (class 2) carries no name.
                        let info = build_key_value_info(args[2], "", ty, &data);
                        smss_copyout(args[5], &(info.len() as u32).to_le_bytes());
                        if info.len() > args[4] as usize {
                            0x8000_0005 // STATUS_BUFFER_OVERFLOW
                        } else {
                            smss_copyout(args[3], &info);
                            0 // STATUS_SUCCESS
                        }
                    }
                }
            },
            // NtQuerySystemInformation(Class[R10]=args[0], Buffer[RDX]=args[1], Len[R8]=args[2],
            // *RetLen[R9]=args[3]). RtlCreateHeap needs SystemBasicInformation (class 0): PageSize,
            // AllocationGranularity, and the user-mode address range. Copyout the fields it reads.
            NativeService::NtQuerySystemInformation => unsafe {
                let class = args[0];
                let buf = args[1];
                let retlen_ptr = args[3]; // R9 = *ReturnLength (a register)
                if class == 0 {
                    smss_stack_write(buf + 0x08, 0x1000); // PageSize
                    smss_stack_write(buf + 0x18, 0x10000); // AllocationGranularity
                    smss_stack_write(buf + 0x20, 0x10000); // MinimumUserModeAddress
                    smss_stack_write(buf + 0x28, 0x0000_7FFF_FFFE_FFFF); // MaximumUserModeAddress
                    smss_stack_write(retlen_ptr, 0x40);
                }
                0
            },
            // NtQueryInformationProcess(Handle[R10]=args[0], Class[RDX]=args[1], Buffer[R8]=args[2],
            // Len[R9]=args[3], *RetLen[arg5]=args[4]).
            NativeService::NtQueryInformationProcess => unsafe {
                let class = args[1]; // ProcessInformationClass
                let buf = args[2]; // R8 = ProcessInformation buffer (a stack local)
                if class == 0 {
                    // ProcessBasicInformation — PROCESS_BASIC_INFORMATION (x64, 48 bytes). Both
                    // processes' PEB is at PEB_VA (own VSpace).
                    smss_stack_write(buf + 0x00, 0); // ExitStatus (running)
                    smss_stack_write(buf + 0x08, PEB_VA); // PebBaseAddress
                    smss_stack_write(buf + 0x10, 1); // AffinityMask
                    smss_stack_write(buf + 0x18, 13); // BasePriority
                    smss_stack_write(buf + 0x20, (self.pi as u64 + 1) * 0x100); // UniqueProcessId (fake)
                    smss_stack_write(buf + 0x28, 0); // InheritedFromUniqueProcessId
                    let retlen = args[4]; // *ReturnLength
                    if retlen != 0 {
                        smss_stack_write32(retlen, 48);
                    }
                    0
                } else if class == 36 {
                    // ProcessCookie — a per-process value ntdll caches for RtlEncode/DecodePointer.
                    smss_stack_write(buf, 0x1a2b_3c4d);
                    0
                } else if class == 28 {
                    // ProcessLUIDDeviceMapsEnabled — a ULONG BOOL. Not enabled → 0.
                    smss_stack_write32(buf, 0);
                    let retlen = args[4];
                    if retlen != 0 {
                        smss_stack_write32(retlen, 4);
                    }
                    0
                } else if class == 23 {
                    // ProcessDeviceMap — an EMPTY drive map (no drives) so SmpCreatePagingFiles
                    // finds no boot volume and smss proceeds without a paging file.
                    for k in 0..(36u64 / 4) {
                        smss_stack_write32(buf + k * 4, 0);
                    }
                    let retlen = args[4];
                    if retlen != 0 {
                        smss_stack_write32(retlen, 36);
                    }
                    0
                } else {
                    print_str(b"[ntos-exec] NtQueryInformationProcess class=");
                    print_u64(class);
                    print_str(b" len=");
                    print_u64(args[3]);
                    print_str(b"\n");
                    self.stop = true; // surfaces the class — stop the process
                    0xC0000002 // STATUS_NOT_IMPLEMENTED
                }
            },
            // NtProtectVirtualMemory(Process, *Base, *Size, NewProtect, *OldProtect[arg5]=args[4]).
            // We don't model per-page protection yet — report success + a plausible previous
            // protection so LdrpInitialize's protect/restore pairs proceed.
            NativeService::NtProtectVirtualMemory => unsafe {
                let oldprot_ptr = args[4]; // *OldAccessProtection
                if oldprot_ptr != 0 {
                    // DWORD write: OldProtect is a ULONG; an 8-byte write clobbers the caller's
                    // adjacent local (in LdrpSetProtection that is the section-header pointer).
                    smss_stack_write32(oldprot_ptr, 0x04); // PAGE_READWRITE
                }
                0
            },
            // NtDisplayString(*String[R10]=args[0] = PUNICODE_STRING). smss prints boot/status text;
            // route it to the serial console.
            NativeService::NtDisplayString => unsafe {
                let s16 = smss_read_ustr(args[0]);
                print_str(b"[smss] ");
                for &w in &s16 {
                    let b = w as u8;
                    debug_put_char(if (0x20..0x7f).contains(&b) || b == b'\n' {
                        b
                    } else {
                        b'.'
                    });
                }
                print_str(b"\n");
                0
            },
            // NtQueryDebugFilterState — return FALSE (filter disabled), the state of a machine with
            // no kernel debugger attached, so DbgPrintEx suppresses the message (see the ladder note
            // this replaces: a TRUE here makes ntdll format a null-relative string → VMFault).
            NativeService::NtQueryDebugFilterState => 0,
            // NtOpenThreadToken — no impersonation token → STATUS_NO_TOKEN; the caller falls back to
            // the process token.
            NativeService::NtOpenThreadToken => 0xC000007C,
            // NtCreatePort(*PortHandle[R10=args[0]], *ObjectAttributes[RDX=args[1]],
            // MaxConnInfo[R8=args[2]], MaxMsg[R9=args[3]], MaxPool[stack]). Create a REAL named port
            // in the isolated LPC connection broker (control plane) and hand the caller its handle.
            // ★ BUG FIX: the out *PortHandle is arg1 = R10 (the x64 out-arg; the stub did `mov r10,rcx`
            // and RCX at the fault holds the return IP). The old fake wrote RCX → csrsrv's CsrSbApiPort
            // stayed 0 → SmConnectToSm returned STATUS_INVALID_PARAMETER_MIX before ever issuing
            // NtConnectPort. Writing to R10 via the out-writer queue (csrss: a .data global; smss: a
            // stack local) lands the handle where the caller reads it → SmConnectToSm reaches connect.
            NativeService::NtCreatePort => unsafe {
                // Robust .rdata-capable name read (csrss's \Windows\ApiPort name is in csrsrv .rdata,
                // unreachable by the mirror-only smss_read_objattr_name) so the port registers under
                // its real name → winlogon's NtSecureConnectPort matches it → the authentic CSR accept.
                let mut name16 = self.read_objattr_name(args[1]);
                if name16.is_empty() {
                    name16 = smss_read_objattr_name(args[1]);
                }
                // csrss's OA + ObjectName UNICODE_STRING are csrsrv .data globals unreachable by the
                // mirror/scratch readers → the name reads EMPTY, so the port would register unnamed and
                // winlogon's NtSecureConnectPort(\Windows\ApiPort) could not match it. csrss creates
                // exactly two ports, in a fixed order: CsrApiPortInitialize(\Windows\ApiPort) then
                // CsrSbApiPortInitialize(\Windows\SbApiPort). Assign the canonical name by order so the
                // ports register correctly → the authentic CSR accept can find the pending connection.
                if self.pi == 1 && name16.is_empty() {
                    let n = CSR_CREATEPORT_N.fetch_add(1, Ordering::Relaxed);
                    let canon: &str = if n == 0 { "\\Windows\\ApiPort" } else { "\\Windows\\SbApiPort" };
                    name16 = canon.encode_utf16().collect();
                }
                let handle = lpc_client()
                    .and_then(|c| {
                        c.create_port(&name16, args[2] as u32, args[3] as u32, 0).ok()
                    })
                    .unwrap_or_else(|| {
                        self.mint_handle()
                    });
                self.queue_write(args[0], handle);
                0
            },
            // SM/CSR worker threads + semaphores. ★ OUT-PARAM FIX (path-B prep): the fake handle now
            // goes to the x64 out-arg0 *Handle = R10 = args[0] via the out-writer queue (was RCX =
            // get_recv_mr(2), which at UnknownSyscall-fault holds the syscall RETURN IP, so the handle
            // landed on a code address and silently missed) — the SAME class as the NtCreatePort /
            // NtCreateEvent bug. Harmless-but-latent while the handles are unused; making it correct is
            // load-bearing for the AUTHENTIC path B (smss's real SmpApiLoop thread needs a REAL handle
            // from NtCreateThread), so land the correct target now. NtCreateThread's REAL spawn (a
            // running smss thread in smss's VSpace) is the next path-B step.
            NativeService::NtCreateThread | NativeService::NtCreateSemaphore => {
                let h = self.mint_handle();
                self.queue_write(args[0], h); // *Handle = R10 = args[0] (drained via smss_stack_write)
                // Path B: smss creates its SmpApiLoop worker threads via NtCreateThread. Signal the
                // loop to spawn ONE REAL SM-loop thread (the first). The loop reads the CONTEXT (Rip =
                // SmpApiLoop, Rcx = \SmApiPort handle) off the caller's stack + spawns in smss's PML4.
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 0
                    && SM_LOOP_TCB.load(Ordering::Relaxed) == 0
                {
                    self.sm_spawn_request = true;
                }
                // Authentic CSR accept: csrss's FIRST NtCreateThread is its CsrApiRequestThread
                // (CsrApiPortInitialize runs before CsrSbApiPortInitialize). Spawn ONE real thread.
                // ★ Also write a chosen ClientId to the *ClientId out-param ([sp+0x28] = arg5): csrss's
                // CsrAddStaticServerThread then registers a CSR_THREAD with this CID, so the connection
                // rendezvous can marshal the SAME CID into the connect message → CsrLocateThreadByClientId
                // finds it → CsrProcess=CsrRootProcess → the accept is ALLOWED (the self-connect
                // simplification, analogous to SM's PID_SMSS — FLAGGED residual).
                if matches!(ctx.service, NativeService::NtCreateThread)
                    && self.pi == 1
                    && CSR_LOOP_TCB.load(Ordering::Relaxed) == 0
                {
                    unsafe {
                        let sp = get_recv_mr(16);
                        let cid_ptr = smss_stack_read(sp + 0x28); // arg5 = *ClientId
                        if cid_ptr != 0 {
                            self.queue_write(cid_ptr, CSR_STATIC_CID_PROC);
                            self.queue_write(cid_ptr + 8, CSR_STATIC_CID_THREAD);
                        }
                    }
                    self.csr_spawn_request = true;
                }
                0
            }
            // NtSecureConnectPort — the CSR client connect (kernel32's CsrClientConnectToServer →
            // \Windows\ApiPort, from winlogon's BaseDllInitialize). The SECURE variant (SecurityQos +
            // ServerSid) is CSR-only in this system: SmConnectToSm uses plain NtConnectPort(33), so 218
            // unambiguously means "a Win32 client connecting to CSR". csrss OWNS \Windows\ApiPort but
            // its real CsrApiRequestThread doesn't run (interim), so the executive MODELS the CSR
            // acceptor: auto-accept in the broker + fill the CSR_API_CONNECTINFO reply (SharedSection
            // pointers + a BASE_STATIC_SERVER_DATA) + the LpcWrite PORT_VIEW, so kernel32's DllMain
            // proceeds. See `csr_client_connect`. (Authentic swap: drive csrss's real
            // CsrApiRequestThread via a csr_rendezvous, mirroring the SM path A→B.)
            // x64 ABI: PortHandle=R10=args[0], PortName=RDX=args[1], SecurityQos=R8, ClientView=R9,
            // ServerSid=[sp+0x28], ServerView=[sp+0x30], MaxMsgLen=[sp+0x38], ConnInfo=[sp+0x40],
            // ConnInfoLen=[sp+0x48].
            NativeService::NtSecureConnectPort => unsafe {
                let name16 = self.read_lpc_name(args[1]);
                let sp = get_recv_mr(16);
                let porthandle_ptr = get_recv_mr(9); // R10 = *PortHandle (&CsrApiPort, ntdll .data)
                let clientview_ptr = get_recv_mr(8); // R9 = *ClientView (PORT_VIEW, stack local)
                let conninfo_ptr = smss_stack_read(sp + 0x40); // arg8 = *ConnectionInformation (stack)
                self.csr_client_connect(&name16, porthandle_ptr, clientview_ptr, conninfo_ptr)
            },
            // NtRequestWaitReplyPort(PortHandle=R10, RequestMessage=RDX, ReplyMessage=R8) — the LPC
            // message DATA plane. kernel32's CsrClientCallServer sends the CsrpClientConnect message
            // (ApiNumber 0, ServerId=BASESRV) right after the port connect; its reply Status must be
            // STATUS_SUCCESS or BaseDllInitialize fails. Serviced by the DIRECT cross-badge message
            // plane: the executive reads the CSR_API_MESSAGE off the caller's stack (mirror) and models
            // csrss's reply in place (Status=SUCCESS), against the cached winlogon↔\Windows\ApiPort
            // LpcConnRecord — never a round-trip to the isolated broker. (Interim: a real acceptor would
            // be csrss's CsrApiRequestThread; this models it, like SM path A.)
            NativeService::NtRequestWaitReplyPort => unsafe {
                let reqmsg = args[1]; // RDX = &ApiMessage.Header (request, in/out = same buffer)
                // CSR_API_MESSAGE: PORT_MESSAGE Header(0x28), CsrCaptureData@0x28, ApiNumber@0x30,
                // Status@0x34. Read ApiNumber, model the CSR server: every call → STATUS_SUCCESS.
                let api_number = {
                    let mut b = [0u8; 4];
                    if smss_copyin(reqmsg + 0x30, &mut b) {
                        u32::from_le_bytes(b)
                    } else {
                        0xFFFF_FFFF
                    }
                };
                // Reply in place: Status@+0x34 = STATUS_SUCCESS + mark the PORT_MESSAGE Type = LPC_REPLY.
                smss_stack_write32(reqmsg + 0x34, 0); // ApiMessage.Status = STATUS_SUCCESS
                smss_stack_write16(reqmsg + 0x04, nt_lpc_abi::msg_type::LPC_REPLY); // Header.u2.s2.Type
                print_str(b"[csr-msg] winlogon CsrClientCallServer ApiNumber=0x");
                print_hex(api_number);
                print_str(b" -> modeled reply Status=SUCCESS (direct message plane)\n");
                CSR_MSGS.fetch_add(1, Ordering::Relaxed);
                0
            },
            // NtConnectPort(*PortHandle[R10=args[0]], *PortName[RDX=args[1]], *Qos[R8], *ClientView[R9],
            // *ServerView, *MaxMsg, *ConnInfo, *ConnInfoLen). The SM connect (SmConnectToSm →
            // \SmApiPort). Route to the LPC broker; on the interim AutoAccept path the connect completes
            // synchronously → write the client comm-port handle to the caller's *PortHandle (arg1=R10)
            // + cache the connection; on Manual (path B) the loop drives the authentic SmpApiLoop accept
            // via sm_rendezvous. This is what unblocks csrss's SmConnectToSm.
            NativeService::NtConnectPort => unsafe {
                let name16 = self.read_lpc_name(args[1]);
                match lpc_client().map(|c| c.connect_port(&name16, 0, &[])) {
                    Some(Ok(r)) => {
                        if !r.pending && r.handle != 0 {
                            // AutoAccept (interim): the broker modelled the acceptor — complete now.
                            self.queue_write(args[0], r.handle);
                            self.cache_lpc_connection(r.connection_id, r.handle, &name16);
                            0 // STATUS_SUCCESS
                        } else if r.pending {
                            // Manual (path B, authentic): the connection is Pending in the broker.
                            // Signal the LOOP to drive `sm_rendezvous` (the REAL SmpApiLoop accept)
                            // synchronously, write the completed client comm-port handle to *PortHandle
                            // (args[0]=R10), and reply csrss. The loop needs smss's PML4 + the smss
                            // image/ntdll refs (loop-resident), so it can't run here.
                            self.lpc_rendezvous_conn = r.connection_id;
                            self.lpc_rendezvous_out = args[0];
                            0 // SUCCESS (the loop overrides with the rendezvous outcome)
                        } else {
                            0x0000_0103 // STATUS_PENDING (broker returned no handle + not pending)
                        }
                    }
                    Some(Err(st)) => st.raw() as u32, // e.g. OBJECT_NAME_NOT_FOUND
                    None => 0xC000_0001,              // STATUS_UNSUCCESSFUL (broker absent)
                }
            },
            // NtAcceptConnectPort/NtCompleteConnectPort — the server-side rendezvous (path B). Under
            // AutoAccept these are not reached (the server models the acceptor at connect); wired to
            // the broker so path B is a policy swap, not new plumbing.
            NativeService::NtAcceptConnectPort => unsafe {
                // (*PortHandle[R10], PortContext[RDX], *ConnReq[R8], Accept[R9], ...). We don't yet
                // decode the connection id from the received PORT_MESSAGE (path B), so accept the most
                // recent pending connection is a bulk concern — return success placeholder for now.
                let h = self.mint_handle();
                self.queue_write(args[0], h);
                0
            },
            NativeService::NtCompleteConnectPort => 0,
            // NtCreateEvent(*EventHandle[R10], ACCESS, *OA, EVENT_TYPE, InitialState). winsrv's
            // UserServerDllInitialization creates ghPowerRequestEvent/ghMediaRequestEvent here and
            // hands them to NtUserInitialize (SSN 0x125a); win32k's IntInitWin32PowerManagement then
            // does ObReferenceObjectByHandle(hEvent, *ExEventObjectType, &gpPowerRequestCalloutEvent)
            // on the power event. So the minted handle MUST reach the caller's *EventHandle — which
            // is arg1 = R10 (the x64 out-arg; the syscall stub moved the caller's RCX there, and RCX
            // at the fault holds the return IP, out of any writable range). For csrss that PHANDLE is
            // a winsrv .data global, so QUEUE the write for the loop's per-process out-writer
            // (csrss_out_write demand-pages the global; smss_stack_write handles an smss stack local).
            // The out PHANDLE is arg1 = R10, and for csrss it is a winsrv .bss global. Our csrss
            // demand-fill window is only 256 pages (csrss demand-pages ~343), so `csrss_out_write`
            // cannot reliably reach winsrv's late .bss page — the handle would arrive back at winsrv
            // as NULL (as it did pre-fix, masked by a fake). So instead of writing the flaky global,
            // RECORD the minted handle (csrss only) and DELIVER it to win32k by substituting it into
            // NtUserInitialize's event args at the forward point (see the SSN>=0x1000 arm). That gives
            // win32k the REAL event handles winsrv created, which it models as typed Event objects.
            // (Memory behaviour matches the pre-fix baseline: nothing is written to the caller here.)
            NativeService::NtCreateEvent => {
                let h = self.mint_handle();
                if self.pi == 1 {
                    // Keep the two most-recent csrss event handles in creation order (winsrv creates
                    // hPowerRequestEvent then hMediaRequestEvent right before NtUserInitialize).
                    if self.csrss_event_n < self.csrss_event_handles.len() {
                        self.csrss_event_handles[self.csrss_event_n] = h;
                    } else {
                        self.csrss_event_handles[0] = self.csrss_event_handles[1];
                        self.csrss_event_handles[1] = h;
                    }
                    self.csrss_event_n += 1;
                }
                0
            }
            // NtOpenProcessToken(ProcessHandle, DesiredAccess, *TokenHandle). R8 = out handle.
            NativeService::NtOpenProcessToken => unsafe {
                let out = get_recv_mr(7); // R8
                let h = self.mint_handle();
                smss_stack_write(out, h);
                0
            },
            // NtMakeTemporaryObject — clears OBJ_PERMANENT on a link SmpInit re-creates; we don't
            // track permanence. Success no-op.
            NativeService::NtMakeTemporaryObject => 0,
            // No-op → STATUS_SUCCESS: the bump allocator never frees, we don't model thread/process
            // attribute sets, per-object security, keyed events, or a real handle table. (277
            // NtUnmapViewOfSection: we never reclaim a mapped view; 246 NtSetSecurityObject; 214
            // NtResumeThread: CSR worker not modeled; 236 NtSetInformationObject.)
            NativeService::NtFreeVirtualMemory
            | NativeService::NtSetInformationThread
            | NativeService::NtSetInformationProcess
            | NativeService::NtTestAlert
            | NativeService::NtFlushInstructionCache
            | NativeService::NtCreateKeyedEvent
            | NativeService::NtAdjustPrivilegesToken
            | NativeService::NtDeleteValueKey
            | NativeService::NtInitializeRegistry
            | NativeService::NtSetValueKey
            | NativeService::NtSetSystemInformation
            | NativeService::NtUnmapViewOfSection
            | NativeService::NtSetSecurityObject
            | NativeService::NtResumeThread
            | NativeService::NtSetInformationObject => 0,
            // NtQueryVirtualMemory(Process, Base[RDX]=args[1], Class, Buffer[R9]=args[3], Len,
            // *RetLen[arg6]=args[5]). LdrpInitialize queries MemoryBasicInformation (class 0) for
            // [TEB+0x10]. Report a plausible committed private region; the env page is 1-page.
            NativeService::NtQueryVirtualMemory => unsafe {
                let base = args[1];
                let buf = args[3];
                let retlen_ptr = args[5];
                let page = base & !0xFFFu64;
                // The env block is a SINGLE mapped page at SMSS_PARAMS_VA+0x1000; report the true
                // 1-page region so ntdll's env-duplication memmove stays in bounds.
                let is_env = page == SMSS_PARAMS_VA + 0x1000;
                let region = if is_env { 0x1000u64 } else { 0x10000u64 };
                let alloc_base = if is_env { page } else { base & !0xFFFFu64 };
                smss_stack_write(buf + 0x00, page); // BaseAddress
                smss_stack_write(buf + 0x08, alloc_base); // AllocationBase
                smss_stack_write(buf + 0x10, 0x04); // AllocationProtect = PAGE_READWRITE
                smss_stack_write(buf + 0x18, region); // RegionSize
                smss_stack_write(buf + 0x20, 0x1000 | (0x04u64 << 32)); // State=MEM_COMMIT, Protect=RW
                smss_stack_write(buf + 0x28, 0x20000); // Type = MEM_PRIVATE
                if retlen_ptr != 0 {
                    smss_stack_write(retlen_ptr, 0x30);
                }
                0
            },
            // NtQueryInformationToken(TokenHandle, Class[RDX]=args[1], buf[R8]=args[2],
            // len[R9]=args[3], *RetLen[arg5]=args[4]). csrss runs as Local System (S-1-5-18).
            NativeService::NtQueryInformationToken => unsafe {
                let class = args[1];
                let buf = args[2];
                let len = args[3];
                let retlen_ptr = args[4];
                match class {
                    1 | 5 => {
                        // TokenUser(1)/TokenPrimaryGroup(5): SID_AND_ATTRIBUTES + the S-1-5-18 SID.
                        let needed: u32 = 0x1C;
                        if len < needed as u64 {
                            if let Some(m) = smss_mirror(retlen_ptr, 4) {
                                core::ptr::write_volatile(m as *mut u32, needed);
                            }
                            0xC000_0023 // STATUS_BUFFER_TOO_SMALL
                        } else if let Some(m) = smss_mirror(buf, needed as u64) {
                            core::ptr::write_volatile((m + 0x00) as *mut u64, buf + 0x10); // Sid → +0x10
                            core::ptr::write_volatile((m + 0x08) as *mut u32, 0); // Attributes
                            core::ptr::write_volatile((m + 0x10) as *mut u64, 0x0500_0000_0000_0101); // Rev,Cnt,IdAuth
                            core::ptr::write_volatile((m + 0x18) as *mut u32, 18); // SubAuthority[0]
                            if let Some(rl) = smss_mirror(retlen_ptr, 4) {
                                core::ptr::write_volatile(rl as *mut u32, needed);
                            }
                            0
                        } else {
                            0xC000_0023
                        }
                    }
                    _ => {
                        print_str(b"[ntos-exec] NtQueryInformationToken class=");
                        print_u64(class);
                        print_str(b" (unhandled)\n");
                        self.stop = true;
                        0xC0000002
                    }
                }
            },
            // NtQueryObject(Handle[R10]=args[0], class[RDX]=args[1], buf[R8]=args[2], len[R9]=args[3],
            // *RetLen[arg5]=args[4]). DIAGNOSTIC: log + return a zeroed buffer + retlen.
            NativeService::NtQueryObject => unsafe {
                let class = args[1];
                let handle = args[0];
                let buf = args[2];
                let len = args[3];
                let retlen_ptr = args[4];
                print_str(b"[ntos-exec] NtQueryObject handle=0x");
                print_hex(handle as u32);
                print_str(b" class=");
                print_u64(class);
                print_str(b" len=");
                print_u64(len);
                print_str(b"\n");
                if len > 0 {
                    if let Some(m) = smss_mirror(buf, len.min(64)) {
                        for i in 0..len.min(64) {
                            core::ptr::write_volatile((m + i) as *mut u8, 0);
                        }
                    }
                }
                if retlen_ptr != 0 {
                    if let Some(m) = smss_mirror(retlen_ptr, 4) {
                        core::ptr::write_volatile(m as *mut u32, 0);
                    }
                }
                0
            },
            // NtWaitForSingleObject — csrsrv's CsrApiPortInitialize waits on its worker-thread
            // startup event; we don't model the worker → STATUS_WAIT_0 (0) so init proceeds.
            // Scoped to csrss (pi==1); smss never issues 281, so a smss 281 stops (as before).
            NativeService::NtWaitForSingleObject => {
                if self.pi == 1 {
                    0
                } else {
                    // smss now issues 281 too: SmpLoadSubSystem waits on NewSubsystem->Event for csrss
                    // to signal init-complete (smsubsys.c:432). csrss IS initialized (parked after
                    // CsrServerInitialization), so model the wait as satisfied (STATUS_WAIT_0). Print
                    // the handle + caller chain once for identification while grinding forward.
                    unsafe {
                        let sp = get_recv_mr(16);
                        print_str(b"[281] smss wait handle=0x");
                        print_hex(args[0] as u32);
                        print_str(b" chain:");
                        let mut shown = 0;
                        for i in 0..96u64 {
                            let v = smss_stack_read(sp + i * 8);
                            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                                print_str(b" n+0x");
                                print_hex((v - NTDLL_BASE) as u32);
                                shown += 1;
                            } else if v >= PE_LOAD_BASE && v < PE_LOAD_BASE + 0x40000 {
                                print_str(b" s+0x");
                                print_hex((v - PE_LOAD_BASE) as u32);
                                shown += 1;
                            }
                            if shown >= 12 {
                                break;
                            }
                        }
                        print_str(b"\n");
                    }
                    0 // STATUS_WAIT_0
                }
            }
            // NtOpen/CreateDirectoryObject(*Handle[R10]=args[0], DesiredAccess, *OA[R8]=args[2]).
            // Resolve/insert in the executive object namespace, hand back a real handle.
            NativeService::NtOpenDirectoryObject | NativeService::NtCreateDirectoryObject => unsafe {
                let out = args[0]; // R10 = *Handle
                let oa = args[2]; // R8 = *OBJECT_ATTRIBUTES
                let mut rd = [0u8; 8];
                let _ = smss_copyin(oa + 8, &mut rd);
                let root_dir = u64::from_le_bytes(rd);
                let name16 = smss_read_objattr_name(oa);
                let mut nbuf = [0u8; 40];
                let nlen = Self::fold_name(&name16, &mut nbuf);
                let root_idx = if root_dir >= OBJ_HANDLE_BASE {
                    (root_dir - OBJ_HANDLE_BASE) as usize
                } else {
                    0
                };
                let idx = if ctx.service == NativeService::NtCreateDirectoryObject {
                    self.obj_create(&nbuf[..nlen], root_idx, 0, &[])
                } else {
                    self.obj_resolve(&nbuf[..nlen], root_idx)
                };
                match idx {
                    Some(i) => {
                        smss_stack_write(out, OBJ_HANDLE_BASE + i as u64);
                        0
                    }
                    None => 0xC0000034, // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            // NtCreateSymbolicLinkObject(*Handle[R10]=args[0], access, *OA[R8]=args[2],
            // *LinkTarget[R9]=args[3]). SmpInit creates the \?? drive-letter links.
            NativeService::NtCreateSymbolicLinkObject => unsafe {
                let out = args[0];
                let oa = args[2];
                let tgt = args[3]; // R9 = PUNICODE_STRING target
                let mut rd = [0u8; 8];
                let _ = smss_copyin(oa + 8, &mut rd);
                let root_dir = u64::from_le_bytes(rd);
                let name16 = smss_read_objattr_name(oa);
                let mut nbuf = [0u8; 40];
                let nlen = Self::fold_name(&name16, &mut nbuf);
                let target16 = smss_read_ustr(tgt);
                let mut tbuf = [0u8; 40]; // keep the target's case (a device path)
                let mut tl = 0;
                for &w in &target16 {
                    if tl >= tbuf.len() {
                        break;
                    }
                    tbuf[tl] = w as u8;
                    tl += 1;
                }
                let root_idx = if root_dir >= OBJ_HANDLE_BASE {
                    (root_dir - OBJ_HANDLE_BASE) as usize
                } else {
                    0
                };
                match self.obj_create(&nbuf[..nlen], root_idx, 1, &tbuf[..tl]) {
                    Some(i) => {
                        smss_stack_write(out, OBJ_HANDLE_BASE + i as u64);
                        0
                    }
                    None => 0xC0000034,
                }
            },
            // NtOpenSymbolicLinkObject(*Handle[R10]=args[0], DesiredAccess, *OA[R8]=args[2]).
            // Resolve; hand back a handle only for an actual symbolic link (a dir match is a miss).
            NativeService::NtOpenSymbolicLinkObject => unsafe {
                let out = args[0];
                let oa = args[2];
                let mut rd = [0u8; 8];
                let _ = smss_copyin(oa + 8, &mut rd);
                let root_dir = u64::from_le_bytes(rd);
                let name16 = smss_read_objattr_name(oa);
                let mut nbuf = [0u8; 40];
                let nlen = Self::fold_name(&name16, &mut nbuf);
                let root_idx = if root_dir >= OBJ_HANDLE_BASE {
                    (root_dir - OBJ_HANDLE_BASE) as usize
                } else {
                    0
                };
                match self.obj_resolve(&nbuf[..nlen], root_idx) {
                    Some(i) if self.obj_ns[i].kind == 1 => {
                        smss_stack_write(out, OBJ_HANDLE_BASE + i as u64);
                        0
                    }
                    _ => 0xC0000034, // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            // NtQuerySystemTime(*SystemTime[R10]=args[0]). Return a non-zero monotonic 64-bit clock
            // (rdtsc — a plain ring-3 instruction; do NOT `syscall` from the executive). The out-ptr
            // write is queued so the loop demand-fills it (csrss arbitrary VA vs smss stack local).
            NativeService::NtQuerySystemTime => {
                let out = args[0];
                let now = unsafe { core::arch::x86_64::_rdtsc() };
                self.queue_write(out, now);
                0
            }
            // NtQueryPerformanceCounter(*Counter[R10]=args[0], *Frequency[RDX]=args[1] optional).
            NativeService::NtQueryPerformanceCounter => {
                let ctr_ptr = args[0];
                let freq_ptr = args[1];
                let now = unsafe { core::arch::x86_64::_rdtsc() };
                let freq = 1_000_000_000u64; // 1 GHz — plausible TSC frequency
                self.queue_write(ctr_ptr, now);
                if freq_ptr != 0 {
                    self.queue_write(freq_ptr, freq);
                }
                0
            }
            // NtQueryVolumeInformationFile(FileHandle, *IoStatusBlock[RDX]=args[1], FsInfo[R8]=args[2],
            // Length[R9]=args[3], FsInformationClass[arg5]=args[4]). CsrServerInitialization probes a
            // handle's volume; no real FS → conservative answer. All writes queued (csrss-only).
            NativeService::NtQueryVolumeInformationFile => {
                let iosb = args[1];
                let buf = args[2];
                let len = args[3];
                // FsInformationClass is a ULONG; the 8-byte stack slot has garbage in the high dword.
                let class = args[4] & 0xFFFF_FFFF;
                let info_bytes: u64;
                if class == 4 {
                    // FileFsDeviceInformation { DeviceType=FILE_DEVICE_DISK(7), Characteristics=0 }.
                    self.queue_write(buf, 0x0000_0000_0000_0007);
                    info_bytes = 8;
                } else {
                    print_str(b"[ntos-exec] NtQueryVolumeInformationFile class=");
                    print_u64(class);
                    print_str(b" len=");
                    print_u64(len);
                    print_str(b"\n");
                    let n = len.min(32) / 8;
                    for k in 0..n {
                        self.queue_write(buf + k * 8, 0);
                    }
                    info_bytes = len.min(32);
                }
                if iosb != 0 {
                    self.queue_write(iosb, 0); // Status = STATUS_SUCCESS
                    self.queue_write(iosb + 8, info_bytes); // Information = bytes written
                }
                0
            }
            // NtAllocateVirtualMemory(ProcessHandle, *BaseAddress[RDX]=args[1], ZeroBits,
            // *RegionSize[R9]=args[3], Type[arg5]=args[4], Protect). RESERVE (base in==0) picks a
            // per-process bump base; COMMIT maps frames + mirrors the first heap window (group C:
            // page_map target pml4 comes from the loop ctx).
            NativeService::NtAllocateVirtualMemory => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let base_ptr = args[1]; // RDX
                let size_ptr = args[3]; // R9
                let alloc_type = args[4]; // arg5 = Type
                let base_in = smss_stack_read(base_ptr);
                let want = smss_stack_read(size_ptr);
                let rounded = ((want + 0xFFF) & !0xFFFu64).max(0x1000);
                let base = if base_in != 0 {
                    base_in
                } else if self.pi == 1 {
                    NEXT_CSRSS_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                } else if self.pi == 2 {
                    NEXT_WINLOGON_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                } else {
                    NEXT_SMSS_ALLOC.fetch_add(rounded, Ordering::Relaxed)
                };
                if alloc_type & 0x1000 != 0 {
                    // MEM_COMMIT — back it with real frames.
                    let mut p = 0u64;
                    while p < rounded {
                        let f = alloc_frame();
                        let _ = page_map(f, base + p, RW_NX, ctx.pml4);
                        // Mirror the first heap window into the executive so smss_copyin can read
                        // heap-resident pointer args, into the ACTIVE process's heap mirror.
                        let va = base + p;
                        if va >= SMSS_ALLOC_VA && va < SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
                            let mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
                            let _ = page_map(copy_cap(f),
                                mirror + (va - SMSS_ALLOC_VA), RW_NX, CAP_INIT_THREAD_VSPACE);
                        }
                        p += 0x1000;
                    }
                }
                smss_stack_write(base_ptr, base);
                smss_stack_write(size_ptr, rounded);
                NTALLOC_SERVICED.fetch_add(1, Ordering::Relaxed);
                0
            },
            // NtOpenSection(*SectionHandle[R10]=args[0], DesiredAccess, *ObjectAttributes[R8]=args[2]).
            // Provide the US-ASCII NLS code-page section \Nls\NlsSectionCP20127 (csrss's Win32 stack
            // maps it during a DllMain); everything else → NOT_FOUND. Records nls_section_handle.
            NativeService::NtOpenSection => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let name16 = smss_read_objattr_name(args[2]); // R8 = *ObjectAttributes
                print_str(b"[ntos-exec] NtOpenSection name=\"");
                for &w in name16.iter().take(96) {
                    debug_put_char(if (0x20..0x7f).contains(&w) { w as u8 } else { b'?' });
                }
                print_str(b"\"\n");
                let mut nb = [0u8; 96];
                let mut nlen = 0;
                for &w in &name16 {
                    if nlen >= nb.len() {
                        break;
                    }
                    nb[nlen] = (w as u8).to_ascii_lowercase();
                    nlen += 1;
                }
                if nb[..nlen].windows(17).any(|w| w == b"nlssectioncp20127") {
                    let h = self.mint_handle();
                    smss_stack_write(args[0], h); // R10 = *SectionHandle
                    *ctx.nls_section_handle = h;
                    print_str(b"[ntos-exec] NtOpenSection NlsCP20127 -> handle 0x");
                    print_hex(*ctx.nls_section_handle as u32);
                    print_str(b"\n");
                    0 // STATUS_SUCCESS
                } else {
                    0xC0000034 // STATUS_OBJECT_NAME_NOT_FOUND
                }
            },
            // NtQueryAttributesFile(*OBJECT_ATTRIBUTES[R10], *FILE_BASIC_INFORMATION[RDX]=args[1]).
            // RtlDosSearchPath_U probes for csrss.exe here (SmpParseCommandLine). Report it EXISTS
            // (FileAttributes = FILE_ATTRIBUTE_NORMAL) so SMP_INVALID_PATH isn't set; everything else
            // → not-found so the loader's manifest probes keep failing.
            NativeService::NtQueryAttributesFile => unsafe {
                let name16 = smss_read_objattr_name(get_recv_mr(9)); // R10 = *OA
                let mut nb = [0u8; 96];
                let mut nlen = 0;
                for &w in &name16 {
                    if nlen >= nb.len() {
                        break;
                    }
                    nb[nlen] = (w as u8).to_ascii_lowercase();
                    nlen += 1;
                }
                // Report EXISTS for csrss.exe + any registry DLL (csrsrv/basesrv/winsrv). The registry
                // rejects SxS probes itself; the csrss.exe (EXE) probe is guarded by its own SxS check
                // so the loader doesn't take the .Local\ redirection or a manifest path.
                let is_sxs = nt_dll_registry::Registry::is_sxs_probe(&nb[..nlen]);
                // The substring only CLASSIFIES which file the loader is probing (path-form
                // tolerant); the REAL nt-fs namespace (seeded in ExecNtHandler::new) authoritatively
                // answers whether csrss.exe exists and its attributes. Identical accept set: csrss.exe
                // is seeded, so a csrss probe resolves EXISTS; if the seed were removed nt-fs would
                // correctly report not-found. Content delivery stays on the nt-dll-registry/PE path.
                let is_csrss_probe = !is_sxs && nb[..nlen].windows(5).any(|w| w == b"csrss");
                // winlogon.exe — smss's SmpParseCommandLine probes the initial command (×N paths).
                // Not scoped to a pi: smss (pi==0) launches it, exactly like csrss.
                let is_winlogon_probe = !is_sxs && nb[..nlen].windows(8).any(|w| w == b"winlogon");
                let csrss_attrs = if is_csrss_probe {
                    self.fs.query_attributes(r"\SystemRoot\System32\csrss.exe")
                } else if is_winlogon_probe {
                    self.fs.query_attributes(r"\SystemRoot\System32\winlogon.exe")
                } else {
                    None
                };
                // DLL existence for csrss (pi==1) now comes from the REAL nt-fs System32 namespace
                // (seeded with SYSTEM32_FILES). NtQueryAttributesFile is a pure existence/attributes
                // query with no image geometry, so nt-fs is cleanly the sole authority here;
                // nt-dll-registry keeps the SEC_IMAGE base/geometry role in NtOpenFile/NtCreateSection.
                // Scoped to a DLL-loading process (pi>=1: csrss OR winlogon) so smss's (pi==0)
                // KnownDLLs probes keep failing and it launches csrss/winlogon.
                let dll_exists = self.pi >= 1 && self.fs_system32_has(&nb[..nlen]);
                if let Some(si) = csrss_attrs {
                    // FILE_BASIC_INFORMATION: 4×8-byte times, then FileAttributes(u32) @ +0x20.
                    // Attributes come from nt-fs: a file → NORMAL, a directory → DIRECTORY.
                    let attr = if si.is_directory { 0x10 } else { 0x80 };
                    smss_stack_write32(args[1] + 0x20, attr);
                    0
                } else if dll_exists {
                    smss_stack_write32(args[1] + 0x20, 0x80); // FILE_ATTRIBUTE_NORMAL
                    0
                } else {
                    // DIAG: log the not-found probes from a DLL-loading process (csrss/winlogon) —
                    // a DllMain probes several files before failing init; we need to know which are
                    // load-bearing.
                    if self.pi >= 1 {
                        print_str(b"[ntos-exec] NtQueryAttributesFile(hosted) not-found: \"");
                        for &w in name16.iter().take(96) {
                            debug_put_char(if (0x20..0x7f).contains(&w) { w as u8 } else { b'?' });
                        }
                        print_str(b"\"\n");
                    }
                    0xC0000034
                }
            },
            // NtOpenFile(*FileHandle[R10], DesiredAccess[RDX], *OBJECT_ATTRIBUTES[R8],
            // *IoStatusBlock[R9], ShareAccess[sp+0x28], OpenOptions[sp+0x30]).
            // SmpCreateInitialSession opens %SystemRoot%\system32 as a DIRECTORY
            // (FILE_DIRECTORY_FILE) before creating the KnownDllPath symlink + looping KnownDLLs.
            // Hand back a directory handle so it proceeds; a plain FILE open (an individual
            // KnownDLL) still fails → smss `continue`s past each DLL and completes the loop.
            NativeService::NtOpenFile => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let reg = &mut *ctx.reg;
                const FILE_DIRECTORY_FILE: u64 = 0x01;
                let sp = get_recv_mr(16);
                // Succeed ONLY for SmpInit's KnownDLL directory open (…\system32). The loader's
                // actctx/manifest opens (individual .manifest FILES, and the \??\C:\Windows SxS
                // search directory) must keep failing so ntdll falls back to its defaults and
                // proceeds to SmpInit — otherwise we divert the loader down the SxS path. Match the
                // (folded) object name against "system32".
                let name16 = smss_read_objattr_name(get_recv_mr(7));
                let mut nb = [0u8; 96];
                let nlen = {
                    let mut n = 0;
                    for &w in &name16 {
                        if n >= nb.len() {
                            break;
                        }
                        nb[n] = (w as u8).to_ascii_lowercase();
                        n += 1;
                    }
                    n
                };
                // Reject SxS/actctx probes (csrss.exe.local, csrss.exe.manifest, *.config).
                let is_sxs = nb[..nlen].windows(6).any(|w| w == b".local")
                    || nb[..nlen].windows(9).any(|w| w == b".manifest")
                    || nb[..nlen].windows(7).any(|w| w == b".config");
                // The System32 DIRECTORY open (SmpCreateInitialSession → KnownDLLs) resolves through
                // the REAL nt-fs namespace: the substring classifies the probe, nt-fs authoritatively
                // confirms \Windows\System32 exists AND is a directory (canonical path is
                // mount-resolvable, so path-form independent).
                let want_dir = smss_stack_read(sp + 0x30) & FILE_DIRECTORY_FILE != 0;
                let is_sys32_dir = want_dir
                    && nb[..nlen].windows(8).any(|w| w == b"system32")
                    && self
                        .fs
                        .query_attributes(r"\SystemRoot\System32")
                        .is_some_and(|si| si.is_directory);
                // csrss.exe FILE open (SmpExecuteImage): same as NtQueryAttributesFile — substring
                // classifies, nt-fs owns existence + file-vs-dir. Scoped by name so the loader's
                // manifest opens are unaffected.
                let is_csrss = !is_sxs
                    && nb[..nlen].windows(5).any(|w| w == b"csrss")
                    && self
                        .fs
                        .query_attributes(r"\SystemRoot\System32\csrss.exe")
                        .is_some_and(|si| !si.is_directory);
                // winlogon.exe FILE open (SmpExecuteImage → RtlCreateUserProcess): same shape as
                // csrss — substring classifies, nt-fs owns existence + file-vs-dir. Not pi-scoped.
                let is_winlogon = !is_sxs
                    && nb[..nlen].windows(8).any(|w| w == b"winlogon")
                    && self
                        .fs
                        .query_attributes(r"\SystemRoot\System32\winlogon.exe")
                        .is_some_and(|si| !si.is_directory);
                // csrss's static import (csrsrv.dll) + its dynamic ServerDlls (basesrv/winsrv) + the
                // Win32 client stack. SCOPED TO csrss (pi==1): smss's SmpInit enumerates the KnownDLLs
                // — which now include kernel32/user32/gdi32 — and those opens MUST keep failing so
                // smss skips them and launches csrss. Only csrss's loader should resolve these DLLs.
                // nt-dll-registry keeps the image base/geometry role for CONTENT (SEC_IMAGE); nt-fs
                // owns namespace/existence (csrss.exe + System32 dir here). pi>=1 = csrss OR winlogon
                // (both load DLLs); smss (pi==0) still misses so its KnownDLLs opens fail + it
                // launches csrss/winlogon.
                let dll_i = if self.pi >= 1 { reg.resolve_name(&nb[..nlen]) } else { None };
                if is_sys32_dir || is_csrss || is_winlogon || dll_i.is_some() {
                    let h = self.mint_handle();
                    smss_stack_write(get_recv_mr(9), h); // *FileHandle
                    if is_csrss {
                        *ctx.csrss_file_handle = h; // remember it for NtCreateSection
                    }
                    if is_winlogon {
                        *ctx.winlogon_file_handle = h; // for NtCreateSection
                    }
                    if let Some(i) = dll_i {
                        reg.set_file_handle(self.pi, i, h); // per-process: remember for NtCreateSection
                    }
                    let iosb = get_recv_mr(8); // R9 = *IO_STATUS_BLOCK
                    if iosb != 0 {
                        smss_stack_write32(iosb, 0); // Status = STATUS_SUCCESS
                        smss_stack_write(iosb + 8, 1); // Information = FILE_OPENED
                    }
                    0
                } else {
                    0xC0000034 // no filesystem yet → not found (smss skips / uses defaults)
                }
            },
            // NtQuerySection(SectionHandle[R10], class[RDX]=args[1], buf[R8], len[R9], *ResultLen[sp+0x28]).
            // RtlCreateUserProcess queries SectionImageInformation (class 1) for the image's entry
            // point, stack sizes + subsystem before creating the initial thread. Return a 64-byte
            // SECTION_IMAGE_INFORMATION derived from the section's backing PE (a registry DLL at its
            // registry base, or the csrss.exe EXE at PE_LOAD_BASE).
            NativeService::NtQuerySection => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let reg = &*ctx.reg;
                let class = args[1]; // RDX
                let buf = get_recv_mr(7); // R8
                let sect = get_recv_mr(9); // R10 = SectionHandle
                let sp = get_recv_mr(16);
                let csrss_section_handle = *ctx.csrss_section_handle;
                let csrss_pe = &*ctx.csrss_pe;
                let winlogon_section_handle = *ctx.winlogon_section_handle;
                let winlogon_pe = &*ctx.winlogon_pe;
                let info: Option<([u8; 64], &[u8])> = if let Some(i) = reg.index_for_section(self.pi, sect) {
                    reg.image_info(i).map(|b| (b, reg.name(i)))
                } else if self.pi == 0 && csrss_section_handle != 0 && sect == csrss_section_handle {
                    // The csrss.exe SEC_IMAGE section is created + queried ONLY by smss (pi 0) inside
                    // RtlCreateUserProcess. Scope to pi 0 so a DIFFERENT process's dense handle with
                    // the same value (path 1b) can never alias it (reg is matched first regardless).
                    csrss_pe.as_ref().map(|p| {
                        (
                            nt_dll_registry::image_info(
                                PE_LOAD_BASE,
                                p.entry_point_rva(),
                                p.size_of_image(),
                                false,
                            ),
                            b"csrss.exe" as &[u8],
                        )
                    })
                } else if self.pi == 0 && winlogon_section_handle != 0 && sect == winlogon_section_handle {
                    // smss's RtlCreateUserProcess(winlogon) queries SectionImageInformation on the
                    // winlogon SEC_IMAGE section to size the initial thread's stack + find the entry.
                    // Unrecognized before, this stopped the whole demo (the ONLY reason winlogon
                    // couldn't run past its CSR connect); recognized now → smss proceeds + winlogon
                    // (higher prio) keeps running.
                    winlogon_pe.as_ref().map(|p| {
                        (
                            nt_dll_registry::image_info(
                                PE_LOAD_BASE,
                                p.entry_point_rva(),
                                p.size_of_image(),
                                false,
                            ),
                            b"winlogon.exe" as &[u8],
                        )
                    })
                } else {
                    None
                };
                if class == 1 && info.is_some() {
                    let (bytes, who) = info.unwrap();
                    // Copy the 64-byte SECTION_IMAGE_INFORMATION out to `buf` (8 bytes at a time).
                    for k in 0..8 {
                        let mut w = [0u8; 8];
                        w.copy_from_slice(&bytes[k * 8..k * 8 + 8]);
                        smss_stack_write(buf + (k as u64) * 8, u64::from_le_bytes(w));
                    }
                    let rl = smss_stack_read(sp + 0x28); // arg4 = *ResultLength
                    if rl != 0 {
                        smss_stack_write(rl, 64);
                    }
                    let entry = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                    print_str(b"[ntos-exec] NtQuerySection ");
                    print_str(who);
                    print_str(b" entry=0x");
                    print_hex((entry >> 32) as u32);
                    print_hex(entry as u32);
                    print_str(b"\n");
                    0
                } else {
                    self.stop = true;
                    0xC0000002
                }
            },
            // NtQueryDefaultLocale(UserProfile, *DefaultLocaleId[RDX]=args[1]). Write en-US (0x409) to
            // the output, which ntdll points at one of its own .data GLOBALS (not the stack) — so copy
            // out through the target image page's persistent executive scratch mapping, demand-filling
            // the page first if LdrpInitialize hasn't touched it yet.
            NativeService::NtQueryDefaultLocale => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let out = args[1]; // RDX = *DefaultLocaleId
                let pg = out & !0xFFFu64;
                let filled_pages = &mut *ctx.filled_pages;
                let faults = &mut *ctx.faults;
                let mut idx = usize::MAX;
                for i in 0..(*faults as usize).min(filled_pages.len()) {
                    if filled_pages[i] == pg {
                        idx = i;
                        break;
                    }
                }
                if idx == usize::MAX && (*faults as usize) < filled_pages.len() {
                    let (base, tpe): (u64, *const nt_pe_loader::PeFile<'static>) =
                        if pg >= PE_LOAD_BASE && pg < ctx.img_end {
                            (PE_LOAD_BASE, ctx.pe)
                        } else if ctx.nt_base != 0 && pg >= ctx.nt_base && pg < ctx.nt_end {
                            (ctx.nt_base, ctx.ntdll_pe)
                        } else {
                            (0u64, ctx.pe)
                        };
                    if base != 0 {
                        let scratch = ctx.scratch_base + *faults * 0x1000;
                        let f = alloc_frame();
                        let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
                        let rights = fill_image_page(&*tpe, (pg - base) as u32, scratch);
                        let _ = page_map(copy_cap(f), pg, rights, ctx.pml4);
                        filled_pages[*faults as usize] = pg;
                        idx = *faults as usize;
                        *faults += 1;
                    }
                }
                if idx != usize::MAX {
                    core::ptr::write_volatile(
                        (ctx.scratch_base + idx as u64 * 0x1000 + (out & 0xFFF)) as *mut u32,
                        0x409,
                    );
                }
                0
            },
            // NtCreateSection(*SectionHandle[R10], access[RDX], *OA[R8], *MaxSize[R9],
            // PageProtection[sp+0x28], AllocationAttributes[sp+0x30], FileHandle[sp+0x38]).
            // Unlike the other creates, smss USES the section handle (NtCreateProcess), so write it to
            // the real out-param (arg0 = R10). When it's a SEC_IMAGE of csrss.exe, record the handle
            // so NtCreateProcess can spawn the real csrss image from it.
            NativeService::NtCreateSection => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let h = self.mint_handle();
                let reg = &mut *ctx.reg;
                let dll_pes = &*ctx.dll_pes;
                let filled_pages = &mut *ctx.filled_pages;
                let faults = &mut *ctx.faults;
                let sp = get_recv_mr(16);
                let out = get_recv_mr(9); // R10 = *SectionHandle
                // *SectionHandle can live outside the stack/heap/image mirrors (e.g. a csrsrv global).
                csrss_out_write(
                    out, h, filled_pages, faults, ctx.scratch_base, reg, dll_pes,
                    ctx.pml4,
                );
                let sec_file = smss_stack_read(sp + 0x38);
                // The csrss.exe / winlogon.exe EXE sections are created ONLY by smss (pi 0). Scope
                // to pi 0 so a csrss/winlogon DLL section create with a same-valued dense file handle
                // (path 1b) can't spuriously match these (the per-pi reg lookup handles DLLs below).
                if self.pi == 0 && *ctx.csrss_file_handle != 0 && sec_file == *ctx.csrss_file_handle {
                    *ctx.csrss_section_handle = h;
                    print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for csrss.exe -> handle 0x");
                    print_hex((h >> 32) as u32);
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                if self.pi == 0 && *ctx.winlogon_file_handle != 0 && sec_file == *ctx.winlogon_file_handle {
                    *ctx.winlogon_section_handle = h;
                    print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for winlogon.exe -> handle 0x");
                    print_hex((h >> 32) as u32);
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                // A registry DLL (csrsrv/basesrv/winsrv): record its section handle by file handle.
                if let Some(i) = reg.index_for_file(self.pi, sec_file) {
                    reg.set_section_handle(self.pi, i, h);
                    print_str(b"[ntos-exec] NtCreateSection(SEC_IMAGE) for ");
                    print_str(reg.name(i));
                    print_str(b" -> handle 0x");
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                // Anonymous (no FileHandle) section from csrss — its CSR SharedSection shared memory.
                // Record the requested size (from *MaximumSize = R9) so NtMapViewOfSection can back it.
                if sec_file == 0 && self.pi == 1 && *ctx.csrss_anon_section_handle == 0 {
                    let maxsize_ptr = get_recv_mr(8); // R9 = *MaximumSize (LARGE_INTEGER)
                    let size = if let Some(m) = smss_mirror(maxsize_ptr, 8) {
                        core::ptr::read_volatile(m as *const u64)
                    } else {
                        0
                    };
                    *ctx.csrss_anon_section_handle = h;
                    // SEC_RESERVE with MaximumSize==0 gives no size here; reserve a default 1 MiB
                    // window (demand-paged on touch, so unused pages cost nothing).
                    *ctx.csrss_anon_size = if size == 0 { 0x10_0000 } else { size };
                    print_str(b"[ntos-exec] NtCreateSection(anonymous) size=0x");
                    print_hex(*ctx.csrss_anon_size as u32);
                    print_str(b" -> handle 0x");
                    print_hex(h as u32);
                    print_str(b"\n");
                }
                0
            },
            // NtMapViewOfSection(SectionHandle[R10], ProcessHandle[RDX], *BaseAddress[R8],
            // ZeroBits[R9], CommitSize[sp+0x28], *SectionOffset[sp+0x30], *ViewSize[sp+0x38], …).
            // Map a registry DLL SEC_IMAGE at its (fixed) registry base, the anonymous CSR shared
            // section, or the named NLS section into csrss's VSpace; the fault router demand-pages
            // the DLL/anon views and the NLS frames are mapped eagerly here.
            NativeService::NtMapViewOfSection => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let reg = &mut *ctx.reg;
                let dll_pes = &*ctx.dll_pes;
                let filled_pages = &mut *ctx.filled_pages;
                let faults = &mut *ctx.faults;
                let pml4 = ctx.pml4;
                let scratch_base = ctx.scratch_base;
                let sp = get_recv_mr(16);
                let sect = get_recv_mr(9);
                if let Some(i) = reg.index_for_section(self.pi, sect) {
                    // A registry DLL (csrsrv/basesrv/winsrv). Reserve its VA range, hand back its base
                    // + view size, and let the fault router demand-page it from its PE. All DLL slots
                    // share the 0x8000_0000 1 GiB PDPT range, so the PD is created once (first mapped
                    // DLL) and each DLL gets its own PT. csrsrv sits at its preferred ImageBase (no
                    // relocation); the ServerDlls are loader-relocated.
                    if let Some(cpe) = dll_pes[i].as_ref() {
                        let dbase = reg.base(i);
                        // PER-PROCESS PD/PT reservation: the DLL's fixed base is the same in every
                        // process, but each VSpace needs its own page tables. csrss and winlogon load
                        // an overlapping DLL set at identical bases into distinct VSpaces, so gate the
                        // reservation on this process's bitmask, not the registry's global `mapped`.
                        let pi = self.pi;
                        let dll_pd_created = &mut *ctx.dll_pd_created;
                        let dll_mapped_bits = &mut *ctx.dll_mapped_bits;
                        if dll_mapped_bits[pi] & (1u32 << i) == 0 {
                            if !dll_pd_created[pi] {
                                let pd = alloc_slot();
                                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
                                let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, dbase, pml4);
                                dll_pd_created[pi] = true;
                            }
                            let pt = alloc_slot();
                            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                            let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, dbase, pml4);
                            dll_mapped_bits[pi] |= 1u32 << i;
                            // Global flag drives `dll_for_page` VA-range resolution (base-identical).
                            reg.set_mapped(i);
                        }
                        let ext = image_extent(cpe);
                        csrss_out_write(get_recv_mr(7), dbase, filled_pages, faults, scratch_base, reg, dll_pes, pml4); // *BaseAddress
                        let vs_ptr = smss_stack_read(sp + 0x38); // *ViewSize
                        if vs_ptr != 0 {
                            csrss_out_write(vs_ptr, ext, filled_pages, faults, scratch_base, reg, dll_pes, pml4);
                        }
                        print_str(b"[ntos-exec] NtMapViewOfSection ");
                        print_str(reg.name(i));
                        print_str(b" -> base 0x");
                        print_hex(dbase as u32);
                        print_str(b"\n");
                        0
                    } else {
                        self.stop = true;
                        0xC0000002
                    }
                } else if self.pi == 1 && *ctx.csrss_anon_section_handle != 0 && sect == *ctx.csrss_anon_section_handle {
                    // Anonymous section (CSR shared memory): reserve a VA range in csrss's VSpace
                    // (page tables only) and let the fault router demand-page zero frames on touch.
                    const CSRSS_ANON_BASE: u64 = 0x0000_0100_0300_0000;
                    if *ctx.csrss_anon_base == 0 {
                        let npts = ((*ctx.csrss_anon_size + 0x1F_FFFF) / 0x20_0000).max(1);
                        let mut k = 0u64;
                        while k < npts {
                            let pt = alloc_slot();
                            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                            let _ = paging_struct_map(
                                pt,
                                LBL_X86_PAGE_TABLE_MAP,
                                CSRSS_ANON_BASE + k * 0x20_0000,
                                pml4,
                            );
                            k += 1;
                        }
                        *ctx.csrss_anon_base = CSRSS_ANON_BASE;
                    }
                    // *BaseAddress / *ViewSize are csrsrv globals (CsrSrvSharedSectionBase) — write via
                    // the general path so they don't silently miss (NULL base → RtlAllocateHeap(NULL)).
                    csrss_out_write(get_recv_mr(7), *ctx.csrss_anon_base, filled_pages, faults, scratch_base, reg, dll_pes, pml4);
                    let vs_ptr = smss_stack_read(sp + 0x38); // *ViewSize
                    if vs_ptr != 0 {
                        csrss_out_write(vs_ptr, *ctx.csrss_anon_size, filled_pages, faults, scratch_base, reg, dll_pes, pml4);
                    }
                    print_str(b"[ntos-exec] NtMapViewOfSection(anonymous) -> base 0x");
                    print_hex((*ctx.csrss_anon_base >> 32) as u32);
                    print_hex(*ctx.csrss_anon_base as u32);
                    print_str(b"\n");
                    0
                } else if *ctx.nls_section_handle != 0 && sect == *ctx.nls_section_handle {
                    // The named NLS section \Nls\NlsSectionCP20127: map the staged c_20127.nls frames
                    // into csrss at a VA past the DLL bases (same 0x8000_0000 PDPT slot, whose PD the
                    // DLL loads already created), then hand back *BaseAddress / *ViewSize.
                    const NLS_SECTION_CSRSS_VA: u64 = 0x0000_0000_A000_0000;
                    let nls_start = NLS_20127_START.load(Ordering::Relaxed);
                    let nls_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x74) as *const u32) as u64;
                    let npages = (nls_size + 0xFFF) / 0x1000;
                    // Reserve one PT (the DLL PD already covers this 1 GiB PDPT slot).
                    let pt = alloc_slot();
                    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, NLS_SECTION_CSRSS_VA, pml4);
                    for i in 0..npages {
                        let _ = page_map(copy_cap(nls_start + i), NLS_SECTION_CSRSS_VA + i * 0x1000, RW_NX, pml4);
                    }
                    csrss_out_write(get_recv_mr(7), NLS_SECTION_CSRSS_VA, filled_pages, faults, scratch_base, reg, dll_pes, pml4); // *BaseAddress
                    let vs_ptr = smss_stack_read(sp + 0x38); // *ViewSize
                    if vs_ptr != 0 {
                        csrss_out_write(vs_ptr, nls_size, filled_pages, faults, scratch_base, reg, dll_pes, pml4);
                    }
                    print_str(b"[ntos-exec] NtMapViewOfSection NlsCP20127 -> base 0xA0000000\n");
                    0
                } else {
                    self.stop = true; // other sections not modeled
                    0xC0000002
                }
            },
            // NtCreateProcess(*ProcessHandle[R10], access[RDX], *OA[R8], ParentProcess[R9],
            // InheritHandles[sp+0x28], SectionHandle[sp+0x30], …). Control-flow case: validate the
            // SectionHandle names the tracked csrss.exe SEC_IMAGE, then hand the actual spawn to the
            // loop (it needs fault_ep + the per-badge process arrays) via `spawn_request`.
            NativeService::NtCreateProcess => unsafe {
                let ctx = self.loop_ctx.unwrap();
                let sp = get_recv_mr(16);
                let sect = smss_stack_read(sp + 0x30); // SectionHandle
                // NtCreateProcess(csrss/winlogon) is issued ONLY by smss (pi 0); scope so a dense
                // section handle of the same value in another process can't trigger a spawn (1b).
                if self.pi == 0
                    && *ctx.csrss_section_handle != 0
                    && sect == *ctx.csrss_section_handle
                    && (*ctx.csrss_pe).is_some()
                {
                    self.spawn_request = true; // the loop performs the spawn + writes *ProcessHandle
                    0
                } else if self.pi == 0
                    && *ctx.winlogon_section_handle != 0
                    && sect == *ctx.winlogon_section_handle
                    && (*ctx.winlogon_pe).is_some()
                {
                    self.winlogon_spawn_request = true; // loop spawns winlogon (3rd process)
                    0
                } else {
                    self.stop = true; // not a known section / not staged -> clean stop
                    0xC0000002
                }
            },
            // NtTerminateProcess(ProcessHandle[R10]=args[0], ExitStatus[RDX]=args[1]). Route the
            // POLICY teardown through pm: mark the target EPROCESS Terminated (signalled), terminate
            // its threads, release its image-section map ref. NOT reached during a normal boot (no
            // hosted process self-terminates); additive + proven by the post-loop self-test. FLAG:
            // the seL4 MECHANISM teardown (reclaim the VSpace/CSpace/TCB caps + the mirror/scratch
            // frames) is NOT done here — that needs the trusted-root-task cap reclamation and is the
            // next path-2 follow-up; today the process simply stops faulting and its frames persist.
            NativeService::NtTerminateProcess => {
                PM_TERMINATE_CALLS.fetch_add(1, Ordering::Relaxed);
                let handle = args.first().copied().unwrap_or(0);
                let status = args.get(1).copied().unwrap_or(0) as u32;
                if let Some(pid) = self.resolve_process_handle(handle) {
                    let _ = self.pm.terminate_process(pid, status);
                }
                0 // STATUS_SUCCESS (matches the prior broker fallback for an unresolved handle)
            }
            // NtTerminateThread(ThreadHandle, ExitStatus[RDX]) for NtCurrentThread()==-2 → the
            // caller's main thread. Uses `exit_thread` (NO process cascade — a hosted process's other
            // threads keep it alive), matching the live broker-arm routing (item 2a). This arm is NOT
            // table-registered (267 stays in the broker arm to preserve park_caller); it exists so the
            // policy is exercisable and args-defensive should a future flow register it.
            NativeService::NtTerminateThread => {
                let handle = args.first().copied().unwrap_or(0);
                let status = args.get(1).copied().unwrap_or(0) as u32;
                if handle == 0xFFFF_FFFF_FFFF_FFFE {
                    if let Some(tid) = PM_TIDS.get(self.pi).map(|t| t.load(Ordering::Relaxed)) {
                        if tid != 0 {
                            let _ = self.pm.exit_thread(tid as nt_process::ThreadId, status);
                        }
                    }
                }
                0
            }
            _ => 0xC000_0002, // STATUS_NOT_IMPLEMENTED — never silently succeed
        }
    }
}

// ===================== ALPC last-mile item (a): register the NtAlpc* SSNs =========================
// SSNs EXTRACTED (not hardcoded — the rootserver-constant-drift trap) from references/ntdll.dll (a
// real Windows x64 ntdll, the Win7-pivot target; ReactOS ros-ntdll.dll, which the LIVE smss/csrss/
// winlogon run, exports NO NtAlpc* at all — ALPC is Vista+ and ReactOS has only kernel-less stubs).
//   NtAlpcAcceptConnectPort=111 NtAlpcConnectPort=113 NtAlpcCreatePort=114 NtAlpcCreatePortSection=115
//   NtAlpcCreateSectionView=117 NtAlpcDisconnectPort=123 NtAlpcSendWaitReceivePort=130
// ★ CONSTANT-DRIFT / COLLISION FINDING (load-bearing): the Win7 ALPC SSN block (111..131) OVERLAPS
// the live ReactOS SSN space — e.g. Win7 NtAlpcConnectPort=113 == the live ReactOS NtMapViewOfSection
// =113 (registered in build_nt_table). So the ALPC route MUST NOT be merged into build_nt_table nor
// fired on a raw m0 for the 3 live ReactOS processes (that would HIJACK live NtMapViewOfSection etc.).
// It is a DEDICATED recognizer, gated by ALPC-PROCESS IDENTITY (`ALPC_HOST_PRESENT`, never set at
// boot — no ALPC binary yet), so it is DORMANT (byte-identical boot) yet genuinely wired into the
// fault dispatcher. The recognizer + the SSN→adapter routing are proven by counted specs
// (exec_alpc_ssn_registered / exec_alpc_ssn_routes_to_adapter); a live hosted caller arrives with a
// real ALPC binary running the Win7 ntdll (whose ntdll then defines the authoritative SSNs).
pub const SSN_NT_ALPC_ACCEPT_CONNECT_PORT: u64 = 111;
pub const SSN_NT_ALPC_CONNECT_PORT: u64 = 113;
pub const SSN_NT_ALPC_CREATE_PORT: u64 = 114;
pub const SSN_NT_ALPC_CREATE_PORT_SECTION: u64 = 115;
pub const SSN_NT_ALPC_CREATE_SECTION_VIEW: u64 = 117;
pub const SSN_NT_ALPC_DISCONNECT_PORT: u64 = 123;
pub const SSN_NT_ALPC_SEND_WAIT_RECEIVE_PORT: u64 = 130;

/// Set true ONLY when a real ALPC binary (running the Win7 ntdll) is hosted. Never set at boot, so
/// `try_route_alpc_ssn` is dormant — the Win7 ALPC SSNs can never hijack the live ReactOS SSN space.
static ALPC_HOST_PRESENT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Recognizer: map a Win7 `NtAlpc*` SSN to its unified port-service ALPC wire opcode (0x2300 block).
/// This IS the registration of the NtAlpc* SSNs in the executive's dispatch logic.
pub fn alpc_ssn_to_opcode(ssn: u64) -> Option<u16> {
    use nt_alpc_abi::opcode as aop;
    Some(match ssn {
        SSN_NT_ALPC_CREATE_PORT => aop::ALPC_OP_CREATE_PORT,
        SSN_NT_ALPC_CONNECT_PORT => aop::ALPC_OP_CONNECT_PORT,
        SSN_NT_ALPC_ACCEPT_CONNECT_PORT => aop::ALPC_OP_ACCEPT_CONNECT,
        SSN_NT_ALPC_SEND_WAIT_RECEIVE_PORT => aop::ALPC_OP_SEND_RECEIVE,
        SSN_NT_ALPC_DISCONNECT_PORT => aop::ALPC_OP_DISCONNECT_PORT,
        SSN_NT_ALPC_CREATE_PORT_SECTION => aop::ALPC_OP_CREATE_PORT_SECTION,
        SSN_NT_ALPC_CREATE_SECTION_VIEW => aop::ALPC_OP_CREATE_SECTION_VIEW,
        _ => return None,
    })
}

/// Fault-dispatcher hook: if a hosted ALPC process (running the Win7 ntdll) issued an `NtAlpc*`
/// syscall, translate its SSN → the ALPC adapter opcode and route it to the unified port service
/// over the shared ring (`LPC_CLIENT`), returning the NTSTATUS. DORMANT unless `ALPC_HOST_PRESENT`
/// (never set at boot) — so it can NEVER fire for the 3 live ReactOS processes whose SSN space
/// collides with the Win7 ALPC SSNs. The per-binary marshalling of the native ALPC arg blocks
/// (PORT_MESSAGE + ALPC_MESSAGE_ATTRIBUTES from the fault register/stack image) is the shim that
/// lands with a real ALPC binary; the recognizer + adapter routing here are proven by counted specs.
unsafe fn try_route_alpc_ssn(ssn: u64, req: &[u8], out: &mut [u8]) -> Option<u64> {
    if !ALPC_HOST_PRESENT.load(Ordering::Relaxed) {
        return None;
    }
    let op = alpc_ssn_to_opcode(ssn)?;
    #[allow(static_mut_refs)]
    let lpc = LPC_CLIENT.as_mut()?;
    let (status, _f, _i, _d0, _d1) = lpc.backend_mut().0.raw(op, req, out);
    Some(status as u64)
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
            (NativeService::NtEnumerateValueKey, SSN_NT_ENUM_VALUE_KEY as u32),
            (NativeService::NtQueryValueKey, SSN_NT_QUERY_VALUE_KEY as u32),
            // Workstream A batch 1: services migrated off the hand-wired ladder into the table.
            (NativeService::NtQuerySystemInformation, SSN_NT_QUERY_SYSTEM_INFO as u32),
            (NativeService::NtQueryInformationProcess, SSN_NT_QUERY_INFO_PROCESS as u32),
            (NativeService::NtProtectVirtualMemory, SSN_NT_PROTECT_VM as u32),
            (NativeService::NtDisplayString, SSN_NT_DISPLAY_STRING as u32),
            (NativeService::NtQueryDebugFilterState, SSN_NT_QUERY_DEBUG_FILTER_STATE as u32),
            (NativeService::NtOpenThreadToken, SSN_NT_OPEN_THREAD_TOKEN as u32),
            // Workstream A batch 2 (group A): create-handle + no-op services.
            (NativeService::NtCreatePort, SSN_NT_CREATE_PORT as u32),
            (NativeService::NtCreateThread, SSN_NT_CREATE_THREAD as u32),
            (NativeService::NtCreateEvent, SSN_NT_CREATE_EVENT as u32),
            (NativeService::NtCreateSemaphore, SSN_NT_CREATE_SEMAPHORE as u32),
            // NT LPC connection rendezvous → isolated nt-lpc-server (control plane).
            (NativeService::NtConnectPort, SSN_NT_CONNECT_PORT as u32),
            (NativeService::NtSecureConnectPort, SSN_NT_SECURE_CONNECT_PORT as u32),
            (NativeService::NtAcceptConnectPort, SSN_NT_ACCEPT_CONNECT_PORT as u32),
            (NativeService::NtCompleteConnectPort, SSN_NT_COMPLETE_CONNECT_PORT as u32),
            (NativeService::NtRequestWaitReplyPort, SSN_NT_REQUEST_WAIT_REPLY_PORT as u32),
            (NativeService::NtOpenProcessToken, SSN_NT_OPEN_PROCESS_TOKEN as u32),
            (NativeService::NtMakeTemporaryObject, SSN_NT_MAKE_TEMPORARY_OBJECT as u32),
            (NativeService::NtFreeVirtualMemory, SSN_NT_FREE_VM as u32),
            (NativeService::NtSetInformationThread, SSN_NT_SET_INFO_THREAD as u32),
            (NativeService::NtSetInformationProcess, SSN_NT_SET_INFO_PROCESS as u32),
            (NativeService::NtTestAlert, SSN_NT_TEST_ALERT as u32),
            (NativeService::NtFlushInstructionCache, SSN_NT_FLUSH_INSTRUCTION_CACHE as u32),
            (NativeService::NtCreateKeyedEvent, SSN_NT_CREATE_KEYED_EVENT as u32),
            (NativeService::NtAdjustPrivilegesToken, SSN_NT_ADJUST_PRIV_TOKEN as u32),
            (NativeService::NtDeleteValueKey, SSN_NT_DELETE_VALUE_KEY as u32),
            (NativeService::NtInitializeRegistry, SSN_NT_INITIALIZE_REGISTRY as u32),
            (NativeService::NtSetValueKey, SSN_NT_SET_VALUE_KEY as u32),
            (NativeService::NtSetSystemInformation, SSN_NT_SET_SYSTEM_INFORMATION as u32),
            (NativeService::NtUnmapViewOfSection, 277),
            (NativeService::NtSetSecurityObject, 246),
            (NativeService::NtResumeThread, 214),
            (NativeService::NtSetInformationObject, 236),
            // Workstream A batch 3 (group B1): query + object-namespace services.
            (NativeService::NtQueryVirtualMemory, SSN_NT_QUERY_VIRTUAL_MEM as u32),
            (NativeService::NtQueryInformationToken, SSN_NT_QUERY_INFO_TOKEN as u32),
            (NativeService::NtQueryObject, 170),
            (NativeService::NtWaitForSingleObject, 281),
            (NativeService::NtOpenDirectoryObject, SSN_NT_OPEN_DIRECTORY_OBJECT as u32),
            (NativeService::NtCreateDirectoryObject, SSN_NT_CREATE_DIRECTORY_OBJECT as u32),
            (NativeService::NtCreateSymbolicLinkObject, SSN_NT_CREATE_SYMBOLIC_LINK_OBJECT as u32),
            (NativeService::NtOpenSymbolicLinkObject, SSN_NT_OPEN_SYMBOLIC_LINK_OBJECT as u32),
            // Workstream A batch 4 (group B2): out-writing query services (queued-write drain).
            (NativeService::NtQuerySystemTime, SSN_NT_QUERY_SYSTEM_TIME_SVC as u32),
            (NativeService::NtQueryPerformanceCounter, SSN_NT_QUERY_PERF_COUNTER as u32),
            (NativeService::NtQueryVolumeInformationFile, SSN_NT_QUERY_VOLUME_INFO_FILE as u32),
            // Workstream A batch 5 (group C, first cut — demand-fill/alloc subset via ExecLoopCtx).
            (NativeService::NtAllocateVirtualMemory, SSN_NT_ALLOCATE_VM as u32),
            (NativeService::NtOpenSection, SSN_NT_OPEN_SECTION as u32),
            // Workstream A batch 6 (group C ladder migrations): name-scoped file fakes.
            (NativeService::NtQueryAttributesFile, SSN_NT_QUERY_ATTRIBUTES_FILE as u32),
            (NativeService::NtOpenFile, SSN_NT_OPEN_FILE as u32),
            // Workstream A batch 7 (group C): section-image query + locale demand-fill.
            (NativeService::NtQuerySection, SSN_NT_QUERY_SECTION as u32),
            (NativeService::NtQueryDefaultLocale, SSN_NT_QUERY_DEFAULT_LOCALE as u32),
            // Workstream A batch 8 (group C): section creation (csrss.exe SEC_IMAGE + DLL + anon).
            (NativeService::NtCreateSection, SSN_NT_CREATE_SECTION as u32),
            // Workstream A batch 9 (group C): view mapping (DLL SEC_IMAGE + anon + NLS).
            (NativeService::NtMapViewOfSection, 113),
            // Workstream A batch 10 (group C): csrss spawn (table-dispatched-with-post-action).
            (NativeService::NtCreateProcess, SSN_NT_CREATE_PROCESS as u32),
            // ITEM 2a — live terminate-dispatch. NtTerminateProcess IS registered: it is NOT issued
            // during a normal boot (the 3 hosted processes never self-terminate — verified: registering
            // it keeps the boot byte-identical), so routing it to the real pm.terminate_process teardown
            // (via resolve_process_handle: NtCurrentProcess→self, a child ProcessHandle→its Process(pid)
            // via path 1b's value→object index) is additive. terminate_process only mutates below-mark
            // EPROCESS/ETHREAD nodes in place + a transient consumed-and-dropped Vec → safe under the
            // per-syscall heap reset even if a future flow does hit it.
            (NativeService::NtTerminateProcess, SSN_NT_TERMINATE_PROCESS as u32),
            // NtTerminateThread is deliberately NOT registered here — it IS issued live (csrss.exe's
            // init thread self-exits). It stays in the broker arm (`m0 == 267 && badge == CSRSS_BADGE`)
            // so it keeps setting park_caller (the load-bearing "leave the thread blocked" behavior);
            // that arm routes the exit through the real ETHREAD teardown (pm.exit_thread, no cascade).
            // Registering it in the table would shadow the broker arm → drop park_caller (behavior
            // change) — the exact pre-path-2 regression.
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
    let mut ssn_ring_badge = [0u8; 32];
    let mut ssn_ri = 0usize;
    // Distinct fake handles for objects we don't model yet (ports/threads/events/sections) now live
    // on `nt_handler.next_handle` (Workstream A group A) — a single monotonic source shared by the
    // migrated create-handle handlers and the remaining ladder cases (NtCreateSection/Process/File).
    // Track the handles smss uses to launch csrss.exe: the file handle it opens (NtOpenFile), and
    // the SEC_IMAGE section it creates from it (NtCreateSection). NtCreateProcess (next step) will
    // spawn the real process from the section. Parse the staged csrss PE up front to prove it's
    // available (FILEBUF tail; size at STORAGE_SHARED+0x3c).
    let mut csrss_file_handle = 0u64;
    let mut csrss_section_handle = 0u64;
    let mut csrss_process_handle = 0u64;
    // winlogon.exe (the 3rd hosted process, smss's SmpExecuteInitialCommand initial command): the
    // file/section handles smss opens+creates for it, and its process handle once spawned. Same roles
    // as the csrss_* trio; the parsed PE is `winlogon_pe` below.
    let mut winlogon_file_handle = 0u64;
    let mut winlogon_section_handle = 0u64;
    let mut winlogon_process_handle = 0u64;
    // csrss's loadable DLLs (csrsrv + the ServerDlls basesrv/winsrv) are tracked by the generic
    // nt-dll-registry, built below once their PEs are parsed. The shared page-directory covering the
    // 0x8000_0000 1 GiB range (all DLL slots live in it) is created on the first NtMapViewOfSection.
    // Per-process (indexed by pi: 0=smss, 1=csrss, 2=winlogon): the DLL page-directory once-flag +
    // a bitmask of which registry DLLs have their PT reserved in that process's VSpace. csrss and
    // winlogon load an overlapping DLL set at identical bases into DISTINCT VSpaces, so each needs
    // its own PD/PT reservation (the registry's global `mapped` flag stays for VA-range resolution).
    let mut dll_pd_created = [false; 3];
    let mut dll_mapped_bits = [0u32; 3];
    // csrss's ANONYMOUS section (no file backing) — its CSR SharedSection shared memory. Tracked by
    // handle + requested size; NtMapViewOfSection reserves a VA range and the fault router
    // demand-pages ZERO frames into it (commit-on-touch).
    let mut csrss_anon_section_handle = 0u64;
    let mut csrss_anon_base = 0u64;
    let mut csrss_anon_size = 0u64;
    // The named NLS section \Nls\NlsSectionCP20127 (US-ASCII code-page table) csrss's Win32 client
    // stack maps during a DllMain. NtOpenSection records the handle; NtMapViewOfSection maps the
    // staged c_20127.nls frames into csrss.
    let mut nls_section_handle = 0u64;
    // Only the LIVE smss run (ntdll present) launches csrss AND has FILEBUF/STORAGE_SHARED mapped in
    // the executive; the earlier demo SEC_IMAGE call has neither, so skip the read there.
    // P7-A batch 5: source the two hosted-process EXEs csrss.exe + winlogon.exe BY PATH from the FS
    // pool (hybrid; falls back to FILEBUF/WINLOGONBUF on any FS miss). Each is then relocated to its
    // load base (PE_LOAD_BASE) + its OptionalHeader.ImageBase patched to match — exactly as the LIVE
    // smss path does — so ntdll doesn't try to RELOCATE THE EXE (ldrinit.c:2409, the EXE-reloc path,
    // is UNIMPLEMENTED in ReactOS → STATUS_INVALID_IMAGE_FORMAT). The relocation runs on `*_va` (the
    // pool buffer on an FS hit, else the fixed buffer); the demand-fault router reads the relocated
    // bytes via the PeFile slice, so it is agnostic to where the bytes live.
    let (csrss_pe, csrss_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\csrss.exe", b"csrss.exe",
        FILEBUF_VADDR + CSRSS_FILEBUF_OFFSET, 0x3c);
    if let Some(ref cpe) = csrss_pe {
        apply_relocations_to_buf(cpe, csrss_va, PE_LOAD_BASE);
        let e_lfanew = core::ptr::read_volatile((csrss_va + 0x3c) as *const u32) as u64;
        core::ptr::write_volatile((csrss_va + e_lfanew + 0x30) as *mut u64, PE_LOAD_BASE);
    }
    // winlogon.exe — smss's SmpExecuteInitialCommand initial command (the 3rd hosted process).
    let (winlogon_pe, winlogon_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\winlogon.exe", b"winlogon.exe",
        WINLOGONBUF_VADDR, 0x94);
    if let Some(ref wpe) = winlogon_pe {
        apply_relocations_to_buf(wpe, winlogon_va, PE_LOAD_BASE);
        let e_lfanew = core::ptr::read_volatile((winlogon_va + 0x3c) as *const u32) as u64;
        core::ptr::write_volatile((winlogon_va + e_lfanew + 0x30) as *mut u64, PE_LOAD_BASE);
    }
    // csrsrv.dll — csrss.exe's static-import Server DLL. Parsed from the FILEBUF (size at
    // STORAGE_SHARED+0x40); the loader load-path (NtOpenFile/NtCreateSection/NtMapViewOfSection for
    // csrsrv) maps it into csrss's VSpace and demand-pages it from here so csrss's imports resolve.
    // P7-A batch 3: source csrss's csrsrv.dll (static import) + basesrv.dll/winsrv.dll (its two
    // CsrLoadServerDll ServerDlls) BY PATH from the FS pool (hybrid; falls back to FILEBUF/SRVBUF on
    // any FS miss). dll_buf_va[0..3] = *_va below. csrsrv keeps registry base 0x8000_0000 = its
    // preferred ImageBase (relocation delta 0) regardless of where its bytes live.
    let (csrsrv_pe, csrsrv_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\csrsrv.dll", b"csrsrv",
        FILEBUF_VADDR + CSRSRV_FILEBUF_OFFSET, 0x40);
    let (basesrv_pe, basesrv_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\basesrv.dll", b"basesrv",
        SRVBUF_VADDR + BASESRV_SRVBUF_OFFSET, 0x44);
    let (winsrv_pe, winsrv_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\winsrv.dll", b"winsrv",
        SRVBUF_VADDR + WINSRV_SRVBUF_OFFSET, 0x48);
    // P7-A batch 4: the Win32 client stack heavyweights kernel32.dll (~2.66 MiB) + user32.dll
    // (~1.12 MiB) — winsrv.dll's static imports. Sourced BY PATH from the FS pool (hybrid; falls back
    // to WIN32BUF on any FS miss). Done last per the untyped caveat — during hybrid both the pool AND
    // WIN32BUF hold them, but headroom is ample (~36% of the slot budget). dll_buf_va[3..5] = *_va.
    let (kernel32_pe, kernel32_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\kernel32.dll", b"kernel32",
        WIN32BUF_VADDR + KERNEL32_WIN32BUF_OFFSET, 0x4c);
    let (user32_pe, user32_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\user32.dll", b"user32",
        WIN32BUF_VADDR + USER32_WIN32BUF_OFFSET, 0x50);
    // P7-A migration: source gdi32.dll BY PATH from the executive's FS pool; fall back to the fixed
    // WIN32BUF staging only if the FS load fails (hybrid). `gdi32_va` feeds dll_buf_va[5] below so the
    // relocation + demand-fault router use the same bytes the PeFile wraps.
    let mut gdi32_va = WIN32BUF_VADDR + GDI32_WIN32BUF_OFFSET;
    let gdi32_pe: Option<nt_pe_loader::PeFile<'static>> = if ntdll.is_some() {
        let (fs_pe, fs_va) = load_dll_from_fs(b"reactos\\system32\\gdi32.dll", b"gdi32.dll");
        if fs_va != 0 {
            gdi32_va = fs_va;
            fs_pe
        } else {
            let gsz = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x54) as *const u32) as usize;
            if gsz > 0 {
                let bytes: &'static [u8] = core::slice::from_raw_parts(
                    (WIN32BUF_VADDR + GDI32_WIN32BUF_OFFSET) as *const u8,
                    gsz,
                );
                match nt_pe_loader::PeFile::parse(bytes) {
                    Ok(gpe) => {
                        print_str(b"[ntos-exec] staged gdi32.dll: ");
                        print_u64(gsz as u64);
                        print_str(b" bytes (fixed buffer fallback)\n");
                        Some(gpe)
                    }
                    Err(_) => {
                        print_str(b"[ntos-exec] staged gdi32.dll: PARSE FAILED\n");
                        None
                    }
                }
            } else {
                None
            }
        }
    } else {
        None
    };
    // P7-A batch 2: source the 4 mid-size Win32 DLLs BY PATH from the FS pool (hybrid; falls back to
    // WIN32BUF on any FS miss). dll_buf_va[6..10] = *_va below.
    let (rpcrt4_pe, rpcrt4_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\rpcrt4.dll", b"rpcrt4",
        WIN32BUF_VADDR + RPCRT4_WIN32BUF_OFFSET, 0x58);
    let (msvcrt_pe, msvcrt_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\msvcrt.dll", b"msvcrt",
        WIN32BUF_VADDR + MSVCRT_WIN32BUF_OFFSET, 0x5c);
    let (advapi32_pe, advapi32_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\advapi32.dll", b"advapi32",
        WIN32BUF_VADDR + ADVAPI32_WIN32BUF_OFFSET, 0x60);
    let (ws2_32_pe, ws2_32_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\ws2_32.dll", b"ws2_32",
        WIN32BUF_VADDR + WS2_32_WIN32BUF_OFFSET, 0x64);
    // P7-A batch 1: source the 4 small vista-forwarder DLLs BY PATH from the FS pool (hybrid; falls
    // back to WIN32BUF on any FS miss). dll_buf_va[10..14] = *_va below.
    let (kernel32_vista_pe, kernel32_vista_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\kernel32_vista.dll", b"kernel32_vista",
        WIN32BUF_VADDR + KERNEL32_VISTA_WIN32BUF_OFFSET, 0x68);
    let (advapi32_vista_pe, advapi32_vista_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\advapi32_vista.dll", b"advapi32_vista",
        WIN32BUF_VADDR + ADVAPI32_VISTA_WIN32BUF_OFFSET, 0x6c);
    let (ws2help_pe, ws2help_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\ws2help.dll", b"ws2help",
        WIN32BUF_VADDR + WS2HELP_WIN32BUF_OFFSET, 0x70);
    let (ntdll_vista_pe, ntdll_vista_va) = load_dll_hybrid(
        ntdll.is_some(), b"reactos\\system32\\ntdll_vista.dll", b"ntdll_vista",
        WIN32BUF_VADDR + NTDLL_VISTA_WIN32BUF_OFFSET, 0x78);
    // userenv.dll + mpr.dll — winlogon.exe's two extra static imports (the rest of its Win32 stack
    // is shared with csrss above). Staged into WIN32BUF (sizes at STORAGE_SHARED +0x98/+0x9c); the
    // winlogon loader (pi==2) resolves + demand-pages them via the same nt-dll-registry path.
    // P7-A migration: source userenv.dll + mpr.dll BY PATH from the FS pool (fall back to WIN32BUF).
    let mut userenv_va = WIN32BUF_VADDR + USERENV_WIN32BUF_OFFSET;
    let userenv_pe: Option<nt_pe_loader::PeFile<'static>> = if ntdll.is_some() {
        let (fs_pe, fs_va) = load_dll_from_fs(b"reactos\\system32\\userenv.dll", b"userenv.dll");
        if fs_va != 0 {
            userenv_va = fs_va;
            fs_pe
        } else {
            let sz = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x98) as *const u32) as usize;
            if sz > 0 {
                let bytes: &'static [u8] = core::slice::from_raw_parts(
                    (WIN32BUF_VADDR + USERENV_WIN32BUF_OFFSET) as *const u8,
                    sz,
                );
                match nt_pe_loader::PeFile::parse(bytes) {
                    Ok(pe) => {
                        print_str(b"[ntos-exec] staged userenv.dll (fixed buffer fallback)\n");
                        Some(pe)
                    }
                    Err(_) => {
                        print_str(b"[ntos-exec] staged userenv.dll: PARSE FAILED\n");
                        None
                    }
                }
            } else {
                None
            }
        }
    } else {
        None
    };
    let mut mpr_va = WIN32BUF_VADDR + MPR_WIN32BUF_OFFSET;
    let mpr_pe: Option<nt_pe_loader::PeFile<'static>> = if ntdll.is_some() {
        let (fs_pe, fs_va) = load_dll_from_fs(b"reactos\\system32\\mpr.dll", b"mpr.dll");
        if fs_va != 0 {
            mpr_va = fs_va;
            fs_pe
        } else {
            let sz = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x9c) as *const u32) as usize;
            if sz > 0 {
                let bytes: &'static [u8] = core::slice::from_raw_parts(
                    (WIN32BUF_VADDR + MPR_WIN32BUF_OFFSET) as *const u8,
                    sz,
                );
                match nt_pe_loader::PeFile::parse(bytes) {
                    Ok(pe) => {
                        print_str(b"[ntos-exec] staged mpr.dll (fixed buffer fallback)\n");
                        Some(pe)
                    }
                    Err(_) => {
                        print_str(b"[ntos-exec] staged mpr.dll: PARSE FAILED\n");
                        None
                    }
                }
            } else {
                None
            }
        }
    } else {
        None
    };
    // Generic DLL registry: csrss's loadable DLLs — its static import csrsrv.dll + the dynamically
    // loaded ServerDlls basesrv.dll/winsrv.dll (CsrLoadServerDll), and — later — the Win32 client
    // stack, which becomes staging-only. Each is given a fixed 16 MiB base slot from 0x8000_0000;
    // csrsrv (registered first) keeps 0x8000_0000 = its preferred ImageBase so the loader never
    // relocates it (its text is byte-identical and shared read-only). All slots share the 1 GiB
    // 0x8000_0000 PDPT range. Load-flow DECISIONS (name/handle/VA lookups + SECTION_IMAGE_INFORMATION)
    // run through host-tested nt-dll-registry; the executive keeps the parsed PEs parallel (indexed
    // the same) for the effectful demand-fill. Adding a DLL = stage it + one register() call.
    // (winsrv is ~100 pages — the root CNode is an XL page under extern-rootserver, so the caps fit.)
    let dll_pes: [&Option<nt_pe_loader::PeFile>; 16] = [
        &csrsrv_pe, &basesrv_pe, &winsrv_pe, &kernel32_pe, &user32_pe, &gdi32_pe, &rpcrt4_pe,
        &msvcrt_pe, &advapi32_pe, &ws2_32_pe, &kernel32_vista_pe, &advapi32_vista_pe, &ws2help_pe,
        &ntdll_vista_pe, &userenv_pe, &mpr_pe,
    ];
    let dll_seed: [&[u8]; 16] = [
        b"csrsrv", b"basesrv", b"winsrv", b"kernel32", b"user32", b"gdi32", b"rpcrt4", b"msvcrt",
        b"advapi32", b"ws2_32", b"kernel32_vista", b"advapi32_vista", b"ws2help", b"ntdll_vista",
        b"userenv", b"mpr",
    ];
    let mut reg = nt_dll_registry::Registry::new(0x0000_0000_8000_0000, 0x0000_0000_0100_0000);
    for i in 0..16 {
        let (sz, ent) = dll_pes[i]
            .as_ref()
            .map(|p| (image_extent(p), p.entry_point_rva()))
            .unwrap_or((0, 0));
        reg.register(dll_seed[i], sz, ent);
    }
    // Pre-relocate each registry DLL to its fixed registry base + patch OptionalHeader.ImageBase to
    // match. Our fake NtMapViewOfSection does NOT relocate SEC_IMAGE views — real Windows relocates
    // an image section in the kernel at map time, so ntdll's loader trusts it's done and skips its own
    // relocation. So WE must relocate, or a DLL that dereferences an absolute pointer during init
    // faults (advapi32_vista read an un-relocated ImageBase+0x7000). Relocating to a FIXED base also
    // makes each DLL's executable text byte-identical across processes → correctly shared read-only.
    // csrsrv is already at its preferred ImageBase (delta 0 → no-op). Patch ImageBase AFTER relocating
    // (apply_relocations_to_buf reads the old ImageBase to compute the delta) so the loader sees
    // ImageBase == mapped base and doesn't double-relocate.
    let dll_buf_va: [u64; 16] = [
        csrsrv_va,  // P7-A batch 3: pool VA on FS hit, else FILEBUF+CSRSRV_FILEBUF_OFFSET
        basesrv_va, // P7-A batch 3: pool VA on FS hit, else SRVBUF+BASESRV_SRVBUF_OFFSET
        winsrv_va,  // P7-A batch 3: pool VA on FS hit, else SRVBUF+WINSRV_SRVBUF_OFFSET
        kernel32_va, // P7-A batch 4: pool VA on FS hit, else WIN32BUF+KERNEL32_WIN32BUF_OFFSET
        user32_va,   // P7-A batch 4: pool VA on FS hit, else WIN32BUF+USER32_WIN32BUF_OFFSET
        gdi32_va, // P7-A: pool VA when sourced BY PATH, else WIN32BUF+GDI32_WIN32BUF_OFFSET
        rpcrt4_va,   // P7-A batch 2: pool VA on FS hit, else WIN32BUF+RPCRT4_WIN32BUF_OFFSET
        msvcrt_va,   // P7-A batch 2: pool VA on FS hit, else WIN32BUF+MSVCRT_WIN32BUF_OFFSET
        advapi32_va, // P7-A batch 2: pool VA on FS hit, else WIN32BUF+ADVAPI32_WIN32BUF_OFFSET
        ws2_32_va,   // P7-A batch 2: pool VA on FS hit, else WIN32BUF+WS2_32_WIN32BUF_OFFSET
        kernel32_vista_va, // P7-A batch 1: pool VA on FS hit, else WIN32BUF+KERNEL32_VISTA_WIN32BUF_OFFSET
        advapi32_vista_va, // P7-A batch 1: pool VA on FS hit, else WIN32BUF+ADVAPI32_VISTA_WIN32BUF_OFFSET
        ws2help_va,        // P7-A batch 1: pool VA on FS hit, else WIN32BUF+WS2HELP_WIN32BUF_OFFSET
        ntdll_vista_va,    // P7-A batch 1: pool VA on FS hit, else WIN32BUF+NTDLL_VISTA_WIN32BUF_OFFSET
        userenv_va, // P7-A: pool VA when sourced BY PATH, else WIN32BUF+USERENV_WIN32BUF_OFFSET
        mpr_va,     // P7-A: pool VA when sourced BY PATH, else WIN32BUF+MPR_WIN32BUF_OFFSET
    ];
    for i in 0..16 {
        if let Some(pe) = dll_pes[i].as_ref() {
            let base = reg.base(i);
            apply_relocations_to_buf(pe, dll_buf_va[i], base);
            let e_lfanew = core::ptr::read_volatile((dll_buf_va[i] + 0x3c) as *const u32) as u64;
            core::ptr::write_volatile((dll_buf_va[i] + e_lfanew + 0x30) as *mut u64, base);
        }
    }
    // The real NT syscall path (seam): dispatch SSNs the handler implements; the rest fall back
    // to the broker match below.
    let nt_dispatcher = NativeSyscallDispatcher::new(build_nt_table());
    let mut nt_handler = ExecNtHandler::new();
    // Heap high-water mark taken AFTER all persistent state (the service table + the
    // pre-reserved key_handles buffer) is allocated. Each smss syscall we service allocates
    // transient Vec/String (copyin buffers, registry value info) on the no-free bump heap; without
    // reclamation a few hundred registry syscalls exhaust the 128 KiB heap and the executive
    // panics. Rewinding to this mark each iteration reclaims all per-syscall transients while
    // leaving the persistent state (below the mark) intact.
    let heap_mark = allocator::mark();
    // Per-hosted-process state, indexed by fault badge (0 = smss, 1 = csrss). The SINGLE service
    // loop multiplexes both: each thread faults through a fault-EP cap minted with its badge, so the
    // recv badge selects whose VSpace / image / scratch / fault-bookkeeping to use. Slot 1 (csrss)
    // is filled in when NtCreateProcess spawns it; until then only slot 0 (smss) is live. The `mut`
    // working locals (pml4/scratch_base/img_end/pe via shadowing, faults/first/ntfaults/filled_pages)
    // are LOADED from these at the top of each iteration and SAVED back before each recv, so the
    // ~30 body references stay unchanged.
    // smss's PE (the function param `pe` is shadowed per-iteration to the active process's image; the
    // SM-loop rendezvous always demand-fills SMSS's image, so capture it here before the shadow).
    let smss_pe: &nt_pe_loader::PeFile = pe;
    // Bind smss's pre-created main ETHREAD to its real image entry (smss is already running from the
    // initial recv, not a loop spawn — so bind here). Only on the LIVE run (ntdll present).
    if ntdll.is_some() {
        nt_handler.bind_main_thread_entry(0, PE_LOAD_BASE + smss_pe.entry_point_rva() as u64);
    }
    // Slots: 0 = smss, 1 = csrss, 2 = winlogon (filled when NtCreateProcess spawns each). Path 3:
    // the six ex-parallel identity arrays are now ONE array of `ProcExec`, each slot EPROCESS-linked
    // via its `pid` (== PM_PIDS[pi]; the EPROCESS exists at boot, so link all three now). smss (slot
    // 0) is live from the initial recv; csrss/winlogon's pml4/scratch/img_end fill in at their spawn.
    let mut procs = [ProcExec::empty(); 3];
    for (i, p) in procs.iter_mut().enumerate() {
        p.pid = nt_handler.pm_pid_for_pi(i).map(|pid| pid as u64).unwrap_or(0);
    }
    procs[0].pml4 = pml4;
    procs[0].scratch_base = scratch_base;
    procs[0].img_end = img_end;
    // Per-process demand-fill bookkeeping — kept in a `static mut` (3×2 KiB) rather than on the
    // 16 KiB rootserver stack (a [[u64;256];3] local + the loop's other arrays would risk the guard
    // page — the recurring stack-array-overflow hazard). service_sec_image runs once for the live
    // run; zero it at entry so the demo call (ntdll=None) starts clean too.
    let pfilled: &mut [[u64; 256]; 3] = &mut *core::ptr::addr_of_mut!(PFILLED);
    for p in pfilled.iter_mut() {
        for e in p.iter_mut() {
            *e = 0;
        }
    }
    // Fix (B): the INITIAL recv also binds REPLY_MAIN (r12) so the first caller's Call is captured
    // as a reply cap, matching every reply_recv_badge recv in the loop body.
    let (mut badge, mut mi, mut m0, mut m1, mut m2, mut m3) =
        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
    loop {
        // SAFETY: every allocation made past `heap_mark` belongs to the previous iteration's
        // syscall service and is dead now (its Vec/String were dropped at the loop-body's end).
        unsafe { allocator::reset_to(heap_mark) };
        iters += 1;
        // With the per-syscall heap reset above, smss now runs all the way through the ntdll
        // loader + Session Manager SmpInit — enumerating its real registry (NtOpenKey/
        // NtEnumerateValueKey/NtClose) — to a NATURAL stop: SmpInit fails at the missing \??
        // DosDevices object namespace and smss winds down into an unserviced syscall (stop_ssn),
        // ~290 iters, a few seconds. This ceiling is only a safety backstop against a future
        // genuine infinite loop; the run stops well before it.
        if iters > 3000 {
            stop = m1;
            break;
        }
        // Select the hosted process this fault/syscall came from (0 = smss, CSRSS_BADGE = csrss) and
        // LOAD its state into the working locals. pml4/scratch_base/img_end/pe are immutable per
        // process (shadow the params); faults/first/ntfaults/filled_pages are mutable (SAVED back
        // before every recv below).
        let pi = if badge == CSRSS_BADGE {
            1
        } else if badge == WINLOGON_BADGE {
            2
        } else {
            0
        };
        // Convergence (first increment): resolve this fault badge → its real EPROCESS via the Process
        // Manager (badge → pi → PM_PIDS[pi] → pm.process(pid)). Read-only (no alloc under the reset),
        // it proves the live badge-multiplex is backed by real nt-process objects. The ad-hoc per-pi
        // arrays below still carry the load-bearing mechanism state; the bulk migrates that onto the
        // EPROCESS next (see the convergence report).
        if let Some(pid) = nt_handler.pm_pid_for_pi(pi) {
            if nt_handler.pm.process(pid).is_some() {
                PM_BADGE_LOOKUPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Route the shared stack helpers (smss_stack_read/write) to THIS process's stack mirror, so
        // its syscall out-params (e.g. NtAllocateVirtualMemory's base for RtlCreateHeap) land on its
        // own stack, not the other process's.
        ACTIVE_STACK_MIRROR.store(
            match pi {
                1 => CSRSS_STACK_MIRROR_VA,
                2 => WINLOGON_STACK_MIRROR_VA,
                _ => SMSS_STACK_MIRROR_VA,
            },
            Ordering::Relaxed,
        );
        ACTIVE_IMAGE_MIRROR.store(
            match pi {
                1 => CSRSS_IMAGE_MIRROR_VA,
                2 => WINLOGON_IMAGE_MIRROR_VA,
                _ => IMAGE_MIRROR_VA,
            },
            Ordering::Relaxed,
        );
        ACTIVE_HEAP_MIRROR.store(
            match pi {
                1 => CSRSS_HEAP_MIRROR_VA,
                2 => WINLOGON_HEAP_MIRROR_VA,
                _ => SMSS_HEAP_MIRROR_VA,
            },
            Ordering::Relaxed,
        );
        let pml4 = procs[pi].pml4;
        let scratch_base = procs[pi].scratch_base;
        let img_end = procs[pi].img_end;
        let pe: &nt_pe_loader::PeFile = match pi {
            1 => csrss_pe.as_ref().unwrap(),
            2 => winlogon_pe.as_ref().unwrap(),
            _ => pe,
        };
        faults = procs[pi].faults;
        first = procs[pi].first;
        ntfaults = procs[pi].ntfaults;
        filled_pages = pfilled[pi];
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
                        procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = filled_pages;
                        let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 3, fip + 3, m1, m2, 0);
                        badge = nb;
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
            // ROBUSTNESS (gate-safety): a genuine NULL/low deref (addr < 64 KiB) is never a
            // demand-fillable region (image/DLL/scratch/stack/anon all live far above) — it's an
            // unrecoverable client fault (e.g. user32's UserClientDllInitialize deref of a still-null
            // gSharedInfo). Map it and we hand the faulter a zero page → it silently spins on the bad
            // value and the loop never makes progress (deterministic hang). So STOP the loop cleanly
            // with a diagnostic instead — exactly like the win32k `[vmf-out]` stop path.
            if addr < 0x10000 {
                print_str(if pi == 1 { b"[csrss vmf] NULL/low deref ip=0x" } else { b"[smss vmf] NULL/low deref ip=0x" });
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((addr >> 32) as u32);
                print_hex(addr as u32);
                print_str(b" (dll_rva = ip - dll_base; user32@0x84000000, gdi32@0x85000000)\n");
                stop = addr;
                break;
            }
            // Dynamic stack growth (Windows guard-page style): a fault just below the committed
            // stack commits a fresh zeroed page and restarts, so smss's stack grows on demand
            // instead of crashing at the 16 KiB initial commit. Bounded by STACK_GROWTH_FLOOR so it
            // never runs into the env mappings below.
            if page >= STACK_GROWTH_FLOOR && page < STACK_BASE {
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, pml4);
                if pi >= 1 {
                    // A GUI client (csrss pi 1 / winlogon pi 2) stack pointer — shareable into win32k
                    // at the same VA when this client dispatches an NtUser/NtGdi call (per-client).
                    csrss_frame_put(pi as u64, page, f);
                }
                faults += 1;
                procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = filled_pages;
                let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                badge = nb;
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
            // csrss's anonymous section (CSR shared memory): commit a ZERO frame on touch.
            if pi == 1
                && csrss_anon_base != 0
                && page >= csrss_anon_base
                && page < csrss_anon_base + ((csrss_anon_size + 0xFFF) & !0xFFFu64)
            {
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, pml4);
                csrss_frame_put(pi as u64, page, f); // CSR shared section (pi 1) — shareable into win32k
                faults += 1;
                procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = filled_pages;
                let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                badge = nb;
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
            // Route to whichever image contains the faulting page.
            let (base, tpe) = if page >= PE_LOAD_BASE && page < img_end {
                (PE_LOAD_BASE, pe)
            } else if nt_base != 0 && page >= nt_base && page < nt_end {
                ntfaults += 1;
                (nt_base, ntdll.unwrap().1)
            } else if let Some((i, _)) = if pi >= 1 { reg.dll_for_page(page) } else { None } {
                // A mapped registry DLL (csrsrv/basesrv/winsrv/Win32 stack) in a DLL-loading
                // process's VSpace (csrss pi==1 OR winlogon pi==2) — demand-page it from that DLL's
                // parsed PE. csrsrv sits at its preferred ImageBase (no relocation); the others are
                // loader-relocated to their fixed bases. The registry resolves which one owns the page.
                (reg.base(i), dll_pes[i].as_ref().unwrap())
            } else {
                // DIAG: dump the fault so we can tell a stack-growth fault (addr just below the
                // stack) from a real null deref. m0=IP, m1=addr(cr2), m2=prefetch, m3=fsr.
                print_str(b"[vmf-out] ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((addr >> 32) as u32);
                print_hex(addr as u32);
                print_str(b" pf=");
                print_u64(m2);
                print_str(b" fsr=");
                print_u64(m3);
                print_str(b" img_end=0x");
                print_hex((img_end >> 32) as u32);
                print_hex(img_end as u32);
                print_str(b" stack=[0x");
                print_hex(STACK_BASE as u32);
                print_str(b"..0x");
                print_hex((STACK_BASE + STACK_FRAMES * 0x1000) as u32);
                print_str(b")\n");
                stop = addr; // outside both images (unresolved / null deref) — stop safely
                break;
            };
            if faults >= 2000 {
                stop = addr;
                break;
            }
            let rva = (page - base) as u32;
            // SHAREABLE = a registered DLL's executable text (not the per-process main image at
            // PE_LOAD_BASE, and an RX page). Such a page is byte-identical across processes (each DLL
            // is loaded at a fixed base + pre-relocated), so it's filled ONCE into a frame and that
            // frame is mapped READ-ONLY (RX) into every process that faults it — real image sharing.
            let shareable = base != PE_LOAD_BASE && page_rights(tpe, rva) == 2;
            let cached = if shareable { dll_cache_get(page) } else { 0 };
            let (frame, rights) = if cached != 0 {
                DLL_SHARED_HITS.fetch_add(1, Ordering::Relaxed);
                (cached, 2u64) // shared text → RX, no fill, no fresh frame
            } else {
                // MISS (shared, first process) or a per-process page: fill a fresh frame.
                let scratch = scratch_base + faults * 0x1000;
                let (f, fe) = alloc_frame_r();
                let se = page_map_r(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
                let r = fill_image_page(tpe, rva, scratch);
                if fe != 0 || se != 0 {
                    print_str(b"[map-fail] rva=0x");
                    print_hex(rva);
                    print_str(b" retype=");
                    print_u64(fe);
                    print_str(b" smap=");
                    print_u64(se);
                    print_str(b" faults=");
                    print_u64(faults);
                    print_str(b"\n");
                }
                if shareable {
                    dll_cache_put(page, f); // this frame becomes the shared copy for all processes
                } else {
                    // Per-process page (main image, or DLL headers/rdata/data/IAT): record it for
                    // copy-out via its scratch alias, and mirror the main image so smss_copyin can
                    // read static-string args from .rdata.
                    if (faults as usize) < filled_pages.len() {
                        filled_pages[faults as usize] = page;
                    }
                    if pi >= 1 {
                        // Record this GUI client's (csrss pi 1 / winlogon pi 2) frame so win32k can
                        // identity-map + read/write it per-client (a client pointer into user32/gdi32
                        // .data — e.g. the PFNCLIENT arrays — the client's stack-built OBJECT_ATTRIBUTES,
                        // or its own image). The frame is shared with the executive's scratch, so it
                        // holds the client's LIVE runtime data, not the (zeroed) PE static content.
                        csrss_frame_put(pi as u64, page, f);
                    }
                    if base == PE_LOAD_BASE {
                        let off = page - PE_LOAD_BASE;
                        if off < IMAGE_MIRROR_WINDOW {
                            let mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
                            let _ = page_map(copy_cap(f), mirror + off, RW_NX, CAP_INIT_THREAD_VSPACE);
                        }
                    }
                }
                faults += 1; // a fill consumed a scratch slot; shared HITs do not
                (f, if shareable { 2 } else { r })
            };
            // Map the frame into the faulting process (RX for shared text, its fill rights otherwise).
            let (cc, ce) = copy_cap_r(frame);
            let me = page_map_r(cc, page, rights, pml4);
            if ce != 0 || me != 0 {
                print_str(b"[map-fail] va=0x");
                print_hex(page as u32);
                print_str(b" copy=");
                print_u64(ce);
                print_str(b" map=");
                print_u64(me);
                print_str(b" shared=");
                print_u64(shareable as u64);
                print_str(b"\n");
            }
            procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = filled_pages;
            let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
            badge = nb;
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
            ssn_ring_badge[ssn_ri % 32] = badge as u8;
            ssn_ri += 1;
            let resume_ip = m2; // RCX = syscall return address
            let sp = get_recv_mr(16);
            let flags = get_recv_mr(17);
            let mut result = 0u64; // STATUS_SUCCESS unless a handler overrides
            let mut handled = true;
            // Fix (B): set when this syscall was routed to the win32k component. win32k faults
            // during the nested dispatch clobber the executive's `reply_to` (finish_call), so this
            // caller's reply must go back through its bound reply cap (REPLY_MAIN) rather than the
            // legacy reply_to path — see the tail below.
            let mut routed_win32k = false;
            // Set when csrss's NtConnectPort was completed via the nested SM rendezvous (like
            // routed_win32k, the SM-loop thread's faults clobbered `reply_to`, so reply via REPLY_MAIN).
            let mut routed_lpc = false;
            // Set when winlogon's NtSecureConnectPort was completed via the nested CSR rendezvous
            // (like routed_lpc, the CSR thread's faults clobbered reply_to → reply via REPLY_MAIN).
            let mut routed_csr = false;
            // Set when the caller terminates its own thread (NtTerminateThread of NtCurrentThread):
            // leave it blocked in the kernel (never reply) and recv the next event. csrss's main
            // thread does this after CsrServerInitialization ("CSRSRV keeps us going" — the fake API
            // worker threads stand in), so csrss goes quiet and smss proceeds.
            let mut park_caller = false;
            // SEAM: if this SSN is in the real service table, dispatch it through the NT syscall
            // dispatcher -> real handler; otherwise fall through to the broker match. The x64 native
            // ABI passes args in r10(=rcx),rdx,r8,r9 then the stack; here we forward the register
            // args (sized to the service's max) — pointer/stack args come with the copyin layer.
            if let Some(entry) = nt_dispatcher.table().lookup(m0 as u32) {
                let origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
                // x64 native syscall args: arg1=R10 (the stub's `mov r10,rcx`; RCX itself is the
                // syscall return address), arg2=RDX, arg3=R8, arg4=R9, then arg5+ on the caller's
                // stack at [rsp+0x28], [rsp+0x30], … RDX rides in m3; R8/R9/R10 + the stack come
                // from the IPC buffer / stack mirror.
                let mut argv = [0u64; 16];
                argv[0] = get_recv_mr(9); // R10
                argv[1] = m3; // RDX
                argv[2] = get_recv_mr(7); // R8
                argv[3] = get_recv_mr(8); // R9
                let n = (entry.max_args as usize).min(16);
                for i in 4..n {
                    argv[i] = smss_stack_read(sp + 0x28 + (i as u64 - 4) * 8);
                }
                // Refresh the handler's per-call executive context, then clear the stop side-signal
                // + out-write queue so a migrated handler can raise them (group A/B signals).
                nt_handler.pi = pi;
                nt_handler.stop = false;
                nt_handler.out_writes_n = 0;
                nt_handler.spawn_request = false;
                nt_handler.winlogon_spawn_request = false;
                nt_handler.sm_spawn_request = false;
                nt_handler.lpc_rendezvous_conn = 0;
                nt_handler.csr_spawn_request = false;
                nt_handler.csr_rendezvous_conn = 0;
                // Group-C handlers reach the loop's section/registry/demand-fill state through this
                // ctx of raw refs (rebuilt each iteration at the current loop locals).
                nt_handler.loop_ctx = Some(ExecLoopCtx {
                    pml4,
                    nls_section_handle: &mut nls_section_handle as *mut u64,
                    reg: &mut reg as *mut nt_dll_registry::Registry,
                    csrss_file_handle: &mut csrss_file_handle as *mut u64,
                    csrss_section_handle: &mut csrss_section_handle as *mut u64,
                    csrss_pe: &csrss_pe as *const Option<nt_pe_loader::PeFile<'static>>,
                    winlogon_file_handle: &mut winlogon_file_handle as *mut u64,
                    winlogon_section_handle: &mut winlogon_section_handle as *mut u64,
                    winlogon_pe: &winlogon_pe as *const Option<nt_pe_loader::PeFile<'static>>,
                    filled_pages: &mut filled_pages as *mut [u64; 256],
                    faults: &mut faults as *mut u64,
                    scratch_base,
                    // Erase the non-'static lifetime through a thin `*const ()` (the image bytes are
                    // executive-lifetime; the loop outlives every `dispatch`).
                    pe: pe as *const nt_pe_loader::PeFile as *const ()
                        as *const nt_pe_loader::PeFile<'static>,
                    ntdll_pe: match ntdll {
                        Some((_, npe)) => {
                            npe as *const nt_pe_loader::PeFile as *const ()
                                as *const nt_pe_loader::PeFile<'static>
                        }
                        None => core::ptr::null(),
                    },
                    img_end,
                    nt_base,
                    nt_end,
                    dll_pes: &dll_pes as *const [&Option<nt_pe_loader::PeFile>; 16] as *const ()
                        as *const [&'static Option<nt_pe_loader::PeFile<'static>>; 16],
                    csrss_anon_section_handle: &mut csrss_anon_section_handle as *mut u64,
                    csrss_anon_size: &mut csrss_anon_size as *mut u64,
                    csrss_anon_base: &mut csrss_anon_base as *mut u64,
                    dll_pd_created: &mut dll_pd_created as *mut [bool; 3],
                    dll_mapped_bits: &mut dll_mapped_bits as *mut [u32; 3],
                });
                // ALPC last-mile item (a): NtAlpc* SSNs are registered in the dispatcher via this
                // recognizer. DORMANT — `ALPC_HOST_PRESENT` is never set at boot (no ALPC binary
                // yet), and the Win7 ALPC SSNs collide with the live ReactOS SSN space, so it can
                // never fire for the 3 live ReactOS processes → byte-identical boot. When active it
                // routes a real ALPC process's NtAlpc* syscall to the unified port-service ALPC
                // adapter (skipping the native ReactOS dispatch).
                if let Some(st) = try_route_alpc_ssn(m0, &[], &mut [0u8; 8]) {
                    result = st;
                    handled = true;
                } else {
                    let res = nt_dispatcher.dispatch(m0 as u32, &argv[..n], &origin, &mut nt_handler);
                    result = res.status as u64;
                    if nt_handler.stop {
                        handled = false; // handler couldn't service → stop with the SSN recorded
                    }
                }
                // Drain queued out-param writes (group B2): csrss out-ptrs may be arbitrary VAs that
                // need demand-fill (csrss_out_write); smss out-ptrs are stack locals (smss_stack_write).
                for k in 0..nt_handler.out_writes_n {
                    let (ptr, val) = nt_handler.out_writes[k];
                    if badge == CSRSS_BADGE {
                        csrss_out_write(ptr, val, &mut filled_pages, &mut faults, scratch_base,
                            &reg, &dll_pes, pml4);
                    } else {
                        smss_stack_write(ptr, val);
                    }
                }
                // Control-flow post-action (group C): NtCreateProcess validated the csrss section and
                // asked the loop to spawn the subsystem process (needs fault_ep + the per-badge
                // arrays that stay loop-resident). Mirrors the stop/out-write signal-back.
                if nt_handler.spawn_request {
                    // Fault-EP cap minted at CSRSS_BADGE: csrss's faults/syscalls arrive on the shared
                    // service EP tagged with that badge, so this loop multiplexes it against smss.
                    let cf_c = mint_badged(fault_ep, CSRSS_BADGE);
                    let cpe = csrss_pe.as_ref().unwrap();
                    // Priority 101 (above smss's 100) so csrss actually gets scheduled: at equal
                    // priority smss + the executive ping-pong and csrss never runs. csrss preempts
                    // when runnable but blocks on every demand-fault (serviced by THIS loop, badge 2),
                    // which hands smss its turns — so both make progress and smss's own checks still
                    // pass. csrss uses a DISTINCT env-build scratch (0x78_0000, vs smss's 0x74_0000)
                    // so its trampoline/PEB/params frames aren't clobbered by smss's still-mapped ones.
                    // csrss's OWN process parameters (not smss's): its System32 image path drives
                    // the loader's DLL search + ".local" SxS probe, and its Server command line
                    // (ObjectDirectory/ServerDll=…) is what csrss.exe's entry parses once loaded.
                    const CSRSS_IMAGE_PATH: &[u8] = b"\\SystemRoot\\System32\\csrss.exe";
                    // TEMP (Phase 0b): drop the two `ServerDll=winsrv:...` entries. winsrv is the
                    // Win32 GUI server; its UserServerDllInitialization issues win32k NtUser/NtGdi
                    // syscalls (SSN >= 0x1000) that we have no graphics subsystem to service — a
                    // benign-success stub makes it null-deref the fake HWND/HDESK return. Skipping
                    // winsrv makes CsrParseServerCommandLine load only basesrv + csrsrv (neither
                    // touches win32k) so csrss reaches csrsrv's CsrApiPortInitialize / \SmApiPort +
                    // the SM<->CSR handshake, which csrsrv owns independently of winsrv. Real winsrv
                    // init returns once win32k is hosted (Phase 2).
                    // (`ServerDll=csrsrv` is NOT listed: csrsrv is ServerDll index 0, loaded
                    // implicitly by CsrServerInitialization itself. Listing it fails CsrLoadServerDll
                    // with STATUS_INVALID_PARAMETER — it has no ServerId. The real ReactOS command
                    // line omits it too; it was only masked before by winsrv crashing first.)
                    // Milestone C — winsrv DEFERRED pending the gSharedInfo grind (routing + marshaling
                    // infra is IN PLACE; re-enabling is the one-line ServerDll add below). With winsrv
                    // ON, csrsrv loads the full 14-DLL Win32 client stack and user32's DllMain `Init`
                    // (dllmain.c:410) calls **NtUserProcessConnect(NtCurrentProcess(), USERCONNECT*, 0x240)**
                    // = win32k SSN 0x10FA. The executive's SSN>=0x1000 forward arm ROUTES it (translating
                    // NtCurrentProcess()==-1 → the hosted client handle + marshaling the 0x240 USERCONNECT
                    // buffer through the shared ARG frame). BUT win32k's real NtUserProcessConnect handler
                    // then CPU-SPINS (zero faults, never signals done) — with the real ulVersion=USER_VERSION
                    // input it takes the FULL connect path that fills UserCon->siClient (gSharedInfo: psi +
                    // aheList handle table) from win32k's shared section, which isn't set up as a
                    // client-mappable section yet. Completing that (win32k produces a real USERCONNECT +
                    // executive maps win32k's gSharedInfo shared section RO into csrss + user32 derefs
                    // gHandleTable->handles) is the NEXT grind. Until then winsrv stays OUT so the gate is
                    // green. (`ServerDll=csrsrv` also stays OUT — csrsrv is ServerDll index 0, implicit.)
                    const CSRSS_CMD_LINE: &[u8] = b"csrss.exe ObjectDirectory=\\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16";
                    let cpml4 = spawn_sec_image(
                        1, cpe, cf_c, NTDLL_BASE, true, 101, 0x0000_0100_1078_0000,
                        CSRSS_STACK_MIRROR_VA, CSRSS_HEAP_MIRROR_VA, 0, CSRSS_IMAGE_PATH, CSRSS_CMD_LINE,
                    );
                    // Register csrss's per-process state (slot 1) so badge-2 faults resolve against
                    // ITS VSpace/image and a private scratch window.
                    procs[1].pml4 = cpml4;
                    procs[1].img_end = PE_LOAD_BASE + image_extent(cpe);
                    procs[1].scratch_base = CSRSS_SCRATCH_BASE;
                    // Bind csrss's pre-created main ETHREAD to its real image entry — pm at spawn.
                    nt_handler
                        .bind_main_thread_entry(1, PE_LOAD_BASE + cpe.entry_point_rva() as u64);
                    // Record csrss's process handle in smss's (the creator's) EPROCESS table as a
                    // real typed Process object; the returned dense value IS the handle smss gets
                    // (path 1b — process-local value). Fallback to a global value if pids are
                    // unknown (shouldn't happen for the 3 hosted).
                    csrss_process_handle = match (nt_handler.pm_pid_for_pi(0), nt_handler.pm_pid_for_pi(1)) {
                        (Some(smss_pid), Some(csrss_pid)) => {
                            let h = nt_handler.pm.insert_handle(
                                smss_pid,
                                nt_process::HandleObject::Process(csrss_pid),
                                0,
                            );
                            PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                            h.map(|v| v as u64).unwrap_or_else(|_| {
                                let g = nt_handler.next_handle;
                                nt_handler.next_handle += 1;
                                g
                            })
                        }
                        _ => {
                            let g = nt_handler.next_handle;
                            nt_handler.next_handle += 1;
                            g
                        }
                    };
                    smss_stack_write(get_recv_mr(9), csrss_process_handle); // *ProcessHandle (R10)
                    print_str(b"[ntos-exec] NtCreateProcess: spawned csrss (badge 2) -> handle 0x");
                    print_hex((csrss_process_handle >> 32) as u32);
                    print_hex(csrss_process_handle as u32);
                    print_str(b"; its faults now multiplexed into this loop\n");
                }
                // The 3rd hosted process: smss's SmpExecuteInitialCommand → RtlCreateUserProcess
                // created winlogon's SEC_IMAGE section; NtCreateProcess validated it. Spawn winlogon
                // (badge WINLOGON_BADGE) exactly like csrss — its own VSpace + image + ntdll + fault
                // EP, per-process env-scratch/mirrors/alloc-bump (all distinct from smss/csrss). Its
                // ntdll loader then runs, multiplexed into this loop by badge. Prio 102 (> csrss 101 >
                // smss 100) so it is actually scheduled; it blocks on every demand-fault (serviced
                // here), handing the others their turns.
                if nt_handler.winlogon_spawn_request {
                    let wf_c = mint_badged(fault_ep, WINLOGON_BADGE);
                    let wpe = winlogon_pe.as_ref().unwrap();
                    const WINLOGON_IMAGE_PATH: &[u8] = b"\\SystemRoot\\System32\\winlogon.exe";
                    const WINLOGON_CMD_LINE: &[u8] = b"winlogon.exe";
                    let wpml4 = spawn_sec_image(
                        2, wpe, wf_c, NTDLL_BASE, true, 102, 0x0000_0100_107C_0000,
                        WINLOGON_STACK_MIRROR_VA, WINLOGON_HEAP_MIRROR_VA, WINLOGON_IMAGE_MIRROR_VA,
                        WINLOGON_IMAGE_PATH, WINLOGON_CMD_LINE,
                    );
                    procs[2].pml4 = wpml4;
                    procs[2].img_end = PE_LOAD_BASE + image_extent(wpe);
                    procs[2].scratch_base = WINLOGON_SCRATCH_BASE;
                    // Bind winlogon's pre-created main ETHREAD to its real image entry — pm at spawn.
                    nt_handler
                        .bind_main_thread_entry(2, PE_LOAD_BASE + wpe.entry_point_rva() as u64);
                    // Record winlogon's process handle in smss's EPROCESS table as a typed Process
                    // object; the returned dense value IS smss's handle (path 1b).
                    winlogon_process_handle = match (nt_handler.pm_pid_for_pi(0), nt_handler.pm_pid_for_pi(2)) {
                        (Some(smss_pid), Some(winlogon_pid)) => {
                            let h = nt_handler.pm.insert_handle(
                                smss_pid,
                                nt_process::HandleObject::Process(winlogon_pid),
                                0,
                            );
                            PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                            h.map(|v| v as u64).unwrap_or_else(|_| {
                                let g = nt_handler.next_handle;
                                nt_handler.next_handle += 1;
                                g
                            })
                        }
                        _ => {
                            let g = nt_handler.next_handle;
                            nt_handler.next_handle += 1;
                            g
                        }
                    };
                    smss_stack_write(get_recv_mr(9), winlogon_process_handle); // *ProcessHandle (R10)
                    print_str(b"[ntos-exec] NtCreateProcess: spawned winlogon (badge 4) -> handle 0x");
                    print_hex((winlogon_process_handle >> 32) as u32);
                    print_hex(winlogon_process_handle as u32);
                    print_str(b"; its ntdll loader now multiplexed into this loop\n");
                    WINLOGON_SPAWNED.store(1, Ordering::Relaxed);
                }
                // Path B: smss's first NtCreateThread (an SmpApiLoop worker) — spawn the REAL SM-loop
                // thread in smss's VSpace. Read the CONTEXT off smss's stack: the NtCreateThread ABI
                // has Context* at [sp+0x30] (arg6), and RtlInitializeContext(amd64) set CONTEXT.Rip@0xF8
                // = StartAddress (SmpApiLoop) and CONTEXT.Rcx@0x80 = Parameter (the \SmApiPort handle).
                // (pi == 0 here so ACTIVE_STACK_MIRROR = smss's mirror; pml4 = smss's PML4.)
                if nt_handler.sm_spawn_request && SM_LOOP_TCB.swap(1, Ordering::Relaxed) == 0 {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let entry_rip = smss_stack_read(ctx_va + 0xF8);
                    let port_handle = smss_stack_read(ctx_va + 0x80);
                    print_str(b"[sm-loop] spawning REAL SmpApiLoop thread: ctx=0x");
                    print_hex((ctx_va >> 32) as u32);
                    print_hex(ctx_va as u32);
                    print_str(b" entry=0x");
                    print_hex((entry_rip >> 32) as u32);
                    print_hex(entry_rip as u32);
                    print_str(b" port=0x");
                    print_hex((port_handle >> 32) as u32);
                    print_hex(port_handle as u32);
                    print_str(b"\n");
                    let tcb = spawn_sm_loop_thread(pml4, entry_rip, port_handle);
                    SM_LOOP_TCB.store(tcb, Ordering::Relaxed);
                    print_str(b"[sm-loop] spawned tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (parks on its first fault to sm_fault_ep)\n");
                }
                // Authentic CSR accept: csrss's first NtCreateThread (its CsrApiRequestThread) — spawn
                // the REAL CSR API thread in csrss's VSpace (pi == 1 here → pml4 = csrss's PML4,
                // ACTIVE_STACK_MIRROR = csrss's mirror). Same CONTEXT ABI as SM: Context* at [sp+0x30],
                // CONTEXT.Rip@0xF8 = CsrApiRequestThread, CONTEXT.Rcx@0x80 = Parameter (hRequestEvent).
                if nt_handler.csr_spawn_request && CSR_LOOP_TCB.swap(1, Ordering::Relaxed) == 0 {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let entry_rip = smss_stack_read(ctx_va + 0xF8);
                    let param = smss_stack_read(ctx_va + 0x80);
                    print_str(b"[csr-loop] spawning REAL CsrApiRequestThread: entry=0x");
                    print_hex((entry_rip >> 32) as u32);
                    print_hex(entry_rip as u32);
                    print_str(b" param=0x");
                    print_hex(param as u32);
                    print_str(b"\n");
                    let tcb = spawn_csr_loop_thread(pml4, entry_rip, param);
                    CSR_LOOP_TCB.store(tcb, Ordering::Relaxed);
                    print_str(b"[csr-loop] spawned tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (parks on its first fault to csr_fault_ep)\n");
                }
                // Path B (authentic accept): csrss's NtConnectPort left the broker connection Pending
                // (Manual). Drive the REAL SmpApiLoop thread through the connection rendezvous (it runs
                // in smss's VSpace = procs[0].pml4, demand-filling from smss's image + ntdll), then write the
                // completed client comm-port handle to csrss's *PortHandle + reply csrss via REPLY_MAIN.
                if nt_handler.lpc_rendezvous_conn != 0 {
                    let conn_id = nt_handler.lpc_rendezvous_conn;
                    let out_ptr = nt_handler.lpc_rendezvous_out;
                    print_str(b"[sm-rdv] csrss NtConnectPort pending (conn=");
                    print_u64(conn_id);
                    print_str(b") -> driving the real SmpApiLoop accept\n");
                    let client_handle = sm_rendezvous(
                        conn_id,
                        procs[0].pml4,
                        smss_pe,
                        procs[0].img_end,
                        nt_base,
                        nt_end,
                        ntdll.map(|(_, p)| p),
                    );
                    if client_handle != 0 {
                        // csrss's *PortHandle is a csrsrv/csrss VA (demand-fill window) — csrss_out_write.
                        csrss_out_write(out_ptr, client_handle, &mut filled_pages, &mut faults,
                            scratch_base, &reg, &dll_pes, pml4);
                        let name16 = nt_handler.read_lpc_name(m3); // RDX = PortName (for the cache record)
                        nt_handler.cache_lpc_connection(conn_id, client_handle, &name16);
                        result = 0; // STATUS_SUCCESS
                        routed_lpc = true;
                        print_str(b"[sm-rdv] AUTHENTIC accept complete: client handle=0x");
                        print_hex((client_handle >> 32) as u32);
                        print_hex(client_handle as u32);
                        print_str(b" -> csrss NtConnectPort SUCCESS\n");
                    } else {
                        // The rendezvous walled — stop cleanly with a diagnostic (don't hand csrss junk).
                        print_str(b"[sm-rdv] WALL: rendezvous produced no client handle\n");
                        handled = false;
                        result = 0xC0000001;
                    }
                }
                // Authentic CSR accept: winlogon's NtSecureConnectPort left the broker connection
                // Pending (Manual). Drive the REAL CsrApiRequestThread through the connection accept (it
                // runs in csrss's VSpace = procs[1].pml4, demand-filling from csrss's image + the mapped
                // DLLs + ntdll), then write the completed client comm-port handle to winlogon's
                // *PortHandle + reply winlogon via REPLY_MAIN. (pi == 2 here = winlogon, so pml4 =
                // winlogon's; csr_rendezvous takes csrss's PML4 explicitly.)
                if nt_handler.csr_rendezvous_conn != 0 {
                    let conn_id = nt_handler.csr_rendezvous_conn;
                    let out_ptr = nt_handler.csr_rendezvous_out;
                    // Only drive the real accept if csrss actually spawned its CsrApiRequestThread
                    // (CSR_LOOP_TCB is a real cap > 1). Otherwise recv_full_r12(CSR_FAULT_EP) would block
                    // forever with no faulter — fall back to a modeled accept so winlogon still connects.
                    let have_thread = CSR_LOOP_TCB.load(Ordering::Relaxed) > 1
                        && csrss_pe.is_some();
                    let client_handle = if have_thread {
                        print_str(b"[csr-rdv] winlogon NtSecureConnectPort pending (conn=");
                        print_u64(conn_id);
                        print_str(b") -> driving the real CsrApiRequestThread accept\n");
                        csr_rendezvous(
                            conn_id,
                            procs[1].pml4,
                            csrss_pe.as_ref().unwrap(),
                            procs[1].img_end,
                            nt_base,
                            nt_end,
                            ntdll.map(|(_, p)| p),
                            &reg,
                            &dll_pes,
                        )
                    } else {
                        print_str(b"[csr-rdv] no real CSR thread -> modeled accept\n");
                        0
                    };
                    let ch = if client_handle != 0 {
                        // AUTHENTIC: the real CSR thread accepted + completed the connection.
                        nt_handler.cache_lpc_connection(conn_id, client_handle, b"\\Windows\\ApiPort".iter().map(|&b| b as u16).collect::<alloc::vec::Vec<u16>>().as_slice());
                        print_str(b"[csr-rdv] AUTHENTIC accept complete: client handle=0x");
                        print_hex((client_handle >> 32) as u32);
                        print_hex(client_handle as u32);
                        print_str(b" -> winlogon NtSecureConnectPort SUCCESS\n");
                        client_handle
                    } else {
                        // The rendezvous walled — fall back to a modeled accept so winlogon still
                        // connects (behavior-preserving; the boot never hangs on the CSR path).
                        print_str(b"[csr-rdv] WALL: rendezvous produced no handle -> modeled fallback\n");
                        let h = lpc_client()
                            .and_then(|c| {
                                let _ = c.accept_connect(conn_id, true, 0);
                                c.complete_connect(conn_id).ok().map(|(ch, _)| ch)
                            })
                            .unwrap_or_else(|| nt_handler.mint_handle());
                        nt_handler.cache_lpc_connection(conn_id, h, b"\\Windows\\ApiPort".iter().map(|&b| b as u16).collect::<alloc::vec::Vec<u16>>().as_slice());
                        h
                    };
                    if out_ptr != 0 {
                        // winlogon's *PortHandle (&CsrApiPort, an ntdll .data global) — demand-fill window.
                        csrss_out_write(out_ptr, ch, &mut filled_pages, &mut faults,
                            scratch_base, &reg, &dll_pes, pml4);
                    }
                    result = 0; // STATUS_SUCCESS (winlogon's connect always succeeds)
                    routed_csr = true;
                }
            } else if m0 == 287 {
                // NtWriteVirtualMemory(ProcessHandle=R10, BaseAddress=RDX, Buffer=R8, Size=R9,
                // *NumberOfBytesWritten=[sp+0x28]). smss's RtlCreateUserProcess(csrss) reaches here to
                // inject the child's RTL_USER_PROCESS_PARAMETERS. In our hosted model spawn_sec_image
                // already built csrss's REAL PEB/params AND csrss has long since run its loader + SM
                // connect, so this late write is moot (its BaseAddress is garbage — the child-side
                // NtAllocateVirtualMemory that would have reserved the target is faked). Model it as a
                // successful write: set *NumberOfBytesWritten = Size and return SUCCESS so
                // RtlCreateUserProcess completes. TODO(migrate): a real cross-AS NtWriteVirtualMemory
                // belongs in nt-memory-manager once a genuinely-new child needs live param injection.
                let size = get_recv_mr(8); // R9 = NumberOfBytesToWrite
                let sp = get_recv_mr(16);
                let written_ptr = smss_stack_read(sp + 0x28); // arg5 = *NumberOfBytesWritten (optional)
                if written_ptr != 0 {
                    if badge == CSRSS_BADGE {
                        csrss_out_write(written_ptr, size, &mut filled_pages, &mut faults,
                            scratch_base, &reg, &dll_pes, pml4);
                    } else {
                        smss_stack_write(written_ptr, size);
                    }
                }
                result = 0; // STATUS_SUCCESS
            } else if m0 == 223 {
                // NtSetDefaultHardErrorPort(PortHandle=R10). csrsrv's CsrServerInitialization registers
                // its API port as the hard-error port right after SmConnectToSm succeeds
                // (init.c:1119). No kernel state to model in the host — accept it so CsrServerInit
                // returns and csrss.exe's main continues. (One-time; NtRaiseHardError already routes to
                // our diagnostic path.)
                result = 0; // STATUS_SUCCESS
            } else if m0 == 267 && badge == CSRSS_BADGE {
                // NtTerminateThread(ThreadHandle=R10, ExitStatus=RDX). csrss.exe _main's last act is
                // NtTerminateThread(NtCurrentThread()) — its init thread exits and CSRSRV's worker
                // threads (fake here) keep the process alive (csrss.c:93). Park csrss's thread (don't
                // reply → it stays blocked) so csrss goes quiet and smss drives the rest of init.
                //
                // ITEM 2a — LIVE terminate-dispatch: route this real thread-exit through the real
                // ETHREAD teardown. Resolve the caller's thread by identity — NtCurrentThread()==-2
                // → THIS process's (pi=1=csrss) main ETHREAD (PM_TIDS[pi]) — and mark it Terminated
                // via `pm.exit_thread` (marks the ETHREAD signalled + exit status, NO process cascade:
                // csrss's EPROCESS stays Running, its other threads keep it alive). BEHAVIOR-PRESERVING:
                // the seL4 outcome is IDENTICAL to the pre-2a park-only fallback (park_caller=true →
                // the thread stays blocked, never runs again; the process + other processes + the boot
                // are untouched). `exit_thread` is alloc-free (in-place field writes on a below-mark
                // ETHREAD node) → safe under the per-syscall heap reset. Args-defensive: the ExitStatus
                // (RDX=m3) is read directly (no arg-slice → no OOB; the pre-path-2 regression was an
                // args[1] OOB in a table-registered arm — this stays in the broker arm on purpose so it
                // never shadows the park behavior).
                let status = m3 as u32;
                if let Some(tid) = PM_TIDS.get(pi).map(|t| t.load(Ordering::Relaxed)) {
                    if tid != 0 && nt_handler.pm.exit_thread(tid as nt_process::ThreadId, status).is_ok() {
                        PM_TERMINATE_THREAD_LIVE.fetch_add(1, Ordering::Relaxed);
                        PM_TERMINATE_THREAD_STATE.fetch_or(1 << pi, Ordering::Relaxed);
                    }
                }
                park_caller = true;
                result = 0;
            } else if m0 == 228 {
                // NtSetEvent(EventHandle=R10, *PreviousState=RDX). smss signals events during the
                // Session-Manager tail (subsystem/session bookkeeping). No real event object is
                // modeled in the host, so accept it (STATUS_SUCCESS); *PreviousState is optional and
                // smss ignores it here. Lets SmpInit/SmpExecuteInitialCommand proceed.
                result = 0;
            } else if m0 == 195 {
                // NtRegisterThreadTerminatePort(PortHandle=R10). kernel32's CsrNewThread() — the LAST
                // step of BaseDllInitialize after the CSR connect — registers the thread's LPC
                // terminate port (so CSR is told when the thread dies). No terminate-port model in the
                // host → accept it (STATUS_SUCCESS) so winlogon's kernel32 DllMain completes + the
                // loader runs the remaining DllMains toward winlogon's entry.
                result = 0;
            } else if m0 == 71 && badge == 0 {
                // NtDuplicateObject — smss's SmpExecuteInitialCommand duplicates winlogon's process
                // handle (SourceHandle=RDX) into InitialCommandProcess (*TargetHandle=R9) so it can
                // later wait on it (smss.c:344). If this FAILS smss KILLS winlogon (smss.c:355), so it
                // MUST succeed. Model the dup: write the source handle value to *TargetHandle and
                // return STATUS_SUCCESS (no real cross-process handle table needed — smss only uses the
                // dup'd handle in the NtWaitForMultipleObjects below, which we park). This is the smss
                // step that, when serviced, lets the loop keep multiplexing so winlogon (prio 102) runs
                // FORWARD past the desktop paint toward StartServicesManager -> services.exe.
                // ABI: SourceProcess=R10, SourceHandle=RDX(m3), TargetProcess=R8, TargetHandle=R9(PHANDLE).
                let src_handle = m3;
                let target = get_recv_mr(8); // R9 = *TargetHandle
                if target != 0 {
                    smss_stack_write(target, src_handle);
                }
                result = 0; // STATUS_SUCCESS
            } else if m0 == 280 && badge == 0 {
                // NtWaitForMultipleObjects — smss's main thread waits (WaitAny) on {csrss, winlogon}
                // to die (smss.c:518). In our boot NEITHER dies, so smss's correct terminal state is to
                // block here FOREVER. PARK it (never reply, recv the next event) so the higher-priority
                // winlogon keeps running forward. Returning STATUS_WAIT_0 instead would make smss think
                // csrss/winlogon terminated -> its hard-error teardown path (wrong). This is the
                // designed end of smss's lifetime; the loop now terminates on winlogon's next wall.
                park_caller = true;
                result = 0;
            } else if m0 == 136 {
                // NtOpenThreadTokenEx — winlogon's InitKeyboardLayouts calls RegOpenKeyExW(
                // HKEY_CURRENT_USER, "Keyboard Layout\\Preload") -> RtlOpenCurrentUser ->
                // NtOpenThreadToken(Ex). winlogon runs as SYSTEM with no impersonation token, so the
                // authentic result is STATUS_NO_TOKEN (0xC000007C) -> RtlOpenCurrentUser falls back to
                // the process-token user key (\Registry\User\S-1-5-18), which misses our SYSTEM-only
                // hive -> InitKeyboardLayouts loads the default US layout instead. (Mirrors the
                // NtOpenThreadToken=135 handler; 136 is the Ex variant the real ntdll uses.)
                result = 0xC000007C;
            } else if m0 >= win32k_host::WIN32K_SERVICE_BASE
                && (badge == CSRSS_BADGE || badge == WINLOGON_BADGE)
            {
                routed_win32k = true;
                // Tell win32k_dispatch WHICH client this call belongs to (csrss pi 1 / winlogon pi 2)
                // so it attaches win32k's client window to this client's frames (per-client cross-AS
                // client memory — winlogon's OBJECT_ATTRIBUTES resolve to WINLOGON's frames, not the
                // stale csrss frame at the same VA).
                W32_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
                // Phase 2c Milestone C: a win32k NtUser/NtGdi system call (SSN >= 0x1000) issued by
                // csrss (winsrv's UserServerDllInitialization) OR by winlogon (its user32 DllMain's
                // NtUserProcessConnect + WinMain's window-station/desktop calls) — the SECOND hosted
                // GUI client. Forward it to the parked win32k component through the persistent dispatch
                // loop; the handler runs in win32k's OWN context (GS=KPCR / session heap). Both clients
                // are serviced ONE AT A TIME by the main loop (FIFO recv), each bound to REPLY_MAIN at
                // its recv, so the routed reply (send_on_reply(REPLY_MAIN)) resumes exactly this caller
                // — csrss and winlogon never orphan each other. Scalar + handle args ride the registers
                // exactly as the native x64 syscall passed them (arg1=R10, arg2=RDX, arg3=R8, arg4=R9);
                // pointer/buffer args are marshaled per SSN as needed. Per-process stack/heap/image
                // mirrors are already selected by `pi` above (smss_stack_read reaches winlogon's stack).
                let a0 = get_recv_mr(9); // R10 = arg1
                let mut a1 = m3; // RDX = arg2
                let mut a2 = get_recv_mr(7); // R8 = arg3
                let a3 = get_recv_mr(8); // R9 = arg4
                // NtUserInitialize(dwWinVersion=a0, hPowerRequestEvent=a1, hMediaRequestEvent=a2):
                // winsrv created these events via NtCreateEvent but our csrss demand-fill window
                // couldn't write the handle back to winsrv's late .bss global, so they arrive NULL
                // (pre-fix a fake EPROCESS masked that). Substitute the REAL minted handles the
                // executive recorded (creation order = power, media), so win32k models + references
                // genuine typed Event objects. Only fills NULLs (a working marshal is respected).
                if m0 == win32k_host::SSN_NT_USER_INITIALIZE_REAL {
                    if a1 == 0 {
                        a1 = nt_handler.csrss_event_handles[0];
                    }
                    if a2 == 0 {
                        a2 = nt_handler.csrss_event_handles[1];
                    }
                }
                // NtCurrentProcess() == (HANDLE)-1: win32k's ObReferenceObjectByHandle resolves the
                // hosted client's process via the synthetic handle the DriverEntry attach used.
                let d_a0 = if a0 == 0xFFFF_FFFF_FFFF_FFFF { win32k_host::FAKE_PROCESS_HANDLE } else { a0 };
                // CROSS-AS ARG MARSHALING. NtUserProcessConnect(handle, USERCONNECT* buf, size): the
                // buffer is a csrss user pointer (its stack) NOT mapped in win32k's VSpace — passing it
                // raw makes win32k's handler fault/spin on an address win32k_dispatch can't resolve.
                // Copy csrss's input buffer into the shared ARG frame (mapped in BOTH), dispatch with
                // the ARG-frame pointer, then copy win32k's out-params (the USERCONNECT) back to csrss.
                let has_buf = m0 == win32k_host::SSN_NT_USER_INITIALIZE; // 0x10FA = NtUserProcessConnect
                let (d_a1, blen) = if has_buf {
                    let arg = win32k_host::WIN32K_ARG_VADDR;
                    let n = a2.min(win32k_host::WIN32K_ARG_FRAMES * 0x1000);
                    core::ptr::write_bytes(arg as *mut u8, 0, (win32k_host::WIN32K_ARG_FRAMES * 0x1000) as usize);
                    let mut off = 0u64;
                    while off + 8 <= n {
                        core::ptr::write_volatile((arg + off) as *mut u64, smss_stack_read(a1 + off));
                        off += 8;
                    }
                    (arg, n)
                } else {
                    (a1, 0)
                };
                print_str(b"[win32k-svc] csrss -> SSN 0x");
                print_hex(m0 as u32);
                print_str(b" (dispatch)\n");
                // DIAG: NtUserCreateWindowStation(0x122f) OA-pointer probe — read the client's REAL
                // OBJECT_ATTRIBUTES.Length via its stack mirror (pi-selected) so we can tell a stale
                // (wrong-client) frame in win32k from a genuinely-bad OA the client built.
                if m0 == 0x122f {
                    print_str(b"[w32diag] 0x122f OA=0x");
                    print_hex((a0 >> 32) as u32);
                    print_hex(a0 as u32);
                    print_str(b" real-Length=0x");
                    print_hex(smss_stack_read(a0) as u32);
                    print_str(b" pi=");
                    print_u64(pi as u64);
                    print_str(b"\n");
                }
                // ★ THE COUNTED DESKTOP PAINT — winlogon's OWN natural NtUserSwitchDesktop paints the
                // framebuffer, and THIS is the source of the `exec_win32k_desktop_painted` gate spec
                // (scaffold RETIRED — see the m0==0x125a arm, which now runs ONLY the InitVideo/surface
                // bringup, not the paint). Right BEFORE winlogon's SSN 0x1288 we clear the WHOLE fb to
                // magenta — now LOAD-BEARING: it wipes any earlier pixels so the counted spec genuinely
                // proves winlogon's co_IntShowDesktop -> co_UserRedrawWindow -> DesktopWindowProc
                // WM_ERASEBKGND -> IntPaintDesktop re-painted 0x003a6ea5 by the AUTHENTIC boot flow
                // (BOOTBOOT -> kernel -> smss -> csrss -> winlogon -> win32k), not a stale scaffold paint.
                let winlogon_switch = m0 == 0x1288 && badge == WINLOGON_BADGE;
                if winlogon_switch {
                    let fb = FB_VADDR as *mut u32;
                    for i in 0..(1024u64 * 768) {
                        core::ptr::write_volatile(fb.add(i as usize), 0x00FF_00FF);
                    }
                    print_str(b"[win32k-svc] fb cleared to magenta before winlogon NtUserSwitchDesktop\n");
                }
                let (st, ok) = win32k_dispatch(m0, d_a0, d_a1, a2, a3);
                if winlogon_switch {
                    // Read back the 768-px sampled grid; count how many winlogon's OWN SwitchDesktop flow
                    // painted to the WC_DESKTOP background. This drives the counted paint gate.
                    let fb = FB_VADDR as *const u32;
                    let mut matched = 0u32;
                    let mut changed = 0u32;
                    let mut sample0 = 0u32;
                    for r in 0..24u64 {
                        for c in 0..32u64 {
                            let idx = (r * 32 * 1024 + c * 32) as usize;
                            let px = core::ptr::read_volatile(fb.add(idx));
                            if r == 0 && c == 0 {
                                sample0 = px;
                            }
                            if px != 0x00FF_00FF {
                                changed += 1;
                            }
                            if px == FB_DESKTOP_BG {
                                matched += 1;
                            }
                        }
                    }
                    WINLOGON_NATURAL_PAINT.store(matched as u64, Ordering::Relaxed);
                    // Feed the counted `exec_win32k_desktop_painted` gate from winlogon's NATURAL paint
                    // (the scaffold no longer paints — the m0==0x125a arm keeps only InitVideo/surface).
                    FB_PIXELS_DREW.store(if changed > 0 { 2 } else { 1 }, Ordering::Relaxed);
                    FB_PIXELS_MATCH.store(matched as u64, Ordering::Relaxed);
                    FB_PIXELS_SAMPLE0.store(sample0 as u64, Ordering::Relaxed);
                    print_str(b"[win32k-svc] winlogon NtUserSwitchDesktop ret=0x");
                    print_hex(st as u32);
                    print_str(b" -> NATURAL fb readback: changed ");
                    print_u64(changed as u64);
                    print_str(b"/768, desktop-bg ");
                    print_u64(matched as u64);
                    print_str(b"/768 (px0=0x");
                    print_hex(sample0);
                    print_str(b")\n");
                }
                if has_buf && ok {
                    let arg = win32k_host::WIN32K_ARG_VADDR;
                    // gSharedInfo CLIENT-MAPPING. win32k's NtUserProcessConnect handler filled the
                    // USERCONNECT's siClient with pointers into its OWN session-space USER heap
                    // (gpsi / gHandleTable / the handle-entry array — all `UserHeapAlloc`ed), which
                    // is NOT mapped in csrss → user32's DllMain `Init` faults dereferencing
                    // gSharedInfo.aheList->handles. RO-map that heap arena into csrss and rewrite the
                    // siClient pointers (+ ulSharedDelta) to the csrss-relative client addresses so
                    // the client reads valid memory. delta = server(win32k) − client(csrss).
                    let delta = map_win32k_heap_into_csrss(pml4, pi);
                    let heap_lo = win32k_host::WIN32K_HEAP_VADDR;
                    let heap_hi = heap_lo + win32k_host::WIN32K_HEAP_FRAMES * 0x1000;
                    // The handler's own shift (0 in this single-AS host; be robust anyway): recover
                    // the raw server VA before applying our delta.
                    let hd = core::ptr::read_volatile((arg + win32k_host::UC_SI_DELTA) as *const u64);
                    for off in [win32k_host::UC_SI_PSI, win32k_host::UC_SI_AHELIST] {
                        let client = core::ptr::read_volatile((arg + off) as *const u64);
                        if client != 0 {
                            let server = client.wrapping_add(hd);
                            if server >= heap_lo && server < heap_hi {
                                core::ptr::write_volatile(
                                    (arg + off) as *mut u64,
                                    server.wrapping_sub(delta),
                                );
                            }
                        }
                    }
                    core::ptr::write_volatile((arg + win32k_host::UC_SI_DELTA) as *mut u64, delta);
                    core::ptr::write_volatile((arg + win32k_host::UC_SI_PDISPINFO) as *mut u64, 0);
                    // Copy the fixed-up USERCONNECT back to csrss's stack.
                    let mut off = 0u64;
                    while off + 8 <= blen {
                        smss_stack_write(a1 + off, core::ptr::read_volatile((arg + off) as *const u64));
                        off += 8;
                    }
                }
                print_str(b"[win32k-svc] csrss SSN 0x");
                print_hex(m0 as u32);
                print_str(if ok { b" -> status=0x" } else { b" -> WALL status=0x" });
                print_hex(st as u32);
                print_str(b"\n");
                // ★ EAGER DESKTOP-GFX HOOK FULLY RETIRED. There is no longer any m0==0x125a
                // SSN_INIT_DESKTOP_GFX scaffold here: win32k's own NtUserInitialize (0x125a) dispatch
                // seeds the host prerequisites the display init depends on (the system font +
                // WinSta0/Default Ob objects — see win32k_host::dispatch_loop's post-0x125a step). The
                // actual InitVideo/framebuf-surface bringup AND the paint now happen FULLY LAZILY from
                // winlogon's OWN first GUI DC-op: NtUserSwitchDesktop → co_IntShowDesktop →
                // co_UserRedrawWindow → WM_ERASEBKGND → UserGetDCEx(DCX_CACHE) → DceAllocDCE →
                // DceCreateDisplayDC → co_IntGraphicsCheck(TRUE) → co_AddGuiApp →
                // co_IntInitializeDesktopGraphics (InitVideo/surface :278/:286 + the atomic paint :340).
                // The counted exec_win32k_desktop_painted spec is fed by the m0==0x1288 arm above.
                if ok {
                    result = st as u32 as u64; // NTSTATUS (EAX) back to csrss
                } else {
                    handled = false; // dispatch wall — stop with the SSN recorded
                    result = 0xC0000001;
                }
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
            procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = filled_pages;
            let reply_main = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = if park_caller && reply_main != 0 {
                // Don't reply to the self-terminated thread — leave it blocked and recv the next
                // event (re-binding REPLY_MAIN for the next caller). The parked thread never runs again.
                recv_full_r12(fault_ep, reply_main)
            } else if (routed_win32k || routed_lpc || routed_csr) && reply_main != 0 {
                // Fix (B): this caller's syscall was serviced by the win32k component, whose faults
                // clobbered the executive's single `reply_to`. Resume csrss via its BOUND reply cap
                // (REPLY_MAIN, decode_reply -> apply_fault_reply) instead of the now-stale reply_to,
                // then recv the next event (re-binding REPLY_MAIN). Split reply+recv is equivalent to
                // the atomic reply_recv_badge — the executive is the sole replier.
                send_on_reply(reply_main, 18, result, m1, 0, m3);
                recv_full_r12(fault_ep, reply_main)
            } else {
                // Non-routed path: `reply_to` names this caller (never clobbered) — legacy reply.
                reply_recv_badge(fault_ep, 18, result, m1, 0, m3)
            };
            badge = nb;
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
    // === Path 2 lifecycle self-test (POST-LOOP: no more per-syscall heap reset follows, so these
    // durable pm allocations are safe). Proves NtOpenProcess + NtTerminateProcess route through pm.
    // The 3 HOSTED EPROCESSes are left untouched — terminate runs on a THROWAWAY process. ===
    if ntdll.is_some() {
        // NtOpenProcess: smss (pi 0) opens csrss by pid → a real Process(csrss_pid) handle in smss's
        // EPROCESS table.
        nt_handler.pi = 0;
        let mut open_ok = 0u64;
        if let (Some(smss_pid), Some(csrss_pid)) =
            (nt_handler.pm_pid_for_pi(0), nt_handler.pm_pid_for_pi(1))
        {
            if nt_handler.nt_open_process(csrss_pid).is_some() {
                open_ok |= 1;
            }
            if nt_handler
                .pm
                .close_handle_by_object(smss_pid, nt_process::HandleObject::Process(csrss_pid))
            {
                open_ok |= 2; // the opened handle really is in smss's table
            }
        }
        PM_NTOPENPROCESS_OK.store(open_ok, Ordering::Relaxed);

        // NtTerminateProcess: build a throwaway EPROCESS + thread + handle, then run the same policy
        // teardown the handler drives, and verify the process/thread are signalled + wait-able + the
        // handle table closes. Also verify the handler's ProcessHandle resolve (NtCurrentProcess→self).
        let mut life_ok = 0u64;
        let parent = nt_handler.pm_pid_for_pi(0);
        let tpid = nt_handler.pm.create_process("lifecycle-test.exe", parent, None);
        if let Ok(ttid) = nt_handler.pm.create_thread(tpid, 0x1000, 0, false) {
            let th = nt_handler
                .pm
                .insert_handle(tpid, nt_process::HandleObject::Opaque(0xDEAD), 0)
                .ok();
            nt_handler.pi = 0;
            if nt_handler.resolve_process_handle(0xFFFF_FFFF_FFFF_FFFF) == nt_handler.pm_pid_for_pi(0)
            {
                life_ok |= 1; // NtCurrentProcess() resolves to the caller
            }
            if nt_handler.pm.terminate_process(tpid, 0x1234).is_ok() {
                life_ok |= 2;
            }
            if nt_handler.pm.is_process_signaled(tpid) {
                life_ok |= 4;
            }
            if nt_handler.pm.is_thread_signaled(ttid) {
                life_ok |= 8; // teardown signalled the process's threads
            }
            if nt_handler.pm.wait_process(tpid) == Some(0x1234) {
                life_ok |= 16; // exit status readable via wait
            }
            if th.is_some_and(|h| nt_handler.pm.close_handle(tpid, h).is_ok()) {
                life_ok |= 32; // handle-table teardown
            }
        }
        PM_LIFECYCLE_OK.store(life_ok, Ordering::Relaxed);

        // Path 1b COUNTED SPEC — process-local dense handle VALUES. Two DISTINCT live EPROCESSes each
        // allocate their first handle and BOTH get the SAME dense value (0x4), yet it refers to a
        // DIFFERENT object in each: proof of per-process handle namespaces (a global value scheme
        // could not hand out 0x4 twice). Runs post-loop on throwaway EPROCESSes (durable allocs are
        // safe — no reset follows), leaving the 3 hosted processes untouched.
        let pa = nt_handler.pm.create_process("hlocal-a.exe", None, None);
        let pb = nt_handler.pm.create_process("hlocal-b.exe", None, None);
        let ha = nt_handler
            .pm
            .insert_handle(pa, nt_process::HandleObject::Opaque(0xA11CE), 0);
        let hb = nt_handler
            .pm
            .insert_handle(pb, nt_process::HandleObject::Opaque(0xB0B), 0);
        let mut hl_ok = 0u64;
        if ha == Ok(4) && hb == Ok(4) {
            hl_ok |= 1; // both processes' FIRST handle is the same dense value 0x4
        }
        if nt_handler.pm.lookup_handle(pa, 4) == Some(nt_process::HandleObject::Opaque(0xA11CE))
            && nt_handler.pm.lookup_handle(pb, 4) == Some(nt_process::HandleObject::Opaque(0xB0B))
        {
            hl_ok |= 2; // the SAME value 0x4 resolves to a DIFFERENT object in each namespace
        }
        if nt_handler.pm.lookup_handle(pa, 4) != nt_handler.pm.lookup_handle(pb, 4) {
            hl_ok |= 4; // no cross-process aliasing
        }
        PM_HANDLE_LOCAL_OK.store(hl_ok, Ordering::Relaxed);

        // ITEM 2b — prove the seL4 MECHANISM-teardown (reclamation) on a THROWAWAY untyped/caps.
        // Runs here (post-loop, live boot only) alongside the other lifecycle self-tests; it touches
        // ONLY freshly-retyped throwaway caps + an unused scratch page, deletes everything it makes,
        // and never touches the 3 hosted processes' resources → byte-identical boot.
        PM_RECLAIM_OK.store(reclaim_mechanism_selftest(), Ordering::Relaxed);
        // ALPC last-mile item (b) — prove a REAL cross-address-space ALPC section view: two SEPARATE
        // throwaway endpoint VSpaces map the same port-section backing frames (copy_cap + page_map,
        // the CSRSS_ANON_BASE machinery), a hosted thread in one writes big data, a hosted thread in
        // the other reads it back through ITS OWN view mapping. Throwaway-only + reclaimed after →
        // the 3 live hosted processes are untouched (byte-identical boot).
        ALPC_XVIEW_OK.store(alpc_cross_vspace_selftest(), Ordering::Relaxed);
    }
    if csrss_process_handle != 0 {
        print_str(b"[sec-stop] csrss (badge 2) spawned, handle 0x");
        print_hex(csrss_process_handle as u32);
        print_str(b"; demand-paged ");
        print_u64(procs[1].faults);
        print_str(b" page(s) (");
        print_u64(procs[1].ntfaults);
        print_str(b" in ntdll), first fault=0x");
        print_hex((procs[1].first >> 32) as u32);
        print_hex(procs[1].first as u32);
        print_str(b"\n");
    }
    print_str(b"[sec-stop] NEXT_SLOT=");
    print_u64(NEXT_SLOT.load(Ordering::Relaxed));
    print_str(b" shared_frames=");
    print_u64(core::ptr::read(core::ptr::addr_of!(DLL_CACHE_N)) as u64);
    print_str(b" shared_hits=");
    print_u64(DLL_SHARED_HITS.load(Ordering::Relaxed));
    print_str(b"\n[sec-stop] badge=");
    print_u64(badge);
    print_str(b" (");
    print_str(if badge == CSRSS_BADGE {
        b"csrss" as &[u8]
    } else if badge == WINLOGON_BADGE {
        b"winlogon"
    } else {
        b"smss"
    });
    print_str(b") label=");
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
        print_u64(ssn_ring_badge[k % 32] as u64);
        print_str(b":");
        print_u64(ssn_ring[k % 32] as u64);
    }
    // NtWriteVirtualMemory(287) diagnostic: dump the args + scan the caller's stack for smss/ntdll
    // return addresses to identify which routine issued it (RtlCreateUserProcess param-inject?).
    if stop_ssn == 287 {
        let sp = get_recv_mr(16);
        print_str(b"\n[287] proc=0x");
        print_hex(get_recv_mr(9) as u32); // R10 ProcessHandle
        print_str(b" base=0x");
        print_hex((m3 >> 32) as u32);
        print_hex(m3 as u32); // RDX BaseAddress
        print_str(b" buf=0x");
        print_hex((get_recv_mr(7) >> 32) as u32);
        print_hex(get_recv_mr(7) as u32); // R8 Buffer
        print_str(b" size=0x");
        print_hex(get_recv_mr(8) as u32); // R9 Size
        print_str(b" written*=0x");
        print_hex(smss_stack_read(sp + 0x28) as u32);
        print_str(b" chain:");
        let mut shown = 0;
        for i in 0..160u64 {
            let v = smss_stack_read(sp + i * 8);
            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                print_str(b" n+0x");
                print_hex((v - NTDLL_BASE) as u32);
                shown += 1;
            } else if v >= PE_LOAD_BASE && v < PE_LOAD_BASE + 0x40000 {
                // smss image
                print_str(b" s+0x");
                print_hex((v - PE_LOAD_BASE) as u32);
                shown += 1;
            }
            if shown >= 16 {
                break;
            }
        }
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
    // Record winlogon's (slot 2) demand-fault count for the spec check + report line.
    WINLOGON_FAULTS.store(procs[2].faults, Ordering::Relaxed);
    print_str(b"[ntos-exec] winlogon (slot 2) demand-faulted ");
    print_u64(procs[2].faults);
    print_str(b" page(s), first=0x");
    print_hex((procs[2].first >> 32) as u32);
    print_hex(procs[2].first as u32);
    print_str(b"\n");
    // Path 3: record that each folded per-process ProcExec is EPROCESS-linked (live pml4 + its pid
    // matches the ProcessManager's pid for that pi). Read by `exec_eprocess_linked_mechanism`.
    let mut link_ok = 0u64;
    for (i, p) in procs.iter().enumerate() {
        if p.pml4 != 0 && p.pid != 0 && nt_handler.pm_pid_for_pi(i).map(|pid| pid as u64) == Some(p.pid)
        {
            link_ok |= 1 << i;
        }
    }
    PM_EXEC_LINK_OK.store(link_ok, Ordering::Relaxed);
    // Report smss's (slot 0) own fault stats regardless of which process stopped the loop — csrss
    // (slot 1) commonly halts it now that it runs, and the caller's "smss faulted N" line + the
    // exec_reactos_smss_* checks are about smss specifically. csrss's counts are in the sec-stop line.
    (verdict, procs[0].faults, procs[0].first, stop, procs[0].ntfaults, stop_ssn)
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
    map_image_skeleton(pml4, img_count);
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

/// Spawn the AUTHENTIC SM-loop thread (path B): a REAL 2nd thread in smss's VSpace (`smss_pml4`)
/// running smss's real `SmpApiLoop` (`entry_rip`) with RCX = the `\SmApiPort` handle (`port_handle`,
/// the SmpApiLoop parameter). Unlike `spawn_thread_in` it builds the full hosted-Windows-thread env
/// (own TEB + GS base, StaticUnicodeString, an ACTIVATION_CONTEXT_STACK, hosted-syscalls flag, a
/// dedicated fault EP) — a trimmed `spawn_sec_image` (the image/ntdll/PEB/params/KUSER are already
/// mapped, shared with smss's main thread). Its stack is MIRRORED into the executive so the nested
/// `sm_rendezvous` can write its syscall out-params. The thread faults to `SM_FAULT_EP`, which has no
/// standing receiver until the rendezvous drives it — so it PARKS on its first fault. Returns the TCB.
unsafe fn spawn_sm_loop_thread(smss_pml4: u64, entry_rip: u64, port_handle: u64) -> u64 {
    let scr = SM_ENV_SCRATCH_VA;
    // Stack (4 frames), mapped into smss AND mirrored into the executive (for out-param copyout).
    for i in 0..SM_STACK_FRAMES {
        let f = alloc_frame();
        let _ = page_map(copy_cap(f), SM_STACK_BASE + i * 0x1000, RW_NX, smss_pml4);
        let _ = page_map(copy_cap(f), SM_STACK_MIRROR_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    // TEB page 1: self@0x30, PEB@0x60 (smss's PEB — shared), StackBase@0x08/StackLimit@0x10, and
    // ActivationContextStackPointer@0x2C8 → an empty ACS in the 2nd TEB page.
    let teb = alloc_frame();
    let _ = page_map(teb, scr, RW_NX, CAP_INIT_THREAD_VSPACE);
    core::ptr::write_volatile((scr + 0x30) as *mut u64, SM_TEB_VA);
    core::ptr::write_volatile((scr + 0x60) as *mut u64, SMSS_PEB_VA);
    core::ptr::write_volatile((scr + 0x08) as *mut u64, SM_STACK_BASE + SM_STACK_FRAMES * 0x1000);
    core::ptr::write_volatile((scr + 0x10) as *mut u64, SM_STACK_BASE);
    let acs_va = SM_TEB_VA + 0x1800;
    core::ptr::write_volatile((scr + 0x2c8) as *mut u64, acs_va);
    let _ = page_map(copy_cap(teb), SM_TEB_VA, RW_NX, smss_pml4);
    // TEB page 2: the ACTIVATION_CONTEXT_STACK + StaticUnicodeString (MaximumLength=522, Buffer in TEB).
    let teb2 = alloc_frame();
    let _ = page_map(teb2, scr + 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    let acs = scr + 0x1000 + 0x800;
    core::ptr::write_volatile((acs + 0x00) as *mut u64, 0);
    core::ptr::write_volatile((acs + 0x08) as *mut u64, acs_va + 0x08);
    core::ptr::write_volatile((acs + 0x10) as *mut u64, acs_va + 0x08);
    core::ptr::write_volatile((acs + 0x18) as *mut u32, 0);
    core::ptr::write_volatile((acs + 0x1c) as *mut u32, 1);
    core::ptr::write_volatile((acs + 0x20) as *mut u32, 1);
    core::ptr::write_volatile((scr + 0x1000 + 0x25a) as *mut u16, 522); // StaticUnicodeString.MaximumLength
    core::ptr::write_volatile((scr + 0x1000 + 0x260) as *mut u64, SM_TEB_VA + 0x1268); // .Buffer
    let _ = page_map(copy_cap(teb2), SM_TEB_VA + 0x1000, RW_NX, smss_pml4);
    // IPC buffer (its own frame + VA; smss's main thread owns IPCBUF_VADDR).
    let ipcbuf = alloc_frame();
    let _ = page_map(ipcbuf, SM_IPCBUF_VA, RW_NX, smss_pml4);
    // Trampoline: RCX = the SmApiPort handle (SmpApiLoop's PVOID Parameter), then `call` SmpApiLoop
    // (call keeps rsp ≡ 8 mod 16 at entry). SmpApiLoop loops forever; the trailing jmp$ is a net.
    let tramp = alloc_frame();
    let _ = page_map(tramp, scr + 0x2000, RW_NX, CAP_INIT_THREAD_VSPACE);
    let mut tb = alloc::vec::Vec::new();
    tb.extend_from_slice(&[0x48, 0xB9]);
    tb.extend_from_slice(&port_handle.to_le_bytes()); // movabs rcx, port_handle
    tb.extend_from_slice(&[0x48, 0xB8]);
    tb.extend_from_slice(&entry_rip.to_le_bytes()); // movabs rax, SmpApiLoop
    tb.extend_from_slice(&[0xFF, 0xD0]); // call rax
    tb.extend_from_slice(&[0xEB, 0xFE]); // jmp $
    for (j, &b) in tb.iter().enumerate() {
        core::ptr::write_volatile((scr + 0x2000 + j as u64) as *mut u8, b);
    }
    let _ = page_map(copy_cap(tramp), SM_TRAMP_VA, /* RX */ 2, smss_pml4);
    // CNode (PML4 of smss + the dedicated fault EP) + TCB.
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, smss_pml4, 0);
    let sm_ep = SM_FAULT_EP.load(Ordering::Relaxed);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, copy_cap(sm_ep), 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, smss_pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, SM_IPCBUF_VA, ipcbuf, 0);
    let _ = tcb_write_registers(tcb, SM_TRAMP_VA, SM_STACK_BASE + SM_STACK_FRAMES * 0x1000 - 16, 0);
    let _ = tcb_set_gs_base(tcb, SM_TEB_VA);
    let _ = tcb_set_priority(tcb, 100);
    const LBL_TCB_SET_HOSTED_SYSCALLS: u64 = 66;
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_HOSTED_SYSCALLS << 12, 0, 0, 0);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    tcb
}

/// Write a u64 to the SM-loop thread's stack (via the executive's SM_STACK_MIRROR alias), for a
/// syscall out-param that lives on its stack (RequestMsg / PortHandle / PROCESS_BASIC_INFORMATION).
unsafe fn sm_stack_write(va: u64, v: u64) {
    if va >= SM_STACK_BASE && va + 8 <= SM_STACK_BASE + SM_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)) as *mut u64, v);
    }
}
/// Write a u16 to the SM-loop thread's stack (for PORT_MESSAGE.Type@0x04).
unsafe fn sm_stack_write16(va: u64, v: u16) {
    if va >= SM_STACK_BASE && va + 2 <= SM_STACK_BASE + SM_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)) as *mut u16, v);
    }
}
/// Demand-fill one code/data page for the SM-loop thread during the rendezvous. The page is in smss's
/// own image (PE_LOAD_BASE..img_end → `smss_pe`) or ntdll (nt_base..nt_end → `ntdll_pe`); it is filled
/// through an isolated executive scratch (SM_FILL_SCRATCH_BASE, its own PT) then mapped into smss's
/// VSpace (shared with the main thread, so this only happens once per page). Returns false if the page
/// belongs to neither image (a genuine fault the rendezvous can't resolve).
unsafe fn sm_fill_page(
    page: u64,
    smss_pml4: u64,
    smss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    fill_idx: &mut u64,
) -> bool {
    let (base, tpe) = if page >= PE_LOAD_BASE && page < img_end {
        (PE_LOAD_BASE, smss_pe)
    } else if nt_base != 0 && page >= nt_base && page < nt_end {
        match ntdll_pe {
            Some(p) => (nt_base, p),
            None => return false,
        }
    } else {
        return false;
    };
    // Ensure the isolated fill-scratch PT exists (once).
    if SM_FILL_PT_DONE.swap(1, Ordering::Relaxed) == 0 {
        let spt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
        let _ = paging_struct_map(spt, LBL_X86_PAGE_TABLE_MAP, SM_FILL_SCRATCH_BASE, CAP_INIT_THREAD_VSPACE);
    }
    // Monotonic scratch slot (one PT = 512 pages; the SM-loop thread faults far fewer, so no wrap).
    let scratch = SM_FILL_SCRATCH_BASE + (*fill_idx).min(511) * 0x1000;
    *fill_idx += 1;
    let f = alloc_frame();
    let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
    let rights = fill_image_page(tpe, (page - base) as u32, scratch);
    let _ = page_map(copy_cap(f), page, rights, smss_pml4);
    true
}

/// AUTHENTIC SM accept (path B): drive smss's REAL `SmpApiLoop` thread through one connection
/// rendezvous. Called synchronously from the main loop when csrss's `NtConnectPort` leaves the broker
/// connection `conn_id` Pending (Manual policy). A nested loop on `SM_FAULT_EP`/`REPLY_SMLOOP`
/// (mirroring `win32k_dispatch`, but the SM-loop thread is a HOSTED faulter, not a Call peer) services
/// its real syscalls until `NtCompleteConnectPort`: the preamble (RtlSetThreadIsCritical →
/// NtSetInformationThread no-op; NtQueryInformationProcess ProcessBasicInformation → write
/// UniqueProcessId = PID_SMSS), then NtReplyWaitReceivePort (drain the pending connection from the
/// broker + marshal the PORT_MESSAGE: Type=LPC_CONNECTION_REQUEST, ClientId.UniqueProcess=PID_SMSS →
/// the "SM connecting to itself" branch of SmpHandleConnectionRequest, no NtOpenProcess/SB connect-back)
/// → NtAcceptConnectPort (broker accept) → NtCompleteConnectPort (broker complete). Demand-fills the
/// thread's code/data faults + skips int-0x2d DPRINTs. Returns the client comm-port handle (0 on
/// failure), which the caller writes to csrss's *PortHandle. Leaves the thread re-parked on its next
/// NtReplyWaitReceivePort (no pending connection).
unsafe fn sm_rendezvous(
    conn_id: u64,
    smss_pml4: u64,
    smss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
) -> u64 {
    const PID_SMSS: u64 = 4; // any nonzero value; must match on both sides (self-connect ClientId)
    const SSN_SET_INFO_THREAD: u64 = 238;
    const SSN_QUERY_INFO_PROCESS: u64 = 161;
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_ACCEPT_CONNECT: u64 = 0;
    const SSN_COMPLETE_CONNECT: u64 = 31;
    let ep = SM_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_SMLOOP_SLOT.load(Ordering::Relaxed);
    if ep == 0 || reply == 0 {
        return 0;
    }
    let mut client_handle = 0u64;
    let mut fill_idx = 0u64;
    let mut guard = 0u64;
    let (_b, mut mi, mut m0, mut m1, mut m2, mut m3) = recv_full_r12(ep, reply);
    loop {
        guard += 1;
        if guard > 8000 {
            print_str(b"[sm-rdv] WALL: guard exhausted\n");
            break;
        }
        let label = mi >> 12;
        if label == 6 {
            // VMFault: demand-fill an smss/ntdll code or data page for the SM-loop thread.
            let page = m1 & !0xFFFu64;
            if m1 < 0x10000 || !sm_fill_page(page, smss_pml4, smss_pe, img_end, nt_base, nt_end, ntdll_pe, &mut fill_idx) {
                print_str(b"[sm-rdv] WALL: unresolved fault ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((m1 >> 32) as u32);
                print_hex(m1 as u32);
                print_str(b"\n");
                break;
            }
            send_on_reply(reply, 0, 0, 0, 0, 0);
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
            continue;
        }
        if label == 3 {
            // Debug ntdll int-0x2d (DbgPrint from a DPRINT1) — skip the `int 0x2d; int3` (3 bytes),
            // like the main loop. m0 = FaultIP.
            let fip = m0;
            if let Some(p) = ntdll_pe {
                if fip >= nt_base && fip < nt_end && pe_byte_at_rva(p, (fip - nt_base) as u32) == Some(0xCD) {
                    send_on_reply(reply, 3, fip + 3, m1, m2, 0);
                    let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
                    mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                }
            }
            print_str(b"[sm-rdv] WALL: exception fip=0x");
            print_hex((fip >> 32) as u32);
            print_hex(fip as u32);
            print_str(b" num=");
            print_u64(m3);
            print_str(b"\n");
            break;
        }
        if label == 2 {
            // A real Nt* syscall from SmpApiLoop.
            let ssn = m0;
            let resume_ip = m2;
            let sp = get_recv_mr(16);
            let flags = get_recv_mr(17);
            let rdx = m3;
            let mut result = 0u64;
            let mut stop_rdv = false;
            let mut done = false;
            match ssn {
                SSN_SET_INFO_THREAD => {} // RtlSetThreadIsCritical → no-op success
                SSN_QUERY_INFO_PROCESS => {
                    // ProcessBasicInformation (class 0): write UniqueProcessId@+0x20 = PID_SMSS so
                    // SmUniqueProcessId is set → the connection request's ClientId matches (self-connect).
                    let class = rdx;
                    let buf = get_recv_mr(7); // R8 = buffer
                    if class == 0 {
                        sm_stack_write(buf + 0x20, PID_SMSS);
                    }
                }
                SSN_REPLY_WAIT_RECV => {
                    let recvmsg = get_recv_mr(8); // R9 = &RequestMsg.h
                    let port = get_recv_mr(9); // R10 = SmApiPort handle
                    let got = lpc_client().and_then(|c| c.reply_wait_receive(port).ok());
                    match got {
                        Some(r) if r.connection_id != 0 => {
                            // Marshal the connection-request PORT_MESSAGE onto the SM-loop stack.
                            sm_stack_write16(recvmsg + 0x04, nt_lpc_client::LPC_CONNECTION_REQUEST); // u2.s2.Type
                            sm_stack_write(recvmsg + 0x08, PID_SMSS); // ClientId.UniqueProcess
                            sm_stack_write(recvmsg + 0x10, PID_SMSS + 4); // ClientId.UniqueThread
                        }
                        _ => {
                            // No pending connection (the 2nd receive): leave the thread PARKED — do NOT
                            // reply. It re-blocks on this NtReplyWaitReceivePort until the next connect.
                            stop_rdv = true;
                        }
                    }
                }
                SSN_ACCEPT_CONNECT => {
                    let porthandle_out = get_recv_mr(9); // R10 = *PortHandle
                    let accept = get_recv_mr(8); // R9 = Accept BOOLEAN
                    let sh = lpc_client()
                        .and_then(|c| c.accept_connect(conn_id, accept != 0, rdx).ok())
                        .unwrap_or(0);
                    sm_stack_write(porthandle_out, sh);
                }
                SSN_COMPLETE_CONNECT => {
                    if let Some((ch, _)) = lpc_client().and_then(|c| c.complete_connect(conn_id).ok()) {
                        client_handle = ch;
                    }
                    // Reply (below), then BREAK: the connection is done. SmpApiLoop loops back to its
                    // next NtReplyWaitReceivePort, which faults FRESH to sm_fault_ep (no receiver) and
                    // re-parks — so a LATER connect's rendezvous can recv that fresh fault (rather than
                    // this rendezvous draining an empty receive, which would leave the thread blocked
                    // on a reply and deadlock the next connect).
                    done = true;
                }
                _ => {
                    print_str(b"[sm-rdv] WALL: unexpected SSN=");
                    print_u64(ssn);
                    print_str(b"\n");
                    stop_rdv = true;
                }
            }
            if stop_rdv {
                break;
            }
            set_reply_mr(15, resume_ip);
            set_reply_mr(16, sp);
            set_reply_mr(17, flags);
            send_on_reply(reply, 18, result, 0, 0, rdx);
            if done {
                break;
            }
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
            continue;
        }
        print_str(b"[sm-rdv] WALL: unexpected label=");
        print_u64(label);
        print_str(b"\n");
        break;
    }
    client_handle
}

/// Number of committed stack frames for the CSR API thread (deeper than SM: CsrApiRequestThread →
/// CsrConnectToUser [loader walk] → CsrApiHandleConnectionRequest).
pub const CSR_STACK_FRAMES: u64 = 8;

/// Spawn csrss's REAL `CsrApiRequestThread` as a 2nd thread in csrss's VSpace (mirrors
/// `spawn_sm_loop_thread`). It faults to `CSR_FAULT_EP` (no standing receiver) so it PARKS on its
/// first fault/syscall until `csr_rendezvous` drains it for winlogon's CSR connect. `param` is the
/// hRequestEvent handle (CsrApiRequestThread's PVOID Parameter). The TEB carries the self-connect
/// ClientId so the thread's own bookkeeping is consistent.
unsafe fn spawn_csr_loop_thread(csrss_pml4: u64, entry_rip: u64, param: u64) -> u64 {
    let scr = CSR_ENV_SCRATCH_VA;
    for i in 0..CSR_STACK_FRAMES {
        let f = alloc_frame();
        let _ = page_map(copy_cap(f), CSR_STACK_BASE + i * 0x1000, RW_NX, csrss_pml4);
        let _ = page_map(copy_cap(f), CSR_STACK_MIRROR_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    // TEB page 1: self@0x30, ClientId@0x40/0x48 (the self-connect CID), PEB@0x60 (csrss's PEB —
    // shared with the main thread), StackBase@0x08/StackLimit@0x10, ACS@0x2C8.
    let teb = alloc_frame();
    let _ = page_map(teb, scr, RW_NX, CAP_INIT_THREAD_VSPACE);
    core::ptr::write_volatile((scr + 0x30) as *mut u64, CSR_TEB_VA);
    core::ptr::write_volatile((scr + 0x40) as *mut u64, CSR_STATIC_CID_PROC);
    core::ptr::write_volatile((scr + 0x48) as *mut u64, CSR_STATIC_CID_THREAD);
    core::ptr::write_volatile((scr + 0x60) as *mut u64, SMSS_PEB_VA);
    core::ptr::write_volatile((scr + 0x08) as *mut u64, CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000);
    core::ptr::write_volatile((scr + 0x10) as *mut u64, CSR_STACK_BASE);
    let acs_va = CSR_TEB_VA + 0x1800;
    core::ptr::write_volatile((scr + 0x2c8) as *mut u64, acs_va);
    let _ = page_map(copy_cap(teb), CSR_TEB_VA, RW_NX, csrss_pml4);
    // TEB page 2: ACTIVATION_CONTEXT_STACK + StaticUnicodeString.
    let teb2 = alloc_frame();
    let _ = page_map(teb2, scr + 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    let acs = scr + 0x1000 + 0x800;
    core::ptr::write_volatile((acs + 0x00) as *mut u64, 0);
    core::ptr::write_volatile((acs + 0x08) as *mut u64, acs_va + 0x08);
    core::ptr::write_volatile((acs + 0x10) as *mut u64, acs_va + 0x08);
    core::ptr::write_volatile((acs + 0x18) as *mut u32, 0);
    core::ptr::write_volatile((acs + 0x1c) as *mut u32, 1);
    core::ptr::write_volatile((acs + 0x20) as *mut u32, 1);
    core::ptr::write_volatile((scr + 0x1000 + 0x25a) as *mut u16, 522);
    core::ptr::write_volatile((scr + 0x1000 + 0x260) as *mut u64, CSR_TEB_VA + 0x1268);
    let _ = page_map(copy_cap(teb2), CSR_TEB_VA + 0x1000, RW_NX, csrss_pml4);
    // IPC buffer.
    let ipcbuf = alloc_frame();
    let _ = page_map(ipcbuf, CSR_IPCBUF_VA, RW_NX, csrss_pml4);
    // Trampoline: RCX = Parameter (hRequestEvent), then `call` CsrApiRequestThread.
    let tramp = alloc_frame();
    let _ = page_map(tramp, scr + 0x2000, RW_NX, CAP_INIT_THREAD_VSPACE);
    let mut tb = alloc::vec::Vec::new();
    tb.extend_from_slice(&[0x48, 0xB9]);
    tb.extend_from_slice(&param.to_le_bytes()); // movabs rcx, param
    tb.extend_from_slice(&[0x48, 0xB8]);
    tb.extend_from_slice(&entry_rip.to_le_bytes()); // movabs rax, CsrApiRequestThread
    tb.extend_from_slice(&[0xFF, 0xD0]); // call rax
    tb.extend_from_slice(&[0xEB, 0xFE]); // jmp $
    for (j, &b) in tb.iter().enumerate() {
        core::ptr::write_volatile((scr + 0x2000 + j as u64) as *mut u8, b);
    }
    let _ = page_map(copy_cap(tramp), CSR_TRAMP_VA, /* RX */ 2, csrss_pml4);
    // CNode (csrss's PML4 + the dedicated CSR fault EP) + TCB.
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, csrss_pml4, 0);
    let csr_ep = CSR_FAULT_EP.load(Ordering::Relaxed);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, copy_cap(csr_ep), 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, csrss_pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, CSR_IPCBUF_VA, ipcbuf, 0);
    let _ = tcb_write_registers(tcb, CSR_TRAMP_VA, CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000 - 16, 0);
    let _ = tcb_set_gs_base(tcb, CSR_TEB_VA);
    let _ = tcb_set_priority(tcb, 100);
    const LBL_TCB_SET_HOSTED_SYSCALLS: u64 = 66;
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_HOSTED_SYSCALLS << 12, 0, 0, 0);
    attach_sched_context(tcb);
    // NOT resumed here: CsrApiRequestThread's pre-loop CsrConnectToUser touches CsrRootProcess's
    // thread list under csrss's process lock, which csrss's MAIN thread is still mutating during init
    // (CsrAddStaticServerThread). Resuming now would race. Instead `csr_rendezvous` resumes it lazily,
    // by which time csrss main has finished init + parked → the CSR thread runs alone in csrss's VSpace.
    tcb
}

/// Write a u64 to the CSR thread's stack (via the executive's CSR_STACK_MIRROR alias).
unsafe fn csr_stack_write(va: u64, v: u64) {
    if va >= CSR_STACK_BASE && va + 8 <= CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((CSR_STACK_MIRROR_VA + (va - CSR_STACK_BASE)) as *mut u64, v);
    }
}
/// Write a u16 to the CSR thread's stack (for PORT_MESSAGE.Type@0x04).
unsafe fn csr_stack_write16(va: u64, v: u16) {
    if va >= CSR_STACK_BASE && va + 2 <= CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((CSR_STACK_MIRROR_VA + (va - CSR_STACK_BASE)) as *mut u16, v);
    }
}

/// Demand-fill one code/data page for the CSR API thread during the rendezvous. The page is in
/// csrss's own image (PE_LOAD_BASE..img_end), ntdll, or a mapped registry DLL (csrsrv/user32/…, via
/// `dll_for_page`). Filled through an isolated executive scratch (CSR_FILL_SCRATCH_BASE, own PT) then
/// mapped into csrss's VSpace. Returns false if the page belongs to none (a genuine fault).
#[allow(clippy::too_many_arguments)]
unsafe fn csr_fill_page(
    page: u64,
    csrss_pml4: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>; 16],
    fill_idx: &mut u64,
) -> bool {
    let (base, tpe) = if page >= PE_LOAD_BASE && page < img_end {
        (PE_LOAD_BASE, csrss_pe)
    } else if nt_base != 0 && page >= nt_base && page < nt_end {
        match ntdll_pe {
            Some(p) => (nt_base, p),
            None => return false,
        }
    } else if let Some((i, _)) = reg.dll_for_page(page) {
        match dll_pes[i].as_ref() {
            Some(p) => (reg.base(i), p),
            None => return false,
        }
    } else {
        return false;
    };
    if CSR_FILL_PT_DONE.swap(1, Ordering::Relaxed) == 0 {
        let spt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
        let _ = paging_struct_map(spt, LBL_X86_PAGE_TABLE_MAP, CSR_FILL_SCRATCH_BASE, CAP_INIT_THREAD_VSPACE);
    }
    let scratch = CSR_FILL_SCRATCH_BASE + (*fill_idx).min(511) * 0x1000;
    *fill_idx += 1;
    let f = alloc_frame();
    let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
    let rights = fill_image_page(tpe, (page - base) as u32, scratch);
    let _ = page_map(copy_cap(f), page, rights, csrss_pml4);
    true
}

/// AUTHENTIC CSR accept: drive csrss's REAL `CsrApiRequestThread` through one connection accept for
/// winlogon's `NtSecureConnectPort(\Windows\ApiPort)`. Mirrors `sm_rendezvous`: a nested loop on
/// `CSR_FAULT_EP`/`REPLY_CSRLOOP` services the thread's real syscalls until `NtCompleteConnectPort`.
/// The thread's pre-loop `CsrConnectToUser` is in-process (no syscalls; ClientThreadSetup is a stub
/// returning TRUE, and CsrLocateThreadInProcess returns non-NULL since csrss registered its static
/// threads at init → no spin). On the connection: NtSetEvent (signal hRequestEvent, no-op) →
/// NtReplyWaitReceivePort (drain the broker's pending connection + marshal the PORT_MESSAGE:
/// Type=LPC_CONNECTION_REQUEST, ClientId = the self-connect CID so CsrLocateThreadByClientId matches a
/// registered CSR_THREAD → CsrProcess=CsrRootProcess → AllowConnection=TRUE) → [NtMapViewOfSection of
/// the CSR shared section — no-op success] → NtAcceptConnectPort (broker accept) → NtCompleteConnectPort
/// (broker complete). Returns the client comm-port handle (0 on wall). Leaves the thread re-parked on
/// its next NtReplyWaitReceivePort (break-after-complete, like SM).
///
/// ★ FLAGGED RESIDUALS (host limitations, NOT the accept mechanism — the real thread runs + issues the
/// real receive/accept syscalls): (a) THE ACCEPT DECISION — CsrApiHandleConnectionRequest's
/// CsrLocateThreadByClientId (hash table, exact CID) finds NO thread for winlogon because winlogon is
/// not a registered CSR_PROCESS (that needs the SM→SB→CsrSrvCreateProcess *session-registration* plane,
/// a separate fork), so the real thread computes AllowConnection=FALSE and passes Accept=FALSE. The
/// executive OVERRIDES the broker to accept+complete at the NtAcceptConnectPort syscall so winlogon
/// connects; (b) the CSR_API_CONNECTINFO reply payload + shared-section mapping into winlogon are still
/// executive-modeled (in `csr_client_connect`) because the isolated LPC broker carries no message
/// payload across the connect. (The marshaled connection-request ClientId is now cosmetic — no hashed
/// CSR_THREAD can match it either way.)
#[allow(clippy::too_many_arguments)]
unsafe fn csr_rendezvous(
    conn_id: u64,
    csrss_pml4: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>; 16],
) -> u64 {
    const SSN_SET_EVENT: u64 = 228;
    const SSN_MAP_VIEW: u64 = 113;
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_ACCEPT_CONNECT: u64 = 0;
    const SSN_COMPLETE_CONNECT: u64 = 31;
    let ep = CSR_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_CSRLOOP_SLOT.load(Ordering::Relaxed);
    if ep == 0 || reply == 0 {
        return 0;
    }
    let mut client_handle = 0u64;
    let mut fill_idx = 0u64;
    let mut guard = 0u64;
    // Lazily resume the CSR thread on the FIRST rendezvous (csrss main has finished init + parked, so
    // the thread runs alone in csrss's VSpace — no race on the CSR process/thread lists). Subsequent
    // rendezvous re-recv the thread already re-parked on its next NtReplyWaitReceivePort.
    if CSR_RESUMED.swap(1, Ordering::Relaxed) == 0 {
        let tcb = CSR_LOOP_TCB.load(Ordering::Relaxed);
        if tcb != 0 && tcb != 1 {
            let _ = tcb_resume(tcb);
        }
    }
    let (_b, mut mi, mut m0, mut m1, mut m2, mut m3) = recv_full_r12(ep, reply);
    loop {
        guard += 1;
        if guard > 8000 {
            print_str(b"[csr-rdv] WALL: guard exhausted\n");
            break;
        }
        let label = mi >> 12;
        if label == 6 {
            let page = m1 & !0xFFFu64;
            if m1 < 0x10000
                || !csr_fill_page(page, csrss_pml4, csrss_pe, img_end, nt_base, nt_end, ntdll_pe, reg, dll_pes, &mut fill_idx)
            {
                print_str(b"[csr-rdv] WALL: unresolved fault ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((m1 >> 32) as u32);
                print_hex(m1 as u32);
                print_str(b"\n");
                break;
            }
            send_on_reply(reply, 0, 0, 0, 0, 0);
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
            continue;
        }
        if label == 3 {
            let fip = m0;
            if let Some(p) = ntdll_pe {
                if fip >= nt_base && fip < nt_end && pe_byte_at_rva(p, (fip - nt_base) as u32) == Some(0xCD) {
                    send_on_reply(reply, 3, fip + 3, m1, m2, 0);
                    let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
                    mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                }
            }
            print_str(b"[csr-rdv] WALL: exception fip=0x");
            print_hex((fip >> 32) as u32);
            print_hex(fip as u32);
            print_str(b" num=");
            print_u64(m3);
            print_str(b"\n");
            break;
        }
        if label == 2 {
            let ssn = m0;
            let resume_ip = m2;
            let sp = get_recv_mr(16);
            let flags = get_recv_mr(17);
            let rdx = m3;
            let mut result = 0u64;
            let mut done = false;
            match ssn {
                SSN_SET_EVENT => {} // NtSetEvent(hRequestEvent) — no-op success
                SSN_MAP_VIEW => {} // NtMapViewOfSection (CSR shared section into CsrRootProcess) — success
                SSN_REPLY_WAIT_RECV => {
                    let recvmsg = get_recv_mr(8); // R9 = &ReceiveMsg.Header
                    let port = get_recv_mr(9); // R10 = CsrApiPort handle
                    let got = lpc_client().and_then(|c| c.reply_wait_receive(port).ok());
                    match got {
                        Some(r) if r.connection_id != 0 => {
                            csr_stack_write16(recvmsg + 0x04, nt_lpc_client::LPC_CONNECTION_REQUEST);
                            csr_stack_write(recvmsg + 0x08, CSR_STATIC_CID_PROC); // ClientId.UniqueProcess
                            csr_stack_write(recvmsg + 0x10, CSR_STATIC_CID_THREAD); // ClientId.UniqueThread
                        }
                        _ => {
                            // No pending connection (the re-park receive): leave the thread PARKED.
                            break;
                        }
                    }
                }
                SSN_ACCEPT_CONNECT => {
                    // The REAL CsrApiHandleConnectionRequest reached NtAcceptConnectPort. ★ FLAGGED
                    // OVERRIDE: in our host winlogon is NOT a registered CSR_PROCESS (that needs the
                    // SM→SB→CsrSrvCreateProcess session plane we don't model), so CsrLocateThreadByClientId
                    // returned NULL → the thread passes Accept=FALSE (R9) and will SKIP NtCompleteConnectPort.
                    // Force the broker to ACCEPT + COMPLETE here so winlogon's connect succeeds — the real
                    // thread issued the accept syscall; only the accept DECISION is executive-supplied.
                    let porthandle_out = get_recv_mr(9); // R10 = *ServerPort
                    let sh = lpc_client()
                        .and_then(|c| c.accept_connect(conn_id, true, rdx).ok())
                        .unwrap_or(0);
                    csr_stack_write(porthandle_out, sh);
                    if let Some((ch, _)) = lpc_client().and_then(|c| c.complete_connect(conn_id).ok()) {
                        client_handle = ch;
                    }
                    // Reply the accept, then break: the thread resumes into its (rejecting) tail +
                    // re-parks on its next NtReplyWaitReceivePort. Single winlogon connect → done.
                    done = true;
                }
                SSN_COMPLETE_CONNECT => {
                    // Defensive: if the accept were ever ALLOWED (a future registered CSR process),
                    // the thread would call this — complete through the broker.
                    if client_handle == 0 {
                        if let Some((ch, _)) = lpc_client().and_then(|c| c.complete_connect(conn_id).ok()) {
                            client_handle = ch;
                        }
                    }
                    done = true;
                }
                _ => {
                    // An incidental syscall on the accept path (NtDelayExecution retry,
                    // NtSetInformationThread, …) — no-op success + keep going (bounded by `guard`).
                    print_str(b"[csr-rdv] incidental SSN=");
                    print_u64(ssn);
                    print_str(b" -> no-op success\n");
                }
            }
            set_reply_mr(15, resume_ip);
            set_reply_mr(16, sp);
            set_reply_mr(17, flags);
            send_on_reply(reply, 18, result, 0, 0, rdx);
            if done {
                break;
            }
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
            continue;
        }
        print_str(b"[csr-rdv] WALL: unexpected label=");
        print_u64(label);
        print_str(b"\n");
        break;
    }
    client_handle
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
    map_image_skeleton(pml4, img_count);
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
    map_image_skeleton(pml4, img_count);
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
    // Granted device resources, mapped into the host's VSpace (all within the cluster PT):
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
    map_image_skeleton(pml4, img_count);
    map_heap_pt(pml4);
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
    for i in 0..allocator::SERVICE_HEAP_FRAMES {
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

/// Spawn the isolated **win32k-service** component: like `spawn_kmdf_host` but scaled to the
/// 2.1 MiB win32k image. Maps the executive image RWX (the trampolines live there), a heap +
/// deep stack, the pre-loaded win32k PE at `WIN32K_CODE_VA` **W^X** (per-frame `code_rights`:
/// RX code / RW data), the pool arena, the data-export region, and the shared handoff page.
/// The executive receives on `fault_ep` (crash-contained): win32k's DriverEntry runs here and
/// every fault (or the completion SENTINEL) is delivered to the executive. Returns the host
/// `pml4` cap so the fault loop can demand-map pages into it.
#[allow(clippy::too_many_arguments)]
unsafe fn spawn_win32k_host(
    entry: unsafe extern "C" fn() -> !,
    fault_ep: u64,
    prio: u64,
    code_base: u64,
    code_rights: &[u64],
    pool_base: u64,
    data_base: u64,
    shared_frame: u64,
    heap_base: u64,
    arg_base: u64,
) -> u64 {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let stack_frames = 32u64; // 128 KiB — win32k init call chains are deep
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    map_image_skeleton(pml4, img_count);
    map_heap_pt(pml4);
    // Executive image RWX (the trampolines + statics the host calls into live in it).
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RWX */ 3, pml4);
    }
    for i in 0..allocator::SERVICE_HEAP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, allocator::HEAP_BASE as u64 + i * 0x1000, RW_NX, pml4);
    }
    // win32k's OWN stack at WIN32K_STACK_VADDR (NOT the hosted-process STACK_BASE — that VA must stay
    // free in win32k's VSpace so the per-client attach can identity-map a client's stack-built pointer
    // there). Its own 2 MiB PT (128 KiB stack fits one PT).
    let wspt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wspt);
    let _ = paging_struct_map(wspt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_STACK_VADDR, pml4);
    let mut stack_slot_base = 0u64;
    for i in 0..stack_frames {
        let f = alloc_slot();
        if i == 0 {
            stack_slot_base = f;
        }
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, win32k_host::WIN32K_STACK_VADDR + i * 0x1000, RW_NX, pml4);
    }
    WIN32K_STACK_SLOT.store(stack_slot_base, Ordering::Relaxed);
    WIN32K_STACK_FRAMES.store(stack_frames, Ordering::Relaxed);
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    // The pre-loaded win32k PE image, W^X (per-frame rights). Two 2 MiB PTs.
    for p in 0..2u64 {
        let cpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, cpt);
        let _ = paging_struct_map(cpt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_CODE_VA + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_IMAGE_FRAMES {
        let cp = copy_cap(code_base + i);
        let rights = code_rights.get(i as usize).copied().unwrap_or(RW_NX);
        let _ = page_map(cp, win32k_host::WIN32K_CODE_VA + i * 0x1000, rights, pml4);
    }
    // DATA/SHARED/SENTINEL/ARG share the aux PT window (0x0700_0000..0x0720_0000); the pool has its
    // own dedicated window (0x0A00_0000, 8 MiB / 4 PTs), pre-mapped.
    let apt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, apt);
    let _ = paging_struct_map(apt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_AUX_PT_VADDR, pml4);
    for p in 0..(win32k_host::WIN32K_POOL_FRAMES + 511) / 512 {
        let ppt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, ppt);
        let _ = paging_struct_map(ppt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_POOL_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_POOL_FRAMES {
        let cp = copy_cap(pool_base + i);
        let _ = page_map(cp, win32k_host::WIN32K_POOL_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // FreeType's separate arena (win32k-only; own window + PTs, pre-mapped) — bounds ftfd's unbounded
    // font-init allocations so they can't starve the main pool.
    for p in 0..(win32k_host::WIN32K_FTYP_FRAMES + 511) / 512 {
        let fpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, fpt);
        let _ = paging_struct_map(fpt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_FTYP_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_FTYP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, win32k_host::WIN32K_FTYP_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // GDI-attribute user-mode VM arena (ZwAllocateVirtualMemory: GDI DC_ATTR / RGN_ATTR pools) —
    // own window + PTs, pre-mapped RW so RESERVE hands out backed memory and COMMIT is a no-op.
    for p in 0..(win32k_host::WIN32K_USERVM_FRAMES + 511) / 512 {
        let upt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, upt);
        let _ = paging_struct_map(upt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_USERVM_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_USERVM_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, win32k_host::WIN32K_USERVM_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The staged system font (arial.ttf) frames — the SAME frames the storage host filled (via
    // FONTBUF_START) mapped into win32k at FONTBUF_VADDR, so load_system_font can feed the raw ttf
    // bytes to IntGdiAddFontMemResource (own PT window at 0x06E0).
    let font_base = FONTBUF_START.load(Ordering::Relaxed);
    if font_base != 0 {
        let fbpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, fbpt);
        let _ = paging_struct_map(fbpt, LBL_X86_PAGE_TABLE_MAP, win32k_host::FONTBUF_VADDR, pml4);
        for i in 0..win32k_host::FONTBUF_FRAMES {
            let _ = page_map(copy_cap(font_base + i), win32k_host::FONTBUF_VADDR + i * 0x1000, RW_NX, pml4);
        }
    }
    for i in 0..win32k_host::WIN32K_DATA_FRAMES {
        let cp = copy_cap(data_base + i);
        let _ = page_map(cp, win32k_host::WIN32K_DATA_VADDR + i * 0x1000, RW_NX, pml4);
    }
    let sh = copy_cap(shared_frame);
    let _ = page_map(sh, win32k_host::WIN32K_SHARED_VADDR, RW_NX, pml4);
    // The cross-AS arg-marshal frame(s) (same pool PT window as pool/data/shared).
    for i in 0..win32k_host::WIN32K_ARG_FRAMES {
        let _ = page_map(copy_cap(arg_base + i), win32k_host::WIN32K_ARG_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The win32k session-heap + Mm-view arena (RtlAllocateHeap + MmMapView*) — 4096 frames =
    // 16 MiB, 8 PTs (0x0740_0000..0x0840_0000).
    for p in 0..(win32k_host::WIN32K_HEAP_FRAMES / 512) {
        let hpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, hpt);
        let _ = paging_struct_map(hpt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_HEAP_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_HEAP_FRAMES {
        let cp = copy_cap(heap_base + i);
        let _ = page_map(cp, win32k_host::WIN32K_HEAP_VADDR + i * 0x1000, RW_NX, pml4);
    }

    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    WIN32K_TCB.store(tcb, Ordering::Relaxed);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = win32k_host::WIN32K_STACK_VADDR + stack_frames * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
    // win32k is a kernel driver: it reads the KPCR via `gs:[..]`. Point GS at a zeroed KPCR
    // placeholder so those reads resolve (0) instead of faulting on linear address `[0x30]` etc.
    let _ = tcb_set_gs_base(tcb, win32k_host::WIN32K_KPCR_VA);
    // NOTE: win32k is NOT marked HOSTED (unlike smss/csrss): its init/trampoline code issues REAL
    // seL4 syscalls (SysDebugPutChar for serial), which must dispatch natively. The dispatch loop's
    // ready/done signal instead faults by putting an INVALID nr in RDX (see `dispatch_signal`), so
    // only that one syscall becomes an UnknownSyscall the executive catches.
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    pml4
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
    srvbuf_start: u64,
    win32buf_start: u64,
    nls_ansi_start: u64,
    nls_oem_start: u64,
    nls_case_start: u64,
    nls20127_start: u64,
    hivebuf_start: u64,
    win32kbuf_start: u64,
    winlogonbuf_start: u64,
) {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    map_image_skeleton(pml4, img_count);
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
    // The server-DLL buffer (basesrv.dll + winsrv.dll, its own PT), same pattern.
    let sb_pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, sb_pt);
    let _ = paging_struct_map(sb_pt, LBL_X86_PAGE_TABLE_MAP, SRVBUF_VADDR, pml4);
    for i in 0..SRVBUF_FRAMES {
        let sb_cp = copy_cap(srvbuf_start + i);
        let _ = page_map(sb_cp, SRVBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The Win32 client-stack buffer (kernel32+user32+gdi32 + Win32 deps, 4 PTs), mapped into the host too.
    for p in 0..4u64 {
        let wpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wpt);
        let _ = paging_struct_map(wpt, LBL_X86_PAGE_TABLE_MAP, WIN32BUF_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..WIN32BUF_FRAMES {
        let wb_cp = copy_cap(win32buf_start + i);
        let _ = page_map(wb_cp, WIN32BUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The raw win32k.sys staging buffer (544 frames = two 2 MiB PTs), mapped into the host too.
    for p in 0..2u64 {
        let kpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, kpt);
        let _ = paging_struct_map(kpt, LBL_X86_PAGE_TABLE_MAP, WIN32KBUF_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..WIN32KBUF_FRAMES {
        let kb_cp = copy_cap(win32kbuf_start + i);
        let _ = page_map(kb_cp, WIN32KBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The raw winlogon.exe staging buffer (its own PT), mapped into the host too so it reads the PE
    // off disk into it; the executive parses the same frames + spawns winlogon.
    let wl_pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wl_pt);
    let _ = paging_struct_map(wl_pt, LBL_X86_PAGE_TABLE_MAP, WINLOGONBUF_VADDR, pml4);
    for i in 0..WINLOGONBUF_FRAMES {
        let wl_cp = copy_cap(winlogonbuf_start + i);
        let _ = page_map(wl_cp, WINLOGONBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The raw dxg.sys / dxgthk.sys staging buffers (one PT each), mapped into the host too.
    for (start, vaddr, frames) in [
        (DXGBUF_START.load(Ordering::Relaxed), DXGBUF_VADDR, DXGBUF_FRAMES),
        (DXGTHKBUF_START.load(Ordering::Relaxed), DXGTHKBUF_VADDR, DXGTHKBUF_FRAMES),
        (FTFDBUF_START.load(Ordering::Relaxed), FTFDBUF_VADDR, FTFDBUF_FRAMES),
        (FRAMEBUFBUF_START.load(Ordering::Relaxed), FRAMEBUFBUF_VADDR, FRAMEBUFBUF_FRAMES),
        (FONTBUF_START.load(Ordering::Relaxed), win32k_host::FONTBUF_VADDR, win32k_host::FONTBUF_FRAMES),
    ] {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, vaddr, pml4);
        for i in 0..frames {
            let _ = page_map(copy_cap(start + i), vaddr + i * 0x1000, RW_NX, pml4);
        }
    }
    // The NLS + SYSTEM-hive buffers share the NTDLLBUF page table (0xA0-0xC0 region) — no extra PT.
    for (start, vaddr, frames) in [
        (nls_ansi_start, NLS_ANSI_VADDR, NLS_ANSI_FRAMES),
        (nls_oem_start, NLS_OEM_VADDR, NLS_OEM_FRAMES),
        (nls_case_start, NLS_CASE_VADDR, NLS_CASE_FRAMES),
        (nls20127_start, NLS_20127_VADDR, NLS_20127_FRAMES),
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
/// csrss's OWN NtAllocateVirtualMemory bump — a SEPARATE counter from smss's so smss's allocations
/// don't push csrss's heap base past the single alloc page table spawn_sec_image maps. Both start at
/// SMSS_ALLOC_VA: the two processes have independent VSpaces, so the same VA (with each's own PT) is
/// fine, and csrss's heap then lands low, within its mapped PT.
static NEXT_CSRSS_ALLOC: AtomicU64 = AtomicU64::new(SMSS_ALLOC_VA);
/// winlogon's OWN NtAllocateVirtualMemory bump (3rd hosted process) — a SEPARATE counter so smss's
/// (or csrss's) allocations don't push winlogon's heap base past the single alloc PT spawn_sec_image
/// maps. Starts at SMSS_ALLOC_VA: independent VSpaces make the same VA (own PT) fine.
static NEXT_WINLOGON_ALLOC: AtomicU64 = AtomicU64::new(SMSS_ALLOC_VA);
/// How many NtAllocateVirtualMemory calls the executive serviced for a SEC_IMAGE process.
static NTALLOC_SERVICED: AtomicU64 = AtomicU64::new(0);
/// NLS shared-buffer frame-cap bases + sizes (set at storage bring-up), so spawn_sec_image can
/// share the c_1252/c_437/l_intl frames into smss and point the PEB NLS fields at them.
static NLS_ANSI_START: AtomicU64 = AtomicU64::new(0);
static NLS_OEM_START: AtomicU64 = AtomicU64::new(0);
static NLS_CASE_START: AtomicU64 = AtomicU64::new(0);
static NLS_20127_START: AtomicU64 = AtomicU64::new(0);
static NLS_ANSI_SIZE: AtomicU64 = AtomicU64::new(0);
static NLS_OEM_SIZE: AtomicU64 = AtomicU64::new(0);
static NLS_CASE_SIZE: AtomicU64 = AtomicU64::new(0);
/// The frame-cap base + byte size of the real SYSTEM hive the storage host read into HIVEBUF.
static HIVEBUF_START: AtomicU64 = AtomicU64::new(0);
static REAL_HIVE_SIZE: AtomicU64 = AtomicU64::new(0);
/// The frame-cap base of the raw win32k.sys the storage host staged into WIN32KBUF (Phase 2b).
static WIN32KBUF_START: AtomicU64 = AtomicU64::new(0);
/// The frame-cap base of the raw winlogon.exe the storage host staged into WINLOGONBUF (3rd process).
static WINLOGONBUF_START: AtomicU64 = AtomicU64::new(0);
/// Set once smss's NtCreateProcess spawns winlogon as the 3rd hosted process (its ntdll loader then
/// runs, multiplexed by badge). Read by the post-run spec checks to prove the milestone.
static WINLOGON_SPAWNED: AtomicU64 = AtomicU64::new(0);
/// How many pages winlogon's ntdll loader demand-faulted (slot 2), for the spec-check report.
static WINLOGON_FAULTS: AtomicU64 = AtomicU64::new(0);
/// Set once winlogon's kernel32 CSR client connect (NtSecureConnectPort → \Windows\ApiPort) is
/// serviced (regions mapped + CSR_API_CONNECTINFO filled). Read by the milestone spec check.
static WINLOGON_CSR_CONNECTED: AtomicU64 = AtomicU64::new(0);
/// How many CSR API messages (NtRequestWaitReplyPort → \Windows\ApiPort) the direct message plane
/// has serviced — proves winlogon↔csrss live traffic over the peer-direct plane.
static CSR_MSGS: AtomicU64 = AtomicU64::new(0);
// === nt-process convergence (policy/mechanism split) ===================================
// The live executive is converging its ad-hoc process IDENTITY tracking (the per-pi `pml4s`/
// `scratch_bases`/… loop arrays + the `badge→pi` switch) onto the real host-tested nt-process
// ProcessManager (EPROCESS/ETHREAD/handle-tables/lifecycle). FIRST INCREMENT (behavior-preserving):
// each hosted process (smss/csrss/winlogon) is backed by a real nt-process EPROCESS created at boot
// in `ExecNtHandler::new()` (below the per-syscall heap mark → survives the bump reset, no runtime
// realloc); the mechanism arrays are unchanged. `PM_PIDS[pi]` maps the mechanism index (pi 0/1/2,
// keyed by fault badge) to the EPROCESS pid — the badge↔pid link. Read by the counted specs.
/// EPROCESS pids for pi 0=smss / 1=csrss / 2=winlogon (0 = not yet created).
static PM_PIDS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
/// How many EPROCESS objects the boot-time ProcessManager holds (expected 3).
static PM_PROC_COUNT: AtomicU64 = AtomicU64::new(0);
/// Bit i set iff EPROCESS pi=i exists AND its image_file_name matches the expected hosted binary AND
/// its pid is distinct — proves the real objects (not just pid scalars) back each hosted process.
static PM_IDENTITY_OK: AtomicU64 = AtomicU64::new(0);
/// Incremented each time the live service loop resolves the current fault BADGE → its EPROCESS via
/// the ProcessManager (`pm.process(PM_PIDS[pi])`) — proves badge↔EPROCESS lookup works at runtime.
static PM_BADGE_LOOKUPS: AtomicU64 = AtomicU64::new(0);
/// Reserved handle-table capacity per hosted EPROCESS (path 1). Measured peak is < ~100 handles per
/// process over a full boot; 256 is ~3× headroom so `insert_handle` never reallocates under the
/// per-syscall bump reset (the non-leaking heap solution). ~256 × 24 B × 3 ≈ 18 KiB of the 2 MiB heap.
// Path 1b: append-only handles (no slot reuse) mean a process's table grows to its TOTAL mint
// count over the run, not its peak-concurrent count, so reserve generously (the whole boot mints
// well under this per process; keeps the durable table from ever reallocating under the heap-reset).
const PM_HANDLE_RESERVE: usize = 1024;
/// Total handles the executive has routed into the real per-EPROCESS handle tables (all mint sites).
static PM_HANDLES_TRACKED: AtomicU64 = AtomicU64::new(0);
/// Peak live handle count in any single EPROCESS table over the boot — the reservation-headroom gauge.
static PM_HANDLE_PEAK: AtomicU64 = AtomicU64::new(0);
/// Handles freed from a per-EPROCESS table by a real `NtClose` (close-by-value-tag) — proves the
/// lifecycle end of the handle path works (was a no-op success before path 1).
static PM_HANDLES_CLOSED: AtomicU64 = AtomicU64::new(0);
/// The handle-table capacity reserved at boot (min across the 3 EPROCESSes). The run proves no
/// reallocation by keeping the peak live count strictly below this — the non-leaking heap headroom.
static PM_HANDLE_CAP_BOOT: AtomicU64 = AtomicU64::new(0);
// === Path 2 — lifecycle: real ETHREADs + create/terminate/open routed through pm ===============
/// Main-thread tids for pi 0=smss / 1=csrss / 2=winlogon (0 = not yet created). Pre-created at boot
/// (identity), like the EPROCESSes — the non-leaking heap solution (BTreeMap/BTreeSet inserts happen
/// below the per-syscall mark), then the image entry is bound at the real spawn (alloc-free).
static PM_TIDS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
/// Bit i set iff EPROCESS pi=i has a real main ETHREAD with the right pid, is Running, and its
/// ClientId resolves — proves each hosted process's main thread is a real nt-process object.
static PM_MAIN_THREADS_OK: AtomicU64 = AtomicU64::new(0);
/// Count of spawn-time `set_thread_start_address` binds (csrss/winlogon main threads bound to their
/// real image entry when the seL4 process is actually spawned) — the "NtCreateThread through pm at
/// real spawn time" routing.
static PM_THREAD_BINDS: AtomicU64 = AtomicU64::new(0);
/// Lifecycle self-test result (post-loop): NtTerminateProcess policy teardown on a throwaway EPROCESS
/// (process signalled + main thread terminated + exit status via wait + handle-table closed).
static PM_LIFECYCLE_OK: AtomicU64 = AtomicU64::new(0);
/// Path 1b counted-spec result (post-loop): two distinct EPROCESSes both allocate dense handle 0x4,
/// each resolving to a DIFFERENT object — proof of process-local handle namespaces (bits 0b111).
static PM_HANDLE_LOCAL_OK: AtomicU64 = AtomicU64::new(0);
/// NtOpenProcess self-test result (post-loop): opening a process by ClientId mints a Process handle in
/// the opener's EPROCESS table that resolves back to the target pid.
static PM_NTOPENPROCESS_OK: AtomicU64 = AtomicU64::new(0);
/// Count of real NtTerminateProcess calls the executive serviced (0 during a normal boot — no hosted
/// process terminates; the handler is additive + proven by the post-loop self-test).
static PM_TERMINATE_CALLS: AtomicU64 = AtomicU64::new(0);
/// Count of LIVE NtTerminateThread self-exits routed through the real ETHREAD teardown (item 2a).
/// csrss.exe's init thread exits via NtTerminateThread(NtCurrentThread()) once during a normal boot
/// ("CSRSRV keeps us going"); the executive marks that ETHREAD Terminated via `pm.exit_thread` (no
/// process cascade — csrss keeps running) and parks the seL4 thread, unchanged. >=1 proves the live
/// thread-exit was routed to the real teardown (not the pre-2a benign park-only fallback).
static PM_TERMINATE_THREAD_LIVE: AtomicU64 = AtomicU64::new(0);
/// Bit i set iff pi=i's main ETHREAD is Terminated (signalled) via a live NtTerminateThread. Bit 1
/// (csrss) is set during a normal boot; bits 0/2 stay clear (smss/winlogon don't self-exit at boot).
static PM_TERMINATE_THREAD_STATE: AtomicU64 = AtomicU64::new(0);
/// ITEM 2b — seL4 MECHANISM-teardown (reclamation) self-test result (post-loop). Bitmask (0b11_1111
/// = all proven): child untyped carved / frame Untyped-return reclamation (retype→delete→retype ==)
/// / TCB suspend+delete / PML4+CNode delete / frame-unmap-on-delete / child untyped returned.
static PM_RECLAIM_OK: AtomicU64 = AtomicU64::new(0);
/// ALPC last-mile item (b): the two-VSpace cross-AS section-view self-test result (0x3F = all 6).
static ALPC_XVIEW_OK: AtomicU64 = AtomicU64::new(0);
// === Path 3 — fold the per-pi IDENTITY arrays into an EPROCESS-linked per-process struct =========
/// Executive-side per-hosted-process MECHANISM state, EPROCESS-linked. Path 3 of the nt-process
/// convergence folds the six parallel `[_;3]` identity arrays that `service_sec_image` indexed by
/// `pi` (pml4s / scratch_bases / img_ends / pfaults / pfirst / pntfaults) into ONE array-of-structs,
/// each slot carrying its own mechanism state PLUS the `pid` link to its real nt-process EPROCESS
/// (== the pid in `PM_PIDS[pi]`). Behavior-preserving: the same values, keyed the same way (fault
/// badge → pi), just consolidated + EPROCESS-linked instead of six parallel arrays. The seL4 VSpace
/// cap + the scratch/image VAs stay executive-side (only the trusted root task holds those caps — the
/// policy/mechanism split); this struct just consolidates them under the EPROCESS link so the service
/// loop reads a process's mechanism state via its EPROCESS instead of parallel arrays.
#[derive(Clone, Copy)]
struct ProcExec {
    /// EPROCESS pid backing this hosted process (0 until linked); mirrors `PM_PIDS[pi]` — the
    /// badge↔pid convergence link, so the loop reaches the per-process mechanism via the EPROCESS.
    pid: u64,
    /// seL4 VSpace (PML4) cap for this process's address space (0 until the process is spawned).
    pml4: u64,
    /// Per-process demand-fill scratch base VA (was `scratch_bases[pi]`).
    scratch_base: u64,
    /// End VA of this process's mapped image — the demand-fill upper bound (was `img_ends[pi]`).
    img_end: u64,
    /// Total page faults serviced for this process (was `pfaults[pi]`).
    faults: u64,
    /// First faulting address seen for this process — diagnostics (was `pfirst[pi]`).
    first: u64,
    /// NT-syscall faults serviced for this process (was `pntfaults[pi]`).
    ntfaults: u64,
}
impl ProcExec {
    const fn empty() -> Self {
        ProcExec { pid: 0, pml4: 0, scratch_base: 0, img_end: 0, faults: 0, first: 0, ntfaults: 0 }
    }
}
/// Bit i set iff `procs[i]` (the folded EPROCESS-linked per-process struct) has a live pml4 AND its
/// `pid` matches the ProcessManager's pid for pi=i — proves the consolidated per-process mechanism
/// struct is EPROCESS-linked at runtime (path 3). Expected 0b111 (all 3 hosted processes spawned).
static PM_EXEC_LINK_OK: AtomicU64 = AtomicU64::new(0);
/// Frame-cap bases of the raw dxg.sys / dxgthk.sys staged into DXGBUF / DXGTHKBUF (DirectX host).
static DXGBUF_START: AtomicU64 = AtomicU64::new(0);
static DXGTHKBUF_START: AtomicU64 = AtomicU64::new(0);
/// Frame-cap base of the raw ftfd.dll staged into FTFDBUF (FreeType font driver).
static FTFDBUF_START: AtomicU64 = AtomicU64::new(0);
/// Frame-cap base of the raw framebuf.dll staged into FRAMEBUFBUF (display driver).
static FRAMEBUFBUF_START: AtomicU64 = AtomicU64::new(0);
/// Frame-cap base of the staged system font (arial.ttf) in FONTBUF (fed to IntGdiAddFontMemResource).
static FONTBUF_START: AtomicU64 = AtomicU64::new(0);
/// The win32k component's stack frame-cap base + count + TCB (for the fault-time stack backtrace).
static WIN32K_STACK_SLOT: AtomicU64 = AtomicU64::new(0);
static WIN32K_STACK_FRAMES: AtomicU64 = AtomicU64::new(0);
static WIN32K_TCB: AtomicU64 = AtomicU64::new(0);
/// One-shot guard: the dispatch-path backtrace mirror PT has been created (SYS_SEND paging is
/// fire-and-forget so we can't re-map the PT idempotently).
static WIN32K_DISP_BT_PT: AtomicU64 = AtomicU64::new(0);
/// The win32k component's fault endpoint + host PML4 (set once DriverEntry+attach parked it at the
/// dispatch signal), so `win32k_dispatch` can drive its persistent service loop from anywhere.
static WIN32K_FAULT_EP: AtomicU64 = AtomicU64::new(0);
static WIN32K_HOST_PML4: AtomicU64 = AtomicU64::new(0);
/// The frame-cap cptr base of win32k's global USER heap arena (`heap_base`, WIN32K_HEAP_FRAMES
/// consecutive caps). Retained so the connect marshaling can copy_cap + RO-map the arena into a
/// GUI client's VSpace (the gSharedInfo client-mapping).
static WIN32K_HEAP_FRAME_BASE: AtomicU64 = AtomicU64::new(0);
/// 0 until win32k's USER heap arena has been RO-mapped into csrss (one-time; guards re-mapping on a
/// second NtUserProcessConnect from the same client).
static WIN32K_CLIENT_MAPPED: AtomicU64 = AtomicU64::new(0);
/// The BOOTBOOT framebuffer's frame-cap base + count (set in Phase 0a's `claim_device_pages`), so the
/// win32k bring-up can copy_cap + map the SAME physical fb frames into win32k's VSpace at WIN32K_FB_VA
/// (framebuf.dll's IOCTL_VIDEO_MAP_VIDEO_MEMORY reports that VA → framebuf writes pixels to the real fb).
static FB_FRAME_BASE: AtomicU64 = AtomicU64::new(0);
static FB_FRAME_COUNT: AtomicU64 = AtomicU64::new(0);
/// Framebuffer-pixel readback result after the desktop-graphics init: 0=not run, 1=unchanged, 2=drew.
static FB_PIXELS_DREW: AtomicU64 = AtomicU64::new(0);
/// Count (of the 768-px sampled grid) whose value == [`FB_DESKTOP_BG`] after the desktop-graphics
/// init — i.e. how many sampled pixels hold the authentic WC_DESKTOP background win32k painted.
/// The `exec_win32k_desktop_painted` gate asserts this is the full 768 (see the summary section).
static FB_PIXELS_MATCH: AtomicU64 = AtomicU64::new(0);
/// The first sampled pixel (grid origin) after the desktop-graphics init — recorded so the gate
/// report shows the actual painted COLORREF (expected [`FB_DESKTOP_BG`]).
static FB_PIXELS_SAMPLE0: AtomicU64 = AtomicU64::new(0);
/// The number of framebuffer pixels sampled on the readback grid (24 rows x 32 cols).
const FB_SAMPLE_COUNT: u64 = 24 * 32;
/// Proof that winlogon's OWN natural NtUserSwitchDesktop -> co_IntShowDesktop -> IntPaintDesktop
/// flow paints the framebuffer. Set by the forward arm around winlogon's SwitchDesktop (SSN 0x1288):
/// the fb is cleared to magenta (0x00FF00FF) BEFORE the switch and the sampled grid is re-read AFTER —
/// this records how many sampled pixels winlogon's flow re-painted to [`FB_DESKTOP_BG`]. 0 = not yet
/// observed; a full 768 = the natural flow paints. The EAGER SSN_INIT_DESKTOP_GFX scaffold is now
/// fully RETIRED — winlogon's own DC-op drives BOTH the display init (co_IntGraphicsCheck ->
/// co_IntInitializeDesktopGraphics) and this paint; this is the sole source of the counted spec.
static WINLOGON_NATURAL_PAINT: AtomicU64 = AtomicU64::new(0);
/// The authentic desktop background COLORREF that win32k's WC_DESKTOP class `hbrBackground` paints
/// (co_IntShowDesktop -> IntPaintDesktop -> NtGdiPatBlt -> DrvBitBlt -> the real framebuffer). This
/// is the value the Phase-0a magenta (0x00FF00FF) test pattern must flip to when the desktop is
/// painted; the `exec_win32k_desktop_painted` gate spec asserts the WHOLE sampled grid == this.
const FB_DESKTOP_BG: u32 = 0x003a_6ea5;
/// The executive's Phase-0a framebuffer window (also read back after the desktop-graphics init to
/// confirm GDI/framebuf drew pixels).
const FB_VADDR: u64 = 0x0000_0200_0000_0000;

/// RO-map win32k's global USER heap arena ([`win32k_host::WIN32K_HEAP_VADDR`], where gpsi /
/// gHandleTable / the USER handle-entry array live) into the caller's (csrss's) VSpace at
/// [`win32k_host::CSRSS_W32_SHARED_VA`], so the Win32 client can dereference the SHAREDINFO the
/// USERCONNECT points at. Maps a fresh copy of each arena frame RO+NX (win32k keeps its own RW
/// copy — coherent shared memory). One-time (guarded). Returns the server→client delta
/// (`WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA`) the marshaling applies to the siClient pointers.
unsafe fn map_win32k_heap_into_csrss(pml4: u64, pi: usize) -> u64 {
    let delta = win32k_host::WIN32K_HEAP_VADDR - win32k_host::CSRSS_W32_SHARED_VA;
    // Per-process guard (bit `pi`): the arena is mapped into EACH GUI client's VSpace independently
    // (csrss = pi 1, winlogon = pi 2) at the same CSRSS_W32_SHARED_VA window, so the delta — hence
    // the siClient rewrite — is identical for both. A single bool would skip the 2nd client's map.
    let bit = 1u64 << pi;
    if WIN32K_CLIENT_MAPPED.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
        return delta; // already mapped into this process's VSpace
    }
    let heap_base = WIN32K_HEAP_FRAME_BASE.load(Ordering::Relaxed);
    if heap_base == 0 {
        return delta;
    }
    const RO_NX: u64 = 2 | PAGE_EXECUTE_NEVER; // read-only, non-executable
    let frames = win32k_host::WIN32K_HEAP_FRAMES;
    // The 1 GiB PD covering 0x8000_0000..0xC000_0000 already exists in csrss (its DLL region shares
    // it). The CSRSS_W32_SHARED_VA window is fresh, so allocate + map one page table per 2 MiB
    // sub-range UP FRONT — deterministic, because the SYS_SEND `page_map` is fire-and-forget and
    // can't report a missing-PT error to drive a retry.
    for p in 0..(frames + 511) / 512 {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            win32k_host::CSRSS_W32_SHARED_VA + p * 0x20_0000,
            pml4,
        );
    }
    for i in 0..frames {
        let cp = copy_cap(heap_base + i);
        let _ = page_map(cp, win32k_host::CSRSS_W32_SHARED_VA + i * 0x1000, RO_NX, pml4);
    }
    print_str(b"[win32k-svc] RO-mapped win32k USER heap into csrss @0x");
    print_hex(win32k_host::CSRSS_W32_SHARED_VA as u32);
    print_str(b" (delta=0x");
    print_hex((delta >> 32) as u32);
    print_hex(delta as u32);
    print_str(b")\n");
    delta
}

// --- win32k cross-AS client-memory sharing (the authentic "win32k shares the caller's user AS") ---
// win32k-side paging structures provisioned for the shared client window, and pages already mapped,
// keyed by a level-tagged aligned index (SYS_SEND paging_struct_map is fire-and-forget so we can't
// detect "already mapped" — track it). Client VAs are all < 0x100_0000_0000 (PML4 slots 0/1), never
// win32k's own PML4[2] (>= 0x100_..), so building a fresh PDPT/PD/PT hierarchy here can't collide
// with win32k's own mappings.
static mut W32_CLIENT_SEEN: [u64; 8192] = [0; 8192];
static mut W32_CLIENT_SEEN_N: usize = 0;
unsafe fn w32_seen(key: u64) -> bool {
    let n = core::ptr::read(core::ptr::addr_of!(W32_CLIENT_SEEN_N));
    let a = core::ptr::addr_of!(W32_CLIENT_SEEN) as *const u64;
    for i in 0..n {
        if core::ptr::read(a.add(i)) == key {
            return true;
        }
    }
    false
}
unsafe fn w32_mark(key: u64) {
    let n = core::ptr::read(core::ptr::addr_of!(W32_CLIENT_SEEN_N));
    if n < 8192 {
        core::ptr::write((core::ptr::addr_of_mut!(W32_CLIENT_SEEN) as *mut u64).add(n), key);
        core::ptr::write(core::ptr::addr_of_mut!(W32_CLIENT_SEEN_N), n + 1);
    }
}
/// Ensure win32k's VSpace has a PDPT/PD/PT chain covering `page` (each created once, tracked in
/// W32_CLIENT_SEEN). Used both for FOREIGN client pages (PML4[0/1], fresh hierarchy) AND for
/// win32k-OWN demand-mapped regions (the demand-mapped pool at 0x0A00, whose 2 MiB PTs don't exist
/// yet). Deterministic because `page_map`/`paging_struct_map` are SYS_SEND (fire-and-forget) and
/// can't report a missing-PT error to drive a retry — so the PT must be created up front. For
/// win32k-own PML4[2] pages the PDPT/PD already exist; the duplicate retype+map fails silently
/// (seL4 won't replace an occupied slot) and only the fresh PT actually takes.
unsafe fn ensure_w32_client_paging(page: u64, w_pml4: u64) {
    let k_pdpt = (1u64 << 60) | (page >> 39);
    if !w32_seen(k_pdpt) {
        let s = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, s);
        let _ = paging_struct_map(s, LBL_X86_PDPT_MAP, page, w_pml4);
        w32_mark(k_pdpt);
    }
    let k_pd = (2u64 << 60) | (page >> 30);
    if !w32_seen(k_pd) {
        let s = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, s);
        let _ = paging_struct_map(s, LBL_X86_PAGE_DIRECTORY_MAP, page, w_pml4);
        w32_mark(k_pd);
    }
    let k_pt = (3u64 << 60) | (page >> 21);
    if !w32_seen(k_pt) {
        let s = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, s);
        let _ = paging_struct_map(s, LBL_X86_PAGE_TABLE_MAP, page, w_pml4);
        w32_mark(k_pt);
    }
}
// --- win32k per-client attach/detach (the KeStackAttachProcess model) ---------------------------
// win32k's client window is shared with EXACTLY ONE GUI client at a time. csrss (pi 1) and winlogon
// (pi 2) map an overlapping DLL/stack set at IDENTICAL VAs but DISTINCT frames, so a static shared
// window can't hold both — win32k must re-point (attach to) the CURRENT dispatch's client. The
// attach table records the client leaf pages currently mapped into win32k (page -> the copy_cap
// slot used, so we can Unmap it on detach). On a client switch we Unmap the previous client's leaf
// pages (they re-fault fresh for the new client, resolving the colliding VA to THIS client's frame);
// the PDPT/PD/PT structures persist in W32_CLIENT_SEEN (empty tables after the leaf Unmap). The
// arch-level Unmap uses the invoked (win32k) cap's asid → only win32k's mapping is torn down; the
// client keeps its own mapping in its own VSpace.
static W32_ATTACHED_PI: AtomicU64 = AtomicU64::new(0xFFFF_FFFF);
/// The pi of the client whose call `win32k_dispatch` is currently servicing (set by the forward arm
/// before each dispatch; defaults to csrss so bring-up/self-test dispatches attach to pi 1). Read by
/// `win32k_dispatch` at entry to drive `w32_client_attach`.
static W32_CLIENT_PI: AtomicU64 = AtomicU64::new(1);
const W32_ATTACH_CAP: usize = 8192;
static mut W32_ATTACH_PAGE: [u64; W32_ATTACH_CAP] = [0; W32_ATTACH_CAP];
static mut W32_ATTACH_SLOT: [u64; W32_ATTACH_CAP] = [0; W32_ATTACH_CAP];
static mut W32_ATTACH_N: usize = 0;
/// Is `page` currently mapped into win32k for the attached client?
unsafe fn w32_attach_mapped(page: u64) -> bool {
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    let a = core::ptr::addr_of!(W32_ATTACH_PAGE) as *const u64;
    for i in 0..n {
        if core::ptr::read(a.add(i)) == page {
            return true;
        }
    }
    false
}
/// Record that `page` is now mapped into win32k via copy-cap `slot` (for a later detach Unmap).
unsafe fn w32_attach_record(page: u64, slot: u64) {
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    if n < W32_ATTACH_CAP {
        core::ptr::write((core::ptr::addr_of_mut!(W32_ATTACH_PAGE) as *mut u64).add(n), page);
        core::ptr::write((core::ptr::addr_of_mut!(W32_ATTACH_SLOT) as *mut u64).add(n), slot);
        core::ptr::write(core::ptr::addr_of_mut!(W32_ATTACH_N), n + 1);
    }
}
/// Attach win32k's client window to GUI client `pi` (the KeStackAttachProcess model). If a DIFFERENT
/// client is currently attached, DETACH it: Unmap all its leaf client pages from win32k so the new
/// client's colliding VAs re-fault to THIS client's frames. Idempotent when `pi` is already attached.
unsafe fn w32_client_attach(pi: u64) {
    let prev = W32_ATTACHED_PI.load(Ordering::Relaxed);
    if prev == pi {
        return;
    }
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    let slots = core::ptr::addr_of!(W32_ATTACH_SLOT) as *const u64;
    for i in 0..n {
        // Unmap win32k's mapping of the previous client's page (arch Unmap uses this cap's win32k
        // asid → csrss/winlogon's own VSpace mapping is untouched). Cap slot is leaked (bump CNode,
        // XL 131072-slot pool → bounded for bring-up); a fresh copy_cap is used on the re-map.
        let _ = page_unmap(core::ptr::read(slots.add(i)));
    }
    print_str(b"[w32attach] client ");
    print_u64(prev);
    print_str(b" -> ");
    print_u64(pi);
    print_str(b" (detached ");
    print_u64(n as u64);
    print_str(b" client pages)\n");
    core::ptr::write(core::ptr::addr_of_mut!(W32_ATTACH_N), 0);
    W32_ATTACHED_PI.store(pi, Ordering::Relaxed);
}
/// Share GUI client `pi`'s frame for `page` into win32k's VSpace at the SAME VA (identity) so
/// win32k's handler dereferences the caller's real user memory. Returns false if the page isn't
/// backed by a known client frame (win32k would read garbage → the caller stops with a diagnostic).
/// Idempotent per page for the currently-attached client (see `w32_client_attach`).
unsafe fn map_csrss_page_into_win32k(page: u64, pi: u64, w_pml4: u64) -> bool {
    if w32_attach_mapped(page) {
        return true; // already shared for the currently-attached client
    }
    let fr = csrss_frame_get(pi, page);
    if fr == 0 {
        return false;
    }
    ensure_w32_client_paging(page, w_pml4);
    // RW: win32k (kernel-mode) may read AND write the caller's user memory; the frame is shared with
    // the client so writes propagate back (out-params). Non-executable — client data, not code.
    let cc = copy_cap(fr);
    let _ = page_map(cc, page, RW_NX, w_pml4);
    w32_attach_record(page, cc);
    true
}

/// Load ONE driver PE (raw at `src_va` in the executive) into `dst_va` in BOTH the executive (RW,
/// to load) and win32k (W^X, to run). Reuses [`win32k_host::load_driver_into`]. `dxgthk_base` names
/// a prior-loaded dxgthk for import resolution (0 for a leaf). Returns (entry_rva, export_dir_rva,
/// size_of_image). The reusable driver-loader mechanism (framebuf.dll will use it too).
unsafe fn load_one_driver(
    src_va: u64,
    dst_va: u64,
    frames: u64,
    host_pml4: u64,
    dxgthk_base: u64,
) -> Option<(u32, u32, u32)> {
    // Executive-side PT + frames (RW), to load into.
    let ept = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, ept);
    let _ = paging_struct_map(ept, LBL_X86_PAGE_TABLE_MAP, dst_va, CAP_INIT_THREAD_VSPACE);
    let base = alloc_frame();
    for _ in 1..frames {
        let _ = alloc_frame();
    }
    for i in 0..frames {
        let _ = page_map(copy_cap(base + i), dst_va + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    // Parse + copy + reloc + resolve imports (writes via the executive's RW mapping). The per-frame
    // rights live in a `static` (ftfd.dll = 248 frames overflows a stack array; the rootserver stack
    // is only 16 KiB). Single-threaded + sequential loads → the shared static is safe.
    static mut DRIVER_RIGHTS: [u64; 256] = [RW_NX; 256];
    let rights = &mut *core::ptr::addr_of_mut!(DRIVER_RIGHTS);
    for r in rights.iter_mut() {
        *r = RW_NX;
    }
    let res = win32k_host::load_driver_into(
        src_va,
        dst_va,
        frames,
        &mut rights[..frames as usize],
        dxgthk_base,
    )?;
    // Map the SAME frames W^X into win32k's VSpace at the same VA (RX code / RW data).
    let wpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wpt);
    let _ = paging_struct_map(wpt, LBL_X86_PAGE_TABLE_MAP, dst_va, host_pml4);
    for i in 0..frames {
        let r = rights[i as usize];
        let _ = page_map(copy_cap(base + i), dst_va + i * 0x1000, r, host_pml4);
    }
    Some(res)
}

/// Pre-load dxg.sys + its dxgthk.sys dependency into win32k's VSpace so win32k's
/// `ZwSetSystemInformation(SystemLoadGdiDriverInformation)` (from InitializeGreCSRSS →
/// DxDdStartupDxGraphics) can report the hosted dxg image. dxgthk (leaf) first, then dxg (imports
/// dxgthk's Eng* + ntoskrnl). Called once at win32k bring-up.
unsafe fn load_directx_drivers(host_pml4: u64) {
    let dxg_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x80) as *const u32);
    let dxgthk_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x84) as *const u32);
    if dxg_size == 0 || dxgthk_size == 0 {
        print_str(b"[win32k-svc] dxg/dxgthk not staged - DirectX gate will fail\n");
        return;
    }
    if load_one_driver(DXGTHKBUF_VADDR, win32k_host::DXGTHK_VA, win32k_host::DXGTHK_LOAD_FRAMES, host_pml4, 0)
        .is_none()
    {
        print_str(b"[win32k-svc] dxgthk load failed\n");
        return;
    }
    match load_one_driver(
        DXGBUF_VADDR,
        win32k_host::DXG_VA,
        win32k_host::DXG_LOAD_FRAMES,
        host_pml4,
        win32k_host::DXGTHK_VA,
    ) {
        Some((entry, expdir, len)) => {
            win32k_host::record_dxg(entry, expdir, len);
            print_str(b"[win32k-svc] hosted dxg.sys + dxgthk.sys: entry_rva=0x");
            print_hex(entry);
            print_str(b" export_dir_rva=0x");
            print_hex(expdir);
            print_str(b" len=0x");
            print_hex(len);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] dxg load failed\n"),
    }
}

/// Host ftfd.dll (the FreeType font driver) into win32k's VSpace + patch win32k's OWN IAT for its 34
/// FT_* imports against ftfd's export table. Unlike dxg (dynamic, via ZwSetSystemInformation), ftfd
/// is a STATIC win32k import: win32k's InitFontSupport → FT_Init_FreeType calls it directly. ftfd
/// imports only 8 Eng*/Rtl thunks back from win32k.sys (resolved by load_driver_into's is_win32k arm).
/// Called once at win32k bring-up, AFTER win32k is loaded (its exports must be present for ftfd's IAT)
/// and BEFORE any FT_* call (which happens far later, during a routed NtUserInitialize dispatch).
unsafe fn load_ftfd_driver(host_pml4: u64) {
    let ftfd_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x88) as *const u32);
    if ftfd_size == 0 {
        print_str(b"[win32k-svc] ftfd.dll not staged - font gate will fail\n");
        return;
    }
    match load_one_driver(
        FTFDBUF_VADDR,
        win32k_host::FTFD_VA,
        win32k_host::FTFD_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, _expdir, len)) => {
            let patched = win32k_host::patch_win32k_ftfd_imports(win32k_host::FTFD_VA);
            print_str(b"[win32k-svc] hosted ftfd.dll: entry_rva=0x");
            print_hex(entry);
            print_str(b" len=0x");
            print_hex(len);
            print_str(b" win32k FT_* IAT patched=");
            print_u64(patched as u64);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] ftfd load failed\n"),
    }
}

/// Host framebuf.dll (the display driver) into win32k's VSpace + map the BOOTBOOT framebuffer into
/// win32k. win32k loads framebuf DYNAMICALLY (like dxg) via ZwSetSystemInformation when it enables the
/// display device (co_IntInitializeDesktopGraphics → PDEVOBJ_Create → LDEVOBJ_pLoadDriver("framebuf")),
/// so pre-load it + record it for the s_zw_set_system_information trampoline. framebuf's video-miniport
/// IOCTLs (DrvEnablePDEV/DrvEnableSurface) are serviced by the patched EngDeviceIoControl intercept,
/// which returns WIN32K_FB_VA — the fb frames mapped here.
unsafe fn load_framebuf_driver(host_pml4: u64) {
    let sz = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x8C) as *const u32);
    if sz == 0 {
        print_str(b"[win32k-svc] framebuf.dll not staged - display gate will fail\n");
        return;
    }
    match load_one_driver(
        FRAMEBUFBUF_VADDR,
        win32k_host::FRAMEBUF_VA,
        win32k_host::FRAMEBUF_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, expdir, len)) => {
            win32k_host::record_framebuf(entry, expdir, len);
            print_str(b"[win32k-svc] hosted framebuf.dll: entry_rva=0x");
            print_hex(entry);
            print_str(b" (DrvEnableDriver) len=0x");
            print_hex(len);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] framebuf load failed\n"),
    }
    // Map the BOOTBOOT framebuffer (Phase-0a fb device frames) into win32k at WIN32K_FB_VA, RW.
    let base = FB_FRAME_BASE.load(Ordering::Relaxed);
    let count = FB_FRAME_COUNT.load(Ordering::Relaxed);
    if base != 0 && count != 0 {
        for p in 0..(count + 511) / 512 {
            let pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
            let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_FB_VA + p * 0x20_0000, host_pml4);
        }
        for i in 0..count {
            let _ = page_map(copy_cap(base + i), win32k_host::WIN32K_FB_VA + i * 0x1000, RW_NX, host_pml4);
        }
        print_str(b"[win32k-svc] mapped BOOTBOOT framebuffer into win32k: ");
        print_u64(count);
        print_str(b" frames @ WIN32K_FB_VA=0x");
        print_hex((win32k_host::WIN32K_FB_VA >> 32) as u32);
        print_hex(win32k_host::WIN32K_FB_VA as u32);
        print_str(b"\n");
    }
}

/// Dispatch one win32k SSN (>= 0x1000) into the parked win32k component and run its fault-service
/// loop until the handler completes (Milestone B). PRECONDITION: the component is blocked in its
/// dispatch `seL4_Call` on `w_fault` (the executive has received the Call but not yet replied). We
/// fill the request in the shared page, reply (the Call returns → the component runs the handler),
/// then demand-page the handler's faults until the component issues its NEXT dispatch Call = "done".
/// Returns `(status, ok)`; `ok=false` on a wall (null deref / W^X / demand cap / unexpected fault).
unsafe fn win32k_dispatch(ssn: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> (i32, bool) {
    let w_fault = WIN32K_FAULT_EP.load(Ordering::Relaxed);
    let host_pml4 = WIN32K_HOST_PML4.load(Ordering::Relaxed);
    if w_fault == 0 {
        return (0xC000_0001u32 as i32, false);
    }
    // Attach win32k's client window to the CURRENT dispatch client (KeStackAttachProcess). If this is
    // a different client than last time, the previous client's leaf pages are Unmapped so the new
    // client's identical VAs re-fault to THIS client's frames (per-client cross-AS client memory).
    let client_pi = W32_CLIENT_PI.load(Ordering::Relaxed);
    w32_client_attach(client_pi);
    let sh = win32k_host::WIN32K_SHARED_VADDR;
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_SSN) as *mut u64, ssn);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_A0) as *mut u64, a0);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_A1) as *mut u64, a1);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_A2) as *mut u64, a2);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_A3) as *mut u64, a3);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_STATUS) as *mut i32, 0);
    let code_va = win32k_host::WIN32K_CODE_VA;
    // The desktop-graphics init (co_IntInitializeDesktopGraphics) is a deep chain that demand-maps
    // many pages and trips many checked-build asserts; allow generous headroom (still bounded).
    const DEMAND_CAP: u64 = 8192;
    let mut demand = 0u64;
    let mut skips = 0u64; // int-0x2c asserts skipped (bounded, so a looping assert still walls)
    // Fix (A): WAKE the parked component with a PLAIN Send (it is blocked in `recv_req`, waiting for
    // a request). A plain Send does NOT touch the executive's single `reply_to` slot, so a csrss
    // syscall reply in flight on this same executive thread is preserved (the root-caused nesting
    // bug). The component reads SH_REQ_* + runs the handler on its own scheduling context.
    //
    // Fix (B): the component's demand-page FAULTS are delivered as Calls to `w_fault`; recv them
    // with REPLY_W32 registered (r12) so the kernel binds win32k to REPLY_W32 (finish_call) INSTEAD
    // of relying on `reply_to`. We then resume win32k via Send-on-REPLY_W32 (decode_reply). This
    // leaves REPLY_MAIN's binding to the outer csrss caller intact across win32k faults — removing
    // the (A) caveat where a nested faulting SSN clobbered `reply_to`. The DONE signal is still a
    // plain Send (no cap), distinguished by its label. cptr 0 (pre-retype) falls back to reply_to.
    let rw = REPLY_W32_SLOT.load(Ordering::Relaxed);
    ep_send(w_fault, win32k_host::W32_DISPATCH_LABEL);
    let (_b0, mut mi, mut m0, mut m1, mut m2, mut m3) = if rw != 0 {
        recv_full_r12(w_fault, rw)
    } else {
        ep_recv_full(w_fault)
    };
    loop {
        let label = mi >> 12;
        if label == 6 {
            let addr = m1;
            let in_image =
                addr >= code_va && addr < code_va + win32k_host::WIN32K_IMAGE_FRAMES * 0x1000;
            // A foreign CLIENT pointer: the handler dereferenced a csrss/user32/gdi32/winlogon USER
            // pointer directly. Rather than zero-fill (WRONG data), SHARE the current client's OWN
            // frame for that page into win32k at the same VA — the authentic model where win32k
            // dereferences the calling process's user address space. Detection: (a) anything below
            // 0x100_.. is a client DLL/heap/anon pointer (win32k's own regions are all PML4[2] >=
            // 0x100_0680_0000); (b) a HIGH client pointer — the hosted-process STACK lives at
            // STACK_BASE=0x100_105C_0000 (PML4[2], ABOVE win32k's own regions), so an address-range
            // test alone misses a stack-built OBJECT_ATTRIBUTES; identify it by the per-client frame
            // table (win32k's OWN demand pages — session/pool/past-image — are never recorded there).
            let page = addr & !0xFFF;
            let foreign = addr < 0x0000_0100_0000_0000
                || (addr >= 0x10000 && !in_image && csrss_frame_get(client_pi, page) != 0);
            if demand < 60 {
                print_str(b"[w32disp] fault #");
                print_u64(demand);
                print_str(b" ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" RVA=0x");
                print_hex(m0.wrapping_sub(code_va) as u32);
                print_str(b" addr=0x");
                print_hex((addr >> 32) as u32);
                print_hex(addr as u32);
                if foreign {
                    print_str(b" (client ptr - sharing csrss frame)");
                }
                print_str(b"\n");
            }
            // Hard walls: a genuine null/low deref, a W^X write into the RX image, or the demand cap.
            if addr < 0x10000 || in_image || demand >= DEMAND_CAP {
                win32k_dispatch_backtrace();
                return (0xC000_0001u32 as i32, false);
            }
            if foreign {
                // Map the CALLER's (csrss's) own frame for this page into win32k at the identical VA.
                // False = the page isn't backed by a recorded csrss frame (win32k would read garbage,
                // or it's a PML4[2] client range needing per-SSN marshaling) — stop cleanly.
                if !map_csrss_page_into_win32k(page, client_pi, host_pml4) {
                    return (0xC000_0001u32 as i32, false);
                }
            } else {
                // A win32k-own demand-pageable page (past the image tail / session arena / the
                // demand-mapped pool): ensure its page table exists (SYS_SEND page_map can't report a
                // missing-PT error to drive a retry), then zero-fill.
                ensure_w32_client_paging(page, host_pml4);
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, host_pml4);
            }
            demand += 1;
            // Fix (B): resume win32k via its bound reply cap (Send-on-REPLY_W32 -> decode_reply ->
            // apply_fault_reply for the VMFault, length 0) then recv the next fault/DONE re-binding
            // REPLY_W32. Falls back to the legacy reply_recv on the single `reply_to` if REPLY_W32
            // wasn't retyped.
            let (nmi, nm0, nm1) = if rw != 0 {
                send_on_reply(rw, 0, 0, 0, 0, 0);
                let (_b, nmi, nm0, nm1, _, _) = recv_full_r12(w_fault, rw);
                (nmi, nm0, nm1)
            } else {
                let (nmi, nm0, nm1, _, _) = reply_recv_full(w_fault, 0, 0, 0, 0, 0);
                (nmi, nm0, nm1)
            };
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            continue;
        }
        if label == win32k_host::W32_DISPATCH_LABEL {
            // The component sent its DONE signal (a plain Send) — handler finished. Read back the
            // status. The component then loops to `recv_req` (blocked), ready for the next dispatch.
            let _ = m0;
            let status = core::ptr::read_volatile((sh + win32k_host::SH_REQ_STATUS) as *const i32);
            return (status, true);
        }
        if label == 3 {
            // UserException — almost always a checked-build `int 0x2c` NT_ASSERT
            // (DbgRaiseAssertionFailure). Verify the faulting instruction (CD 2C) via the executive's
            // RW view of win32k's image at the SAME VA, then SKIP it (resume at IP+2), treating the
            // assert as ignored — like a release build. Our single-threaded lock/thread stubs trip
            // lock-ownership + context asserts that a real multi-threaded kernel wouldn't; the
            // underlying operation is fine. m0 = FaultIP.
            let ip = m0;
            let in_win32k = ip >= code_va && ip < code_va + win32k_host::WIN32K_IMAGE_FRAMES * 0x1000;
            let is_int2c = in_win32k
                && core::ptr::read_volatile(ip as *const u8) == 0xCD
                && core::ptr::read_volatile((ip + 1) as *const u8) == 0x2C;
            if is_int2c && rw != 0 && skips < 4000 {
                if skips < 40 {
                    print_str(b"[w32disp] skip int 0x2c assert @ RVA 0x");
                    print_hex(ip.wrapping_sub(code_va) as u32);
                    print_str(b"\n");
                }
                skips += 1;
                send_on_reply(rw, 1, ip + 2, 0, 0, 0); // label 0, len 1, MR0 = resume FaultIP (past CD 2C)
                let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(w_fault, rw);
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
        }
        // Any other fault (a real wall inside the handler) — fail. Diagnose: label + fault IP/addr
        // (m0=IP, m1=addr for exceptions; for UnknownSyscall m0=SSN). RVA relative to code / dxg.
        print_str(b"[w32disp] WALL label=");
        print_u64(label);
        print_str(b" m0=0x");
        print_hex((m0 >> 32) as u32);
        print_hex(m0 as u32);
        print_str(b" RVA=0x");
        print_hex(m0.wrapping_sub(code_va) as u32);
        print_str(b" dxgRVA=0x");
        print_hex(m0.wrapping_sub(win32k_host::DXG_VA) as u32);
        print_str(b" m1=0x");
        print_hex((m1 >> 32) as u32);
        print_hex(m1 as u32);
        // For a UserException (label 3): m2=FLAGS, m3=exception Number (#UD=6, #NM=7, #GP=13, #AC=17).
        print_str(b" exc#=");
        print_u64(m3);
        print_str(b" flags=0x");
        print_hex(m2 as u32);
        print_str(b"\n");
        return (0xC000_0001u32 as i32, false);
    }
}

/// `seL4_TCB_ReadRegisters` (label 2, legacy length-0 form) → the target's `(rip, rsp, rax)`.
unsafe fn tcb_read_rsp(tcb: u64) -> u64 {
    let rsp: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") 2u64 << 12 => _, // TCBReadRegisters, length 0
        lateout("r10") _,             // MR0 = rip
        lateout("r8") rsp,            // MR1 = rsp
        lateout("r9") _,              // MR2 = rax
        lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rsp
}

/// Print the win32k call chain (return-address RVAs, deepest first) at a `win32k_dispatch` wall.
/// Mirrors win32k's ACTIVE stack (fault-time RSP .. stack_top) into the executive's own VSpace and
/// scans it for return addresses in win32k's image — same technique as the DriverEntry-path backtrace.
unsafe fn win32k_dispatch_backtrace() {
    let ss = WIN32K_STACK_SLOT.load(Ordering::Relaxed);
    let sf = WIN32K_STACK_FRAMES.load(Ordering::Relaxed);
    let tcb = WIN32K_TCB.load(Ordering::Relaxed);
    if ss == 0 || sf == 0 || tcb == 0 {
        return;
    }
    let mirror = 0x0000_0100_0732_0000u64;
    if WIN32K_DISP_BT_PT.load(Ordering::Relaxed) == 0 {
        let spt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
        let _ = paging_struct_map(spt, LBL_X86_PAGE_TABLE_MAP, mirror, CAP_INIT_THREAD_VSPACE);
        for i in 0..sf {
            let _ = page_map(copy_cap(ss + i), mirror + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
        WIN32K_DISP_BT_PT.store(1, Ordering::Relaxed);
    }
    let rsp = tcb_read_rsp(tcb);
    let sbase = win32k_host::WIN32K_STACK_VADDR;
    let stack_top = sbase + sf * 0x1000;
    let start = if rsp >= sbase && rsp < stack_top { rsp } else { sbase };
    let code_va = win32k_host::WIN32K_CODE_VA;
    let lo = code_va;
    let hi = code_va + win32k_host::WIN32K_IMAGE_FRAMES * 0x1000;
    print_str(b"[w32disp] backtrace rsp=0x");
    print_hex((rsp >> 32) as u32);
    print_hex(rsp as u32);
    print_str(b"\n");
    // RAW stack window from fault rsp: each qword annotated with its win32k RVA if it lands in the
    // image (a return address). RtlpCheckListEntry (0x24c50) did `sub rsp,0x28`, so its own return
    // address is at [rsp+0x28] = the exact InsertXxxList wrapper caller — read that precisely.
    if start >= sbase && start + 0x120 <= stack_top {
        let mut off = 0u64;
        while off < 0x120 {
            let va = start + off;
            let v = core::ptr::read_volatile((mirror + (va - sbase)) as *const u64);
            if v >= lo && v < hi {
                print_str(b"  [rsp+0x");
                print_hex(off as u32);
                print_str(b"] rva=0x");
                print_hex(v.wrapping_sub(code_va) as u32);
                print_str(b"\n");
            }
            off += 8;
        }
    }
}

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

/// Like `dir_find` but matches EITHER the 8.3 short entry OR the reassembled long (LFN) name of
/// `comp` — case-insensitive ASCII — so names WITHOUT a clean 8.3 alias (e.g. `advapi32_vista.dll`,
/// `windowscodecs.dll`) resolve by their real name. Returns `(first_cluster, size, attr)`. VFAT
/// stores 0-N LFN entries (attr 0x0F) physically BEFORE the 8.3 entry, each carrying 13 UTF-16
/// chars keyed by a 1-based sequence ordinal; this reassembles them (ASCII only — sufficient for
/// the ReactOS tree) and compares to `comp`. When an entry has an LFN, only the long name is
/// matched (the 8.3 is a mangled alias); otherwise the 8.3 short name is matched (old behavior).
unsafe fn dir_find_lfn(fs: &Fat32, dir_cluster: u32, comp: &[u8]) -> Option<(u32, u32, u8)> {
    let short = name_to_83(comp);
    // Lowercase the target (ASCII) once.
    let mut want = [0u8; 256];
    let want_len = if comp.len() < 256 { comp.len() } else { 256 };
    let mut i = 0;
    while i < want_len {
        let c = comp[i];
        want[i] = if c.is_ascii_uppercase() { c + 32 } else { c };
        i += 1;
    }
    // Does `comp` fit a clean 8.3 (base<=8, ext<=3, at most one dot)? If NOT, the 8.3 fallback
    // is UNSAFE: `name_to_83` truncates (e.g. "kernel32_vista.dll" -> "KERNEL32DLL") and would
    // COLLIDE with a different file's short entry ("kernel32.dll"). So the short-name match is
    // gated on `fits_83`; a long name matches ONLY via its reassembled LFN.
    let (mut base_len, mut ext_len, mut dots) = (0usize, 0usize, 0usize);
    for &c in comp {
        if c == b'.' {
            dots += 1;
        } else if dots >= 1 {
            ext_len += 1;
        } else {
            base_len += 1;
        }
    }
    let fits_83 = dots <= 1 && base_len >= 1 && base_len <= 8 && ext_len <= 3;
    let lfn_off: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    let mut lfn = [0u8; 260]; // reassembled long name (lowercased ASCII)
    let mut term: Option<usize> = None; // index of the 0x0000 terminator, if seen
    let mut hi_ord = 0usize;
    let mut have_lfn = false;
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
                    have_lfn = false; term = None; hi_ord = 0; // deleted — drop any pending LFN
                    continue;
                }
                let attr = *ent.add(0x0B);
                if attr == 0x0F {
                    // LFN fragment: place its 13 chars at [(ord-1)*13 ..].
                    let ord = (first & 0x1F) as usize;
                    if ord >= 1 && ord <= 20 {
                        have_lfn = true;
                        if ord > hi_ord { hi_ord = ord; }
                        let base = (ord - 1) * 13;
                        let mut k = 0;
                        while k < 13 {
                            let o = lfn_off[k];
                            let lo = *ent.add(o);
                            let hi = *ent.add(o + 1);
                            let idx = base + k;
                            if idx < 260 {
                                if lo == 0 && hi == 0 {
                                    if term.is_none() { term = Some(idx); }
                                } else if !(lo == 0xFF && hi == 0xFF) {
                                    lfn[idx] = if hi == 0 {
                                        if lo.is_ascii_uppercase() { lo + 32 } else { lo }
                                    } else {
                                        0xFF // non-ASCII — won't match an ASCII target
                                    };
                                }
                            }
                            k += 1;
                        }
                    }
                    continue;
                }
                if (attr & 0x08) != 0 {
                    have_lfn = false; term = None; hi_ord = 0; // volume label
                    continue;
                }
                // 8.3 entry: decide match against the long name (if any) or the short name.
                let matched = if have_lfn {
                    let len = term.unwrap_or(hi_ord * 13);
                    len == want_len && {
                        let mut m = true;
                        let mut j = 0;
                        while j < len {
                            if lfn[j] != want[j] { m = false; break; }
                            j += 1;
                        }
                        m
                    }
                } else {
                    fits_83 && {
                        let mut m = true;
                        let mut j = 0;
                        while j < 11 {
                            if *ent.add(j) != short[j] { m = false; break; }
                            j += 1;
                        }
                        m
                    }
                };
                if matched {
                    let hi = core::ptr::read_unaligned(ent.add(0x14) as *const u16) as u32;
                    let lo = core::ptr::read_unaligned(ent.add(0x1A) as *const u16) as u32;
                    let size = core::ptr::read_unaligned(ent.add(0x1C) as *const u32);
                    return Some(((hi << 16) | lo, size, attr));
                }
                have_lfn = false; term = None; hi_ord = 0;
            }
        }
        cl = fat_next(fs, cl);
    }
    None
}

/// Convert one path component (e.g. `b"ntdll.dll"`) to a space-padded 8.3 FAT short name.
/// ASCII-uppercases; splits on the LAST '.' (a leading dot is treated as part of the base);
/// truncates base to 8 and extension to 3. Good enough for the ReactOS install tree, whose
/// names (`reactos`, `system32`, `ntdll.dll`, …) all have clean 8.3 aliases — verified: mcopy
/// stores the uppercased 8.3 short entry (`REACTOS`, `SYSTEM32`, `NTDLL   DLL`) alongside an
/// LFN, and `dir_find` matches the short entry (skipping LFN fragments). No `~1` mangling.
fn name_to_83(comp: &[u8]) -> [u8; 11] {
    let mut out = [b' '; 11];
    let upper = |c: u8| if c.is_ascii_lowercase() { c - 32 } else { c };
    // Locate the extension separator = the last '.' that isn't the first char.
    let mut dot: Option<usize> = None;
    let mut i = 0usize;
    while i < comp.len() {
        if comp[i] == b'.' && i != 0 {
            dot = Some(i);
        }
        i += 1;
    }
    let (base_end, ext_start) = match dot {
        Some(d) => (d, d + 1),
        None => (comp.len(), comp.len()),
    };
    let mut j = 0usize;
    while j < 8 && j < base_end {
        out[j] = upper(comp[j]);
        j += 1;
    }
    let mut k = 0usize;
    while k < 3 && ext_start + k < comp.len() {
        out[8 + k] = upper(comp[ext_start + k]);
        k += 1;
    }
    out
}

/// Resolve a `\`- or `/`-separated PATH (e.g. `b"reactos\\system32\\ntdll.dll"`) from the
/// volume root, walking each component with `dir_find`. Returns `(first_cluster, size)` of the
/// final file, or `None` if any component is missing. 8.3 short names only (no LFN reassembly)
/// — sufficient for the real ReactOS tree, whose names carry clean 8.3 aliases. Each non-final
/// component must be a directory (FAT attr bit 0x10). This is the FS-backed-by-path primitive:
/// the seam a full `\SystemRoot\system32\X` loader generalizes (see P7).
unsafe fn fat_open_path(fs: &Fat32, path: &[u8]) -> Option<(u32, u32)> {
    let mut cur = fs.root_cl;
    let mut start = 0usize;
    let mut i = 0usize;
    let mut result: Option<(u32, u32)> = None;
    while i <= path.len() {
        let is_sep = i == path.len() || path[i] == b'\\' || path[i] == b'/';
        if is_sep {
            if i > start {
                let (cl, sz, attr) = dir_find_lfn(fs, cur, &path[start..i])?;
                if i == path.len() {
                    result = Some((cl, sz)); // final component = the file
                } else {
                    if (attr & 0x10) == 0 {
                        return None; // intermediate must be a directory
                    }
                    cur = cl;
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    result
}

/// Open `\reactos\system32\<leaf>` from the volume (the common ReactOS binary location) via the
/// LFN-aware path walk. Returns `(first_cluster, size)`. Builds the path in a stack buffer (the
/// storage host has no allocator). `leaf` may itself contain `\` for a sub-dir (e.g.
/// `b"drivers\\dxg.sys"`, `b"config\\system"`).
unsafe fn open_sys32(fs: &Fat32, leaf: &[u8]) -> Option<(u32, u32)> {
    let mut path = [0u8; 160];
    let mut n = 0usize;
    for &c in b"reactos\\system32\\" {
        path[n] = c;
        n += 1;
    }
    let mut i = 0;
    while i < leaf.len() && n < path.len() {
        path[n] = leaf[i];
        n += 1;
        i += 1;
    }
    fat_open_path(fs, &path[..n])
}

// --- P7-A: EXECUTIVE-SIDE FS-BY-PATH LOADER (generic, zero-per-binary) ---------------------------
// After the isolated storage host reports and PARKS, the executive drives the SAME AHCI HBA itself
// (it owns the BAR cap at AHCI_VADDR + the DMA frame cap + the VT-d IO mapping at AHCI_IOVA) to
// resolve ANY \reactos path → bytes on demand. This is the mechanism that retires the fixed
// per-binary staging buffers: instead of the host batch-reading a hardcoded file list into ~15
// fixed dual-mapped buffers, the executive reads each binary BY PATH into a dynamically pooled
// buffer at load time. The demand-fault router + nt-dll-registry consume it UNCHANGED — they operate
// on PeFile byte-slices, which now point into the pool. Adding a P5 binary (services.exe/lsass/
// explorer) then needs NO new buffer/offset/fake: it just resolves from the FS.

/// The executive's own live FAT32 handle, mounted after the storage host parks (bound to the
/// executive's AHCI BAR + DMA-frame mappings). `None` until mounted. Read-only.
static mut EXEC_FS: Option<Fat32> = None;

/// Copy of the executive's mounted FAT32 handle (Fat32 is Copy), or None if not yet mounted.
/// Read via a raw pointer to avoid the static_mut_refs lint (single-threaded executive).
unsafe fn exec_fs() -> Option<Fat32> {
    core::ptr::read(core::ptr::addr_of!(EXEC_FS))
}

/// Load `path` (root-relative) from the executive's live FS into the pool and PE32+-parse it — the
/// generic replacement for a per-binary staging block. Returns `(Some(pe), pool_va)` on success (the
/// bytes stay resident in the pool for the demand-fault router), or `(None, 0)` so the caller can
/// fall back to a fixed staging buffer during the hybrid migration. `name` is for the boot log.
unsafe fn load_dll_from_fs(
    path: &[u8],
    name: &[u8],
) -> (Option<nt_pe_loader::PeFile<'static>>, u64) {
    if let Some(fs) = exec_fs() {
        if let Some((va, sz)) = load_file_to_pool(&fs, path) {
            let bytes: &'static [u8] = core::slice::from_raw_parts(va as *const u8, sz as usize);
            if let Ok(pe) = nt_pe_loader::PeFile::parse(bytes) {
                print_str(b"[ntos-exec] FS-by-path ");
                print_str(name);
                print_str(b": ");
                print_u64(sz as u64);
                print_str(b" bytes, PE32+ @pool=0x");
                print_hex((va >> 32) as u32);
                print_hex(va as u32);
                print_str(b"\n");
                return (Some(pe), va);
            }
            print_str(b"[ntos-exec] FS-by-path ");
            print_str(name);
            print_str(b": PARSE FAILED (fallback to staged buffer)\n");
        }
    }
    (None, 0)
}

/// Hybrid per-DLL loader: on the LIVE run (`live`), source a registry DLL BY PATH from the FS pool;
/// on any FS miss (or the demo run) fall back to its fixed staging buffer. Returns `(pe, buf_va)`
/// where `buf_va` is the pool VA on an FS hit else `fb_va` — so `dll_buf_va[i] = buf_va` ALWAYS holds
/// a valid backing VA (never 0) for relocation + the demand-fault router, exactly like the proven
/// gdi32/userenv/mpr per-block migration. `fb_off` = the STORAGE_SHARED size offset of the fixed
/// buffer. Centralizing the fixed-buffer arm here means retirement later = delete it in ONE place.
unsafe fn load_dll_hybrid(
    live: bool,
    path: &[u8],
    name: &[u8],
    fb_va: u64,
    fb_off: u64,
) -> (Option<nt_pe_loader::PeFile<'static>>, u64) {
    if !live {
        return (None, fb_va);
    }
    let (fs_pe, fs_va) = load_dll_from_fs(path, name);
    if fs_va != 0 {
        return (fs_pe, fs_va);
    }
    let sz = core::ptr::read_volatile((STORAGE_SHARED_VADDR + fb_off) as *const u32) as usize;
    if sz > 0 {
        let bytes: &'static [u8] = core::slice::from_raw_parts(fb_va as *const u8, sz);
        if let Ok(pe) = nt_pe_loader::PeFile::parse(bytes) {
            print_str(b"[ntos-exec] staged ");
            print_str(name);
            print_str(b" (fixed buffer)\n");
            return (Some(pe), fb_va);
        }
        print_str(b"[ntos-exec] staged ");
        print_str(name);
        print_str(b": PARSE FAILED\n");
    }
    (None, fb_va)
}

/// Mount the FAT32 volume bound to the given AHCI/DMA mappings: read sector 0, parse the BPB.
/// Same BPB layout `storage_probe` parses; factored so both the host and the executive can mount.
unsafe fn fat32_mount(ahci_vaddr: u64, dma_vaddr: u64, dma_paddr: u64) -> Option<Fat32> {
    let _ = ahci_read_sector(ahci_vaddr, dma_vaddr, dma_paddr, 0);
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
    if bps == 512 && spc >= 1 && is_fat32 {
        Some(Fat32 {
            ahci_vaddr,
            dma_vaddr,
            dma_paddr,
            bps,
            spc,
            fat_start: reserved,
            data_start: reserved + nfats * spf32,
            root_cl,
        })
    } else {
        None
    }
}

/// The executive's on-demand file-buffer POOL: a fresh VA region whose frames are allocated + mapped
/// (into the executive's own VSpace) on demand, one file at a time. Replaces the ~15 fixed staging
/// buffers with a single bump-allocated arena. Each loaded PE's bytes persist here for the run so the
/// demand-fault router can fill hosted-process pages from them (same lifetime as the old buffers).
pub const POOL_VADDR: u64 = 0x0000_0100_1500_0000;
pub const POOL_PTS: u64 = 24; // 48 MiB (24 * 2 MiB) — headroom for the whole stack + P5 binaries
static POOL_NEXT: AtomicU64 = AtomicU64::new(0);
static POOL_INITED: AtomicU64 = AtomicU64::new(0);

/// Reserve the pool's page tables in the executive's VSpace (once). Idempotent.
unsafe fn pool_init() {
    if POOL_INITED.swap(1, Ordering::Relaxed) != 0 {
        return;
    }
    for p in 0..POOL_PTS {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            POOL_VADDR + p * 0x20_0000,
            CAP_INIT_THREAD_VSPACE,
        );
    }
}

/// Allocate `nbytes` (page-rounded) of pool space, mapping fresh RW frames into the executive's
/// VSpace. Returns the base VA, or None if the pool is exhausted. Bump-only (no free) — pool buffers
/// live for the whole run, exactly like the fixed buffers they replace.
unsafe fn pool_alloc(nbytes: u32) -> Option<u64> {
    pool_init();
    let pages = ((nbytes as u64) + 0xFFF) / 0x1000;
    let off = POOL_NEXT.fetch_add(pages * 0x1000, Ordering::Relaxed);
    if off + pages * 0x1000 > POOL_PTS * 0x20_0000 {
        return None;
    }
    let base = POOL_VADDR + off;
    for i in 0..pages {
        let f = alloc_frame();
        let _ = page_map(f, base + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    Some(base)
}

/// Resolve `path` (root-relative, e.g. `b"reactos\\system32\\version.dll"`) on the executive's live
/// volume, read the WHOLE file into a fresh pool buffer, and return `(va, size)`. The bytes stay
/// resident for the run so a PeFile parsed over them + the demand-fault router keep working. This is
/// the single call the per-binary staging blocks collapse into: open path → bytes.
unsafe fn load_file_to_pool(fs: &Fat32, path: &[u8]) -> Option<(u64, u32)> {
    let (cluster, size) = fat_open_path(fs, path)?;
    if size == 0 {
        return None;
    }
    let va = pool_alloc(size)?;
    let read = fat_read_file(fs, cluster, size, va);
    if read < size {
        return None;
    }
    Some((va, size))
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
    srvbuf_dest: u64,
    win32buf_dest: u64,
    nls_ansi_dest: u64,
    nls_oem_dest: u64,
    nls_case_dest: u64,
    nls20127_dest: u64,
    win32kbuf_dest: u64,
    winlogonbuf_dest: u64,
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
        // P7-A: source every ReactOS binary BY PATH from the real \reactos\system32 tree (LFN-aware
        // fat_open_path), NOT from the flat root ::NAME files. Each read tries the real path first
        // and falls back to the flat 8.3 name so the boot stays green during the migration; the
        // hit/miss counters below prove whether the WHOLE stack came from the FS (miss==0 =>
        // verdict 0x200). `open_or_sys32!`/`open_or_path!` return dir_find's (cluster,size,attr).
        let mut fs_hits = 0u32; // files resolved BY PATH from \reactos\...
        let mut fs_miss = 0u32; // files that fell back to the flat ::NAME
        macro_rules! open_or_sys32 {
            ($leaf:expr, $short:expr) => {{
                match open_sys32(&fs, $leaf) {
                    Some((c, s)) => { fs_hits += 1; Some((c, s, 0u8)) }
                    None => { let r = dir_find(&fs, fs.root_cl, $short); if r.is_some() { fs_miss += 1; } r }
                }
            }};
        }
        macro_rules! open_or_path {
            ($path:expr, $short:expr) => {{
                match fat_open_path(&fs, $path) {
                    Some((c, s)) => { fs_hits += 1; Some((c, s, 0u8)) }
                    None => { let r = dir_find(&fs, fs.root_cl, $short); if r.is_some() { fs_miss += 1; } r }
                }
            }};
        }
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
        if let Some((smss_cl, ssize, _)) = open_or_sys32!(b"smss.exe", b"SMSS    EXE") {
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
        // csrss.exe — the Win32 subsystem launcher smss starts. Staged into the FILEBUF tail (past
        // smss), its size reported at STORAGE_SHARED+0x3c. Only if it fits clear of smss.
        if let Some((cc, csz, _)) = open_or_sys32!(b"csrss.exe", b"CSRSS   EXE") {
            let cap = CSRSRV_FILEBUF_OFFSET as u32 - CSRSS_FILEBUF_OFFSET as u32;
            if csz > 0 && csz <= cap && smss_size <= CSRSS_FILEBUF_OFFSET as u32 {
                let got = fat_read_file(&fs, cc, csz, smss_dest + CSRSS_FILEBUF_OFFSET);
                if got == csz {
                    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x3c) as *mut u32, csz);
                }
            }
        }
        // csrsrv.dll — csrss.exe's static-import Server DLL. Staged further into the FILEBUF (past
        // csrss), size at STORAGE_SHARED+0x40. The executive maps it into csrss's VSpace on the DLL
        // load so csrss's imports resolve (else STATUS_DLL_NOT_FOUND).
        if let Some((rc, rsz, _)) = open_or_sys32!(b"csrsrv.dll", b"CSRSRV  DLL") {
            let cap = (FILEBUF_FRAMES * 0x1000) as u32 - CSRSRV_FILEBUF_OFFSET as u32;
            if rsz > 0 && rsz <= cap {
                let got = fat_read_file(&fs, rc, rsz, smss_dest + CSRSRV_FILEBUF_OFFSET);
                if got == rsz {
                    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x40) as *mut u32, rsz);
                    print_str(b"[storage-host] CSRSRV.DLL size=");
                    print_u64(rsz as u64);
                    print_str(b"\n");
                }
            }
        }
        // basesrv.dll — csrss's ServerDll=basesrv. Staged into the SRVBUF (offset 0), size at
        // STORAGE_SHARED+0x44; the executive parses+maps it into csrss's VSpace on the DLL load.
        if let Some((c, sz, _)) = open_or_sys32!(b"basesrv.dll", b"BASESRV DLL") {
            if sz > 0 && sz <= (WINSRV_SRVBUF_OFFSET as u32) {
                let got = fat_read_file(&fs, c, sz, srvbuf_dest + BASESRV_SRVBUF_OFFSET);
                if got == sz {
                    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x44) as *mut u32, sz);
                    print_str(b"[storage-host] BASESRV.DLL size=");
                    print_u64(sz as u64);
                    print_str(b"\n");
                }
            }
        }
        // winsrv.dll — csrss's ServerDll=winsrv. Staged into the SRVBUF (past basesrv, +0x10000),
        // size at STORAGE_SHARED+0x48; the executive parses+maps it into csrss's VSpace.
        if let Some((c, sz, _)) = open_or_sys32!(b"winsrv.dll", b"WINSRV  DLL") {
            if sz > 0 && sz <= ((SRVBUF_FRAMES * 0x1000) as u32 - WINSRV_SRVBUF_OFFSET as u32) {
                let got = fat_read_file(&fs, c, sz, srvbuf_dest + WINSRV_SRVBUF_OFFSET);
                if got == sz {
                    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x48) as *mut u32, sz);
                    print_str(b"[storage-host] WINSRV.DLL size=");
                    print_u64(sz as u64);
                    print_str(b"\n");
                }
            }
        }
        // The Win32 client stack (kernel32/user32/gdi32) + winsrv's transitive import closure
        // (rpcrt4/msvcrt/advapi32/ws2_32 + the vista forwarders + ws2help) — staged into the WIN32BUF
        // (its own 8 MiB region), sizes reported at STORAGE_SHARED +0x4c..+0x70.
        for (leaf, short, off, shoff, cap) in [
            (b"kernel32.dll".as_slice(), b"KERNEL32DLL", KERNEL32_WIN32BUF_OFFSET, 0x4cu64, USER32_WIN32BUF_OFFSET),
            (b"user32.dll".as_slice(), b"USER32  DLL", USER32_WIN32BUF_OFFSET, 0x50, GDI32_WIN32BUF_OFFSET - USER32_WIN32BUF_OFFSET),
            (b"gdi32.dll".as_slice(), b"GDI32   DLL", GDI32_WIN32BUF_OFFSET, 0x54, RPCRT4_WIN32BUF_OFFSET - GDI32_WIN32BUF_OFFSET),
            (b"rpcrt4.dll".as_slice(), b"RPCRT4  DLL", RPCRT4_WIN32BUF_OFFSET, 0x58, MSVCRT_WIN32BUF_OFFSET - RPCRT4_WIN32BUF_OFFSET),
            (b"msvcrt.dll".as_slice(), b"MSVCRT  DLL", MSVCRT_WIN32BUF_OFFSET, 0x5c, ADVAPI32_WIN32BUF_OFFSET - MSVCRT_WIN32BUF_OFFSET),
            (b"advapi32.dll".as_slice(), b"ADVAPI32DLL", ADVAPI32_WIN32BUF_OFFSET, 0x60, WS2_32_WIN32BUF_OFFSET - ADVAPI32_WIN32BUF_OFFSET),
            (b"ws2_32.dll".as_slice(), b"WS2_32  DLL", WS2_32_WIN32BUF_OFFSET, 0x64, KERNEL32_VISTA_WIN32BUF_OFFSET - WS2_32_WIN32BUF_OFFSET),
            (b"kernel32_vista.dll".as_slice(), b"K32VISTADLL", KERNEL32_VISTA_WIN32BUF_OFFSET, 0x68, ADVAPI32_VISTA_WIN32BUF_OFFSET - KERNEL32_VISTA_WIN32BUF_OFFSET),
            (b"advapi32_vista.dll".as_slice(), b"A32VISTADLL", ADVAPI32_VISTA_WIN32BUF_OFFSET, 0x6c, WS2HELP_WIN32BUF_OFFSET - ADVAPI32_VISTA_WIN32BUF_OFFSET),
            (b"ws2help.dll".as_slice(), b"WS2HELP DLL", WS2HELP_WIN32BUF_OFFSET, 0x70, NTDLL_VISTA_WIN32BUF_OFFSET - WS2HELP_WIN32BUF_OFFSET),
            (b"ntdll_vista.dll".as_slice(), b"NTDLLVISDLL", NTDLL_VISTA_WIN32BUF_OFFSET, 0x78, USERENV_WIN32BUF_OFFSET - NTDLL_VISTA_WIN32BUF_OFFSET),
            // winlogon.exe's two extra static imports (the rest of its stack is shared with csrss).
            (b"userenv.dll".as_slice(), b"USERENV DLL", USERENV_WIN32BUF_OFFSET, 0x98, MPR_WIN32BUF_OFFSET - USERENV_WIN32BUF_OFFSET),
            (b"mpr.dll".as_slice(), b"MPR     DLL", MPR_WIN32BUF_OFFSET, 0x9c, WIN32BUF_FRAMES * 0x1000 - MPR_WIN32BUF_OFFSET),
        ] {
            if let Some((c, sz, _)) = open_or_sys32!(leaf, short) {
                if sz > 0 && (sz as u64) <= cap {
                    let got = fat_read_file(&fs, c, sz, win32buf_dest + off);
                    if got == sz {
                        core::ptr::write_volatile((STORAGE_SHARED_VADDR + shoff) as *mut u32, sz);
                        print_str(b"[storage-host] ");
                        for &ch in leaf { debug_put_char(ch); }
                        print_str(b" size="); print_u64(sz as u64); print_str(b"\n");
                    }
                }
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
        // Resolved BY PATH from \reactos\system32\ntdll.dll (verdict bit 0x100 = the by-path spec,
        // set ONLY on a genuine path resolution), falling back to the flat ::NTDLL.DLL. Bytes are
        // identical, so the loaded ntdll is unchanged.
        let ntdll_ent = match open_sys32(&fs, b"ntdll.dll") {
            Some((c, s)) => { fs_hits += 1; verdict |= 0x100; Some((c, s, 0u8)) }
            None => { let r = dir_find(&fs, fs.root_cl, b"NTDLL   DLL"); if r.is_some() { fs_miss += 1; } r }
        };
        if let Some((nc, nsz, _)) = ntdll_ent {
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
        for (leaf, short, dest, frames, out) in [
            (b"c_1252.nls".as_slice(), b"C_1252  NLS", nls_ansi_dest, NLS_ANSI_FRAMES, &mut nls_ansi_size),
            (b"c_437.nls".as_slice(), b"C_437   NLS", nls_oem_dest, NLS_OEM_FRAMES, &mut nls_oem_size),
            (b"l_intl.nls".as_slice(), b"L_INTL  NLS", nls_case_dest, NLS_CASE_FRAMES, &mut nls_case_size),
        ] {
            if let Some((c, sz, _)) = open_or_sys32!(leaf, short) {
                let cap = (frames * 0x1000) as u32;
                let want = if sz < cap { sz } else { cap };
                let got = fat_read_file(&fs, c, want, dest);
                print_str(b"[storage-host] NLS ");
                for &ch in leaf { debug_put_char(ch); }
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
        // c_20127.nls (US-ASCII CP20127) into `nls20127_dest`; report its size at STORAGE_SHARED+0x74
        // (a direct write like the DLL size reads, so it doesn't need a tuple return slot). csrss maps
        // the named section \Nls\NlsSectionCP20127 from this during a DllMain.
        if let Some((c, sz, _)) = open_or_sys32!(b"c_20127.nls", b"C_20127 NLS") {
            let cap = (NLS_20127_FRAMES * 0x1000) as u32;
            let want = if sz < cap { sz } else { cap };
            let got = fat_read_file(&fs, c, want, nls20127_dest);
            print_str(b"[storage-host] NLS C_20127 NLS size=");
            print_u64(sz as u64);
            print_str(b" read=");
            print_u64(got as u64);
            print_str(b"\n");
            if got == want && sz > 0 {
                core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x74) as *mut u32, sz);
            }
        }
        // win32k.sys (~2.1 MiB, PE32+) — the ReactOS GUI subsystem kernel driver. Staged into the
        // WIN32KBUF (its own 2 MiB-aligned window); size reported at STORAGE_SHARED+0x7c so the
        // executive can load it into the isolated win32k-service component (Phase 2b).
        if let Some((c, sz, _)) = open_or_sys32!(b"win32k.sys", b"WIN32K  SYS") {
            let cap = (WIN32KBUF_FRAMES * 0x1000) as u32;
            let want = if sz < cap { sz } else { cap };
            let got = fat_read_file(&fs, c, want, win32kbuf_dest);
            print_str(b"[storage-host] WIN32K.SYS size=");
            print_u64(sz as u64);
            print_str(b" read=");
            print_u64(got as u64);
            print_str(b"\n");
            if got == want && sz > 0 {
                core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x7c) as *mut u32, sz);
            }
        }
        // dxg.sys + dxgthk.sys (DirectX kernel driver + thunk table) into their own buffers; sizes
        // reported at STORAGE_SHARED+0x80 / +0x84 so the executive can host them into win32k.
        for (path, short, dest, cap_frames, off) in [
            (b"reactos\\system32\\drivers\\dxg.sys".as_slice(), b"DXG     SYS", DXGBUF_VADDR, DXGBUF_FRAMES, 0x80u64),
            (b"reactos\\system32\\drivers\\dxgthk.sys".as_slice(), b"DXGTHK  SYS", DXGTHKBUF_VADDR, DXGTHKBUF_FRAMES, 0x84u64),
            (b"reactos\\system32\\ftfd.dll".as_slice(), b"FTFD    DLL", FTFDBUF_VADDR, FTFDBUF_FRAMES, 0x88u64),
            (b"reactos\\system32\\framebuf.dll".as_slice(), b"FRAMEBUFDLL", FRAMEBUFBUF_VADDR, FRAMEBUFBUF_FRAMES, 0x8Cu64),
            (b"reactos\\Fonts\\arial.ttf".as_slice(), b"ARIAL   TTF", win32k_host::FONTBUF_VADDR, win32k_host::FONTBUF_FRAMES, 0x90u64),
        ] {
            if let Some((c, sz, _)) = open_or_path!(path, short) {
                let cap = (cap_frames * 0x1000) as u32;
                let want = if sz < cap { sz } else { cap };
                let got = fat_read_file(&fs, c, want, dest);
                print_str(b"[storage-host] ");
                print_str(short);
                print_str(b" size=");
                print_u64(sz as u64);
                print_str(b" read=");
                print_u64(got as u64);
                print_str(b"\n");
                if got == want && sz > 0 {
                    core::ptr::write_volatile((STORAGE_SHARED_VADDR + off) as *mut u32, sz);
                }
            }
        }
        // winlogon.exe — smss's SmpExecuteInitialCommand initial command. Staged into its own
        // WINLOGONBUF (256 KiB, own PT), size reported at STORAGE_SHARED+0x94 so the executive can
        // parse it PE32+ and spawn it as the 3rd hosted process.
        if let Some((c, sz, _)) = open_or_sys32!(b"winlogon.exe", b"WINLOGONEXE") {
            let cap = (WINLOGONBUF_FRAMES * 0x1000) as u32;
            let want = if sz < cap { sz } else { cap };
            let got = fat_read_file(&fs, c, want, winlogonbuf_dest);
            print_str(b"[storage-host] WINLOGON.EXE size=");
            print_u64(sz as u64);
            print_str(b" read=");
            print_u64(got as u64);
            print_str(b"\n");
            if got == want && sz > 0 {
                core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x94) as *mut u32, sz);
            }
        }
        // The real ReactOS SYSTEM registry hive (::ROSSYS.HIV, regf) into HIVEBUF; report its
        // size at STORAGE_SHARED+0x38 so the executive can nt-hive-regf-parse it for smss.
        if let Some((c, sz, _)) = open_or_path!(b"reactos\\system32\\config\\system", b"ROSSYS  HIV") {
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
        // P7-A proof: publish the by-path hit/miss tally. verdict 0x200 = the WHOLE ReactOS stack
        // (smss/csrss/csrsrv/basesrv/winsrv/ntdll + the Win32 client stack + NLS + win32k/dxg/ftfd/
        // framebuf/arial/winlogon + the SYSTEM hive) was sourced BY PATH from the real \reactos tree
        // with ZERO fallbacks to a flat ::NAME file.
        core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0xA0) as *mut u32, fs_hits);
        core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0xA4) as *mut u32, fs_miss);
        print_str(b"[storage-host] FS-by-path: hits=");
        print_u64(fs_hits as u64);
        print_str(b" fallbacks=");
        print_u64(fs_miss as u64);
        print_str(b"\n");
        if fs_miss == 0 && fs_hits >= 28 {
            verdict |= 0x200;
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

    // Fix (B): retype two MCS Reply objects (OBJ_REPLY=6, fixed size, size_bits=0) into the
    // executive's root cspace — one for the main service loop (csrss/smss), one for win32k's
    // dispatch faults. Cap-based reply IPC decouples each channel's pending reply from the single
    // per-TCB `reply_to` slot, so a nested win32k fault no longer orphans csrss's reply.
    let rm = alloc_slot();
    let e_rm = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, rm);
    let rw = alloc_slot();
    let e_rw = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, rw);
    if e_rm == 0 {
        REPLY_MAIN_SLOT.store(rm, Ordering::Relaxed);
    }
    if e_rw == 0 {
        REPLY_W32_SLOT.store(rw, Ordering::Relaxed);
    }
    // Path B: a dedicated fault endpoint + reply object for the real SM-loop thread's rendezvous.
    let sm_ep = make_object(OBJ_ENDPOINT);
    SM_FAULT_EP.store(sm_ep, Ordering::Relaxed);
    let rs = alloc_slot();
    let e_rs = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, rs);
    if e_rs == 0 {
        REPLY_SMLOOP_SLOT.store(rs, Ordering::Relaxed);
    }
    // Authentic CSR accept: a dedicated fault endpoint + reply object for the real CsrApiRequestThread
    // (mirrors the SM triad above).
    let csr_ep = make_object(OBJ_ENDPOINT);
    CSR_FAULT_EP.store(csr_ep, Ordering::Relaxed);
    let rc = alloc_slot();
    let e_rc = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, rc);
    if e_rc == 0 {
        REPLY_CSRLOOP_SLOT.store(rc, Ordering::Relaxed);
    }
    print_str(b"[ntos-exec] reply caps: REPLY_MAIN cptr=0x");
    print_hex(REPLY_MAIN_SLOT.load(Ordering::Relaxed) as u32);
    print_str(b" (retype e=0x");
    print_hex(e_rm as u32);
    print_str(b") REPLY_W32 cptr=0x");
    print_hex(REPLY_W32_SLOT.load(Ordering::Relaxed) as u32);
    print_str(b" (retype e=0x");
    print_hex(e_rw as u32);
    print_str(b")\n");

    print_str(b"[ntos-exec] NT executive core: spawning the Object Manager as an isolated service\n");

    // The executive's own working VAs (rings, sysarg, device MMIO, driver code/arena) were
    // relocated out of the 64 MiB ELF reserve into the shared cluster region; the kernel's ELF
    // page tables no longer cover them, so build the cluster PT in the executive's own VSpace.
    map_cluster_pt(CAP_INIT_THREAD_VSPACE);

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

    // --- Fourth isolated service: the LPC connection broker over SURT (control plane). Stood up
    // BEFORE the live smss/csrss run so their NtCreatePort/NtConnectPort syscalls resolve through
    // it. The client is stashed in a static (LPC_CLIENT) that the LPC syscall handlers reach.
    print_str(b"[ntos-exec] spawning the LPC connection broker as a fourth isolated service\n");
    let mut lpc = LpcClient::new(LpcChan(stand_up_service(
        lpc_server::lpc_server_entry,
        LPC_SUB_VADDR,
        LPC_COMP_VADDR,
        LPC_REQ_VADDR,
        LPC_REP_VADDR,
    )));
    check(b"exec_lpc_ping", lpc.ping(), &mut passed);
    // Self-test the AUTHENTIC (Manual/path-B) connect rendezvous end-to-end through the isolated
    // server over the real SURT ring: create a distinct test port, connect (→ Pending), then drive
    // the real receive → accept → complete drain (as the SM-loop thread does) → a client comm-port
    // handle. Uses \LpcSelfTest (NOT \SmApiPort) so the live smss \SmApiPort creation stays honest.
    let selftest: Vec<u16> = "\\LpcSelfTest".encode_utf16().collect();
    let selftest_port = lpc.create_port(&selftest, 0x88, 0x148, 0x2400);
    check(b"exec_lpc_create_port", selftest_port.is_ok(), &mut passed);
    let selftest_ph = selftest_port.unwrap_or(0);
    // Manual policy: the connect leaves the connection Pending (a real receiver must drain it).
    let selftest_conn = lpc.connect_port(&selftest, 2, &[]);
    let conn_id = match &selftest_conn {
        Ok(r) if r.pending => r.connection_id,
        _ => 0,
    };
    // Drive the server-side rendezvous: receive the connection request, accept, complete.
    let lpc_rdv_ok = conn_id != 0
        && matches!(lpc.reply_wait_receive(selftest_ph),
            Ok(rr) if rr.connection_id == conn_id
                && rr.msg_type == nt_lpc_client::LPC_CONNECTION_REQUEST)
        && lpc.accept_connect(conn_id, true, 0).map(|sh| sh != 0).unwrap_or(false)
        && lpc.complete_connect(conn_id).map(|(ch, _)| ch != 0).unwrap_or(false);
    check(b"exec_lpc_connect_rendezvous", lpc_rdv_ok, &mut passed);
    // Live ALPC + LPC↔ALPC bridge self-test over the SAME ring/component/core (the
    // integration proof — no real ALPC binary exists yet). Drives ALPC + classic-LPC
    // message-plane opcodes raw on the shared channel, uses distinct \AlpcLive /
    // \BridgeLive ports (the live smss \SmApiPort path stays untouched).
    alpc_selftest::run(&mut lpc.backend_mut().0, &mut passed);
    // Publish the client to the static so the live-run LPC syscall handlers can drive it.
    // SAFETY: single-threaded executive; set once before the service loop runs.
    unsafe {
        LPC_CLIENT = Some(lpc);
    }

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
        let pml4 = spawn_sec_image(0, &pe, si_fault_c, 0, false, 100, 0x0000_0100_1074_0000, SMSS_STACK_MIRROR_VA, SMSS_HEAP_MIRROR_VA, 0, b"\\SystemRoot\\System32\\smss.exe", b"smss.exe");
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

    // --- Phase 0a: the BOOTBOOT linear framebuffer. The kernel publishes its
    // geometry in BootInfo and hands its physical memory over as the LAST device
    // untyped (is_device=1, paddr == fb_paddr). Map every framebuffer frame into
    // our VSpace, write a recognizable pattern, and read pixels back — proving the
    // display path a win32k/framebuf display driver will later drive. Headless QEMU
    // won't SHOW the pixels, but the map+write+readback proves the mapping is real.
    {
        let fb_paddr = bi.fb_paddr;
        let fb_w = bi.fb_width as u64;
        let fb_h = bi.fb_height as u64;
        let fb_scan = bi.fb_scanline as u64;
        let fb_size = bi.fb_size as u64;
        let fb_type = bi.fb_type;
        print_str(b"[ntos-exec] Phase 0a: BOOTBOOT framebuffer paddr=0x");
        print_hex((fb_paddr >> 32) as u32);
        print_hex(fb_paddr as u32);
        print_str(b" ");
        print_u64(fb_w);
        print_str(b"x");
        print_u64(fb_h);
        print_str(b" scanline=");
        print_u64(fb_scan);
        print_str(b" size=0x");
        print_hex(fb_size as u32);
        print_str(b" type=");
        print_u64(fb_type as u64);
        print_str(b"\n");

        // Geometry sanity: a real framebuffer with 32-bpp pixels — nonzero
        // dimensions, pitch at least width*4, and size covering height*pitch.
        let geometry_ok = fb_paddr != 0
            && fb_w != 0
            && fb_h != 0
            && fb_scan >= fb_w * 4
            && fb_size >= fb_scan * fb_h;
        check(b"exec_framebuffer_geometry_sane", geometry_ok, &mut passed);

        let mut map_ok = false;
        let mut pattern_ok = false;
        if geometry_ok {
            // The framebuffer window: a fresh, unused PML4 slot (PML4[4]) so it
            // can't collide with the executive's existing user mappings (which
            // sprawl through PML4[2]). We build the whole paging chain — PDPT, PD,
            // and one leaf page table per 2 MiB slice — into our own VSpace.
            const FB_VADDR: u64 = 0x0000_0200_0000_0000;
            let n_pages = (fb_size + 0xFFF) / 0x1000;

            let pdpt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
            let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, FB_VADDR, CAP_INIT_THREAD_VSPACE);
            let pd = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
            let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, FB_VADDR, CAP_INIT_THREAD_VSPACE);
            // One leaf page table per 2 MiB slice the window spans.
            let win_end = FB_VADDR + fb_size;
            let mut pt_va = FB_VADDR & !0x1F_FFFFu64; // round down to 2 MiB
            while pt_va < win_end {
                let pt = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, pt_va, CAP_INIT_THREAD_VSPACE);
                pt_va += 0x20_0000;
            }

            // Retype + map every framebuffer frame from its device untyped.
            // claim_device_pages finds the untyped whose paddr == fb_paddr and
            // hands out consecutive frames fb_paddr + i*4K at FB_VADDR + i*4K.
            let base_slot = claim_device_pages(bi, fb_paddr, FB_VADDR, n_pages);
            map_ok = base_slot != 0;
            // Retain the fb frame-cap base + count so the win32k bring-up can map the SAME physical
            // frames into win32k's VSpace (framebuf.dll draws pixels there → the real framebuffer).
            FB_FRAME_BASE.store(base_slot, Ordering::Relaxed);
            FB_FRAME_COUNT.store(n_pages, Ordering::Relaxed);
            check(b"exec_framebuffer_map", map_ok, &mut passed);

            if map_ok {
                // Write a recognizable test pattern. Fill the first scanline solid
                // magenta, drop a green marker in the last pixel of the last page
                // (proves the far end of the mapping is live), then read them back.
                const MAGENTA: u32 = 0x00FF_00FF;
                const GREEN: u32 = 0x0000_FF00;
                let fb = FB_VADDR as *mut u32;
                // Fill the WHOLE framebuffer magenta (not just line 0) so that a later GDI/framebuf
                // draw (the desktop-graphics init) is reliably detectable by a readback anywhere.
                let total_px = (fb_size / 4) as usize;
                for x in 0..total_px {
                    core::ptr::write_volatile(fb.add(x), MAGENTA);
                }
                // Last fully-addressable pixel in the framebuffer.
                let last_px = total_px - 1;
                core::ptr::write_volatile(fb.add(last_px), GREEN);

                let p0 = core::ptr::read_volatile(fb.add(0));
                let pmid = core::ptr::read_volatile(fb.add((fb_w / 2) as usize));
                let pend = core::ptr::read_volatile(fb.add((fb_w - 1) as usize));
                let plast = core::ptr::read_volatile(fb.add(last_px));
                print_str(b"[ntos-exec] framebuffer readback px0=0x");
                print_hex(p0);
                print_str(b" pxlast=0x");
                print_hex(plast);
                print_str(b"\n");
                pattern_ok = p0 == MAGENTA
                    && pmid == MAGENTA
                    && pend == MAGENTA
                    && plast == GREEN;
            }
        }
        check(b"exec_framebuffer_pattern_readback", pattern_ok, &mut passed);
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
            // The server-DLL buffer (basesrv.dll + winsrv.dll, its own PT), mapped in the executive
            // too so it can parse them for the csrss ServerDll load path.
            let sb_pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, sb_pt);
            let _ = paging_struct_map(sb_pt, LBL_X86_PAGE_TABLE_MAP, SRVBUF_VADDR, CAP_INIT_THREAD_VSPACE);
            let srvbuf_start = alloc_frame();
            for _ in 1..SRVBUF_FRAMES {
                let _ = alloc_frame();
            }
            for i in 0..SRVBUF_FRAMES {
                let _ = page_map(copy_cap(srvbuf_start + i), SRVBUF_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            // The Win32 client-stack buffer (kernel32+user32+gdi32 + Win32 deps, 4 PTs), mapped in the
            // executive too so it can parse them for the csrss loader's Win32 imports.
            for p in 0..4u64 {
                let wpt = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wpt);
                let _ = paging_struct_map(wpt, LBL_X86_PAGE_TABLE_MAP, WIN32BUF_VADDR + p * 0x20_0000, CAP_INIT_THREAD_VSPACE);
            }
            let win32buf_start = alloc_frame();
            for _ in 1..WIN32BUF_FRAMES { let _ = alloc_frame(); }
            for i in 0..WIN32BUF_FRAMES {
                let _ = page_map(copy_cap(win32buf_start + i), WIN32BUF_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            // The raw win32k.sys buffer (544 frames, two 2 MiB PTs), mapped in the executive too so
            // it can parse+load win32k.sys into the isolated win32k-service component (Phase 2b).
            for p in 0..2u64 {
                let kpt = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, kpt);
                let _ = paging_struct_map(kpt, LBL_X86_PAGE_TABLE_MAP, WIN32KBUF_VADDR + p * 0x20_0000, CAP_INIT_THREAD_VSPACE);
            }
            let win32kbuf_start = alloc_frame();
            for _ in 1..WIN32KBUF_FRAMES { let _ = alloc_frame(); }
            for i in 0..WIN32KBUF_FRAMES {
                let _ = page_map(copy_cap(win32kbuf_start + i), WIN32KBUF_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            WIN32KBUF_START.store(win32kbuf_start, Ordering::Relaxed);
            // The raw winlogon.exe buffer (64 frames, its own PT), mapped in the executive too so it
            // can parse+spawn winlogon as the 3rd hosted process.
            let wl_pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wl_pt);
            let _ = paging_struct_map(wl_pt, LBL_X86_PAGE_TABLE_MAP, WINLOGONBUF_VADDR, CAP_INIT_THREAD_VSPACE);
            let winlogonbuf_start = alloc_frame();
            for _ in 1..WINLOGONBUF_FRAMES { let _ = alloc_frame(); }
            for i in 0..WINLOGONBUF_FRAMES {
                let _ = page_map(copy_cap(winlogonbuf_start + i), WINLOGONBUF_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            WINLOGONBUF_START.store(winlogonbuf_start, Ordering::Relaxed);
            // The raw dxg.sys / dxgthk.sys buffers (one PT each), mapped in the executive too so it
            // can parse+load them into win32k's VSpace (DirectX driver hosting).
            for (st_static, vaddr, frames) in [
                (&DXGBUF_START, DXGBUF_VADDR, DXGBUF_FRAMES),
                (&DXGTHKBUF_START, DXGTHKBUF_VADDR, DXGTHKBUF_FRAMES),
                (&FTFDBUF_START, FTFDBUF_VADDR, FTFDBUF_FRAMES),
                (&FRAMEBUFBUF_START, FRAMEBUFBUF_VADDR, FRAMEBUFBUF_FRAMES),
                (&FONTBUF_START, win32k_host::FONTBUF_VADDR, win32k_host::FONTBUF_FRAMES),
            ] {
                let pt = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, vaddr, CAP_INIT_THREAD_VSPACE);
                let start = alloc_frame();
                for _ in 1..frames { let _ = alloc_frame(); }
                for i in 0..frames {
                    let _ = page_map(copy_cap(start + i), vaddr + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
                }
                st_static.store(start, Ordering::Relaxed);
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
            // c_20127.nls (US-ASCII CP20127) — also shares the NTDLLBUF 0xA0-0xC0 PT (at 0xB9_0000,
            // past HIVEBUF), so map its contiguous frame run in the executive with no extra PT.
            let nls20127_start = alloc_frame();
            for _ in 1..NLS_20127_FRAMES {
                let _ = alloc_frame();
            }
            for i in 0..NLS_20127_FRAMES {
                let _ = page_map(copy_cap(nls20127_start + i), NLS_20127_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            NLS_20127_START.store(nls20127_start, Ordering::Relaxed);
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
                srvbuf_start,
                win32buf_start,
                nls_starts[0],
                nls_starts[1],
                nls_starts[2],
                nls20127_start,
                hivebuf_start,
                win32kbuf_start,
                winlogonbuf_start,
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
            // P7 FS-BACKED-BY-PATH: the storage host resolved + read ntdll.dll from the real
            // install tree at \reactos\system32\ntdll.dll via a nested-directory walk (not the
            // flat staged ::NTDLL.DLL) — the first binary loaded from a real FS BY PATH.
            check(b"exec_ntdll_loaded_from_fs_by_path", (verdict & 0x100) != 0, &mut passed);
            // P7-A: the WHOLE ReactOS stack (smss/csrss/csrsrv/basesrv/winsrv/ntdll + the Win32
            // client stack + NLS + win32k/dxg/ftfd/framebuf/arial/winlogon + the SYSTEM hive) was
            // sourced BY PATH from the real \reactos install tree — ZERO fallbacks to a flat ::NAME.
            let fs_hits = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0xA0) as *const u32);
            let fs_fallbacks = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0xA4) as *const u32);
            print_str(b"[ntos-exec] FS-by-path load: hits=");
            print_u64(fs_hits as u64);
            print_str(b" fallbacks=");
            print_u64(fs_fallbacks as u64);
            print_str(b"\n");
            check(b"exec_full_stack_from_fs", (verdict & 0x200) != 0, &mut passed);

            // --- P7-A: EXECUTIVE-SIDE FS-BY-PATH — the storage host has now PARKED, so the executive
            // drives the same (idle) AHCI HBA itself to resolve ANY \reactos path on demand. It
            // already owns the AHCI BAR (mapped at AHCI_VADDR) + the DMA frame cap + the VT-d IO
            // mapping (AHCI_IOVA); it only needs a CPU-side mapping of that DMA frame. Map it at
            // AHCI_DMA_VADDR (same page table as AHCI_VADDR/STORAGE_SHARED — no new PT), mount the
            // FAT32 volume into a persistent handle (EXEC_FS), then PROVE the generic loader: read a
            // binary NOT in the staged set (version.dll) BY PATH into the pool and PE32+-parse it.
            // This is the P5 enabler — adding services.exe/lsass/explorer needs zero per-binary code.
            let dma_exec = copy_cap(dma_frame);
            let _ = page_map(dma_exec, AHCI_DMA_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
            let mut generic_loader_ok = false;
            if let Some(fs) = fat32_mount(AHCI_VADDR, AHCI_DMA_VADDR, AHCI_IOVA) {
                EXEC_FS = Some(fs);
                if let Some((va, sz)) = load_file_to_pool(&fs, b"reactos\\system32\\version.dll") {
                    let bytes = core::slice::from_raw_parts(va as *const u8, sz as usize);
                    let mz = sz >= 2 && bytes[0] == b'M' && bytes[1] == b'Z';
                    let parsed = nt_pe_loader::PeFile::parse(bytes).is_ok();
                    print_str(b"[ntos-exec] P7-A generic loader: version.dll BY PATH size=");
                    print_u64(sz as u64);
                    print_str(b" MZ=");
                    print_u64(mz as u64);
                    print_str(b" PE32+=");
                    print_u64(parsed as u64);
                    print_str(b" @pool=0x");
                    print_hex((va >> 32) as u32);
                    print_hex(va as u32);
                    print_str(b"\n");
                    generic_loader_ok = mz && parsed && sz >= 0x4000;
                } else {
                    print_str(b"[ntos-exec] P7-A generic loader: version.dll load FAILED\n");
                }
            } else {
                print_str(b"[ntos-exec] P7-A: executive FAT32 mount FAILED\n");
            }
            // A binary the fixed staging never touched loaded purely BY PATH from the real \reactos
            // tree through the executive's own FS reader + pool — no new buffer, offset, or fake.
            check(b"exec_generic_loader_by_path", generic_loader_ok, &mut passed);

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

    // --- Phase 2b (graphics): LOAD the real ReactOS win32k.sys into an ISOLATED win32k-service
    // component and RUN its DriverEntry as far as it goes. The storage host staged the 2.1 MiB
    // image into WIN32KBUF; the executive parses+relocates+IAT-patches it into a run of frames at
    // WIN32K_CODE_VA (W^X), spawns the component with its fault endpoint armed, and drives a
    // crash-contained fault-recv loop that reports each faulting IP as `win32k RVA = ip - CODE_VA`
    // and demand-maps benign accesses — pinning exactly where init stops.
    {
        let win32k_size =
            core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x7c) as *const u32) as usize;
        let win32kbuf_start = WIN32KBUF_START.load(Ordering::Relaxed);
        print_str(b"[win32k-svc] staged win32k.sys size=");
        print_u64(win32k_size as u64);
        print_str(b"\n");
        check(b"win32k_sys_staged", win32k_size > 0 && win32kbuf_start != 0, &mut passed);
        if win32k_size > 0 && win32kbuf_start != 0 {
            // Executive-side PTs + frames: CODE (544 frames, 2 PTs, mapped RW to load into),
            // POOL (256), DATA (4), and the shared handoff page. DATA + SHARED are mapped in the
            // executive (load_into writes the cells + the entry rva); POOL is host-only.
            for p in 0..2u64 {
                let cpt = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, cpt);
                let _ = paging_struct_map(cpt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_CODE_VA + p * 0x20_0000, CAP_INIT_THREAD_VSPACE);
            }
            let code_base = alloc_frame();
            for _ in 1..win32k_host::WIN32K_IMAGE_FRAMES { let _ = alloc_frame(); }
            for i in 0..win32k_host::WIN32K_IMAGE_FRAMES {
                let _ = page_map(copy_cap(code_base + i), win32k_host::WIN32K_CODE_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            let pool_base = alloc_frame();
            for _ in 1..win32k_host::WIN32K_POOL_FRAMES { let _ = alloc_frame(); }
            let data_base = alloc_frame();
            for _ in 1..win32k_host::WIN32K_DATA_FRAMES { let _ = alloc_frame(); }
            let shared = alloc_frame();
            // The cross-AS arg-marshal frame(s) — mapped in both the executive and the component.
            let arg_base = alloc_frame();
            for _ in 1..win32k_host::WIN32K_ARG_FRAMES { let _ = alloc_frame(); }
            // The win32k session-heap arena (host-only; the executive doesn't map it). Retain the
            // frame-cap base so the connect marshaling can RO-map the global USER heap into a GUI
            // client's VSpace (the gSharedInfo client-mapping).
            let heap_base = alloc_frame();
            for _ in 1..win32k_host::WIN32K_HEAP_FRAMES { let _ = alloc_frame(); }
            WIN32K_HEAP_FRAME_BASE.store(heap_base, Ordering::Relaxed);
            // The aux-window PT in the executive VSpace (covers DATA @0x0710 + SHARED @0x0718 + ARG
            // @0x071A; the pool is host-only, in its own window, so not mapped in the executive).
            let ppt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, ppt);
            let _ = paging_struct_map(ppt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_AUX_PT_VADDR, CAP_INIT_THREAD_VSPACE);
            for i in 0..win32k_host::WIN32K_DATA_FRAMES {
                let _ = page_map(copy_cap(data_base + i), win32k_host::WIN32K_DATA_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            let _ = page_map(copy_cap(shared), win32k_host::WIN32K_SHARED_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
            for i in 0..win32k_host::WIN32K_ARG_FRAMES {
                let _ = page_map(copy_cap(arg_base + i), win32k_host::WIN32K_ARG_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            // Parse + copy sections + relocate + patch IAT. Fully HEAP-FREE + STACK-light: the
            // 128 KiB bump heap is exhausted by this point (after smss/csrss) and the rootserver
            // stack is only 16 KiB — load_into parses win32k.sys manually and records the W^X
            // frame rights into its own `static`.
            let entry_rva = win32k_host::load_into(WIN32KBUF_VADDR, win32k_size).unwrap_or(0);
            print_str(b"[win32k-svc] loaded win32k.sys; DriverEntry rva=0x");
            print_hex(entry_rva);
            print_str(b"\n");
            check(b"win32k_loaded", entry_rva == win32k_pe::WIN32K_PE.entry_rva, &mut passed);
            core::ptr::write_volatile(
                (win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_ENTRY_RVA) as *mut u64,
                entry_rva as u64,
            );
            core::ptr::write_volatile((win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_VERDICT) as *mut u32, 0);
            // Pass the staged system-font (.ttf) byte size so the host can feed it to
            // IntGdiAddFontMemResource at bring-up (storage reported it at STORAGE_SHARED+0x90).
            let font_sz = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x90) as *const u32);
            core::ptr::write_volatile(
                (win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_FONT_SIZE) as *mut u32,
                font_sz,
            );
            print_str(b"[win32k-svc] staged system font size=0x");
            print_hex(font_sz);
            print_str(b"\n");

            // Spawn the isolated component (prio 100; the executive is 255 and blocks in the fault
            // loop, yielding to it) and receive its faults.
            let w_fault = make_object(OBJ_ENDPOINT);
            let host_pml4 = spawn_win32k_host(
                win32k_host::win32k_host_entry,
                w_fault,
                100,
                code_base,
                win32k_host::code_rights(),
                pool_base,
                data_base,
                shared,
                heap_base,
                arg_base,
            );

            const DEMAND_CAP: u64 = 512;
            let code_va = win32k_host::WIN32K_CODE_VA;
            let mut faults = 0u64;
            let mut demand = 0u64;
            let mut finished = false;
            let (mut wall_ip, mut wall_addr, mut wall_label) = (0u64, 0u64, 0u64);
            let (mut _bdg, mut mi, mut m0, mut m1, mut m2, mut m3) = ep_recv_full(w_fault);
            loop {
                let label = mi >> 12;
                if label == 6 {
                    // VMFault: MR0 = fault IP, MR1 = fault address.
                    let ip = m0;
                    let addr = m1;
                    faults += 1;
                    if faults <= 40 {
                        print_str(b"[win32k-svc] fault #");
                        print_u64(faults);
                        print_str(b" ip=0x");
                        print_hex((ip >> 32) as u32);
                        print_hex(ip as u32);
                        print_str(b" RVA=0x");
                        print_hex(ip.wrapping_sub(code_va) as u32);
                        print_str(b" addr=0x");
                        print_hex((addr >> 32) as u32);
                        print_hex(addr as u32);
                        print_str(b"\n");
                    }
                    // A null-region deref (missing/too-shallow placeholder), a W^X write into the
                    // RX image, or a runaway is a real wall — stop and report. Otherwise demand-map
                    // a zero page and resume.
                    let in_image = addr >= code_va
                        && addr < code_va + win32k_host::WIN32K_IMAGE_FRAMES * 0x1000;
                    if addr < 0x10000 || in_image || demand >= DEMAND_CAP {
                        wall_ip = ip;
                        wall_addr = addr;
                        wall_label = label;
                        break;
                    }
                    // Ensure the page's table exists (SYS_SEND page_map can't report a missing-PT
                    // error to drive a retry — critical for the demand-mapped pool at 0x0A00 whose
                    // 2 MiB PTs aren't pre-created), then zero-fill.
                    let page = addr & !0xFFF;
                    ensure_w32_client_paging(page, host_pml4);
                    let f = alloc_frame();
                    let _ = page_map(f, page, RW_NX, host_pml4);
                    demand += 1;
                    let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(w_fault, 0, 0, 0, 0, 0);
                    mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                } else if label == win32k_host::W32_DISPATCH_LABEL {
                    // DriverEntry+attach complete: the component reached its dispatch loop and sent
                    // its ready signal (fix A: a plain `send_done` on the fault EP). It is now blocked
                    // in `recv_req` awaiting a request — `win32k_dispatch` wakes it with a plain Send.
                    let _ = (m2, m3);
                    finished = true;
                    break;
                } else {
                    // UnknownSyscall(2)/UserException(3)/CapFault(1): win32k hit a fail-loud
                    // trap import, a bad IAT slot, or an invalid instruction. Record + stop.
                    wall_ip = m0;
                    wall_addr = m1;
                    wall_label = label;
                    break;
                }
            }

            // If DriverEntry+attach parked the component at the dispatch sentinel (`finished`), it is
            // now blocked awaiting reply — record its fault EP + host PML4 so `win32k_dispatch` can
            // drive its persistent service loop (Milestone B) from anywhere (the csrss loop, later).
            if finished {
                WIN32K_FAULT_EP.store(w_fault, Ordering::Relaxed);
                WIN32K_HOST_PML4.store(host_pml4, Ordering::Relaxed);
                // Pre-load the DirectX graphics driver (dxg.sys + dxgthk.sys) into win32k's VSpace so
                // NtUserInitialize → InitializeGreCSRSS → DxDdStartupDxGraphics (ZwSetSystemInformation
                // SystemLoadGdiDriverInformation) finds a real hosted dxg image.
                load_directx_drivers(host_pml4);
                // Host ftfd.dll (FreeType font driver) + patch win32k's IAT for its 34 FT_* imports so
                // InitFontSupport → FT_Init_FreeType initialises the font subsystem for real.
                load_ftfd_driver(host_pml4);
                // Host framebuf.dll (display driver) + map the BOOTBOOT framebuffer into win32k, so
                // win32k's desktop-graphics init (PDEVOBJ_Create → DrvEnablePDEV/DrvEnableSurface) can
                // enable the primary surface on the real framebuffer → PIXELS.
                load_framebuf_driver(host_pml4);
            }

            let verdict = core::ptr::read_volatile((win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_VERDICT) as *const u32);
            let de_status = core::ptr::read_volatile((win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_DE_STATUS) as *const i32);
            let ssdt_base = core::ptr::read_volatile((win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_SSDT_BASE) as *const u64);
            let ssdt_count = core::ptr::read_volatile((win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_SSDT_COUNT) as *const u32);
            let pool_used = core::ptr::read_volatile((win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_POOL_USED) as *const u64);
            print_str(b"[win32k-svc] DriverEntry ");
            if finished {
                print_str(b"RETURNED status=0x");
                print_hex(de_status as u32);
            } else {
                print_str(b"STOPPED label=");
                print_u64(wall_label);
                print_str(b" ip=0x");
                print_hex((wall_ip >> 32) as u32);
                print_hex(wall_ip as u32);
                print_str(b" RVA=0x");
                print_hex(wall_ip.wrapping_sub(code_va) as u32);
                print_str(b" addr=0x");
                print_hex((wall_addr >> 32) as u32);
                print_hex(wall_addr as u32);
            }
            print_str(b" verdict=0x");
            print_hex(verdict);
            print_str(b" faults=");
            print_u64(faults);
            print_str(b" demand=");
            print_u64(demand);
            print_str(b" pool_used=0x");
            print_hex(pool_used as u32);
            print_str(b"\n");
            if (verdict & win32k_host::V_SSDT) != 0 {
                print_str(b"[win32k-svc] win32k registered its NtUser/NtGdi SSDT: base=0x");
                print_hex((ssdt_base >> 32) as u32);
                print_hex(ssdt_base as u32);
                print_str(b" count=");
                print_u64(ssdt_count as u64);
                print_str(b"\n");
            }
            // Phase 2c: report the per-process attach (win32k's process-create callout) + the SSN
            // 0x10FA (NtUserProcessConnect) dispatch through the SSDT.
            let nt_handler = core::ptr::read_volatile((win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_NTUSER_HANDLER) as *const u64);
            let nt_status = core::ptr::read_volatile((win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_NTUSER_STATUS) as *const i32);
            if (verdict & win32k_host::V_CALLOUT_ENTERED) != 0 {
                print_str(b"[win32k-svc] win32k process-create callout ");
                if (verdict & win32k_host::V_CALLOUT_RETURNED) != 0 {
                    print_str(b"RETURNED");
                } else {
                    print_str(b"ran then faulted (see backtrace)");
                }
                print_str(b"\n");
            }
            if (verdict & win32k_host::V_NTUSER_ENTERED) != 0 {
                print_str(b"[win32k-svc] NtUserProcessConnect(0x10FA) via SSDT -> handler RVA=0x");
                print_hex(nt_handler.wrapping_sub(code_va) as u32);
                if (verdict & win32k_host::V_NTUSER_RETURNED) != 0 {
                    print_str(b" RETURNED status=0x");
                    print_hex(nt_status as u32);
                    if (verdict & win32k_host::V_NTUSER_SUCCESS) != 0 {
                        print_str(b" (STATUS_SUCCESS)");
                    }
                } else {
                    print_str(b" (ran in component context, then faulted - see backtrace)");
                }
                print_str(b"\n");
            }
            // The routing seam works end-to-end: SSN>=0x1000 resolved to a real win32k handler
            // (verdict bit set before the fault-prone callout/connect, so this stays gate-stable).
            check(b"win32k_ntuser_ssn_routed", (verdict & win32k_host::V_NTUSER_RESOLVED) != 0, &mut passed);
            // On a fault wall, backtrace: map the component's stack into the executive and print
            // every return address that lands in the win32k image, as an RVA — the call chain.
            if !finished {
                let ss = WIN32K_STACK_SLOT.load(Ordering::Relaxed);
                let sf = WIN32K_STACK_FRAMES.load(Ordering::Relaxed);
                if ss != 0 && sf != 0 {
                    let mirror = 0x0000_0100_0730_0000u64;
                    let spt = alloc_slot();
                    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
                    let _ = paging_struct_map(spt, LBL_X86_PAGE_TABLE_MAP, mirror, CAP_INIT_THREAD_VSPACE);
                    for i in 0..sf {
                        let _ = page_map(copy_cap(ss + i), mirror + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
                    }
                    // Scan the ACTIVE stack only (from the fault-time RSP up to stack_top), so the
                    // return addresses are the real call chain (deepest first) — no stale frames.
                    let rsp = tcb_read_rsp(WIN32K_TCB.load(Ordering::Relaxed));
                    let stack_top = STACK_BASE + sf * 0x1000;
                    let start = if rsp >= STACK_BASE && rsp < stack_top { rsp } else { STACK_BASE };
                    print_str(b"[win32k-svc] stack backtrace from rsp=0x");
                    print_hex((rsp >> 32) as u32);
                    print_hex(rsp as u32);
                    print_str(b" (win32k return-address RVAs, deepest first):\n");
                    let lo = code_va;
                    let hi = code_va + win32k_host::WIN32K_IMAGE_FRAMES * 0x1000;
                    let mut n = 0u32;
                    let mut va = start;
                    while va < stack_top && n < 20 {
                        let v = core::ptr::read_volatile((mirror + (va - STACK_BASE)) as *const u64);
                        if v >= lo && v < hi {
                            print_str(b"  rva=0x");
                            print_hex(v.wrapping_sub(code_va) as u32);
                            print_str(b"\n");
                            n += 1;
                        }
                        va += 8;
                    }
                }
            }
            // Progress checks: the component spawned and win32k's DriverEntry was ENTERED (its
            // trampoline-bound code ran) is the Phase-2b milestone. SSDT registration + full
            // STATUS_SUCCESS are further progress markers reported when reached.
            check(b"win32k_driver_entry_entered", (verdict & win32k_host::V_ENTERED) != 0, &mut passed);
            check(b"win32k_ssdt_registered", (verdict & win32k_host::V_SSDT) != 0, &mut passed);
            // Phase-2b milestone: GreDriverEntry ran through init and registered its NtUser/NtGdi
            // SSDT (the prerequisite for Phase-2c SSN>=0x1000 routing). Whether DriverEntry then ran
            // to STATUS_SUCCESS or stopped at the next missing init piece (RVA in the log above) is
            // reported non-gating — this check passes at the achieved milestone.
            let progressed = (verdict & win32k_host::V_ENTERED) != 0
                && (verdict & win32k_host::V_SSDT) != 0;
            check(b"win32k_gredriverentry_progressed", progressed, &mut passed);
            // The milestone: win32k's DriverEntry ran to completion and returned STATUS_SUCCESS.
            // V_SUCCESS is set right after DriverEntry returns 0, BEFORE the exploratory per-process
            // callout/connect below — so a fault there doesn't flip this gate-critical check.
            let success = (verdict & win32k_host::V_SUCCESS) != 0;
            if success {
                print_str(b"[win32k-svc] DriverEntry ran to STATUS_SUCCESS\n");
            }
            check(b"win32k_driver_entry_success", success, &mut passed);

            // --- Milestone B: prove the PERSISTENT DISPATCH LOOP end-to-end. The component is now
            // parked at the dispatch sentinel (not parked/dead). Marshal a USERCONNECT buffer into
            // the shared arg frame and dispatch NtUserProcessConnect (SSN 0x10FA) THROUGH the loop
            // (win32k_dispatch resume-replies the sentinel, services handler faults, waits the next
            // sentinel = done). A clean round-trip (ok=true) proves csrss's win32k syscalls can be
            // routed to the live component. The arg frame stands in for csrss's user pointer.
            if finished {
                core::ptr::write_bytes(win32k_host::WIN32K_ARG_VADDR as *mut u8, 0, 0x240);
                let (st, ok) = win32k_dispatch(
                    win32k_host::SSN_NT_USER_INITIALIZE,
                    0x0000_0000_5A5A_0100, // a process handle (ObReferenceObjectByHandle → EPROCESS)
                    win32k_host::WIN32K_ARG_VADDR, // USERCONNECT buffer in the shared arg frame
                    0x240,
                    0,
                );
                let seq = core::ptr::read_volatile(
                    (win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_REQ_SEQ) as *const u64,
                );
                print_str(b"[win32k-svc] DISPATCH-LOOP round-trip: SSN 0x10FA -> status=0x");
                print_hex(st as u32);
                print_str(if ok { b" (serviced, seq=" } else { b" (WALL, seq=" });
                print_u64(seq);
                print_str(b")\n");
                check(b"win32k_dispatch_loop_roundtrip", ok && seq >= 1, &mut passed);

                // --- Fix (B): prove a win32k dispatch whose handler FAULTS is resolved through the
                // per-caller reply cap (REPLY_W32 / decode_reply), NOT the single per-TCB reply_to.
                // SSN_TEST_FAULT's handler reads an un-demand-paged page → the executive demand-maps
                // it via Send-on-REPLY_W32 + recv-with-r12 and resumes win32k, which returns the
                // sentinel. A clean round-trip means the dispatch fault path no longer depends on
                // reply_to — so a nested faulting SSN can't clobber an outer caller's pending reply.
                let (fst, fok) = win32k_dispatch(win32k_host::SSN_TEST_FAULT, 0, 0, 0, 0);
                let fseq = core::ptr::read_volatile(
                    (win32k_host::WIN32K_SHARED_VADDR + win32k_host::SH_REQ_SEQ) as *const u64,
                );
                print_str(b"[win32k-svc] FAULTING dispatch (reply-cap path): status=0x");
                print_hex(fst as u32);
                print_str(if fok { b" (serviced, seq=" } else { b" (WALL, seq=" });
                print_u64(fseq);
                print_str(b")\n");
                check(
                    b"win32k_dispatch_fault_via_reply_cap",
                    fok && fst == win32k_host::TEST_FAULT_STATUS && REPLY_W32_SLOT.load(Ordering::Relaxed) != 0,
                    &mut passed,
                );
            }
        }
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
                    let pml4 = spawn_sec_image(0, &pe, si_fault_c, NTDLL_BASE, true, 100, 0x0000_0100_1074_0000, SMSS_STACK_MIRROR_VA, SMSS_HEAP_MIRROR_VA, 0, b"\\SystemRoot\\System32\\smss.exe", b"smss.exe");
                    // Demand-fault scratch: each filled image/ntdll page keeps a persistent
                    // executive mapping (indexed by fill order, for syscall copy-out to smss pages),
                    // so the region grows one page per fault. The old 0x6C scratch shared the FILEBUF
                    // PT and collided with the env buffer at 0x74 after ~128 faults — smss runs far
                    // deeper into ntdll now, so give it an ISOLATED range with its own page tables
                    // (8 PTs = 4096 pages) that can't collide with any other executive mapping.
                    const SCRATCH_BASE: u64 = 0x0000_0100_1100_0000;
                    for k in 0..8u64 {
                        let pt = alloc_slot();
                        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
                        let _ = paging_struct_map(
                            pt,
                            LBL_X86_PAGE_TABLE_MAP,
                            SCRATCH_BASE + k * 0x20_0000,
                            CAP_INIT_THREAD_VSPACE,
                        );
                    }
                    let (heap_verdict, sfaults, sfirst, sstop, ntfaults, sssn) = service_sec_image(
                        si_fault,
                        pml4,
                        &pe,
                        SCRATCH_BASE,
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
                    // winlogon bring-up: smss's SmpExecuteInitialCommand found + launched
                    // winlogon.exe as the 3rd hosted process (NtOpenFile→NtCreateSection→
                    // NtCreateProcess), the executive spawned it, and its ntdll loader ran
                    // (demand-faulting pages) — multiplexed into the same badge-keyed loop.
                    let wl_staged = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x94) as *const u32) > 0;
                    check(b"exec_winlogon_staged", wl_staged, &mut passed);
                    check(
                        b"exec_winlogon_spawned",
                        WINLOGON_SPAWNED.load(Ordering::Relaxed) == 1,
                        &mut passed,
                    );
                    check(
                        b"exec_winlogon_loader_runs",
                        WINLOGON_FAULTS.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    // winlogon's kernel32 CSR client connect (NtSecureConnectPort → \Windows\ApiPort)
                    // was serviced: the CSR regions were mapped + the CSR_API_CONNECTINFO reply filled,
                    // so BaseDllInitialize proceeds past the (otherwise fatal) connect.
                    check(
                        b"exec_winlogon_csr_connect",
                        WINLOGON_CSR_CONNECTED.load(Ordering::Relaxed) == 1,
                        &mut passed,
                    );
                    // The DIRECT cross-badge message plane carried live winlogon↔csrss CSR API traffic
                    // (NtRequestWaitReplyPort → the CsrpClientConnect message, modeled reply=SUCCESS).
                    check(
                        b"exec_csr_message_plane",
                        CSR_MSGS.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    // nt-process convergence (first increment): the real Process Manager backs the 3
                    // hosted processes with EPROCESS objects. `exec_process_manager_up` = 3 EPROCESSes
                    // exist; `exec_eprocess_backs_badges` = each pi's EPROCESS names its hosted binary
                    // with a distinct pid (identity is real, not a scalar); `exec_eprocess_lookup_by_badge`
                    // = the live service loop resolved a fault badge → its EPROCESS through the manager.
                    check(
                        b"exec_process_manager_up",
                        PM_PROC_COUNT.load(Ordering::Relaxed) == 3,
                        &mut passed,
                    );
                    check(
                        b"exec_eprocess_backs_badges",
                        PM_IDENTITY_OK.load(Ordering::Relaxed) == 0b111,
                        &mut passed,
                    );
                    check(
                        b"exec_eprocess_lookup_by_badge",
                        PM_BADGE_LOOKUPS.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    // Path 1 — handle-table routing: the ~15 executive handle-mint sites now record
                    // every handle into the caller's REAL per-EPROCESS handle table, and NtClose frees
                    // it (was a no-op). `exec_eprocess_handle_table_routed` = handles were routed;
                    // `exec_eprocess_handle_table_no_realloc` = peak live count stayed BELOW the
                    // pre-reserved capacity → insert_handle never reallocated under the per-syscall
                    // bump reset (the non-leaking heap-reset solution proven under live load).
                    let tracked = PM_HANDLES_TRACKED.load(Ordering::Relaxed);
                    let peak = PM_HANDLE_PEAK.load(Ordering::Relaxed);
                    let cap = PM_HANDLE_CAP_BOOT.load(Ordering::Relaxed);
                    check(b"exec_eprocess_handle_table_routed", tracked >= 10, &mut passed);
                    check(
                        b"exec_eprocess_handle_table_no_realloc",
                        cap >= PM_HANDLE_RESERVE as u64 && peak > 0 && peak < cap,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] nt-process path1: handles routed=0x");
                    print_hex(tracked as u32);
                    print_str(b" closed=0x");
                    print_hex(PM_HANDLES_CLOSED.load(Ordering::Relaxed) as u32);
                    print_str(b" peak=0x");
                    print_hex(peak as u32);
                    print_str(b" reserved=0x");
                    print_hex(cap as u32);
                    print_str(b" (no realloc)\n");
                    // Path 2 — lifecycle: real ETHREADs back the 3 main threads (bound to their image
                    // entry at spawn), and NtTerminateProcess/NtOpenProcess route through pm (proven
                    // by the post-loop self-test on a throwaway EPROCESS; the 3 hosted are untouched).
                    check(
                        b"exec_ethread_backs_main_threads",
                        PM_MAIN_THREADS_OK.load(Ordering::Relaxed) == 0b111,
                        &mut passed,
                    );
                    check(
                        b"exec_main_thread_bound_at_spawn",
                        PM_THREAD_BINDS.load(Ordering::Relaxed) >= 3,
                        &mut passed,
                    );
                    check(
                        b"exec_ntopenprocess_mints_handle",
                        PM_NTOPENPROCESS_OK.load(Ordering::Relaxed) == 0b11,
                        &mut passed,
                    );
                    check(
                        b"exec_ntterminateprocess_teardown",
                        PM_LIFECYCLE_OK.load(Ordering::Relaxed) == 0b11_1111,
                        &mut passed,
                    );
                    // ITEM 2a — LIVE terminate-dispatch: csrss.exe's init thread self-exits via
                    // NtTerminateThread(NtCurrentThread()) during the real boot, and the executive now
                    // routes that live exit through the real ETHREAD teardown (pm.exit_thread, no
                    // cascade — csrss's EPROCESS stays Running). `exec_live_terminate_thread_routed` =
                    // the live exit fired (>=1) AND csrss's (pi=1) main ETHREAD is marked Terminated,
                    // while smss/winlogon (bits 0/2) are NOT (they don't self-exit at boot) → the exit
                    // was routed to the CORRECT thread by identity, not the whole process.
                    check(
                        b"exec_live_terminate_thread_routed",
                        PM_TERMINATE_THREAD_LIVE.load(Ordering::Relaxed) >= 1
                            && PM_TERMINATE_THREAD_STATE.load(Ordering::Relaxed) == 0b010,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] item2a live-terminate-thread: count=0x");
                    print_hex(PM_TERMINATE_THREAD_LIVE.load(Ordering::Relaxed) as u32);
                    print_str(b" ethread-terminated-bits=0x");
                    print_hex(PM_TERMINATE_THREAD_STATE.load(Ordering::Relaxed) as u32);
                    print_str(b" nt-terminate-process-calls=0x");
                    print_hex(PM_TERMINATE_CALLS.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
                    // ITEM 2b — seL4 MECHANISM teardown (reclamation) proven end-to-end on a THROWAWAY
                    // untyped/caps: the kernel's CNodeDelete does full reclamation (TCB suspend, frame-
                    // PTE unmap, pool-slot release, AND parent-Untyped free_index rollback = return-to-
                    // Untyped), so NO new kernel primitive is needed. 0b11_1111 = all 6 sub-proofs pass:
                    // child untyped carved, frame Untyped-return (retype→delete→retype == full count),
                    // TCB suspend+delete, PML4+CNode delete, frame-unmap-on-delete, child untyped
                    // returned. The 3 hosted processes' caps/frames are UNTOUCHED (boot byte-identical).
                    check(
                        b"exec_sel4_reclaim_mechanism",
                        PM_RECLAIM_OK.load(Ordering::Relaxed) == 0b11_1111,
                        &mut passed,
                    );
                    // ALPC last-mile item (b) — the PHYSICAL two-VSpace port-section view (WOW64
                    // big-data path). Two SEPARATE endpoint VSpaces map the SAME port-section backing
                    // frames at the view VA via copy_cap + page_map (the CSRSS_ANON_BASE machinery); a
                    // hosted thread in endpoint A writes big data, a hosted thread in endpoint B reads
                    // it back THROUGH ITS OWN mapping. 0x3F = all 6: two separate VSpaces stood up,
                    // writer wrote in A, reader read page0 + page1 in B (== A's write → genuine cross-
                    // VSpace shared memory, multi-page), a 3rd executive window confirms one physical
                    // frame, and the throwaway VSpaces + section frames were CNodeDelete-reclaimed.
                    check(
                        b"exec_alpc_section_view_cross_vspace",
                        ALPC_XVIEW_OK.load(Ordering::Relaxed) == 0b11_1111,
                        &mut passed,
                    );
                    // Path 3 — the six ex-parallel per-pi identity arrays (pml4s/scratch_bases/
                    // img_ends/pfaults/pfirst/pntfaults) are now ONE array of `ProcExec`, each slot
                    // EPROCESS-linked via its `pid`. `exec_eprocess_linked_mechanism` = every hosted
                    // process's folded mechanism struct has a live pml4 AND its pid matches the
                    // ProcessManager's pid for that badge slot (0b111 = all 3 spawned + linked).
                    check(
                        b"exec_eprocess_linked_mechanism",
                        PM_EXEC_LINK_OK.load(Ordering::Relaxed) == 0b111,
                        &mut passed,
                    );
                    // Path 1b — process-local dense handle VALUES. Two distinct EPROCESSes both hold
                    // handle 0x4 referring to DIFFERENT objects (0b111 = same-value + distinct-object
                    // + no-aliasing). The on-kernel proof that handle namespaces are per-process.
                    check(
                        b"exec_process_local_handle_values",
                        PM_HANDLE_LOCAL_OK.load(Ordering::Relaxed) == 0b111,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] nt-process path1b: process-local-handles=0x");
                    print_hex(PM_HANDLE_LOCAL_OK.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
                    print_str(b"[ntos-exec] nt-process path2: main-threads-ok=0x");
                    print_hex(PM_MAIN_THREADS_OK.load(Ordering::Relaxed) as u32);
                    print_str(b" binds=0x");
                    print_hex(PM_THREAD_BINDS.load(Ordering::Relaxed) as u32);
                    print_str(b" open-ok=0x");
                    print_hex(PM_NTOPENPROCESS_OK.load(Ordering::Relaxed) as u32);
                    print_str(b" terminate-ok=0x");
                    print_hex(PM_LIFECYCLE_OK.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
                    print_str(b"[ntos-exec] nt-process: EPROCESS pids smss/csrss/winlogon = ");
                    print_hex(PM_PIDS[0].load(Ordering::Relaxed) as u32);
                    print_str(b"/");
                    print_hex(PM_PIDS[1].load(Ordering::Relaxed) as u32);
                    print_str(b"/");
                    print_hex(PM_PIDS[2].load(Ordering::Relaxed) as u32);
                    print_str(b" badge-lookups=0x");
                    print_hex(PM_BADGE_LOOKUPS.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
                } else {
                    check(b"exec_reactos_smss_live_paged", false, &mut passed);
                    check(b"exec_reactos_smss_calls_into_ntdll", false, &mut passed);
                    check(b"exec_reactos_ldrinit_runs_deep", false, &mut passed);
                    check(b"exec_reactos_ldrinit_creates_heap", false, &mut passed);
                    check(b"exec_reactos_ldrinit_reads_image", false, &mut passed);
                    check(b"exec_winlogon_staged", false, &mut passed);
                    check(b"exec_winlogon_spawned", false, &mut passed);
                    check(b"exec_winlogon_loader_runs", false, &mut passed);
                    check(b"exec_winlogon_csr_connect", false, &mut passed);
                    check(b"exec_csr_message_plane", false, &mut passed);
                    check(b"exec_process_manager_up", false, &mut passed);
                    check(b"exec_eprocess_backs_badges", false, &mut passed);
                    check(b"exec_eprocess_lookup_by_badge", false, &mut passed);
                    check(b"exec_eprocess_handle_table_routed", false, &mut passed);
                    check(b"exec_eprocess_handle_table_no_realloc", false, &mut passed);
                    check(b"exec_ethread_backs_main_threads", false, &mut passed);
                    check(b"exec_main_thread_bound_at_spawn", false, &mut passed);
                    check(b"exec_ntopenprocess_mints_handle", false, &mut passed);
                    check(b"exec_ntterminateprocess_teardown", false, &mut passed);
                    check(b"exec_live_terminate_thread_routed", false, &mut passed);
                    check(b"exec_sel4_reclaim_mechanism", false, &mut passed);
                    check(b"exec_eprocess_linked_mechanism", false, &mut passed);
                    check(b"exec_process_local_handle_values", false, &mut passed);
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

    // --- Graphics: the counted desktop paint. The ENTIRE eager desktop-graphics scaffold is RETIRED —
    // both the display init AND the paint are now winlogon-natural. winlogon's OWN first GUI DC-op
    // (NtUserSwitchDesktop -> co_IntShowDesktop -> WM_ERASEBKGND -> DceAllocDCE -> co_IntGraphicsCheck)
    // lazily drives co_IntInitializeDesktopGraphics (InitVideo/surface) THEN IntPaintDesktop paints the
    // framebuffer (the m0==0x1288 forward arm cleared the fb to magenta first, then re-read the grid,
    // stashing the result in FB_PIXELS_DREW/MATCH/SAMPLE0). There is no longer any m0==0x125a arm; win32k's
    // own NtUserInitialize dispatch only seeds the host prerequisites (system font + WinSta0/Default Ob).
    {
        let d = FB_PIXELS_DREW.load(Ordering::Relaxed);
        let matched = FB_PIXELS_MATCH.load(Ordering::Relaxed);
        let sample0 = FB_PIXELS_SAMPLE0.load(Ordering::Relaxed);
        print_str(b"[ntos-exec] win32k desktop-graphics framebuffer pixels: ");
        print_str(match d {
            2 => b"DREW (non-magenta)\n".as_slice(),
            1 => b"unchanged (no draw)\n".as_slice(),
            _ => b"gfx-init not reached\n".as_slice(),
        });
        print_str(b"[ntos-exec] desktop-bg match ");
        print_u64(matched);
        print_str(b"/");
        print_u64(FB_SAMPLE_COUNT);
        print_str(b" px, px0=0x");
        print_hex(sample0 as u32);
        print_str(b" (expected 0x");
        print_hex(FB_DESKTOP_BG);
        print_str(b")\n");
        // PERMANENT GATE: the whole sampled framebuffer grid must hold the authentic WC_DESKTOP
        // background painted by winlogon's NATURAL co_IntShowDesktop -> IntPaintDesktop. Because the
        // fb was cleared to magenta right before winlogon's SwitchDesktop, a full 768/768 match here
        // PROVES the desktop is painted by the authentic boot flow (BOOTBOOT -> kernel -> smss ->
        // csrss -> winlogon -> win32k) with no scaffold paint. A regression that stops the paint (or
        // changes the color) FAILS the gate.
        check(
            b"exec_win32k_desktop_painted",
            d == 2 && matched == FB_SAMPLE_COUNT && sample0 as u32 == FB_DESKTOP_BG,
            &mut passed,
        );
        // Echo winlogon's natural-paint count (same source as the counted spec above — the scaffold
        // paint is retired, so these agree by construction).
        let nat = WINLOGON_NATURAL_PAINT.load(Ordering::Relaxed);
        print_str(b"[ntos-exec] winlogon NATURAL SwitchDesktop paint: ");
        print_u64(nat);
        print_str(b"/");
        print_u64(FB_SAMPLE_COUNT);
        print_str(if nat == FB_SAMPLE_COUNT {
            b" px re-painted 0x003a6ea5 (natural flow PAINTS)\n".as_slice()
        } else {
            b" px (natural flow did NOT fully re-paint)\n".as_slice()
        });
    }

    // --- Phase 2 (graphics): PROTOTYPE-bind the real ReactOS win32k.sys against the driver-host
    // load contract. Classify + BIND win32k's exact ntoskrnl+hal+ftfd import surface (the names
    // extracted from the real binary) to runtime trampolines — the runtime half of Phase 1's
    // static contract — and prove the KeAddSystemServiceTable -> SSDT routing seam that Phase 2
    // forwards a caller's SSN>=0x1000 through. win32k's DriverEntry is NOT executed here: the
    // 2.1 MiB image can't live in the executive (its ELF is mapped RO at IMAGE_BASE with the
    // 128 KiB heap 512 KiB above), so running it belongs in the isolated win32k-service component
    // (staged off disk into untyped frames — the next increment).
    {
        let pe = &win32k_pe::WIN32K_PE;
        print_str(b"[win32k] win32k.sys (ReactOS 0.4.17): ");
        print_u64(pe.size);
        print_str(b" bytes, image=");
        print_hex(pe.size_of_image);
        print_str(b" (");
        print_u64(pe.image_frames as u64);
        print_str(b" frames), entry_rva=");
        print_hex(pe.entry_rva);
        print_str(b", sections=");
        print_u64(pe.sections as u64);
        print_str(b", relocs=");
        print_u64(pe.relocs as u64);
        print_str(if pe.has_gs_cookie { b", /GS=yes\n" } else { b", /GS=no\n" });

        let c = &win32k_pe::CLASSIFICATION;
        print_str(b"[win32k] imports=");
        print_u64((c.ntoskrnl + c.hal + c.ftfd) as u64);
        print_str(b" (ntoskrnl=");
        print_u64(c.ntoskrnl as u64);
        print_str(b" hal=");
        print_u64(c.hal as u64);
        print_str(b" ftfd=");
        print_u64(c.ftfd as u64);
        print_str(b"); ntoskrnl+hal bind: Implemented=");
        print_u64(c.implemented as u64);
        print_str(b" Partial=");
        print_u64(c.partial as u64);
        print_str(b" Stub=");
        print_u64(c.stub as u64);
        print_str(b" Trap=");
        print_u64(c.trap as u64);
        print_str(b" Blocked=");
        print_u64(c.blocked as u64);
        print_str(b"\n");
        let ssdt_ok = win32k_pe::ssdt_seam_selftest();
        print_str(if ssdt_ok {
            b"[win32k] KeAddSystemServiceTable -> SSDT resolve(0x1000..) seam: OK\n"
        } else {
            b"[win32k] KeAddSystemServiceTable -> SSDT seam: FAIL\n"
        });
        // The load contract holds iff no ntoskrnl+hal import blocks the load AND the Phase-2 SSDT
        // routing seam records + resolves correctly. (The full 225-import binding is exhaustively
        // asserted by nt-compat-exports' host test; CLASSIFICATION is that verified breakdown.)
        let contract_ok = c.blocked == 0
            && (c.implemented + c.partial + c.stub + c.trap) == (c.ntoskrnl + c.hal)
            && ssdt_ok;
        check(b"exec_win32k_load_contract", contract_ok, &mut passed);
    }

    print_str(b"[ntos-exec summary: ");
    print_u64(passed);
    print_str(b"/94 executive->isolated-service checks passed]\n");
    print_str(b"[microtest done]\n");
    park()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Dump the panic site (file:line) after the '!' marker: a bare '!' + park is
    // indistinguishable from a userspace spin over the serial console (it cost a
    // long debugging detour once — a heap-exhaustion panic mid-smss-service read
    // as an smss spin). The location makes the next one a one-line diagnosis.
    debug_put_char(b'!');
    if let Some(loc) = _info.location() {
        debug_put_char(b'@');
        for &b in loc.file().as_bytes() {
            debug_put_char(b);
        }
        debug_put_char(b':');
        let mut n = loc.line();
        let mut buf = [b'0'; 10];
        let mut i = 10;
        if n == 0 {
            debug_put_char(b'0');
        }
        while n > 0 && i > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        for &b in &buf[i..] {
            debug_put_char(b);
        }
        debug_put_char(b'\n');
    }
    park()
}
