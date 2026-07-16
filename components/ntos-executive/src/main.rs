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
mod ntoskrnl_shared;
mod server;
mod win32k_pe;
mod win32k_subsystem;
mod storage_host;
mod service_sec_image;
pub(crate) use service_sec_image::*;
mod loader_trace_diag;
pub(crate) use loader_trace_diag::*;
mod exec_handler;
mod fs_loader;
pub(crate) use fs_loader::*;
mod rendezvous;
pub(crate) use rendezvous::*;
mod spawn_hosts;
pub(crate) use spawn_hosts::*;
mod device_io;
pub(crate) use device_io::*;
mod pnp;
pub(crate) use pnp::*;
mod selftests;
pub(crate) use selftests::*;
mod img_spawn;
pub(crate) use img_spawn::*;
mod win32k_glue;
pub(crate) use win32k_glue::*;
mod driver_launch;
pub(crate) use driver_launch::*;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
/// The 4th hosted process — services.exe (badge 6, pi 3), spawned by winlogon's Win32 CreateProcessW
/// (StartServicesManager). Same env VAs (SMSS_*) in its own VSpace; only the EXECUTIVE-side mirrors +
/// the demand-fill scratch must be distinct from smss/csrss/winlogon. STACK mirror is in the FILEBUF
/// PT (present); HEAP/IMAGE mirrors get their own PTs in spawn_sec_image (past winlogon's 0x1240).
/// SCRATCH_BASE is PT2 of smss's pre-mapped 8-PT scratch range (0x1100..0x1200; PT0 smss / PT4 csrss /
/// PT6 winlogon → PT2 free). Env-build scratch sits between smss's 0x1074 and csrss's 0x1078.
pub const SERVICES_STACK_MIRROR_VA: u64 = 0x0000_0100_106D_0000; // FILEBUF PT, present
pub const SERVICES_HEAP_MIRROR_VA: u64 = 0x0000_0100_1260_0000; // own PT (spawn_sec_image creates it)
pub const SERVICES_IMAGE_MIRROR_VA: u64 = 0x0000_0100_1280_0000; // own PT (spawn_sec_image creates it)
pub const SERVICES_ENV_SCRATCH_VA: u64 = 0x0000_0100_1076_0000; // FILEBUF PT (between smss/csrss env)
/// The 5th hosted process — lsass.exe (badge 8, pi 4), spawned by winlogon's StartLsass Win32
/// CreateProcessW(L"lsass.exe") (the LSA subsystem). Same env VAs (SMSS_*) in its OWN VSpace; only
/// the EXECUTIVE-side mirrors + demand-fill scratch must be distinct. STACK mirror FILEBUF PT;
/// HEAP/IMAGE get their own PTs (past services' 0x1280); env scratch 0x1077 (past services' 0x1076).
pub const LSASS_STACK_MIRROR_VA: u64 = 0x0000_0100_106E_0000; // FILEBUF PT, present
pub const LSASS_HEAP_MIRROR_VA: u64 = 0x0000_0100_12A0_0000; // own PT (spawn_sec_image creates it)
pub const LSASS_IMAGE_MIRROR_VA: u64 = 0x0000_0100_12C0_0000; // own PT (spawn_sec_image creates it)
pub const LSASS_ENV_SCRATCH_VA: u64 = 0x0000_0100_1077_0000; // FILEBUF PT (past services' 0x1076)
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
// --- General NtCreateThread: a REAL Nth thread in ANY hosted process (first live user: winlogon's
// RPC listener thread). Reuses the SM numeric VSpace VAs (0x1044-0x104B) in the TARGET process's OWN
// pml4 (isolated from smss/csrss's threads at the same VAs) — they fall in the STACK_BASE 2 MiB PT
// that every spawn_sec_image already created. The EXECUTIVE-side env scratch must be DISTINCT from
// SM (0x1070) / CSR (0x1071) / smss-spawn (0x1074) / csrss-spawn (0x1078) / winlogon-spawn (0x107C).
pub const WL_LISTENER_STACK_BASE: u64 = SM_STACK_BASE; // target VSpace (4 frames)
pub const WL_LISTENER_STACK_FRAMES: u64 = 4;
pub const WL_LISTENER_IPCBUF_VA: u64 = SM_IPCBUF_VA; // target VSpace
pub const WL_LISTENER_TEB_VA: u64 = SM_TEB_VA; // target VSpace (2 pages)
pub const WL_LISTENER_TRAMP_VA: u64 = SM_TRAMP_VA; // target VSpace
/// Executive scratch (3 pages) to build the listener thread's TEB/trampoline before copy_cap into
/// the target VSpace. FILEBUF PT, clear of every other env-scratch VA.
pub const WL_LISTENER_ENV_SCRATCH_VA: u64 = 0x0000_0100_1072_0000;
/// The fault-EP badge for winlogon's rpcrt4 server WORKER thread — the main loop maps it to (pi 2,
/// worker), switching ACTIVE_STACK_MIRROR to the worker's OWN mirror. Same N-threads multiplex as the
/// SVC/LSASS listeners; this makes winlogon's RPC server WORKER actually RUN (its wait array →
/// NtWaitForMultipleObjects parks; the main thread's signal_state_changed wakes it → it SetEvents
/// server_ready_event → the main thread's WaitForSingleObject(server_ready_event) wakes).
pub const WINLOGON_WORKER_BADGE: u64 = 11;
/// Executive-side stack mirror for winlogon's rpcrt4 worker thread (its syscall out-params / stack-arg
/// reads route to its OWN stack, not winlogon's main-thread stack). Distinct 8-page window (past
/// LSASS_LISTENER2's 0x1370).
pub const WINLOGON_WORKER_STACK_MIRROR_VA: u64 = 0x0000_0100_1378_0000;
pub const WL_WORKER2_STACK_BASE: u64 = 0x0000_0100_104C_0000;
pub const WL_WORKER2_STACK_FRAMES: u64 = 8;
pub const WL_WORKER2_IPCBUF_VA: u64 = 0x0000_0100_104E_0000;
pub const WL_WORKER2_TEB_VA: u64 = 0x0000_0100_104F_0000;
pub const WL_WORKER2_TRAMP_VA: u64 = 0x0000_0100_1051_0000;
pub const WL_WORKER2_ENV_SCRATCH_VA: u64 = 0x0000_0100_107B_0000;
pub const WINLOGON_WORKER2_BADGE: u64 = 12;
pub const WINLOGON_WORKER2_STACK_MIRROR_VA: u64 = 0x0000_0100_1380_0000;
pub const WL_WORKER3_STACK_BASE: u64 = 0x0000_0100_1052_0000;
pub const WL_WORKER3_STACK_FRAMES: u64 = 8;
pub const WL_WORKER3_IPCBUF_VA: u64 = 0x0000_0100_1054_0000;
pub const WL_WORKER3_TEB_VA: u64 = 0x0000_0100_1055_0000;
pub const WL_WORKER3_TRAMP_VA: u64 = 0x0000_0100_1057_0000;
pub const WL_WORKER3_ENV_SCRATCH_VA: u64 = 0x0000_0100_107D_0000;
pub const WINLOGON_WORKER3_BADGE: u64 = 13;
static HOSTED_STACK_MIRROR_PT_BITS: AtomicU64 = AtomicU64::new(0);
pub const WINLOGON_WORKER3_STACK_MIRROR_VA: u64 = 0x0000_0100_1388_0000;
// --- services' RPC listener thread (the SCM's ScmStartRpcServer io_thread). Runs in services' OWN
// pml4 (pi 3) at the SAME target VSpace VAs as WL_LISTENER (isolated per-VSpace); its executive-side
// env-scratch + stack-mirror must be DISTINCT. Unlike WL_LISTENER (suspended), this one RESUMES and
// its faults route into the main service loop keyed by SVC_LISTENER_BADGE (the N-threads multiplex).
pub const SVC_LISTENER_STACK_BASE: u64 = SM_STACK_BASE; // services VSpace (own pml4)
pub const SVC_LISTENER_STACK_FRAMES: u64 = 8;
pub const SVC_LISTENER_IPCBUF_VA: u64 = SM_IPCBUF_VA;
pub const SVC_LISTENER_TEB_VA: u64 = SM_TEB_VA;
pub const SVC_LISTENER_TRAMP_VA: u64 = SM_TRAMP_VA;
/// Executive scratch (3 pages) — distinct from WL_LISTENER (0x1072). FILEBUF PT.
pub const SVC_LISTENER_ENV_SCRATCH_VA: u64 = 0x0000_0100_1073_0000;
/// Executive-side stack mirror for services' listener (so its syscall out-params / arg reads route to
/// its OWN stack, not services' main-thread stack). Distinct 8-page window.
pub const SVC_LISTENER_STACK_MIRROR_VA: u64 = 0x0000_0100_1360_0000;
/// The fault-EP badge for services' RPC listener thread — the main loop maps it to (pi 3, listener),
/// switching ACTIVE_STACK_MIRROR to the listener's mirror. The N-threads-per-process sub-selection.
pub const SVC_LISTENER_BADGE: u64 = 7;
// --- lsass' LSA server thread(s) (StartAuthenticationPort / LsapRmServerThread, created by lsass'
// LsapInitDatabase via NtCreateThread). Runs in lsass' OWN pml4 (pi 4) at the SAME target VSpace VAs
// as the SM/SVC listeners (isolated per-VSpace); its executive-side env-scratch + stack-mirror must be
// DISTINCT. RESUMES + faults route into the main service loop keyed by LSASS_LISTENER_BADGE (the
// N-threads multiplex — the SERVICE-9 C-c pattern replicated for lsass).
pub const LSASS_LISTENER_STACK_BASE: u64 = SM_STACK_BASE; // lsass VSpace (own pml4)
pub const LSASS_LISTENER_STACK_FRAMES: u64 = 8;
pub const LSASS_LISTENER_IPCBUF_VA: u64 = SM_IPCBUF_VA;
pub const LSASS_LISTENER_TEB_VA: u64 = SM_TEB_VA;
pub const LSASS_LISTENER_TRAMP_VA: u64 = SM_TRAMP_VA;
/// Executive scratch (3 pages) — distinct from SVC_LISTENER (0x1073) / lsass-main env (0x1077). FILEBUF PT.
pub const LSASS_LISTENER_ENV_SCRATCH_VA: u64 = 0x0000_0100_1079_0000;
/// Executive-side stack mirror for lsass' listener (its syscall out-params / arg reads route to its OWN
/// stack, not lsass' main-thread stack). Distinct 8-page window (past SVC_LISTENER's 0x1360).
pub const LSASS_LISTENER_STACK_MIRROR_VA: u64 = 0x0000_0100_1368_0000;
/// The fault-EP badge for lsass' LSA server thread — the main loop maps it to (pi 4, listener),
/// switching ACTIVE_STACK_MIRROR to the listener's mirror. The N-threads-per-process sub-selection.
pub const LSASS_LISTENER_BADGE: u64 = 9;
// --- lsass' SECOND LSA server thread (LsapRmServerThread — lsass creates TWO server threads in
// LsapInitDatabase: StartAuthenticationPort then LsapRmServerThread). It runs in lsass' pml4 (pi 4) too,
// so it needs its OWN target-VSpace VAs (a distinct TEB → distinct GS base, distinct stack/tramp/ipcbuf)
// plus distinct executive-side env-scratch + stack-mirror. Same multiplex, badge LSASS_LISTENER2_BADGE.
pub const LSASS_LISTENER2_STACK_BASE: u64 = 0x0000_0100_104C_0000; // lsass VSpace (own pml4), 0x1040 PT
pub const LSASS_LISTENER2_STACK_FRAMES: u64 = 8;
pub const LSASS_LISTENER2_IPCBUF_VA: u64 = 0x0000_0100_104E_0000;
pub const LSASS_LISTENER2_TEB_VA: u64 = 0x0000_0100_104F_0000; // 2 pages
pub const LSASS_LISTENER2_TRAMP_VA: u64 = 0x0000_0100_1051_0000;
/// Executive scratch (3 pages) — distinct from LSASS_LISTENER (0x1079). FILEBUF PT.
pub const LSASS_LISTENER2_ENV_SCRATCH_VA: u64 = 0x0000_0100_107A_0000;
/// Executive-side stack mirror for lsass' 2nd server thread. Distinct 8-page window (past 0x1368).
pub const LSASS_LISTENER2_STACK_MIRROR_VA: u64 = 0x0000_0100_1370_0000;
/// The fault-EP badge for lsass' 2nd LSA server thread.
pub const LSASS_LISTENER2_BADGE: u64 = 10;
pub const LSASS_LISTENER3_STACK_BASE: u64 = WL_WORKER3_STACK_BASE;
pub const LSASS_LISTENER3_STACK_FRAMES: u64 = WL_WORKER3_STACK_FRAMES;
pub const LSASS_LISTENER3_IPCBUF_VA: u64 = WL_WORKER3_IPCBUF_VA;
pub const LSASS_LISTENER3_TEB_VA: u64 = WL_WORKER3_TEB_VA;
pub const LSASS_LISTENER3_TRAMP_VA: u64 = WL_WORKER3_TRAMP_VA;
pub const LSASS_LISTENER3_ENV_SCRATCH_VA: u64 = 0x0000_0100_107E_0000;
pub const LSASS_LISTENER3_STACK_MIRROR_VA: u64 = 0x0000_0100_1390_0000;
pub const LSASS_LISTENER3_BADGE: u64 = 14;
/// ntdll's NtAllocateVirtualMemory system-service number (from its export stub).
pub const SSN_NT_ALLOCATE_VM: u64 = 0x12;
/// ReactOS x64 `ntoskrnl/sysfuncs.lst` zero-based service numbers for the global atom family.
pub const SSN_NT_ADD_ATOM: u64 = 8;
pub const SSN_NT_DELETE_ATOM: u64 = 62;
pub const SSN_NT_FIND_ATOM: u64 = 80;
pub const SSN_NT_QUERY_INFORMATION_ATOM: u64 = 157;
/// Fixed, allocation-free storage for the executive-lifetime global atom table.
pub const GLOBAL_ATOM_CAPACITY: usize = 32;
/// ntdll's NtQuerySystemInformation SSN (RtlCreateHeap needs SystemBasicInformation).
pub const SSN_NT_QUERY_SYSTEM_INFO: u64 = 0xb5;
/// ntdll's NtQueryVirtualMemory SSN (LdrpInitialize queries the region at [TEB+0x10] early).
pub const SSN_NT_QUERY_VIRTUAL_MEM: u64 = 186;
/// ntdll's NtQuerySystemTime SSN (csrss init reads the clock during CsrServerInitialization).
pub const SSN_NT_QUERY_SYSTEM_TIME_SVC: u64 = 182;
/// ReactOS x64 NtDelayExecution(Alertable, *DelayInterval).
pub const SSN_NT_DELAY_EXECUTION: u64 = 61;
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
/// ntdll's NtEnumerateKey SSN (winlogon's StartRpcServer path enumerates subkeys).
pub const SSN_NT_ENUMERATE_KEY: u64 = 75;
pub const SSN_NT_QUERY_KEY: u64 = 167;
/// ntdll's NtCreateFile SSN (rpcrt4's ncacn_np client opens \Device\NamedPipe\lsarpc; lsass pi 4).
pub const SSN_NT_CREATE_FILE: u64 = 39;
/// ReactOS completion-port syscall family (`sysfuncs.lst` line minus one).
pub const SSN_NT_CREATE_IO_COMPLETION: u64 = 40;
pub const SSN_NT_OPEN_IO_COMPLETION: u64 = 123;
pub const SSN_NT_QUERY_IO_COMPLETION: u64 = 166;
pub const SSN_NT_REMOVE_IO_COMPLETION: u64 = 198;
pub const SSN_NT_SET_IO_COMPLETION: u64 = 241;
/// ntdll's NtCreateNamedPipeFile SSN (rpcrt4's ncacn_np server creates \pipe\winreg).
pub const SSN_NT_CREATE_NAMED_PIPE_FILE: u64 = 46;
/// ntdll's NtFsControlFile SSN (rpcrt4's pipe listen/connect FSCTLs).
pub const SSN_NT_FS_CONTROL_FILE: u64 = 88;
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
/// NtQueryDirectoryObject SSN (sysfuncs.lst line 153 = SSN 152). ntdll's named-object path
/// enumerates \BaseNamedObjects when services' SCM CreateEventW resolves a named event.
pub const SSN_NT_QUERY_DIRECTORY_OBJECT: u64 = 152;
/// NtOpenEvent SSN (sysfuncs.lst line 121 = SSN 120). CreateEventW's ERROR_ALREADY_EXISTS
/// fallback + OpenEventW open an existing named event in \BaseNamedObjects.
pub const SSN_NT_OPEN_EVENT: u64 = 120;
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
// ★ BATCH 22 demand-fault scratch layout. The old scheme packed all 5 processes' scratch into the
// single 8-PT span 0x1100..0x1200 with ~512-page inter-process spacing — too tight now that the
// BATCH bulk-fill lets a process (lsass) page in its full LSA-init DLL tree (thousands of pages;
// each fill takes a UNIQUE monotonic scratch slot). Each process now gets its OWN 64 MiB window
// (0x400_0000 = 16384 pages, well above FAULT_CAP) in the free high VA region past all other
// executive mappings (POOL_VADDR 0x1500, SRVBUF 0x1400, win32k pools 0x0A00 — all far below
// 0x2000). Their page tables are mapped per-window at spawn (see `map_demand_scratch_pts`).
pub const DEMAND_SCRATCH_WINDOW: u64 = 0x0400_0000; // 64 MiB per process
// Base sits PAST the executive's own heap (`allocator::HEAP_BASE` = 0x2000_0000, 2 MiB) and every
// other executive mapping, and the 5 × 64 MiB windows (→ 0x3500_0000) stay inside the first 1 GiB
// page directory (0..0x4000_0000, already present — the heap + old scratch PTs live in it), so
// `map_demand_scratch_pts` needs to create only PTs, not a fresh PD/PDPT.
pub const SMSS_SCRATCH_BASE: u64 = 0x0000_0100_2100_0000;
/// csrss's demand-fault scratch window (own 64 MiB, PTs mapped at spawn).
pub const CSRSS_SCRATCH_BASE: u64 = SMSS_SCRATCH_BASE + DEMAND_SCRATCH_WINDOW;
/// Fault-endpoint badge for the THIRD hosted process (winlogon). Distinct from smss (0) + csrss (2).
pub const WINLOGON_BADGE: u64 = 4;
/// winlogon's demand-fault scratch window (own 64 MiB).
pub const WINLOGON_SCRATCH_BASE: u64 = SMSS_SCRATCH_BASE + 2 * DEMAND_SCRATCH_WINDOW;
/// Fault-endpoint badge for the FOURTH hosted process (services.exe). Distinct from smss (0) /
/// csrss (2) / winlogon (4).
pub const SERVICES_BADGE: u64 = 6;
/// services.exe's demand-fault scratch window (own 64 MiB).
pub const SERVICES_SCRATCH_BASE: u64 = SMSS_SCRATCH_BASE + 3 * DEMAND_SCRATCH_WINDOW;
/// Fault-endpoint badge for the FIFTH hosted process (lsass.exe). Distinct from smss(0)/csrss(2)/
/// winlogon(4)/services(6)/SVC_LISTENER(7).
pub const LSASS_BADGE: u64 = 8;
/// lsass.exe's demand-fault scratch window (own 64 MiB) — sized so lsass's full LSA-init DLL tree
/// (lsasrv/samsrv/msv1_0 + deps) can page in without overflowing into a neighbour's scratch.
pub const LSASS_SCRATCH_BASE: u64 = SMSS_SCRATCH_BASE + 4 * DEMAND_SCRATCH_WINDOW;
/// Upper bound on the number of hosted-process slots (process index `pi`) the executive's fixed-size
/// per-process arrays are sized for. The 5 current processes (smss/csrss/winlogon/services/lsass =
/// pi 0..4) are live; the extra headroom is for the post-login processes (userinit, explorer, the
/// shell, …) that spawn as the boot advances past the login. Every fixed `[_; MAX_PI]` per-pi array
/// (PM_PIDS/PM_TIDS/PM_POOL_TID, PFILLED, the service_sec_image `procs`/`dll_pd_created`/
/// `dll_pt_bits` locals) is sized to this so a 6th/7th hosted process never silently overflows a
/// per-process slot. The pi-indexed WRITE sites guard `pi < MAX_PI` and panic LOUDLY (never a silent
/// spin) if a spawn ever exceeds this — bump `MAX_PI` (a scalar cost) or move to a per-pid map. The
/// per-pi VA-LAYOUT still uses distinct fixed windows per process (SCRATCH_BASE / *_MIRROR_VA above),
/// so a fully-dynamic pi > current requires assigning those windows too (the follow-up); this ceiling
/// makes the SLOT arrays ready and the overflow LOUD in the meantime.
pub const MAX_PI: usize = 16;
/// Hosted-process DLL VA arena. Images receive stable bases at activation and pack at Windows'
/// 64 KiB granularity. The arena ends at the win32k client window, stays below NLS at 0xA000_0000,
/// and remains inside the existing 0x8000_0000..0xC000_0000 1 GiB PD range. csrsrv activates first
/// and therefore retains its preferred 0x8000_0000 base.
pub const DLL_ARENA_START: u64 = 0x0000_0000_8000_0000;
pub const DLL_ARENA_END: u64 = 0x0000_0000_9800_0000;
pub const DLL_ARENA_PT_COUNT: usize =
    ((DLL_ARENA_END - DLL_ARENA_START) / nt_dll_registry::PAGE_TABLE_SPAN) as usize;
pub const DLL_ARENA_PT_WORDS: usize = (DLL_ARENA_PT_COUNT + 63) / 64;
/// Heap-backed metadata capacity. The staged System32 corpus contains 449 DLLs totaling only
/// 111 MiB after 64 KiB alignment, so 512 entries cover it while the bounded arena guards VA use.
pub const DLL_REG_COUNT: usize = 512;
const _: () = assert!(DLL_ARENA_END == win32k_subsystem::CSRSS_W32_SHARED_VA);
const _: () = assert!(DLL_ARENA_PT_COUNT == 192);
const _: () = assert!(DLL_ARENA_PT_WORDS * 64 >= DLL_ARENA_PT_COUNT);
const _: () = assert!(DLL_ARENA_START >= 0x8000_0000 && DLL_ARENA_END <= 0xC000_0000);
const _: () = assert!(win32k_subsystem::CSRSS_W32_SHARED_VA
    + win32k_subsystem::WIN32K_HEAP_FRAMES * 0x1000 <= 0xA000_0000);
/// Slots PINNED (eagerly loaded + registered at BOOT, NOT demand-loaded). The FLAGGED IRREDUCIBLE
/// MINIMUM — every OTHER System32 DLL demand-loads on the fly. Two reasons a DLL must be pinned:
///   • **csrsrv** (slot 0) — needs base 0x8000_0000 (its preferred ImageBase → relocation delta 0 →
///     byte-identical shared text, loader never relocates it). Demand-load assigns slots in
///     loader-request order, which can't guarantee csrsrv lands at slot 0.
///   • **the `_vista` forwarder DLLs + ws2help** — these are loaded by ntdll's loader via the
///     FORWARDER path in `LdrpSnapThunk`/`ldrpe.c` (e.g. advapi32 exports `RegDeleteTreeW` as a
///     forwarder to `advapi32_vista.RegDeleteTreeW`). That forwarder resolution can fail BEFORE it
///     ever reaches NtOpenFile (SxS/actctx redirection returns 0xC0000034 with no implicit act ctx),
///     so the demand-load hook (which fires on the NtOpenFile resolve-miss) never sees the request →
///     the snap fails fatally (observed: "Failed to snap advapi32_vista.dll!RegDeleteTreeW for
///     rpcrt4.dll" → NtRaiseHardError). Pre-registering them means the loader finds them already
///     loaded (`LdrpCheckForLoadedDll` hits) and skips the fragile forwarder-open path. This is a
///     loader limitation, not a demand-load bug — documented pin, not a maintained content list.
/// Every leaf DLL (kernel32/user32/gdi32/advapi32/rpcrt4/msvcrt/ws2_32/basesrv/winsrv + lsass'
/// lsasrv/samsrv/msv1_0 + all P5+ binaries) demand-loads with NO edit here.
pub const DLL_PIN_COUNT: usize = 4;
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
const HPET_GEN_INT_STATUS: u64 = 0x20;
const HPET_T0_CONFIG: u64 = 0x100;
const HPET_T0_COMPARATOR: u64 = 0x108;
/// The executive's own IPC buffer VA (from BootInfo) — stages reply message registers 4+.
static IPC_BUFFER: AtomicU64 = AtomicU64::new(0);
/// The executive stack-mirror base for the process whose fault/syscall is currently being serviced.
/// The 2-process service loop sets this at the top of each iteration (smss vs csrss) so the shared
/// smss_stack_read/write helpers read+write the RIGHT process's stack.
static ACTIVE_STACK_MIRROR: AtomicU64 = AtomicU64::new(SMSS_STACK_MIRROR_VA);
static ACTIVE_STACK_BASE: AtomicU64 = AtomicU64::new(STACK_BASE);
static ACTIVE_STACK_SIZE: AtomicU64 = AtomicU64::new(STACK_FRAMES * 0x1000);
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

/// ═══ Checkpoint B: real reply-cap parking for NtWaitForSingleObject on unsignaled events ═══
/// A parked waiter = a hosted thread that issued `NtWaitForSingleObject` on an event whose
/// `signalled` flag is 0. Instead of returning STATUS_WAIT_0 with the thread still runnable (the
/// old immediate-return stub, which made rpcrt4/winlogon proceed on unsatisfied state), the service
/// loop DOESN'T reply — the thread stays blocked in-kernel on its Call. To keep it bound while the
/// loop keeps receiving other callers, we can't re-use the single REPLY_MAIN reply object for the
/// next recv (that would rebind + orphan the parked caller), so the loop STEALS the reply object that
/// received this caller into a waiter slot and rotates REPLY_MAIN_SLOT to a fresh POOL object for
/// subsequent recvs. On `NtSetEvent(that event)` the loop does `send_on_reply(stolen_cap, WAIT_0)` to
/// wake exactly that parked caller, then returns the reply object to the pool. No new kernel
/// primitive — reuses the existing MCS reply-cap machinery (recv-with-r12 + Send-on-reply).
const WAIT_REPLY_POOL_N: usize = 8;
/// The pool of spare MCS Reply objects (cptrs) allocated at boot. Index 0 is the "active" one
/// currently installed in REPLY_MAIN_SLOT; the rest are free spares. A park swaps the active out
/// (into a waiter slot) and installs a free spare as the new active.
static WAIT_REPLY_POOL: [AtomicU64; WAIT_REPLY_POOL_N] =
    [const { AtomicU64::new(0) }; WAIT_REPLY_POOL_N];
/// Free/used bitmap for the pool (bit i set = pool[i] is currently the active REPLY_MAIN or is held
/// by a parked waiter). Managed by wait_park / wait_wake_event.
static WAIT_REPLY_POOL_USED: AtomicU64 = AtomicU64::new(0);
/// The waiter queue: each slot parks one blocked caller.
///
/// A single-object wait (NtWaitForSingleObject) records ONE event in slot 0 of its event set
/// (count 1); a multi-object wait (NtWaitForMultipleObjects) records up to `WAITER_MAX_EVENTS`
/// obj_ns event indices + a `wait_all` flag. `WAITER_EVENT_IDX[i]` == u32::MAX means the slot is free
/// (it doubles as event[0]). Fixed-capacity; parking past capacity falls back to the immediate-return
/// path (documented, never a hang).
const WAITER_N: usize = 16;
/// Max events a single multi-object waiter can wait on (NT MAXIMUM_WAIT_OBJECTS is 64; rpcrt4's
/// np/sock server wait arrays are small — mgr_event + a handful of listen events — so 8 is ample and
/// keeps the .bss table compact). Waits with more objects fall back to the immediate path.
const WAITER_MAX_EVENTS: usize = 8;
/// event[0] of each waiter's set (u32::MAX = free slot). Kept as the slot-free sentinel for backward
/// compat with the single-object callers/spec.
static WAITER_EVENT_IDX: [AtomicU64; WAITER_N] = [const { AtomicU64::new(u64::MAX) }; WAITER_N];
/// The FULL event set for a multi-object waiter (event[1..count]; event[0] is WAITER_EVENT_IDX).
static WAITER_EVENTS: [[AtomicU64; WAITER_MAX_EVENTS]; WAITER_N] =
    [const { [const { AtomicU64::new(u64::MAX) }; WAITER_MAX_EVENTS] }; WAITER_N];
/// Number of events in this waiter's set (1 for a single-object wait).
static WAITER_EVENT_COUNT: [AtomicU64; WAITER_N] = [const { AtomicU64::new(0) }; WAITER_N];
/// Wait mode: 0 = WaitAny (WAIT_TYPE WaitAnyObject — wake on the first signalled event, return its
/// index as STATUS_WAIT_0+i), 1 = WaitAll (wake only when ALL events are signalled, return WAIT_0).
static WAITER_WAIT_ALL: [AtomicU64; WAITER_N] = [const { AtomicU64::new(0) }; WAITER_N];
static WAITER_REPLY_CAP: [AtomicU64; WAITER_N] = [const { AtomicU64::new(0) }; WAITER_N];
static WAITER_TID: [AtomicU64; WAITER_N] = [const { AtomicU64::new(0) }; WAITER_N];
/// Monotonic 100ns deadline (`u64::MAX` = infinite) for finite event waits.
static WAITER_DEADLINE: [AtomicU64; WAITER_N] = [const { AtomicU64::new(u64::MAX) }; WAITER_N];
/// The parked waiter's syscall resume context (RCX/RSP/RFLAGS): a native-syscall (UnknownSyscall)
/// fault is resumed by an apply_fault_reply that restores RCX←resume_ip, RSP←sp, RFLAGS←flags and
/// RAX/r10←status. The service loop sets these in the IPC buffer at reply time, so we must snapshot
/// them per-waiter at park and re-install them (set_reply_mr 15/16/17) before the wake send.
static WAITER_RESUME_IP: [AtomicU64; WAITER_N] = [const { AtomicU64::new(0) }; WAITER_N];
static WAITER_RESUME_SP: [AtomicU64; WAITER_N] = [const { AtomicU64::new(0) }; WAITER_N];
static WAITER_RESUME_FLAGS: [AtomicU64; WAITER_N] = [const { AtomicU64::new(0) }; WAITER_N];
/// Diagnostics/proof counters for the specs: how many waiters have been parked and woken.
static WAIT_PARKED_COUNT: AtomicU64 = AtomicU64::new(0);
static WAIT_WOKEN_COUNT: AtomicU64 = AtomicU64::new(0);
const DELAY_WAITER_N: usize = WAIT_REPLY_POOL_N - 1;
const DELAY_TIMER_BADGE: u64 = 0x4000_0000_0000_0000;
const DELAY_TIMER_IRQ: u64 = 12;
const LBL_TCB_BIND_NOTIFICATION: u64 = 14;
const LBL_TCB_UNBIND_NOTIFICATION: u64 = 15;
const LBL_IRQ_ACK: u64 = 31;
const NT_SYSTEM_TIME_BOOT_100NS: u64 = 0x01DA_0000_0000_0000;
static HPET_PERIOD_FS: AtomicU64 = AtomicU64::new(0);
static DELAY_TIMER_HANDLER: AtomicU64 = AtomicU64::new(0);
static DELAY_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static DELAY_PARKED_COUNT: AtomicU64 = AtomicU64::new(0);
static DELAY_WOKEN_COUNT: AtomicU64 = AtomicU64::new(0);
static DELAY_OTHER_BADGE_PROGRESS: AtomicU64 = AtomicU64::new(0);
static DELAY_TIMER_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
/// Set once lsass signals LSA_RPC_SERVER_ACTIVE (its essential init is complete: the LSA RPC server is
/// up). After this, an unrecoverable fault on lsass' MAIN thread (e.g. rpcrt4 NdrSimpleTypeUnmarshall
/// dereferencing a bogus request buffer while servicing a self-directed RPC) is CONTAINED (the loop
/// parks that thread) instead of stopping the boot — lsass has already done its job for the milestone
/// (winlogon's WaitForLsass can now wake), so the boot advances to winlogon's login path.
static LSA_RPC_SERVER_ACTIVE_SIGNALLED: AtomicU64 = AtomicU64::new(0);
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
/// General NtCreateThread: a dedicated fault endpoint the RPC-listener (and any future park-only Nth
/// thread) faults to — NO standing receiver, so the thread PARKS on its first fault (its real TEB
/// stays mapped + queryable by the main thread). 0 = not yet retyped. Distinct from SM/CSR EPs so a
/// listener fault never lands in the SM/CSR rendezvous receivers.
static WL_LISTENER_FAULT_EP: AtomicU64 = AtomicU64::new(0);
/// The winlogon RPC-listener thread's TCB (0 until winlogon's first NtCreateThread spawns it).
static WL_LISTENER_TCB: AtomicU64 = AtomicU64::new(0);
static WL_WORKER2_TCB: AtomicU64 = AtomicU64::new(0);
static WL_WORKER3_TCB: AtomicU64 = AtomicU64::new(0);
/// The listener thread's real ETHREAD tid (a pool ETHREAD popped at NtCreateThread), and a count of
/// real threads created through the general NtCreateThread path (for the counted spec).
static PM_LISTENER_TID: AtomicU64 = AtomicU64::new(0);
static WL_WORKER2_TID: AtomicU64 = AtomicU64::new(0);
static WL_WORKER3_TID: AtomicU64 = AtomicU64::new(0);
static PM_GENERAL_THREADS_CREATED: AtomicU64 = AtomicU64::new(0);
static THREAD_LIFECYCLE_TRACE_N: AtomicU64 = AtomicU64::new(0);
static THREAD_QUERY_TRACE_N: AtomicU64 = AtomicU64::new(0);
static EVENT_TRACE_N: AtomicU64 = AtomicU64::new(0);
/// services' RPC listener thread — its TCB (0 until services' NtCreateThread spawns it) + a request
/// flag the loop reads to spawn+RESUME it, and a count of listener faults serviced (multiplex proof).
static SVC_LISTENER_TCB: AtomicU64 = AtomicU64::new(0);
static SVC_LISTENER_TID: AtomicU64 = AtomicU64::new(0);
static SVC_LISTENER_FAULTS: AtomicU64 = AtomicU64::new(0);
/// lsass' LSA server thread — same shape as SVC_LISTENER, for pi 4 (the N-threads multiplex).
static LSASS_LISTENER_TCB: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER_TID: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER_FAULTS: AtomicU64 = AtomicU64::new(0);
/// lsass' SECOND LSA server thread (LsapRmServerThread).
static LSASS_LISTENER2_TCB: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER2_TID: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER2_FAULTS: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER3_TCB: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER3_TID: AtomicU64 = AtomicU64::new(0);
static LSASS_LISTENER3_FAULTS: AtomicU64 = AtomicU64::new(0);
/// Multiplex-event counter for winlogon's rpcrt4 server WORKER thread (badge WINLOGON_WORKER_BADGE).
/// Proves the worker actually RUNS (not suspended) — spec `exec_winlogon_worker_multiplex`.
static WL_WORKER_FAULTS: AtomicU64 = AtomicU64::new(0);
/// Set once the main thread has queried the real listener thread's TEB/ClientId via
/// NtQueryInformationThread(ThreadBasicInformation) — proves the NULL-deref is gone.
static WL_LISTENER_TEB_QUERIED: AtomicU64 = AtomicU64::new(0);

/// Per-hosted-process demand-fill bookkeeping (page VA per fault index), one row per process
/// (0 = smss, 1 = csrss, 2 = winlogon, 3 = services, 4 = lsass; MAX_PI rows for post-login growth).
/// Kept off the 16 KiB rootserver stack — this array as a local plus service_sec_image's other
/// arrays would risk the guard page. In `.bss`, so growth to MAX_PI is free (no stack cost).
/// Zeroed at service_sec_image entry; only that single loop touches it.
static mut PFILLED: [[u64; 256]; MAX_PI] = [[0u64; 256]; MAX_PI];
/// SERVICE 10 stack relief: the per-iteration `filled_pages` WORKING buffer (loaded from / saved to
/// `PFILLED[pi]` around each dispatch) lives in a static, not on the 16 KiB rootserver stack. Adding a
/// 5th hosted process pushed `service_sec_image`'s frame — its `[u64;256]` working array plus the
/// ~20 DLL-PE locals — over the stack guard on the DEEP FS-walk call chain (fat_open_path →
/// dir_find_lfn), corrupting that loop's cluster variable → an infinite FAT cluster-chain spin
/// (100% CPU, no panic). Single-threaded executive → one active pi per iteration → one shared buffer
/// is safe. Removing this 2 KiB from the frame keeps the boot within the 4-page stack (no kernel
/// change → sel4test byte-identical).
static mut FILLED_WORK: [u64; 256] = [0u64; 256];

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
/// Map the page tables backing one hosted process's 64 MiB demand-fault scratch window
/// (`*_SCRATCH_BASE`) in the executive's own VSpace. Each demand fill takes a UNIQUE monotonic
/// scratch slot within this window (`scratch_base + faults*0x1000`), so it must cover FAULT_CAP
/// pages; 16 PTs = 8192 pages > FAULT_CAP (6000). Called once per process at spawn.
pub(crate) unsafe fn map_demand_scratch_pts(base: u64) {
    for k in 0..16u64 {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, base + k * 0x20_0000, CAP_INIT_THREAD_VSPACE);
    }
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
/// CNodeRevoke on the cap at `idx` under the root CNode: delete all its descendants (and, for an
/// Untyped cap, roll its `free_index` back to 0 = full-capacity reclamation). Mirror of
/// `cnode_delete_r`; used by the reclamation self-test to definitively reset a throwaway child
/// untyped between fill rounds (plain per-object delete didn't reset free_index under a deeper boot).
const LBL_CNODE_REVOKE: u64 = 22;
unsafe fn cnode_revoke_r(idx: u64) -> u64 {
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") CAP_INIT_THREAD_CNODE => _,
        inout("rsi") LBL_CNODE_REVOKE << 12 => reply,
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

fn monotonic_time_100ns() -> u64 {
    let period = HPET_PERIOD_FS.load(Ordering::Relaxed);
    if period != 0 {
        let ticks = unsafe { core::ptr::read_volatile((HPET_VADDR + HPET_MAIN_COUNTER) as *const u64) };
        nt_delay_execution::ticks_to_100ns(ticks, period)
    } else {
        unsafe { core::arch::x86_64::_rdtsc() / 10 }
    }
}

fn nt_system_time_100ns() -> u64 {
    NT_SYSTEM_TIME_BOOT_100NS.saturating_add(monotonic_time_100ns())
}

fn print_hex_u64(value: u64) {
    print_hex((value >> 32) as u32);
    print_hex(value as u32);
}

fn release_reply_pool_cap(cap: u64) {
    for index in 0..WAIT_REPLY_POOL_N {
        if WAIT_REPLY_POOL[index].load(Ordering::Relaxed) == cap {
            WAIT_REPLY_POOL_USED.fetch_and(!(1u64 << index), Ordering::Relaxed);
            break;
        }
    }
}

unsafe fn delay_timer_init() -> bool {
    if DELAY_TIMER_HANDLER.load(Ordering::Relaxed) != 0 {
        return true;
    }
    let period = HPET_PERIOD_FS.load(Ordering::Relaxed);
    if period == 0 {
        print_str(b"[delay] HPET unavailable; refusing nonzero immediate-success fallback\n");
        return false;
    }
    let route_cap = (core::ptr::read_volatile((HPET_VADDR + HPET_T0_CONFIG) as *const u64) >> 32) as u32;
    if route_cap == 0 {
        return false;
    }
    let already_used = 31 - route_cap.leading_zeros();
    let remaining = route_cap & !(1u32 << already_used);
    if remaining == 0 {
        print_str(b"[delay] HPET timer0 has no spare IOAPIC route\n");
        return false;
    }
    let pin = (31 - remaining.leading_zeros()) as u64;
    let notification = make_object(OBJ_NOTIFICATION);
    let badged = alloc_slot();
    let _ = syscall5(
        SYS_SEND,
        CAP_INIT_THREAD_CNODE,
        LBL_CNODE_MINT << 12,
        badged,
        notification,
        DELAY_TIMER_BADGE,
    );
    let handler = alloc_slot();
    ioapic_issue_irq_handler(handler, pin, DELAY_TIMER_IRQ, 1, 0);
    let _ = irq_handler_set_notification(handler, badged);
    // The initial root TCB cap is slot 1. Binding lets an HPET signal cancel the executive's
    // blocking Recv on the hosted-process endpoint, returning DELAY_TIMER_BADGE with empty msginfo.
    let _ = syscall5(
        SYS_SEND,
        1,
        LBL_TCB_BIND_NOTIFICATION << 12,
        notification,
        0,
        0,
    );
    core::ptr::write_volatile((HPET_VADDR + HPET_GEN_INT_STATUS) as *mut u64, 1);
    let config = (1u64 << 2) | (pin << 9);
    core::ptr::write_volatile((HPET_VADDR + HPET_T0_CONFIG) as *mut u64, config);
    let general = core::ptr::read_volatile((HPET_VADDR + HPET_GEN_CONF) as *const u64);
    core::ptr::write_volatile((HPET_VADDR + HPET_GEN_CONF) as *mut u64, general | 1);
    DELAY_TIMER_HANDLER.store(handler, Ordering::Relaxed);
    print_str(b"[delay] timer ready pin=");
    print_u64(pin);
    print_str(b" irq=");
    print_u64(DELAY_TIMER_IRQ);
    print_str(b" period_fs=");
    print_u64(period);
    print_str(b" bound_badge=0x");
    print_hex_u64(DELAY_TIMER_BADGE);
    print_str(b"\n");
    true
}

unsafe fn delay_timer_rearm(queue: &nt_delay_execution::Queue<DELAY_WAITER_N>) {
    let handler = DELAY_TIMER_HANDLER.load(Ordering::Relaxed);
    if handler == 0 {
        return;
    }
    let mut config = core::ptr::read_volatile((HPET_VADDR + HPET_T0_CONFIG) as *const u64);
    let event_deadline = (0..WAITER_N)
        .filter(|slot| WAITER_EVENT_IDX[*slot].load(Ordering::Relaxed) != u64::MAX)
        .map(|slot| WAITER_DEADLINE[slot].load(Ordering::Relaxed))
        .filter(|deadline| *deadline != u64::MAX)
        .min();
    let deadline = match (queue.next_deadline(), event_deadline) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    if let Some(deadline) = deadline {
        let period = HPET_PERIOD_FS.load(Ordering::Relaxed);
        let target = nt_delay_execution::hundred_ns_to_ticks_ceil(deadline, period);
        let now = core::ptr::read_volatile((HPET_VADDR + HPET_MAIN_COUNTER) as *const u64);
        core::ptr::write_volatile(
            (HPET_VADDR + HPET_T0_COMPARATOR) as *mut u64,
            target.max(now.saturating_add(1)),
        );
        config |= 1u64 << 1;
    } else {
        config &= !(1u64 << 1);
    }
    core::ptr::write_volatile((HPET_VADDR + HPET_T0_CONFIG) as *mut u64, config);
}

unsafe fn delay_park(
    queue: &mut nt_delay_execution::Queue<DELAY_WAITER_N>,
    deadline_100ns: u64,
    reply_cap: u64,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    thread_id: u64,
    badge: u64,
) -> bool {
    if reply_cap == 0 || !delay_timer_init() {
        return false;
    }
    let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
    let Some(fresh_index) = (0..WAIT_REPLY_POOL_N).find(|&index| {
        used & (1u64 << index) == 0 && WAIT_REPLY_POOL[index].load(Ordering::Relaxed) != 0
    }) else {
        return false;
    };
    let waiter = nt_delay_execution::Waiter {
        deadline_100ns,
        sequence: 0,
        reply_cap,
        resume_ip,
        resume_sp: sp,
        resume_flags: flags,
        thread_id,
        badge,
    };
    if queue.insert(waiter).is_err() {
        return false;
    }
    let fresh = WAIT_REPLY_POOL[fresh_index].load(Ordering::Relaxed);
    WAIT_REPLY_POOL_USED.fetch_or(1u64 << fresh_index, Ordering::Relaxed);
    REPLY_MAIN_SLOT.store(fresh, Ordering::Relaxed);
    DELAY_PARKED_COUNT.fetch_add(1, Ordering::Relaxed);
    delay_timer_rearm(queue);
    true
}

unsafe fn delay_wake_due(queue: &mut nt_delay_execution::Queue<DELAY_WAITER_N>) -> u64 {
    let now = monotonic_time_100ns();
    let mut woken = 0;
    while let Some(waiter) = queue.pop_due(now) {
        set_reply_mr(15, waiter.resume_ip);
        set_reply_mr(16, waiter.resume_sp);
        set_reply_mr(17, waiter.resume_flags);
        send_on_reply(waiter.reply_cap, 18, 0, 0, 0, 0);
        release_reply_pool_cap(waiter.reply_cap);
        woken += 1;
        let wake_number = DELAY_WOKEN_COUNT.fetch_add(1, Ordering::Relaxed);
        if wake_number < 16 {
            print_str(b"[delay] WAKE #");
            print_u64(wake_number + 1);
            print_str(b" tid=");
            print_u64(waiter.thread_id);
            print_str(b" badge=");
            print_u64(waiter.badge);
            print_str(b" deadline_100ns=");
            print_u64(waiter.deadline_100ns);
            print_str(b" now_100ns=");
            print_u64(now);
            print_str(b" status=STATUS_SUCCESS\n");
        }
    }
    delay_timer_rearm(queue);
    woken
}

unsafe fn delay_timer_interrupt(queue: &mut nt_delay_execution::Queue<DELAY_WAITER_N>) {
    core::ptr::write_volatile((HPET_VADDR + HPET_GEN_INT_STATUS) as *mut u64, 1);
    let _ = delay_wake_due(queue);
    let _ = wait_wake_due();
    delay_timer_rearm(queue);
    // Timer 0 is level-triggered. Disable/rearm the comparator and clear the status before Ack
    // unmasks the IOAPIC line; acknowledging first lets the still-asserted line immediately storm.
    core::ptr::write_volatile((HPET_VADDR + HPET_GEN_INT_STATUS) as *mut u64, 1);
    let handler = DELAY_TIMER_HANDLER.load(Ordering::Relaxed);
    if handler != 0 {
        let _ = syscall5(SYS_SEND, handler, LBL_IRQ_ACK << 12, 0, 0, 0);
    }
}

unsafe fn delay_timer_shutdown(queue: &nt_delay_execution::Queue<DELAY_WAITER_N>) {
    if DELAY_TIMER_HANDLER.load(Ordering::Relaxed) == 0 || queue.len() != 0 {
        return;
    }
    let mut config = core::ptr::read_volatile((HPET_VADDR + HPET_T0_CONFIG) as *const u64);
    config &= !(1u64 << 1);
    core::ptr::write_volatile((HPET_VADDR + HPET_T0_CONFIG) as *mut u64, config);
    core::ptr::write_volatile((HPET_VADDR + HPET_GEN_INT_STATUS) as *mut u64, 1);
    let _ = syscall5(
        SYS_SEND,
        1,
        LBL_TCB_UNBIND_NOTIFICATION << 12,
        0,
        0,
        0,
    );
}

unsafe fn delay_cancel_thread(
    queue: &mut nt_delay_execution::Queue<DELAY_WAITER_N>,
    thread_id: u64,
) {
    while let Some(waiter) = queue.pop_thread(thread_id) {
        let cap = waiter.reply_cap;
        let deleted = cnode_delete_r(cap);
        let retyped = if deleted == 0 {
            untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, cap)
        } else {
            u64::MAX
        };
        if deleted == 0 && retyped == 0 {
            release_reply_pool_cap(cap);
        }
        print_str(b"[delay] CANCEL tid=");
        print_u64(thread_id);
        print_str(b" reply=0x");
        print_hex_u64(cap);
        print_str(b" delete=");
        print_u64(deleted);
        print_str(b" retype=");
        print_u64(retyped);
        print_str(b"\n");
    }
    delay_timer_rearm(queue);
}

/// ═══ Checkpoint B park/wake helpers (real reply-cap parking) ═══
/// PARK the current caller on `event_idx`: the reply object CURRENTLY installed in REPLY_MAIN_SLOT is
/// bound (by the last recv-with-r12) to THIS caller's blocked Call, so we STEAL it into a free waiter
/// slot and rotate a fresh POOL reply object into REPLY_MAIN_SLOT so the loop's next recv binds a
/// NEW object (never rebinding/orphaning the parked one). The caller stays blocked in-kernel until
/// `wait_wake_event` sends on the stolen cap. Returns true on success; false if the pool/waiter queue
/// is exhausted (caller must then fall back to an immediate reply → never a hang).
unsafe fn wait_park(
    event_idx: usize,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    tid: u64,
    deadline: Option<u64>,
) -> bool {
    // Single-object wait = a 1-event WaitAny set.
    wait_park_multi(&[event_idx], false, resume_ip, sp, flags, tid, deadline)
}

unsafe fn wait_cancel_thread(tid: u64) {
    for slot in 0..WAITER_N {
        if WAITER_EVENT_IDX[slot].load(Ordering::Relaxed) == u64::MAX
            || WAITER_TID[slot].load(Ordering::Relaxed) != tid
        {
            continue;
        }
        let cap = WAITER_REPLY_CAP[slot].load(Ordering::Relaxed);
        if cap != 0 {
            let deleted = cnode_delete_r(cap);
            let retyped = if deleted == 0 {
                untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, cap)
            } else {
                u64::MAX
            };
            if deleted == 0 && retyped == 0 {
                release_reply_pool_cap(cap);
            }
        }
        WAITER_EVENT_IDX[slot].store(u64::MAX, Ordering::Relaxed);
        WAITER_EVENT_COUNT[slot].store(0, Ordering::Relaxed);
        WAITER_REPLY_CAP[slot].store(0, Ordering::Relaxed);
        WAITER_TID[slot].store(0, Ordering::Relaxed);
        WAITER_DEADLINE[slot].store(u64::MAX, Ordering::Relaxed);
    }
}

/// Consume the Reply object bound to the current native-syscall fault without sending on it, then
/// rotate a fresh pool object into `REPLY_MAIN_SLOT`. Deleting the bound object clears the only
/// capability that can resume this Call; the caller remains blocked until its TCB is destroyed.
/// The vacated cptr is immediately retyped as an unbound Reply object and returned to the pool.
unsafe fn drop_current_syscall_reply() -> bool {
    let active = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if active == 0 {
        return false;
    }
    let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
    let active_index = (0..WAIT_REPLY_POOL_N)
        .find(|&index| WAIT_REPLY_POOL[index].load(Ordering::Relaxed) == active);
    let fresh_index = (0..WAIT_REPLY_POOL_N).find(|&index| {
        used & (1u64 << index) == 0 && WAIT_REPLY_POOL[index].load(Ordering::Relaxed) != 0
    });
    let (active_index, fresh_index) = match (active_index, fresh_index) {
        (Some(active_index), Some(fresh_index)) => (active_index, fresh_index),
        _ => return false,
    };
    let fresh = WAIT_REPLY_POOL[fresh_index].load(Ordering::Relaxed);
    let delete = cnode_delete_r(active);
    if delete != 0 {
        print_str(b"[thread-term] reply-drop cap=0x");
        print_hex(active as u32);
        print_str(b" delete=");
        print_u64(delete);
        print_str(b"\n");
        return false;
    }
    WAIT_REPLY_POOL_USED.fetch_and(!(1u64 << active_index), Ordering::Relaxed);
    WAIT_REPLY_POOL_USED.fetch_or(1u64 << fresh_index, Ordering::Relaxed);
    REPLY_MAIN_SLOT.store(fresh, Ordering::Relaxed);
    let retype = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, active);
    if retype != 0 {
        WAIT_REPLY_POOL[active_index].store(0, Ordering::Relaxed);
    }
    print_str(b"[thread-term] reply-drop cap=0x");
    print_hex(active as u32);
    print_str(b" next=0x");
    print_hex(fresh as u32);
    print_str(b" delete=0 retype=");
    print_u64(retype);
    print_str(b"\n");
    true
}

fn hosted_thread_tcb_cell(tid: u64) -> Option<&'static AtomicU64> {
    if tid == PM_LISTENER_TID.load(Ordering::Relaxed) {
        Some(&WL_LISTENER_TCB)
    } else if tid == WL_WORKER2_TID.load(Ordering::Relaxed) {
        Some(&WL_WORKER2_TCB)
    } else if tid == WL_WORKER3_TID.load(Ordering::Relaxed) {
        Some(&WL_WORKER3_TCB)
    } else if tid == SVC_LISTENER_TID.load(Ordering::Relaxed) {
        Some(&SVC_LISTENER_TCB)
    } else if tid == LSASS_LISTENER_TID.load(Ordering::Relaxed) {
        Some(&LSASS_LISTENER_TCB)
    } else if tid == LSASS_LISTENER2_TID.load(Ordering::Relaxed) {
        Some(&LSASS_LISTENER2_TCB)
    } else if tid == LSASS_LISTENER3_TID.load(Ordering::Relaxed) {
        Some(&LSASS_LISTENER3_TCB)
    } else {
        (0..MAX_PI)
            .find(|&index| tid == PM_TIDS[index].load(Ordering::Relaxed))
            .map(|index| &PM_MAIN_TCBS[index])
    }
}

fn runtime_thread_slot(tid: u64) -> Option<(usize, usize)> {
    for pi in 0..MAX_PI {
        for slot in 0..PM_RUNTIME_THREAD_SLOTS {
            if PM_POOL_TID[pi][slot].load(Ordering::Relaxed) == tid {
                return Some((pi, slot));
            }
        }
    }
    None
}

unsafe fn terminate_hosted_thread_mechanism(
    tid: u64,
    delay_queue: &mut nt_delay_execution::Queue<DELAY_WAITER_N>,
) -> bool {
    let cell = match hosted_thread_tcb_cell(tid) {
        Some(cell) => cell,
        None => return false,
    };
    let tcb = cell.load(Ordering::Relaxed);
    if tcb <= 1 {
        return false;
    }
    delay_cancel_thread(delay_queue, tid);
    wait_cancel_thread(tid);
    let suspend = tcb_suspend_r(tcb);
    let delete = if suspend == 0 {
        cnode_delete_r(tcb)
    } else {
        u64::MAX
    };
    print_str(b"[thread-term] mechanism tid=");
    print_u64(tid);
    print_str(b" tcb=0x");
    print_hex(tcb as u32);
    print_str(b" suspend=");
    print_u64(suspend);
    print_str(b" delete=");
    print_u64(delete);
    print_str(b"\n");
    if suspend == 0 && delete == 0 {
        cell.store(0, Ordering::Relaxed);
        PM_TERMINATE_THREAD_TCB_RECLAIMED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// GENERAL park: block the current caller on a SET of obj_ns events (`events`), with `wait_all`
/// selecting WaitAll (wake when all signalled → WAIT_0) vs WaitAny (wake on the first signalled →
/// WAIT_0+index). Steals this caller's bound reply object (REPLY_MAIN) into a free waiter slot and
/// rotates a fresh pool object into REPLY_MAIN so subsequent recvs bind a new object. Returns true on
/// success; false if the pool/queue is exhausted OR the set is too large (`events.len() >
/// WAITER_MAX_EVENTS`) → the caller must then fall back to an immediate reply (never a hang).
unsafe fn wait_park_multi(
    events: &[usize],
    wait_all: bool,
    resume_ip: u64,
    sp: u64,
    flags: u64,
    tid: u64,
    deadline: Option<u64>,
) -> bool {
    if events.is_empty() || events.len() > WAITER_MAX_EVENTS {
        return false;
    }
    // Find a free waiter slot.
    let mut wslot = usize::MAX;
    for i in 0..WAITER_N {
        if WAITER_EVENT_IDX[i].load(Ordering::Relaxed) == u64::MAX {
            wslot = i;
            break;
        }
    }
    if wslot == usize::MAX {
        return false;
    }
    // The reply object bound to this caller is the active REPLY_MAIN.
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if stolen == 0 {
        return false;
    }
    // Find a FREE pool object to become the new active REPLY_MAIN. The stolen one is (still) marked
    // used; we need a different free bit.
    let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
    let mut fresh = 0u64;
    let mut fresh_bit = 0usize;
    for i in 0..WAIT_REPLY_POOL_N {
        if used & (1u64 << i) == 0 {
            let cp = WAIT_REPLY_POOL[i].load(Ordering::Relaxed);
            if cp != 0 {
                fresh = cp;
                fresh_bit = i;
                break;
            }
        }
    }
    if fresh == 0 {
        return false; // pool exhausted → caller reports STATUS_INSUFFICIENT_RESOURCES
    }
    // Commit: record the waiter's event set + its syscall resume context, install the fresh object as
    // the active recv reply cap.
    for (k, &ev) in events.iter().enumerate() {
        WAITER_EVENTS[wslot][k].store(ev as u64, Ordering::Relaxed);
    }
    for k in events.len()..WAITER_MAX_EVENTS {
        WAITER_EVENTS[wslot][k].store(u64::MAX, Ordering::Relaxed);
    }
    WAITER_EVENT_COUNT[wslot].store(events.len() as u64, Ordering::Relaxed);
    WAITER_WAIT_ALL[wslot].store(wait_all as u64, Ordering::Relaxed);
    WAITER_REPLY_CAP[wslot].store(stolen, Ordering::Relaxed);
    WAITER_TID[wslot].store(tid, Ordering::Relaxed);
    WAITER_DEADLINE[wslot].store(deadline.unwrap_or(u64::MAX), Ordering::Relaxed);
    WAITER_RESUME_IP[wslot].store(resume_ip, Ordering::Relaxed);
    WAITER_RESUME_SP[wslot].store(sp, Ordering::Relaxed);
    WAITER_RESUME_FLAGS[wslot].store(flags, Ordering::Relaxed);
    // WAITER_EVENT_IDX doubles as the slot-free sentinel: set it LAST (after the set) so a slot never
    // looks "used but empty".
    WAITER_EVENT_IDX[wslot].store(events[0] as u64, Ordering::Relaxed);
    WAIT_REPLY_POOL_USED.fetch_or(1u64 << fresh_bit, Ordering::Relaxed);
    REPLY_MAIN_SLOT.store(fresh, Ordering::Relaxed);
    WAIT_PARKED_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// WAKE every waiter whose wait condition is now satisfied, given the obj_ns event table. `just_set`
/// is the event index just signalled (drives WaitAny index selection). AUTO-RESET events consumed by
/// a wake have their `signalled` flag cleared (NT auto-reset semantics — e.g. rpcrt4's mgr_event /
/// server_ready_event). Returns the number woken. Called from the NtSetEvent handler after setting the
/// event's `signalled` flag.
unsafe fn wait_wake_event_set(just_set: usize, events: &mut EventStore) -> u64 {
    let mut woken = 0u64;
    for i in 0..WAITER_N {
        let slot_ev0 = WAITER_EVENT_IDX[i].load(Ordering::Relaxed);
        if slot_ev0 == u64::MAX {
            continue; // free slot
        }
        let count = WAITER_EVENT_COUNT[i].load(Ordering::Relaxed) as usize;
        if count == 0 {
            continue;
        }
        let wait_all = WAITER_WAIT_ALL[i].load(Ordering::Relaxed) != 0;
        // Does this waiter's condition hold, and if WaitAny, which index fired?
        let mut wake = false;
        let mut wake_index = 0u64;
        if wait_all {
            // Wake only when ALL events in the set are signalled.
            let mut all = true;
            for k in 0..count.min(WAITER_MAX_EVENTS) {
                let ev = WAITER_EVENTS[i][k].load(Ordering::Relaxed) as usize;
                if !events.read_state(ev as u64) {
                    all = false;
                    break;
                }
            }
            wake = all;
            wake_index = 0; // WaitAll returns WAIT_OBJECT_0
        } else {
            // WaitAny: the first (lowest-index) signalled event determines the return value. `just_set`
            // is guaranteed signalled; prefer the lowest index in the set that is signalled.
            for k in 0..count.min(WAITER_MAX_EVENTS) {
                let ev = WAITER_EVENTS[i][k].load(Ordering::Relaxed) as usize;
                if ev == just_set || events.read_state(ev as u64) {
                    wake = true;
                    wake_index = k as u64;
                    break;
                }
            }
        }
        if !wake {
            continue;
        }
        // Auto-reset the CONSUMED event (WaitAny: the one at wake_index; WaitAll: all of them) if it's
        // an auto-reset event, so the next wait blocks again.
        if wait_all {
            for k in 0..count.min(WAITER_MAX_EVENTS) {
                let ev = WAITER_EVENTS[i][k].load(Ordering::Relaxed) as usize;
                events.consume_existing(ev as u64);
            }
        } else {
            let ev = WAITER_EVENTS[i][wake_index as usize].load(Ordering::Relaxed) as usize;
            events.consume_existing(ev as u64);
        }
        let cap = WAITER_REPLY_CAP[i].load(Ordering::Relaxed);
        if cap != 0 {
            // Resume the parked wait with STATUS_WAIT_0 + index. The waiter blocked as a native syscall
            // (UnknownSyscall fault); apply_fault_reply restores RCX←resume_ip, RSP←sp, RFLAGS←flags
            // (IPC MR15/16/17) and RAX/r10←status. r10 (status) = wake_index = WAIT_OBJECT_0+index.
            set_reply_mr(15, WAITER_RESUME_IP[i].load(Ordering::Relaxed));
            set_reply_mr(16, WAITER_RESUME_SP[i].load(Ordering::Relaxed));
            set_reply_mr(17, WAITER_RESUME_FLAGS[i].load(Ordering::Relaxed));
            send_on_reply(cap, 18, wake_index, 0, 0, 0);
            // Return this reply object to the pool (clear its used bit).
            for p in 0..WAIT_REPLY_POOL_N {
                if WAIT_REPLY_POOL[p].load(Ordering::Relaxed) == cap {
                    WAIT_REPLY_POOL_USED.fetch_and(!(1u64 << p), Ordering::Relaxed);
                    break;
                }
            }
            woken += 1;
            WAIT_WOKEN_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        // Free the slot.
        WAITER_EVENT_IDX[i].store(u64::MAX, Ordering::Relaxed);
        WAITER_EVENT_COUNT[i].store(0, Ordering::Relaxed);
        WAITER_REPLY_CAP[i].store(0, Ordering::Relaxed);
        WAITER_TID[i].store(0, Ordering::Relaxed);
        WAITER_DEADLINE[i].store(u64::MAX, Ordering::Relaxed);
    }
    woken
}

unsafe fn wait_wake_due() -> u64 {
    let now = monotonic_time_100ns();
    let mut woken = 0;
    for slot in 0..WAITER_N {
        if WAITER_EVENT_IDX[slot].load(Ordering::Relaxed) == u64::MAX
            || WAITER_DEADLINE[slot].load(Ordering::Relaxed) > now
        {
            continue;
        }
        let cap = WAITER_REPLY_CAP[slot].load(Ordering::Relaxed);
        if cap != 0 {
            set_reply_mr(15, WAITER_RESUME_IP[slot].load(Ordering::Relaxed));
            set_reply_mr(16, WAITER_RESUME_SP[slot].load(Ordering::Relaxed));
            set_reply_mr(17, WAITER_RESUME_FLAGS[slot].load(Ordering::Relaxed));
            send_on_reply(cap, 18, 0x102, 0, 0, 0);
            release_reply_pool_cap(cap);
            woken += 1;
        }
        WAITER_EVENT_IDX[slot].store(u64::MAX, Ordering::Relaxed);
        WAITER_EVENT_COUNT[slot].store(0, Ordering::Relaxed);
        WAITER_REPLY_CAP[slot].store(0, Ordering::Relaxed);
        WAITER_TID[slot].store(0, Ordering::Relaxed);
        WAITER_DEADLINE[slot].store(u64::MAX, Ordering::Relaxed);
    }
    woken
}

unsafe fn set_reply_mr(i: usize, v: u64) {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((base + 8 + (i as u64) * 8) as *mut u64, v);
}
pub(crate) unsafe fn get_recv_mr(i: usize) -> u64 {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::read_volatile((base + 8 + (i as u64) * 8) as *const u64)
}
/// Stage a value into the executive's IPC-buffer RECEIVE MR slot `i` (ntdll_plan Step 6.A). Used to
/// NORMALIZE a native-seL4-Call NT_NATIVE_SYSCALL message into the register-slot layout the
/// `(mi>>12)==2` UnknownSyscall service arm reads (which reads args from the fault frame's saved
/// register slots via `get_recv_mr`), so the native transport reuses that arm's full servicing body
/// unchanged. Same address math as `set_reply_mr`/`get_recv_mr` (MR `i` at byte `8 + i*8`).
unsafe fn set_recv_mr(i: usize, v: u64) {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((base + 8 + (i as u64) * 8) as *mut u64, v);
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
/// `key_handles` stores a `KeyRef` (u32). A real hive `KeyRef` is an hbin-relative cell offset
/// (well under the ~204 KiB hive size). A `KeyRef` in the range `[OVERLAY_KEY_TAG,
/// OVERLAY_KEY_TAG+OVERLAY_KEY_MAX)` instead names an OVERLAY (created) key — its low bits are the
/// index into `ExecNtHandler::overlay`. The range sits far above any real cell offset and below
/// `SYNTH_CPU_KEY` (0xFFFF_FF00), so it collides with neither.
const OVERLAY_KEY_TAG: u32 = 0x8000_0000;
const OVERLAY_KEY_MAX: u32 = 0x1000;
/// If a `KeyRef` names an overlay (created) key, return its overlay index.
fn overlay_key_idx(kr: KeyRef) -> Option<usize> {
    if kr >= OVERLAY_KEY_TAG && kr < OVERLAY_KEY_TAG + OVERLAY_KEY_MAX {
        Some((kr - OVERLAY_KEY_TAG) as usize)
    } else {
        None
    }
}
/// NtCreateKey SSN (ReactOS ntdll — `sysfuncs.lst` line 44). services' SCM creates volatile keys
/// (e.g. `Control\ServiceCurrent`) here; the write plane is the [`RegistryOverlay`].
pub const SSN_NT_CREATE_KEY: u64 = 43;
/// Registry key create dispositions (NtCreateKey *Disposition out-param).
const REG_CREATED_NEW_KEY: u32 = 1;
const REG_OPENED_EXISTING_KEY: u32 = 2;

/// P5 — PAINT-SAFE keyboard-layout registry fix. advapi32's `MapDefaultKey` opens a predefined
/// root (HKLM=`\Registry\Machine`, HKCU, HKCR) via `NtOpenKey(RootDirectory=0, ObjectName=<.rdata
/// static>)`; that name lives in a mapped DLL's `.rdata`, which the executive's copyin mirror can't
/// read, so `smss_read_objattr_name` returns EMPTY. Pre-fix we return NOT_FOUND, so `MapDefaultKey`
/// fails and EVERY HKLM/HKCU subkey open fails — including winlogon's `InitKeyboardLayouts` fallback
/// `LoadKeyboardLayoutW("00000409")` which opens `HKLM\SYSTEM\...\Keyboard Layouts\00000409` — so
/// `InitKeyboardLayouts` returns FALSE → fatal `NtRaiseHardError`. Fix: hand back this sentinel for
/// an absolute empty-name (predefined-root) open so `MapDefaultKey` succeeds, then resolve ONLY the
/// keyboard-layout subkey (relative to this sentinel), returning NOT_FOUND for EVERY other subkey.
/// That preserves the pre-fix outcome (not-found) for all non-keyboard opens, so win32k's paint-time
/// client registry reads are byte-for-byte unchanged (a broad DLL-`.rdata`-name read was tried and
/// regressed the desktop paint by letting ALL HKLM reads succeed → the interactive-winsta fork).
const MACHINE_ROOT_HANDLE: u64 = 0x0000_0009_0000_0000;
/// Sentinel key handle returned for the `HKLM\SYSTEM\...\Keyboard Layouts\<KLID>` open. Non-IME
/// KLIDs (e.g. 00000409) need only the key to OPEN — the optional "Layout Id" value read is allowed
/// to miss (a query on this handle returns not-found → `IntLoadKeyboardLayout` keeps the default).
const SYNTH_KBD_HANDLE: u64 = 0x0000_0009_0000_0010;

/// True if `path` is a `...\Keyboard Layouts\<klid>` subkey (the plural "Keyboard Layouts" under
/// `Control`, distinct from the singular HKCU `Keyboard Layout\Preload`/`Substitutes`). Matched
/// case-insensitively; this is the ONLY subkey the MACHINE_ROOT sentinel resolves (paint safety).
fn is_keyboard_layout_key(path: &str) -> bool {
    let lc = path.to_ascii_lowercase();
    lc.contains("keyboard layouts\\")
}
/// True for a path under the LSA SECURITY hive or the SAM hive (`\Registry\Machine\SECURITY[...]` or
/// `\Registry\Machine\SAM[...]`) — lsass' LsapOpenServiceKey / samsrv's SampInitDatabase open these,
/// which our staged SYSTEM hive doesn't contain (real ReactOS creates them at setup). The executive
/// models them as empty overlay hives so lsass can open + populate them (pi 4).
pub(crate) fn is_lsa_hive_path(path: &str) -> bool {
    let lc = path.to_ascii_lowercase();
    lc.starts_with(r"\registry\machine\security") || lc.starts_with(r"\registry\machine\sam")
}
/// Count of `HKLM\...\Keyboard Layouts\<KLID>` opens serviced (drives the `exec_kbd_layout_opened`
/// spec — proves winlogon's InitKeyboardLayouts fallback reached its layout key).
static KBD_LAYOUT_KEY_OPENED: AtomicU64 = AtomicU64::new(0);
/// Count of faked `NtUserLoadKeyboardLayoutEx` (SSN 0x125c) calls — winlogon's InitKeyboardLayouts
/// gets a non-NULL HKL back without routing to win32k's interactive-winsta keyboard-layout fork.
static KBD_LAYOUT_LOADED: AtomicU64 = AtomicU64::new(0);
/// Count of faked non-interactive-service (services/lsass) user32-init class/cursor calls
/// (NtUserFindExistingCursorIcon 0x103d / NtUserRegisterClassExWOW 0x10b4). A NON-interactive
/// service's user32 DllMain still runs RegisterSystemClasses, but win32k's shared system cursors
/// (gasyscur) are NEVER loaded for it (only winlogon's INTERACTIVE SwitchDesktop → co_IntLoadDefaultCursors
/// loads them) → NtUserFindExistingCursorIcon returns NULL forever → user32's per-class LoadCursor
/// fallback + RegisterClassExWOW never satisfy their "have a system cursor" precondition → the loop
/// never advances → the service never finishes process-attach → lsass never reaches LsaInitializeRpcServer
/// → never SetEvent(lsa_rpc_server_active) → winlogon's WaitForLsass parks forever (the deadlock).
/// FIX: for services/lsass (badges 6/8 — NOT winlogon, whose real GUI path is untouched) SATISFY the
/// loop's precondition without dragging in the interactive-winsta cursor fork: return a non-NULL
/// HCURSOR from 0x103d and a fresh class atom from 0x10b4, so user32's RegisterSystemClasses completes
/// and the service advances to its real (LSA/SCM) init. Mirrors the winlogon 0x125c keyboard-layout fake.
pub(crate) static SVC_USER32_FAKE_CALLS: AtomicU64 = AtomicU64::new(0);
/// Monotonic fake class-atom allocator (0xC000.. RTL_ATOM range) for the services/lsass 0x10b4 fake.
pub(crate) static SVC_FAKE_CLASS_ATOM: AtomicU64 = AtomicU64::new(0xC100);
/// Count of NtEnumerateKey calls modeled as empty (STATUS_NO_MORE_ENTRIES).
static NT_ENUMERATE_KEY_CALLS: AtomicU64 = AtomicU64::new(0);
/// Count of NtCreateNamedPipeFile calls modeled (winlogon's StartRpcServer \pipe\winreg).
static NAMED_PIPE_CREATED: AtomicU64 = AtomicU64::new(0);
/// Count of live pipe syscalls (NtCreateNamedPipeFile/NtCreateFile/NtOpenFile/NtFsControlFile/
/// Read/Write) that were ROUTED THROUGH the isolated npfs component (vs modeled-fake). Observability.
static NPFS_ROUTED_IRPS: AtomicU64 = AtomicU64::new(0);
/// Bounded file/pipe frontier traces; they preserve exact evidence without flooding serial output.
static NT_CREATE_FILE_FRONTIER_TRACED: AtomicBool = AtomicBool::new(false);
static NT_CREATE_IO_COMPLETION_TRACED: AtomicBool = AtomicBool::new(false);
static NT_REMOVE_IO_COMPLETION_WAIT_TRACED: AtomicBool = AtomicBool::new(false);
static NT_SET_INFORMATION_FILE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static NT_WRITE_FILE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static NT_READ_FILE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static NT_FLUSH_BUFFERS_FILE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static NT_FLUSH_BUFFERS_FILE_PENDING_COUNT: AtomicU64 = AtomicU64::new(0);
static NT_PIPE_WAIT_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static NT_CREATE_FILE_WINLOGON_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
/// Monotonic fake handle source for modeled sync objects (mutants, etc.) — non-zero, distinct.
static FAKE_SYNC_HANDLE: AtomicU64 = AtomicU64::new(0x7000_0000);

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
/// Opaque-tag payload used by the real per-process handle table for anonymous events. The low
/// 32 bits are the shared object-namespace index; named/global event handles keep OBJ_HANDLE_BASE
/// for win32k and cross-process compatibility.
const EVENT_HANDLE_TAG: u64 = 0x4556_4E54_0000_0000;
const EVENT_HANDLE_TAG_MASK: u64 = 0xFFFF_FFFF_0000_0000;
const EVENT_MODIFY_STATE: u32 = 0x0002;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

/// One node in the executive's minimal object-manager namespace. Inline, `Copy`, no nested heap
/// allocation, so the backing `Vec` (pre-reserved below the per-syscall heap mark) never
/// reallocates and survives the bump-heap reset. Enough for SmpInit's DosDevices bring-up:
/// directories (`\`, `\??`, …) and the drive-letter symbolic links it creates in `\??`.
#[derive(Clone, Copy)]
struct ObjEntry {
    name: [u8; 40],   // leaf name, lowercased ASCII (len in name_len)
    name_len: u8,
    parent: u8,       // index of the parent directory; 0xFF = the root itself
    kind: u8,         // 0 = directory, 1 = symbolic link, 2 = event
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
    /// services.exe (4th hosted process, spawned by winlogon's Win32 CreateProcessW): its file/section
    /// handles (set when winlogon (pi 2) opens+creates the services.exe SEC_IMAGE) + the parsed PE.
    services_file_handle: *mut u64,
    services_section_handle: *mut u64,
    services_pe: *const Option<nt_pe_loader::PeFile<'static>>,
    /// lsass.exe (5th hosted process): file/section handles + parsed PE (winlogon (pi 2) opens/creates).
    lsass_file_handle: *mut u64,
    lsass_section_handle: *mut u64,
    lsass_pe: *const Option<nt_pe_loader::PeFile<'static>>,
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
    /// The loadable DLL PEs (csrsrv/basesrv/winsrv + the Win32 client stack), for
    /// `csrss_out_write`'s demand-fill of a not-yet-faulted DLL .data page. Lifetime-erased.
    dll_pes: *const &'static Option<nt_pe_loader::PeFile<'static>>,
    dll_pes_len: usize,
    /// The mutable backing store for `dll_pes` — the demand-load path (`fs_loader::demand_load_dll`,
    /// called on a `reg.resolve_name` MISS in NtOpenFile) writes a freshly-parsed `PeFile` into a
    /// reserved slot here; `dll_pes[slot]` (a ref AT the slot) then observes it. Raw mut ptr to the
    /// pre-sized heap store allocated below the bump-reset mark.
    dll_pe_store: *mut Option<nt_pe_loader::PeFile<'static>>,
    /// csrss's ANONYMOUS (no-file) section — its CSR SharedSection shared memory: the handle
    /// NtCreateSection records + the requested size NtMapViewOfSection backs. Point at the locals.
    csrss_anon_section_handle: *mut u64,
    csrss_anon_size: *mut u64,
    /// The base NtMapViewOfSection assigned the anonymous CSR section (0 until first mapped) + the
    /// PER-PROCESS once-only flag for the shared 0x8000_0000 DLL page-directory (indexed by pi:
    /// each hosted process's VSpace needs its OWN PD covering the DLL PDPT range). Point at the
    /// loop-locals.
    csrss_anon_base: *mut u64,
    dll_pd_created: *mut [bool; MAX_PI],
    /// Per-process bitset of installed 2 MiB page-table windows across the compact DLL arena.
    dll_pt_bits: *mut [[u64; DLL_ARENA_PT_WORDS]; MAX_PI],
}

impl ExecLoopCtx {
    unsafe fn dll_pes(&self) -> &'static [&'static Option<nt_pe_loader::PeFile<'static>>] {
        core::slice::from_raw_parts(self.dll_pes, self.dll_pes_len)
    }
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
    /// Dispatcher state for every `obj_ns` event, keyed by the stable namespace index. The store
    /// owns manual/auto-reset and signal state; `obj_ns` owns names and identity.
    events: nt_kernel_exec::EventStore,
    /// The session-global atom namespace backing NtAdd/Find/Delete/QueryInformationAtom. Its arena
    /// is allocated once in `new()` below the per-syscall heap mark; atom operations mutate only
    /// that fixed buffer, so duplicate refcounts and names survive bump-allocator rewinds and are
    /// shared across every hosted process (`pi`).
    global_atoms: nt_kernel_exec::rtl_atom::OwnedAtomTable,
    /// Fixed executive completion-port objects and packet queues. SURT remains the cross-component
    /// transport; CQEs are translated into these NT objects through `enqueue_transport`.
    io_completion_ports: nt_io_completion::CompletionPortTable<2, 16, 64>,
    /// Per-call context the dispatch loop refreshes before each `dispatch` (Workstream A: the
    /// converged table-driven path carries executive context on the handler rather than a parallel
    /// mechanism). `pi` = process index (0 = smss, 1 = csrss); `stop` = a side-signal a handler
    /// sets when it can't service the call, so the loop stops the process (the ladder's
    /// `handled = false; break`).
    pi: usize,
    current_tid: u64,
    current_badge: u64,
    post_action: ExecPostAction,
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
    /// Like `spawn_request` but for the 4th hosted process: winlogon's Win32 `NtCreateProcessEx`
    /// (SSN 50, `StartServicesManager`) recognised the services.exe SEC_IMAGE section, so the loop
    /// spawns services (badge SERVICES_BADGE) after dispatch.
    services_spawn_request: bool,
    /// Like `spawn_request` but for the 5th hosted process: winlogon's Win32 `NtCreateProcessEx`
    /// (SSN 50, `StartLsass`) recognised the lsass.exe SEC_IMAGE section, so the loop spawns lsass
    /// (badge LSASS_BADGE) after dispatch.
    lsass_spawn_request: bool,
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
    /// General NtCreateThread: set by winlogon's FIRST `NtCreateThread` (its RPC listener) so the LOOP
    /// spawns the REAL listener thread (`spawn_wl_listener_thread`, which needs winlogon's PML4 + the
    /// caller's SP to read the CONTEXT — loop-resident). Parks on `WL_LISTENER_FAULT_EP`.
    /// One-based winlogon runtime-thread slot awaiting mechanism construction; zero means none.
    wl_spawn_request: u8,
    /// General NtCreateThread: set by services' (pi 3) FIRST `NtCreateThread` (the SCM's RPC listener /
    /// rpcrt4 io_thread) so the LOOP spawns + RESUMES the REAL listener thread
    /// (`spawn_svc_listener_thread`, needs services' PML4 + the caller's SP for the CONTEXT). Unlike
    /// the winlogon listener this one runs into the main multiplex (badge SVC_LISTENER_BADGE).
    svc_listener_spawn: bool,
    /// General NtCreateThread: set by lsass' (pi 4) FIRST `NtCreateThread` (an LSA server thread —
    /// StartAuthenticationPort / LsapRmServerThread) so the LOOP spawns + RESUMES the REAL thread
    /// (`spawn_lsass_listener_thread`) into the main multiplex (badge LSASS_LISTENER_BADGE).
    lsass_listener_spawn: bool,
    /// As `lsass_listener_spawn` but for lsass' SECOND server thread (LsapRmServerThread).
    lsass_listener2_spawn: bool,
    lsass_listener3_spawn: bool,
    /// Checkpoint B: set by NtWaitForSingleObject when the target is a REAL named event whose
    /// `signalled` flag is 0 → the loop must PARK this caller (reply-cap park keyed by this obj_ns
    /// event index) instead of replying, and wake it on the matching NtSetEvent. -1 = no park (either
    /// the wait was satisfied immediately, or the target isn't a parkable real event → immediate
    /// STATUS_WAIT_0 fallback). Reset each dispatch (group-A signal, like spawn_request).
    wait_park_event: i64,
    /// Monotonic 100ns deadline for the pending single-event park (`u64::MAX` = infinite).
    wait_deadline_100ns: u64,
    /// NtDelayExecution asks the service loop to park this syscall's reply until this signed
    /// 100ns interval becomes due. The handler validates/copies the user pointer; the loop owns
    /// deadline conversion and the HPET-backed reply-cap park.
    delay_requested: bool,
    delay_interval_100ns: i64,
    delay_alertable: bool,
    /// A synchronous file-I/O completion requested signaling this real executive event. The loop
    /// consumes it after dispatch so it can also wake reply-cap parked waiters.
    io_signal_event: i64,
    /// Monotonic counter for anonymous (unnamed) event objects (rpcrt4's server_ready_event/mgr_event).
    /// Each anon event gets a unique synthetic name so no two dedup. See `obj_create_anon_event`.
    anon_event_seq: u32,
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
    /// Per-process CSR-connect region guard (bit `pi` = process pi's CSR heap-view + static-server-data
    /// regions have been mapped into ITS VSpace). GENERAL per-process CSR/LPC connect plane: EVERY
    /// hosted Win32 process (winlogon pi 2, services pi 3, …) gets its OWN copy of the CSR regions at
    /// the shared CSR VAs in its own PML4. Was a single `winlogon_csr_view` guard (winlogon-only).
    csr_view_mask: u32,
    /// The real NT Process Manager (nt-process): EPROCESS/ETHREAD, per-process handle tables, and the
    /// process/thread lifecycle. FIRST convergence increment — each hosted process (smss/csrss/
    /// winlogon) is backed by a real EPROCESS created in `new()` (below the per-syscall heap mark, so
    /// its BTreeMap allocations survive the bump reset). This increment only CREATES + LOOKS UP the
    /// EPROCESSes (read-only during the loop, so no runtime realloc); the ad-hoc identity arrays +
    /// `next_handle` fakes stay live and are migrated onto this in the sequenced bulk. Policy lives
    /// here; the seL4 VSpace/CSpace/TCB caps + mirror/scratch VAs (the create MECHANISM) stay in the
    /// executive (only the trusted root task holds those caps), linked to an EPROCESS by `PM_PIDS[pi]`.
    pm: nt_process::ProcessManager,
    /// The Configuration Manager WRITE plane: an in-memory registry overlay ([`RegistryOverlay`])
    /// that shadows the read-only base hive. `NtCreateKey`/`NtSetValueKey` (services, pi 3) land
    /// created keys + set values here; reads (`NtOpenKey`/`NtQueryValueKey`) check the overlay
    /// FIRST then fall through to the base hive. Pre-reserved in `new()` (below the per-syscall heap
    /// mark) so its key vector never reallocates; the executive pins the heap high-water mark past
    /// each mutation (`overlay_dirty`) so the runtime `String`/`Vec` growth survives the bump reset.
    overlay: nt_hive_core::RegistryOverlay,
    /// Set by a handler that mutated `overlay` (`NtCreateKey`/`NtSetValueKey`). The service loop
    /// consumes it after dispatch: it advances the heap high-water mark to the current bump
    /// position so the overlay's runtime allocations are retained past the next per-syscall reset.
    overlay_dirty: bool,
    /// Set by NtOpenFile when it DEMAND-LOADED a DLL (`fs_loader::demand_load_dll` on a
    /// `reg.resolve_name` miss). Like `overlay_dirty`, the service loop advances the heap high-water
    /// mark past whatever the load allocated so the registry's activated slot survives the per-syscall
    /// reset. (The pool bytes + the `dll_pe_store` write are already reset-safe; this covers the
    /// registry's inline-slot fill + any transient — a belt-and-braces pin, minimal leak.)
    dll_loaded_dirty: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecPostAction {
    None,
    TerminateCurrentThread { tid: u64 },
    TerminateRemoteThread { tid: u64 },
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
            (NativeService::NtAddAtom, SSN_NT_ADD_ATOM as u32),
            (NativeService::NtDeleteAtom, SSN_NT_DELETE_ATOM as u32),
            (NativeService::NtFindAtom, SSN_NT_FIND_ATOM as u32),
            (NativeService::NtQueryInformationAtom, SSN_NT_QUERY_INFORMATION_ATOM as u32),
            (NativeService::NtClose, SSN_NT_CLOSE as u32),
            (NativeService::NtOpenKey, SSN_NT_OPEN_KEY as u32),
            (NativeService::NtCreateKey, SSN_NT_CREATE_KEY as u32),
            (NativeService::NtEnumerateValueKey, SSN_NT_ENUM_VALUE_KEY as u32),
            (NativeService::NtEnumerateKey, SSN_NT_ENUMERATE_KEY as u32),
            (NativeService::NtQueryKey, SSN_NT_QUERY_KEY as u32),
            (NativeService::NtCreateFile, SSN_NT_CREATE_FILE as u32),
            (NativeService::NtCreateIoCompletion, SSN_NT_CREATE_IO_COMPLETION as u32),
            (NativeService::NtOpenIoCompletion, SSN_NT_OPEN_IO_COMPLETION as u32),
            (NativeService::NtQueryIoCompletion, SSN_NT_QUERY_IO_COMPLETION as u32),
            (NativeService::NtRemoveIoCompletion, SSN_NT_REMOVE_IO_COMPLETION as u32),
            (NativeService::NtSetIoCompletion, SSN_NT_SET_IO_COMPLETION as u32),
            (NativeService::NtWriteFile, 284),
            (NativeService::NtReadFile, 191),
            (NativeService::NtSetInformationFile, 233),
            (NativeService::NtFlushBuffersFile, 81),
            (NativeService::NtCreateNamedPipeFile, SSN_NT_CREATE_NAMED_PIPE_FILE as u32),
            (NativeService::NtFsControlFile, SSN_NT_FS_CONTROL_FILE as u32),
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
            (NativeService::NtOpenEvent, SSN_NT_OPEN_EVENT as u32),
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
            (NativeService::NtQueryDirectoryObject, SSN_NT_QUERY_DIRECTORY_OBJECT as u32),
            (NativeService::NtCreateSymbolicLinkObject, SSN_NT_CREATE_SYMBOLIC_LINK_OBJECT as u32),
            (NativeService::NtOpenSymbolicLinkObject, SSN_NT_OPEN_SYMBOLIC_LINK_OBJECT as u32),
            // Workstream A batch 4 (group B2): out-writing query services (queued-write drain).
            (NativeService::NtQuerySystemTime, SSN_NT_QUERY_SYSTEM_TIME_SVC as u32),
            (NativeService::NtDelayExecution, SSN_NT_DELAY_EXECUTION as u32),
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
            // ntdll port BATCH 1: our Rust ntdll's RtlCreateUserProcess issues the IMPORTED stub
            // NtCreateProcessEx (SSN 50) — the ntdll export ReactOS binaries actually link — where the
            // real ntdll would issue NtCreateProcess (49). 49's args are a prefix of 50's (50 adds a
            // trailing JobMemberLevel, which smss passes as 0), so route SSN 50 to the SAME
            // NtCreateProcess handler. See ntdll_plan.md Step 2c reconciliation.
            (NativeService::NtCreateProcess, 50),
            // ITEM 2a — live terminate-dispatch. NtTerminateProcess IS registered: it is NOT issued
            // during a normal boot (the 3 hosted processes never self-terminate — verified: registering
            // it keeps the boot byte-identical), so routing it to the real pm.terminate_process teardown
            // (via resolve_process_handle: NtCurrentProcess→self, a child ProcessHandle→its Process(pid)
            // via path 1b's value→object index) is additive. terminate_process only mutates below-mark
            // EPROCESS/ETHREAD nodes in place + a transient consumed-and-dropped Vec → safe under the
            // per-syscall heap reset even if a future flow does hit it.
            (NativeService::NtTerminateProcess, SSN_NT_TERMINATE_PROCESS as u32),
            (NativeService::NtTerminateThread, SSN_NT_TERMINATE_THREAD as u32),
        ],
    )
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

/// Parameters describing a hosted second thread for [`spawn_hosted_thread`]. All VAs in the
/// `*_va`/`*_base` fields live in the TARGET process's VSpace (`pml4`) except `scr` and
/// `stack_mirror_va`, which are in the EXECUTIVE's VSpace (`CAP_INIT_THREAD_VSPACE`).
struct HostedThread {
    /// The target process's VSpace (PML4) cap — the thread runs here, sharing the main thread's
    /// image/ntdll/PEB/KUSER mappings.
    pml4: u64,
    /// The thread's instruction pointer and first two Windows x64 argument registers.
    entry_rip: u64,
    arg0: u64,
    arg1: u64,
    /// Executive-side scratch base (≥ 3 pages: TEB, TEB2/ACS, trampoline) used to write the env
    /// before the frames are mapped into `pml4`.
    scr: u64,
    /// TEB base VA (2 pages), stack base VA + frame count, IPC buffer VA, trampoline VA — all in `pml4`.
    teb_va: u64,
    stack_base: u64,
    stack_frames: u64,
    ipcbuf_va: u64,
    tramp_va: u64,
    /// The shared PEB VA (the process's PEB, mapped by the main thread's spawn).
    peb_va: u64,
    /// Executive-side stack-mirror base (`0` = don't mirror). Only threads driven by a nested
    /// rendezvous that writes their syscall out-params need a mirror (SM/CSR); a park-only thread
    /// (the RPC listener) needs none.
    stack_mirror_va: u64,
    /// The dedicated fault endpoint this thread faults to (no standing receiver → it PARKS until a
    /// rendezvous drives it, or forever for a park-only listener).
    fault_ep: u64,
    /// The `ClientId` written into the TEB (`0,0` leaves the TEB's zero-fill).
    cid_proc: u64,
    cid_thread: u64,
    /// Resume immediately (SM/listener) or leave suspended for a lazy rendezvous-time resume (CSR).
    resume: bool,
    /// Scheduling priority (default 100). The services RPC listener uses a value above the hosted
    /// processes so that, once services' main thread parks (NtTerminateThread), the listener is the
    /// highest runnable thread → it faults into the main multiplex (proving the N-threads mechanism).
    prio: u8,
    /// NATIVE seL4-Call transport (ntdll_plan Step 6.A / BATCH 6). When set, this 2nd thread runs on
    /// OUR ntdll's native transport just like the process's MAIN thread: DON'T set the per-thread
    /// `TCBSetHostedSyscalls` flag (so its `seL4_Call` dispatches natively → MR0=SSN, not an
    /// UnknownSyscall fault whose m0=RAX is garbage), and bind its kernel IPC buffer at the SAME
    /// `IPCBUF_VADDR` the ntdll native stub writes MR4/MR5 to — reusing the process main thread's
    /// ipcbuf FRAME (they share the VSpace and never run concurrently during a rendezvous, so the
    /// shared VA→frame mapping is safe; a fresh frame at `ipcbuf_va` would either collide with the
    /// main thread's mapping or leave MR4/MR5 where the kernel doesn't read them). `ipcbuf_frame`
    /// (non-zero) is that reused frame cap; when 0 (trap/park-only threads) a fresh frame is used.
    native: bool,
    ipcbuf_frame: u64,
}

/// Spawn a REAL 2nd (or Nth) thread in a hosted process's VSpace — the GENERAL hosted-thread
/// mechanism behind `NtCreateThread`. It builds the full hosted-Windows-thread env (own TEB + GS
/// base, StaticUnicodeString, an ACTIVATION_CONTEXT_STACK, an IPC buffer, the hosted-syscalls flag,
/// a dedicated fault EP, a stack, an SC) — a trimmed `spawn_sec_image` (the image/ntdll/PEB/KUSER are
/// already mapped, shared with the main thread) — then a trampoline that restores RCX/RDX and
/// `call`s the context RIP (`call` keeps rsp ≡ 8 mod 16 at entry; the trailing jmp$ is a net).
/// Returns the TCB cap. This is the single path the SM-loop / CSR-API / RPC-listener
/// spawns all express (see the thin wrappers below).
unsafe fn spawn_hosted_thread(t: &HostedThread) -> u64 {
    let scr = t.scr;
    if t.stack_mirror_va != 0 {
        let pt_base = t.stack_mirror_va & !0x1f_ffffu64;
        let pt_index = ((pt_base - (SVC_LISTENER_STACK_MIRROR_VA & !0x1f_ffffu64)) >> 21) as u32;
        let bit = 1u64 << pt_index;
        if HOSTED_STACK_MIRROR_PT_BITS.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            let pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
            let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, pt_base, CAP_INIT_THREAD_VSPACE);
        }
    }
    // Stack, mapped into the target VSpace AND (optionally) mirrored into the executive for a
    // rendezvous's out-param copyout.
    for i in 0..t.stack_frames {
        let f = alloc_frame();
        let _ = page_map(copy_cap(f), t.stack_base + i * 0x1000, RW_NX, t.pml4);
        if t.stack_mirror_va != 0 {
            let _ = page_map(copy_cap(f), t.stack_mirror_va + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
    }
    // TEB page 1: self@0x30, ClientId@0x40/0x48, PEB@0x60 (shared), StackBase@0x08/StackLimit@0x10,
    // ActivationContextStackPointer@0x2C8 → an empty ACS in the 2nd TEB page.
    let teb = alloc_frame();
    let _ = page_map(teb, scr, RW_NX, CAP_INIT_THREAD_VSPACE);
    core::ptr::write_volatile((scr + 0x30) as *mut u64, t.teb_va);
    core::ptr::write_volatile((scr + 0x40) as *mut u64, t.cid_proc);
    core::ptr::write_volatile((scr + 0x48) as *mut u64, t.cid_thread);
    core::ptr::write_volatile((scr + 0x60) as *mut u64, t.peb_va);
    core::ptr::write_volatile((scr + 0x08) as *mut u64, t.stack_base + t.stack_frames * 0x1000);
    core::ptr::write_volatile((scr + 0x10) as *mut u64, t.stack_base);
    let acs_va = t.teb_va + 0x1800;
    core::ptr::write_volatile((scr + 0x2c8) as *mut u64, acs_va);
    let _ = page_map(copy_cap(teb), t.teb_va, RW_NX, t.pml4);
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
    core::ptr::write_volatile((scr + 0x1000 + 0x260) as *mut u64, t.teb_va + 0x1268); // .Buffer
    let _ = page_map(copy_cap(teb2), t.teb_va + 0x1000, RW_NX, t.pml4);
    // IPC buffer. NATIVE transport (BATCH 6): reuse the process MAIN thread's ipcbuf FRAME at
    // IPCBUF_VADDR (already mapped in the shared VSpace) so OUR ntdll's native stub — which writes
    // MR4/MR5 to the hardcoded IPCBUF_VADDR and reads its reply there — hits the SAME frame the
    // kernel binds to this TCB. Don't remap the VA (it's already mapped by the main thread's spawn).
    // Trap/park-only threads (ipcbuf_frame==0): a fresh frame at t.ipcbuf_va, as before.
    let (ipcbuf, ipcbuf_bind_va) = if t.native && t.ipcbuf_frame != 0 {
        (copy_cap(t.ipcbuf_frame), IPCBUF_VADDR)
    } else {
        let f = alloc_frame();
        let _ = page_map(f, t.ipcbuf_va, RW_NX, t.pml4);
        (f, t.ipcbuf_va)
    };
    // Trampoline: restore the Windows x64 thread-entry ABI, then call CONTEXT.Rip.
    let tramp = alloc_frame();
    let _ = page_map(tramp, scr + 0x2000, RW_NX, CAP_INIT_THREAD_VSPACE);
    let tb = nt_thread_start::Amd64ThreadContext {
        rip: t.entry_rip,
        rsp: 0,
        rcx: t.arg0,
        rdx: t.arg1,
    }
    .call_trampoline();
    for (j, &b) in tb.iter().enumerate() {
        core::ptr::write_volatile((scr + 0x2000 + j as u64) as *mut u8, b);
    }
    let _ = page_map(copy_cap(tramp), t.tramp_va, /* RX */ 2, t.pml4);
    // CNode (PML4 + the dedicated fault EP) + TCB.
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, t.pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, copy_cap(t.fault_ep), 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, t.pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, ipcbuf_bind_va, ipcbuf, 0);
    let _ = tcb_write_registers(tcb, t.tramp_va, t.stack_base + t.stack_frames * 0x1000 - 16, 0);
    let _ = tcb_set_gs_base(tcb, t.teb_va);
    let _ = tcb_set_priority(tcb, if t.prio != 0 { t.prio as u64 } else { 100 });
    // Transport (ntdll_plan Step 6.A / BATCH 6): a NATIVE thread must NOT get the hosted-syscalls
    // flag — with it set the kernel forces its native `seL4_Call` into an UnknownSyscall fault whose
    // m0=RAX (garbage), so the rendezvous reads a bogus SSN. Cleared, the Call dispatches natively
    // (MR0=r10=SSN) exactly like the process's MAIN thread. Trap threads keep the flag (byte-id).
    const LBL_TCB_SET_HOSTED_SYSCALLS: u64 = 66;
    if !t.native {
        let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_HOSTED_SYSCALLS << 12, 0, 0, 0);
    }
    attach_sched_context(tcb);
    if t.resume {
        let _ = tcb_resume(tcb);
    }
    tcb
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
/// services.exe's OWN NtAllocateVirtualMemory bump (4th hosted process) — a SEPARATE counter (same
/// rationale as csrss/winlogon: independent VSpaces make the same start VA (own PT) fine).
static NEXT_SERVICES_ALLOC: AtomicU64 = AtomicU64::new(SMSS_ALLOC_VA);
/// lsass.exe's OWN NtAllocateVirtualMemory bump (5th hosted process).
static NEXT_LSASS_ALLOC: AtomicU64 = AtomicU64::new(SMSS_ALLOC_VA);
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
/// Set when winlogon's kernel32 CreateProcessInternalW creates the services.exe SEC_IMAGE section —
/// i.e. the Win32 process-create for services.exe has begun. Used to gate OFF the broad empty-name
/// NtOpenKey → MACHINE_ROOT_HANDLE fallback (which the keyboard-layout path needed, but which makes
/// BasepIsProcessAllowed's AppCertDlls open spuriously succeed → RtlQueryRegistryValues fails
/// c0000002 → "Process not allowed to launch"). The keyboard path runs long before services create.
static SERVICES_CREATE_STARTED: AtomicU64 = AtomicU64::new(0);
/// SERVICE 8 — count of REAL named events services (pi 3) registered in \BaseNamedObjects via
/// NtCreateEvent (SCM_START_EVENT / SC_AutoStartComplete / LSA_RPC_SERVER_ACTIVE / …). Drives the
/// `exec_services_named_events` milestone spec: the SCM's CreateEventW now resolves real event
/// objects + gets a valid handle back (was: no out-handle → CreateEventW returned NULL → wall).
pub(crate) static SERVICES_NAMED_EVENTS: AtomicU64 = AtomicU64::new(0);
/// SERVICE 8 — count of NtQueryDirectoryObject enumerations serviced for pi 3 (ntdll's named-object
/// path walking \BaseNamedObjects). Drives the `exec_services_query_dir_object` spec (was the wall).
pub(crate) static SERVICES_QUERY_DIR_OBJECT: AtomicU64 = AtomicU64::new(0);
/// Set once winlogon's Win32 CreateProcessW (NtCreateProcessEx) spawns services.exe as the 4th hosted
/// process (badge 6) — its ntdll loader then runs, multiplexed by badge. Read by the milestone spec.
static SERVICES_SPAWNED: AtomicU64 = AtomicU64::new(0);
/// How many pages services.exe's ntdll loader demand-faulted (slot 3), for the spec-check report.
static SERVICES_FAULTS: AtomicU64 = AtomicU64::new(0);
/// SERVICE 10 — lsass.exe (5th hosted process, badge 8, pi 4). CREATE_STARTED set at its
/// NtCreateSection; SPAWNED set at NtCreateProcessEx; FAULTS = its loader demand-fault count.
static LSASS_CREATE_STARTED: AtomicU64 = AtomicU64::new(0);
static LSASS_SPAWNED: AtomicU64 = AtomicU64::new(0);
static LSASS_FAULTS: AtomicU64 = AtomicU64::new(0);
/// Set once lsass's lsasrv `LsapRmInitializeServer` NtConnectPort(\SeRmCommandPort) is modeled-accepted
/// — i.e. lsass's LSA init (LsapInitLsa) has resolved lsasrv+samsrv (SERVICE 10 step 2) and is running
/// its real SRM/LSA-database bring-up. Read by the exec_lsass_lsa_init_running milestone spec.
static LSASS_SRM_CONNECTED: AtomicU64 = AtomicU64::new(0);
/// Set once winlogon's kernel32 CSR client connect (NtSecureConnectPort → \Windows\ApiPort) is
/// serviced (regions mapped + CSR_API_CONNECTINFO filled). Read by the milestone spec check.
static WINLOGON_CSR_CONNECTED: AtomicU64 = AtomicU64::new(0);
/// Set once the exec-side CSR fill-scratch page table (WINLOGON_CSR_FILL_SCRATCH) is mapped (once,
/// shared across all hosted processes' CSR-region fills — the executive is single-threaded).
static CSR_FILL_SCRATCH_PT: AtomicU64 = AtomicU64::new(0);
/// Bitmask of hosted processes (bit `pi`) whose GENERAL per-process CSR client connect completed
/// (NtSecureConnectPort → \Windows\ApiPort serviced + their own CSR regions mapped). bit 2 = winlogon,
/// bit 3 = services. Proves the CSR connect is a per-process service, not winlogon-specific.
static CSR_CONNECTED_MASK: AtomicU64 = AtomicU64::new(0);
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
/// EPROCESS pids for pi 0=smss / 1=csrss / 2=winlogon / 3=services (0 = not yet created).
static PM_PIDS: [AtomicU64; MAX_PI] = [const { AtomicU64::new(0) }; MAX_PI];
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
static PM_TIDS: [AtomicU64; MAX_PI] = [const { AtomicU64::new(0) }; MAX_PI];
/// Root-CNode TCB caps backing each hosted process main thread, retained so a successful
/// NtTerminateThread can suspend/delete the exact mechanism instead of merely withholding reply.
pub(crate) static PM_MAIN_TCBS: [AtomicU64; MAX_PI] = [const { AtomicU64::new(0) }; MAX_PI];
/// Each hosted process's MAIN-thread IPC buffer FRAME cap (bound at `IPCBUF_VADDR`). Retained so a
/// runtime NATIVE 2nd thread (SmpApiLoop / CSR-API / listener on OUR ntdll) can bind ITS kernel IPC
/// buffer to the SAME frame at IPCBUF_VADDR — the VA our ntdll native stub writes MR4/MR5 to
/// (BATCH 6). They share the VSpace and never run concurrently during a rendezvous.
pub(crate) static PM_MAIN_IPCBUF: [AtomicU64; MAX_PI] = [const { AtomicU64::new(0) }; MAX_PI];
/// Fixed pool of spare ETHREADs per process, pre-created below the reset mark so runtime thread
/// creation remains allocation-free. Three slots cover the live lsass worker fan-out.
const PM_RUNTIME_THREAD_SLOTS: usize = 3;
static PM_POOL_TID: [[AtomicU64; PM_RUNTIME_THREAD_SLOTS]; MAX_PI] =
    [const { [const { AtomicU64::new(0) }; PM_RUNTIME_THREAD_SLOTS] }; MAX_PI];
static PM_POOL_USED: [AtomicU64; MAX_PI] = [const { AtomicU64::new(0) }; MAX_PI];
/// Bit `slot` is set while a runtime thread still has its initial suspend count.
static PM_POOL_SUSPENDED: [AtomicU64; MAX_PI] = [const { AtomicU64::new(0) }; MAX_PI];
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
/// Bit i set iff pi=i's ETHREAD is Terminated (signalled) via a live NtTerminateThread.
static PM_TERMINATE_THREAD_STATE: AtomicU64 = AtomicU64::new(0);
static PM_TERMINATE_THREAD_TRACE: AtomicU64 = AtomicU64::new(0);
static PM_TERMINATE_THREAD_TCB_RECLAIMED: AtomicU64 = AtomicU64::new(0);
/// Successful current-thread terminations whose bound syscall Reply object was deleted without a
/// send before the exact caller TCB was suspended/deleted. This is the non-return contract proof.
static PM_TERMINATE_THREAD_NO_REPLY: AtomicU64 = AtomicU64::new(0);
/// Badges that issued a successful self-termination and badges observed by the service loop after
/// the first dropped reply. Their difference proves unrelated callers continued making progress.
static PM_TERMINATE_THREAD_BADGES: AtomicU64 = AtomicU64::new(0);
static PM_POST_TERM_CONTINUED_BADGES: AtomicU64 = AtomicU64::new(0);
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
    // Checkpoint B: retype the reply-object POOL. pool[0] IS the REPLY_MAIN object (the loop's active
    // recv reply cap); pool[1..] are spares the loop rotates in when it steals pool[active] to hold a
    // parked waiter's Call. All are OBJ_REPLY (size_bits 0).
    if e_rm == 0 {
        WAIT_REPLY_POOL[0].store(rm, Ordering::Relaxed);
        for i in 1..WAIT_REPLY_POOL_N {
            let rp = alloc_slot();
            let e = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, rp);
            if e == 0 {
                WAIT_REPLY_POOL[i].store(rp, Ordering::Relaxed);
            }
        }
        WAIT_REPLY_POOL_USED.store(1, Ordering::Relaxed); // bit 0 = pool[0] is the active REPLY_MAIN
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
    // General NtCreateThread: a dedicated fault endpoint (no standing receiver) that the RPC-listener
    // and any future park-only Nth thread faults to → it PARKS on its first fault, its real TEB left
    // mapped + queryable by the process's main thread.
    let wl_ep = make_object(OBJ_ENDPOINT);
    WL_LISTENER_FAULT_EP.store(wl_ep, Ordering::Relaxed);
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
        let pml4 = spawn_sec_image(0, &pe, si_fault_c, 0, false, 100, 0x0000_0100_1074_0000, SMSS_STACK_MIRROR_VA, SMSS_HEAP_MIRROR_VA, 0, b"\\SystemRoot\\System32\\smss.exe", b"smss.exe", 0);
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
        let gcap64 = core::ptr::read_volatile(HPET_VADDR as *const u64);
        let gcap = gcap64 as u32;
        HPET_PERIOD_FS.store(gcap64 >> 32, Ordering::Relaxed);
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

    // PnP Manager bus walk — the enumeration is now the host-tested `nt-pnp` policy (parse
    // vendor/device/class + IRQ + decode each BAR with the write-all-ones size probe, restoring
    // it). The executive-side broker (`pnp.rs`) drives it over `pci_read32`/`pci_write32`.
    let pci_devices = enumerate_pci_bus0(pci_io);
    let mut count = 0u64;
    let mut found_storage = false;
    let (mut storage_bar5, mut storage_irq) = (0u32, 0u32);
    let (mut storage_dev, mut storage_func) = (0u8, 0u8);
    let (mut nic_bar0, mut nic_irq, mut found_nic) = (0u32, 0u32, false);
    let (mut nic_dev, mut nic_func) = (0u8, 0u8);
    for d in &pci_devices {
        count += 1;
        let (dev, func) = (d.dev, d.func);
        let class = pci_read32(pci_io, 0, dev, func, 0x08); // [class][sub][progif][rev]
        let bar0 = pci_read32(pci_io, 0, dev, func, 0x10); // raw BAR0 (flag bits intact for the log)
        let irq = d.irq_line as u32;
        print_str(b"  pci 0:");
        print_u64(dev as u64);
        print_str(b".");
        print_u64(func as u64);
        print_str(b" id=");
        print_hex(((d.device as u32) << 16) | d.vendor as u32);
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
        // P1 capstone (its MMIO BAR0 + interrupt line). nt-pnp binds it below.
        if d.base_class() == nt_pnp::PCI_CLASS_NETWORK {
            found_nic = true;
            nic_bar0 = bar0;
            nic_irq = irq;
            nic_dev = dev;
            nic_func = func;
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
    // Driver-model migration: these NIC resources are captured here (VT-d must be enabled by this
    // block BEFORE the storage block) but the real-.sys DRIVER-HOST hosting is DEFERRED until after
    // the FS is mounted, so the driver `.sys` can be loaded BY-PATH (no baked include_bytes!). Hoist
    // the handful of locals the deferred hosting block needs to function scope.
    let mut nic_bar_base = 0u64;
    let mut nic_mmio = 0u64;
    let mut nic_irq_ntfn = 0u64;
    let mut nic_dma_frame = 0u64;
    if found_nic {
        nic_mmio = (nic_bar0 & 0xFFFF_FFF0) as u64; // mask the BAR flag bits
        print_str(b"[ntos-exec] P1 CAPSTONE: mapping e1000e NIC BAR0 ");
        print_hex(nic_mmio as u32);
        print_str(b" (irq ");
        print_u64(nic_irq as u64);
        print_str(b")\n");
        // Map the first 4 pages (16 KiB) of the BAR: page 0 has CTRL/STATUS/interrupt
        // regs, page 3 (offset 0x3000) has the TX descriptor registers (0x3800..0x3828).
        nic_bar_base = claim_device_pages(bi, nic_mmio, NIC_VADDR, 4);
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
            nic_irq_ntfn = make_object(OBJ_NOTIFICATION);
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
            nic_dma_frame = dma_frame; // hoist for the deferred (post-FS-mount) driver-host hosting
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
            // NOTE: the ISOLATED real-.sys DRIVER-HOST hosting used to run here, but it now loads
            // the driver BY-PATH from the FS (no baked include_bytes!), so it is DEFERRED to after
            // the FS mount (search "DEFERRED DRIVER-HOST"). VT-d + the raw NIC MMIO/DMA specs above
            // MUST stay here (before the storage block turns on / relies on VT-d).
        }
    }

    // NOTE: the KMDF DRIVER HOST used to run here, but (like the NIC driver-host) it now loads
    // KmdfBasicTest.sys BY-PATH from the FS (no baked include_bytes!), so it is DEFERRED to after
    // the FS mount (search "DEFERRED DRIVER-HOST").

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
                (&FONTBUF_START, win32k_subsystem::FONTBUF_VADDR, win32k_subsystem::FONTBUF_FRAMES),
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

    // ==== DEFERRED DRIVER-HOST hosting (NIC + KMDF) — driver-model migration ====================
    // The NIC (PnpMmioInterruptTest.sys) + KMDF (KmdfBasicTest.sys) driver hosts are launched here,
    // AFTER the FS is mounted, so both `.sys` binaries are loaded BY-PATH from the FS via the general
    // dynamic path (load_file_to_pool) — NO baked include_bytes!. The raw NIC MMIO/DMA + VT-d specs
    // ran earlier (they must precede the storage block). The bespoke `spawn_driver_host` /
    // `spawn_kmdf_host` are gone: their least-privilege ComponentDescriptors are inlined below and
    // spawned via the generic `spawn_component` engine. Behaviour-preserving (verdict-identical).
    //
    // ---- NIC (WDM) real-.sys driver host: DriverEntry → AddDevice → IRP_MN_START_DEVICE.
    if found_nic && nic_bar_base != 0 {
        // ---- DRIVER HOST AT START: the executive, acting as the PnP manager + HAL, hands an
        // ISOLATED driver host a real NT CM_RESOURCE_LIST (MMIO + interrupt) and a VT-d-confined
        // common DMA buffer, then lets it drive the NIC from its own CSpace/VSpace.
        print_str(b"[ntos-exec] driver host: START with CM_RESOURCE_LIST + confined DMA buffer\n");
        let reslist_frame = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, reslist_frame);
        let _ = page_map(reslist_frame, RESLIST_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
        // PnP resource assignment (host-tested `nt-pnp` policy) → the driver-visible CM_RESOURCE_LIST.
        if let Some(g) = assign_nic(&pci_devices, NIC_MSI_VECTOR as u32, true, 0x1000) {
            write_cm_resource_list(RESLIST_VADDR, 0, &g.assignment, NIC_VADDR, 0x4000);
        }
        core::ptr::write_volatile((RESLIST_VADDR + 0x100) as *mut u64, DMA_VADDR);
        core::ptr::write_volatile((RESLIST_VADDR + 0x108) as *mut u64, NIC_IOVA);
        core::ptr::write_volatile((RESLIST_VADDR + 0x110) as *mut u64, 0x1000u64);
        core::ptr::write_volatile((RESLIST_VADDR + 0x200) as *mut u8, 0); // clear verdict
        core::ptr::write_volatile((RESLIST_VADDR + 0x210) as *mut u8, 0); // clear .sys verdict
        // Load the REAL .sys driver BY-PATH from the FS, map its image frames RW here,
        // parse/map/relocate/patch-IAT to our stubs, then hand the same frames to the host R+X.
        let mut pe_base = 0u64;
        for i in 0..driver_pe::PE_FRAMES {
            let f = alloc_slot();
            if i == 0 {
                pe_base = f;
            }
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
            let _ = page_map(f, driver_pe::CODE_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
        let sys_entry = exec_fs()
            .and_then(|fs| {
                load_file_to_pool(&fs, b"reactos\\system32\\drivers\\PnpMmioInterruptTest.sys")
            })
            .and_then(|(va, sz)| {
                driver_pe::load_into(core::slice::from_raw_parts(va as *const u8, sz as usize))
            })
            .unwrap_or(0);
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
        print_str(b"[ntos-exec] loaded PnpMmioInterruptTest.sys BY-PATH; DriverEntry rva=");
        print_hex(sys_entry);
        print_str(b"\n");
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
        let dh_irq = copy_cap(nic_irq_ntfn);
        let dh_fault = make_object(OBJ_ENDPOINT);
        // Inlined descriptor (was spawn_driver_host): the granted device resources — the 4 NIC BAR
        // pages, the confined DMA buffer, the CM_RESOURCE_LIST frame, the real .sys image (RWX) + its
        // RW arena — each aliasing the executive's frame. Least privilege via `spawn_component`.
        {
            let regions = [
                Region { source: FrameSource::Alias(nic_bar_base), base_va: NIC_VADDR, count: 4, rights: Rights::Uniform(RW_NX), pts: 0 },
                Region { source: FrameSource::Alias(nic_dma_frame), base_va: DMA_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 },
                Region { source: FrameSource::Alias(reslist_frame), base_va: RESLIST_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 },
                Region { source: FrameSource::Alias(pe_base), base_va: driver_pe::CODE_VA, count: driver_pe::PE_FRAMES, rights: Rights::Uniform(3 /* RWX */), pts: 0 },
                Region { source: FrameSource::Alias(arena_base), base_va: driver_pe::ARENA_VADDR, count: driver_pe::ARENA_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 },
            ];
            let d = ComponentDescriptor {
                entry: driver_host::driver_host_entry,
                image_rights: Rights::Uniform(2), // RO
                map_heap_pt: false,
                stack_base: STACK_BASE,
                stack_frames: STACK_FRAMES,
                stack_dedicated_pt: false,
                regions: &regions,
                granted: GrantedCaps { irq_ntfn: Some(dh_irq), result_ntfn: Some(dh_result_badged), fault_ep: Some(dh_fault) },
                prio: 100,
                gs_base: None,
            };
            let _ = spawn_component(&d);
        }
        let _ = dh_fault; // a fault EP so a host fault is contained cleanly, not silent
        let (_z, dhb, _s, _m) = ep_recv(dh_result);
        let dh_verdict = core::ptr::read_volatile((RESLIST_VADDR + 0x200) as *const u8);
        print_str(b"[ntos-exec] driver host signalled badge=");
        print_u64(dhb);
        print_str(b" verdict=");
        print_u64(dh_verdict as u64);
        print_str(b"\n");
        check(b"exec_driver_host_drove_nic", dh_verdict == 1, &mut passed);
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

    // ---- KMDF DRIVER HOST: host a real KMDF driver (KmdfBasicTest.sys) through the FULL WDF
    // lifecycle (DriverEntry → WdfDriverCreate → AddDevice → EvtDevicePrepareHardware → D0Entry →
    // IOCTLs → REMOVE) in a SEPARATE isolated host — crash-contained on the microkernel.
    {
        print_str(b"[ntos-exec] KMDF host: loading real KmdfBasicTest.sys BY-PATH\n");
        let mut kmdf_pe_base = 0u64;
        for i in 0..kmdf_host::KMDF_PE_FRAMES {
            let f = alloc_slot();
            if i == 0 {
                kmdf_pe_base = f;
            }
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
            let _ = page_map(f, kmdf_host::KMDF_CODE_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
        let kmdf_entry = exec_fs()
            .and_then(|fs| load_file_to_pool(&fs, b"reactos\\system32\\drivers\\KmdfBasicTest.sys"))
            .and_then(|(va, sz)| {
                kmdf_host::load_into(core::slice::from_raw_parts(va as *const u8, sz as usize))
            })
            .unwrap_or(0);
        let kmdf_shared = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, kmdf_shared);
        let _ = page_map(kmdf_shared, kmdf_host::KMDF_SHARED_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
        core::ptr::write_volatile(kmdf_host::KMDF_SHARED_VADDR as *mut u64, kmdf_entry as u64);
        core::ptr::write_volatile((kmdf_host::KMDF_SHARED_VADDR + 8) as *mut u32, 0);
        core::ptr::write_volatile((kmdf_host::KMDF_SHARED_VADDR + 0x10) as *mut u32, 0);
        print_str(b"[ntos-exec] loaded KmdfBasicTest.sys BY-PATH; FxDriverEntry rva=");
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
        // Inlined descriptor (was spawn_kmdf_host): image RWX (WDF fn-table/globals live in .bss), a
        // heap (WdfRuntime + Wdf*Create allocate), the KMDF PE (RWX), a shared word, and (optionally)
        // the real e1000e NIC BAR (4 pages aliased) at NIC_VADDR for MmMapIoSpace. Deep stack.
        {
            let mut regions: [Region; 4] = [
                Region { source: FrameSource::FreshZeroed, base_va: allocator::HEAP_BASE as u64, count: allocator::SERVICE_HEAP_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 },
                Region { source: FrameSource::Alias(kmdf_pe_base), base_va: kmdf_host::KMDF_CODE_VA, count: kmdf_host::KMDF_PE_FRAMES, rights: Rights::Uniform(3 /* RWX */), pts: 0 },
                Region { source: FrameSource::Alias(kmdf_shared), base_va: kmdf_host::KMDF_SHARED_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 },
                Region { source: FrameSource::Alias(0), base_va: NIC_VADDR, count: 0, rights: Rights::Uniform(RW_NX), pts: 0 },
            ];
            if kmdf_nic_bar_base != 0 {
                regions[3] = Region { source: FrameSource::Alias(kmdf_nic_bar_base), base_va: NIC_VADDR, count: 4, rights: Rights::Uniform(RW_NX), pts: 0 };
            }
            let d = ComponentDescriptor {
                entry: kmdf_host::kmdf_host_entry,
                image_rights: Rights::Uniform(3), // RWX
                map_heap_pt: true,
                stack_base: STACK_BASE,
                stack_frames: 16, // 64 KiB — WDF call chains are deep
                stack_dedicated_pt: false,
                regions: &regions,
                granted: GrantedCaps { irq_ntfn: None, result_ntfn: Some(kmdf_result_badged), fault_ep: Some(kmdf_fault) },
                prio: 100,
                gs_base: None,
            };
            let _ = spawn_component(&d);
        }
        let _ = kmdf_fault;
        let (_z, _b, _s, _m) = ep_recv(kmdf_result);
        let kv = core::ptr::read_volatile((kmdf_host::KMDF_SHARED_VADDR + 8) as *const u32);
        print_str(b"[ntos-exec] KMDF host lifecycle verdict bits=0x");
        print_hex(kv);
        print_str(b"\n");
        check(b"exec_kmdf_driver_create", (kv & 1) != 0, &mut passed);
        check(b"exec_kmdf_adddevice_queue", (kv & 2) != 0, &mut passed);
        check(b"exec_kmdf_prepare_hw_read_real_nic", (kv & 4) != 0, &mut passed);
        check(b"exec_kmdf_ioctl", (kv & 8) != 0, &mut passed);
        check(b"exec_kmdf_remove", (kv & 16) != 0, &mut passed);
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
                let _ = paging_struct_map(cpt, LBL_X86_PAGE_TABLE_MAP, win32k_subsystem::WIN32K_CODE_VA + p * 0x20_0000, CAP_INIT_THREAD_VSPACE);
            }
            let code_base = alloc_frame();
            for _ in 1..win32k_subsystem::WIN32K_IMAGE_FRAMES { let _ = alloc_frame(); }
            for i in 0..win32k_subsystem::WIN32K_IMAGE_FRAMES {
                let _ = page_map(copy_cap(code_base + i), win32k_subsystem::WIN32K_CODE_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            let pool_base = alloc_frame();
            for _ in 1..win32k_subsystem::WIN32K_POOL_FRAMES { let _ = alloc_frame(); }
            let data_base = alloc_frame();
            for _ in 1..win32k_subsystem::WIN32K_DATA_FRAMES { let _ = alloc_frame(); }
            let shared = alloc_frame();
            // The cross-AS arg-marshal frame(s) — mapped in both the executive and the component.
            let arg_base = alloc_frame();
            for _ in 1..win32k_subsystem::WIN32K_ARG_FRAMES { let _ = alloc_frame(); }
            // The win32k session-heap arena (host-only; the executive doesn't map it). Retain the
            // frame-cap base so the connect marshaling can RO-map the global USER heap into a GUI
            // client's VSpace (the gSharedInfo client-mapping).
            let heap_base = alloc_frame();
            for _ in 1..win32k_subsystem::WIN32K_HEAP_FRAMES { let _ = alloc_frame(); }
            WIN32K_HEAP_FRAME_BASE.store(heap_base, Ordering::Relaxed);
            // The aux-window PT in the executive VSpace (covers DATA @0x0710 + SHARED @0x0718 + ARG
            // @0x071A; the pool is host-only, in its own window, so not mapped in the executive).
            let ppt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, ppt);
            let _ = paging_struct_map(ppt, LBL_X86_PAGE_TABLE_MAP, win32k_subsystem::WIN32K_AUX_PT_VADDR, CAP_INIT_THREAD_VSPACE);
            for i in 0..win32k_subsystem::WIN32K_DATA_FRAMES {
                let _ = page_map(copy_cap(data_base + i), win32k_subsystem::WIN32K_DATA_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            let _ = page_map(copy_cap(shared), win32k_subsystem::WIN32K_SHARED_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
            for i in 0..win32k_subsystem::WIN32K_ARG_FRAMES {
                let _ = page_map(copy_cap(arg_base + i), win32k_subsystem::WIN32K_ARG_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            // Parse + copy sections + relocate + patch IAT. Fully HEAP-FREE + STACK-light: the
            // 128 KiB bump heap is exhausted by this point (after smss/csrss) and the rootserver
            // stack is only 16 KiB — load_into parses win32k.sys manually and records the W^X
            // frame rights into its own `static`.
            let entry_rva = win32k_subsystem::load_into(WIN32KBUF_VADDR, win32k_size).unwrap_or(0);
            print_str(b"[win32k-svc] loaded win32k.sys; DriverEntry rva=0x");
            print_hex(entry_rva);
            print_str(b"\n");
            check(b"win32k_loaded", entry_rva == win32k_pe::WIN32K_PE.entry_rva, &mut passed);
            core::ptr::write_volatile(
                (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_ENTRY_RVA) as *mut u64,
                entry_rva as u64,
            );
            core::ptr::write_volatile((win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_VERDICT) as *mut u32, 0);
            // Pass the staged system-font (.ttf) byte size so the host can feed it to
            // IntGdiAddFontMemResource at bring-up (storage reported it at STORAGE_SHARED+0x90).
            let font_sz = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x90) as *const u32);
            core::ptr::write_volatile(
                (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_FONT_SIZE) as *mut u32,
                font_sz,
            );
            print_str(b"[win32k-svc] staged system font size=0x");
            print_hex(font_sz);
            print_str(b"\n");

            // Spawn the isolated component (prio 100; the executive is 255 and blocks in the fault
            // loop, yielding to it) and receive its faults. The bespoke `spawn_win32k_host` is gone
            // (driver-model migration): its Subsystem-class ComponentDescriptor is inlined here and
            // spawned via the generic `spawn_component` engine. win32k.sys is already loaded BY-PATH
            // (the storage host staged it into WIN32KBUF from the FS), so — like npfs — this is the
            // dynamic path; only the launch scaffolding was bespoke. The region map ORDER + every
            // `pts` value + the alloc sequence are reproduced EXACTLY (PAINT 768/768 @ 0x003a6ea5 is
            // load-bearing). Component-side trampolines (win32k_subsystem) are unchanged.
            let w_fault = make_object(OBJ_ENDPOINT);
            let host_pml4 = {
                let stack_frames = 32u64; // 128 KiB — win32k init call chains are deep
                let code_rights_static: &'static [u64] =
                    core::mem::transmute::<&[u64], &'static [u64]>(win32k_subsystem::code_rights());
                let font_base = FONTBUF_START.load(Ordering::Relaxed);
                let mut regions: [Region; 32] = [Region { source: FrameSource::Alias(0), base_va: 0, count: 0, rights: Rights::Uniform(RW_NX), pts: 0 }; 32];
                let mut n = 0usize;
                // Heap (uses the pre-built heap PT — map_heap_pt=true).
                regions[n] = Region { source: FrameSource::FreshZeroed, base_va: allocator::HEAP_BASE as u64, count: allocator::SERVICE_HEAP_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
                // win32k PE image, W^X, its own two 2 MiB PTs.
                regions[n] = Region { source: FrameSource::Alias(code_base), base_va: win32k_subsystem::WIN32K_CODE_VA, count: win32k_subsystem::WIN32K_IMAGE_FRAMES, rights: Rights::PerFrame(code_rights_static), pts: 2 }; n += 1;
                // The aux PT window (DATA/SHARED/ARG live here) — a single PT built ahead of those frames.
                regions[n] = Region { source: FrameSource::Alias(0), base_va: win32k_subsystem::WIN32K_AUX_PT_VADDR, count: 0, rights: Rights::Uniform(RW_NX), pts: 1 }; n += 1;
                // Pool arena (own window + PTs).
                regions[n] = Region { source: FrameSource::Alias(pool_base), base_va: win32k_subsystem::WIN32K_POOL_VADDR, count: win32k_subsystem::WIN32K_POOL_FRAMES, rights: Rights::Uniform(RW_NX), pts: pts_for(win32k_subsystem::WIN32K_POOL_FRAMES) }; n += 1;
                // FreeType arena (own window + PTs, fresh frames).
                regions[n] = Region { source: FrameSource::FreshZeroed, base_va: win32k_subsystem::WIN32K_FTYP_VADDR, count: win32k_subsystem::WIN32K_FTYP_FRAMES, rights: Rights::Uniform(RW_NX), pts: pts_for(win32k_subsystem::WIN32K_FTYP_FRAMES) }; n += 1;
                // GDI-attribute user-mode VM arena (own window + PTs, fresh frames).
                regions[n] = Region { source: FrameSource::FreshZeroed, base_va: win32k_subsystem::WIN32K_USERVM_VADDR, count: win32k_subsystem::WIN32K_USERVM_FRAMES, rights: Rights::Uniform(RW_NX), pts: pts_for(win32k_subsystem::WIN32K_USERVM_FRAMES) }; n += 1;
                // Staged system font (arial.ttf) — its own PT window, aliased frames (only if present).
                if font_base != 0 {
                    regions[n] = Region { source: FrameSource::Alias(font_base), base_va: win32k_subsystem::FONTBUF_VADDR, count: win32k_subsystem::FONTBUF_FRAMES, rights: Rights::Uniform(RW_NX), pts: 1 }; n += 1;
                }
                // DATA export region (aux PT window — no dedicated PT).
                regions[n] = Region { source: FrameSource::Alias(data_base), base_va: win32k_subsystem::WIN32K_DATA_VADDR, count: win32k_subsystem::WIN32K_DATA_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
                // Shared handoff page (aux PT window).
                regions[n] = Region { source: FrameSource::Alias(shared), base_va: win32k_subsystem::WIN32K_SHARED_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
                // Arg-marshal frame(s) (aux PT window).
                regions[n] = Region { source: FrameSource::Alias(arg_base), base_va: win32k_subsystem::WIN32K_ARG_VADDR, count: win32k_subsystem::WIN32K_ARG_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
                // Session-heap + Mm-view arena (own window + PTs, aliased frames).
                regions[n] = Region { source: FrameSource::Alias(heap_base), base_va: win32k_subsystem::WIN32K_HEAP_VADDR, count: win32k_subsystem::WIN32K_HEAP_FRAMES, rights: Rights::Uniform(RW_NX), pts: win32k_subsystem::WIN32K_HEAP_FRAMES / 512 }; n += 1;
                let d = ComponentDescriptor {
                    entry: win32k_subsystem::win32k_subsystem_entry,
                    image_rights: Rights::Uniform(3), // RWX (trampolines + statics)
                    map_heap_pt: true,
                    // win32k's OWN stack at WIN32K_STACK_VADDR (NOT STACK_BASE — that VA must stay free
                    // for the per-client attach). Its own dedicated PT (128 KiB fits one PT).
                    stack_base: win32k_subsystem::WIN32K_STACK_VADDR,
                    stack_frames,
                    stack_dedicated_pt: true,
                    regions: &regions[..n],
                    granted: GrantedCaps { irq_ntfn: None, result_ntfn: None, fault_ep: Some(w_fault) },
                    prio: 100,
                    // win32k is a kernel driver: it reads the KPCR via gs:[..]. Point GS at a zeroed
                    // KPCR placeholder so those reads resolve (0) instead of faulting.
                    gs_base: Some(win32k_subsystem::WIN32K_KPCR_VA),
                };
                let sc = spawn_component(&d);
                // Stash the globals the demand-map fault loop + per-client attach need. The stack frame
                // base is the first FreshZeroed frame of the dedicated stack.
                WIN32K_STACK_SLOT.store(sc.stack_frame_base, Ordering::Relaxed);
                WIN32K_STACK_FRAMES.store(stack_frames, Ordering::Relaxed);
                WIN32K_TCB.store(sc.tcb, Ordering::Relaxed);
                sc.pml4
            };

            const DEMAND_CAP: u64 = 512;
            let code_va = win32k_subsystem::WIN32K_CODE_VA;
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
                        && addr < code_va + win32k_subsystem::WIN32K_IMAGE_FRAMES * 0x1000;
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
                } else if label == win32k_subsystem::W32_DISPATCH_LABEL {
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

            let verdict = core::ptr::read_volatile((win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_VERDICT) as *const u32);
            let de_status = core::ptr::read_volatile((win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_DE_STATUS) as *const i32);
            let ssdt_base = core::ptr::read_volatile((win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SSDT_BASE) as *const u64);
            let ssdt_count = core::ptr::read_volatile((win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SSDT_COUNT) as *const u32);
            let pool_used = core::ptr::read_volatile((win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_POOL_USED) as *const u64);
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
            if (verdict & win32k_subsystem::V_SSDT) != 0 {
                print_str(b"[win32k-svc] win32k registered its NtUser/NtGdi SSDT: base=0x");
                print_hex((ssdt_base >> 32) as u32);
                print_hex(ssdt_base as u32);
                print_str(b" count=");
                print_u64(ssdt_count as u64);
                print_str(b"\n");
            }
            // Phase 2c: report the per-process attach (win32k's process-create callout) + the SSN
            // 0x10FA (NtUserProcessConnect) dispatch through the SSDT.
            let nt_handler = core::ptr::read_volatile((win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_NTUSER_HANDLER) as *const u64);
            let nt_status = core::ptr::read_volatile((win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_NTUSER_STATUS) as *const i32);
            if (verdict & win32k_subsystem::V_CALLOUT_ENTERED) != 0 {
                print_str(b"[win32k-svc] win32k process-create callout ");
                if (verdict & win32k_subsystem::V_CALLOUT_RETURNED) != 0 {
                    print_str(b"RETURNED");
                } else {
                    print_str(b"ran then faulted (see backtrace)");
                }
                print_str(b"\n");
            }
            if (verdict & win32k_subsystem::V_NTUSER_ENTERED) != 0 {
                print_str(b"[win32k-svc] NtUserProcessConnect(0x10FA) via SSDT -> handler RVA=0x");
                print_hex(nt_handler.wrapping_sub(code_va) as u32);
                if (verdict & win32k_subsystem::V_NTUSER_RETURNED) != 0 {
                    print_str(b" RETURNED status=0x");
                    print_hex(nt_status as u32);
                    if (verdict & win32k_subsystem::V_NTUSER_SUCCESS) != 0 {
                        print_str(b" (STATUS_SUCCESS)");
                    }
                } else {
                    print_str(b" (ran in component context, then faulted - see backtrace)");
                }
                print_str(b"\n");
            }
            // The routing seam works end-to-end: SSN>=0x1000 resolved to a real win32k handler
            // (verdict bit set before the fault-prone callout/connect, so this stays gate-stable).
            check(b"win32k_ntuser_ssn_routed", (verdict & win32k_subsystem::V_NTUSER_RESOLVED) != 0, &mut passed);
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
                    let hi = code_va + win32k_subsystem::WIN32K_IMAGE_FRAMES * 0x1000;
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
            check(b"win32k_driver_entry_entered", (verdict & win32k_subsystem::V_ENTERED) != 0, &mut passed);
            check(b"win32k_ssdt_registered", (verdict & win32k_subsystem::V_SSDT) != 0, &mut passed);
            // Phase-2b milestone: GreDriverEntry ran through init and registered its NtUser/NtGdi
            // SSDT (the prerequisite for Phase-2c SSN>=0x1000 routing). Whether DriverEntry then ran
            // to STATUS_SUCCESS or stopped at the next missing init piece (RVA in the log above) is
            // reported non-gating — this check passes at the achieved milestone.
            let progressed = (verdict & win32k_subsystem::V_ENTERED) != 0
                && (verdict & win32k_subsystem::V_SSDT) != 0;
            check(b"win32k_gredriverentry_progressed", progressed, &mut passed);
            // The milestone: win32k's DriverEntry ran to completion and returned STATUS_SUCCESS.
            // V_SUCCESS is set right after DriverEntry returns 0, BEFORE the exploratory per-process
            // callout/connect below — so a fault there doesn't flip this gate-critical check.
            let success = (verdict & win32k_subsystem::V_SUCCESS) != 0;
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
                core::ptr::write_bytes(win32k_subsystem::WIN32K_ARG_VADDR as *mut u8, 0, 0x240);
                let (st, ok) = win32k_dispatch(
                    win32k_subsystem::SSN_NT_USER_INITIALIZE,
                    0x0000_0000_5A5A_0100, // a process handle (ObReferenceObjectByHandle → EPROCESS)
                    win32k_subsystem::WIN32K_ARG_VADDR, // USERCONNECT buffer in the shared arg frame
                    0x240,
                    0,
                );
                let seq = core::ptr::read_volatile(
                    (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_REQ_SEQ) as *const u64,
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
                let (fst, fok) = win32k_dispatch(win32k_subsystem::SSN_TEST_FAULT, 0, 0, 0, 0);
                let fseq = core::ptr::read_volatile(
                    (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_REQ_SEQ) as *const u64,
                );
                print_str(b"[win32k-svc] FAULTING dispatch (reply-cap path): status=0x");
                print_hex(fst as u32);
                print_str(if fok { b" (serviced, seq=" } else { b" (WALL, seq=" });
                print_u64(fseq);
                print_str(b")\n");
                check(
                    b"win32k_dispatch_fault_via_reply_cap",
                    fok && fst == win32k_subsystem::TEST_FAULT_STATUS && REPLY_W32_SLOT.load(Ordering::Relaxed) != 0,
                    &mut passed,
                );
            }
        }
    }

    // --- SERVICE 9: the GENERAL DYNAMIC driver-launch path, proven with npfs.sys as the FIRST
    // CLIENT (an isolated FSD component). `load_driver` resolves \reactos\system32\drivers\npfs.sys
    // BY-PATH from the FS, IAT-patches it against the npfs ntoskrnl-import trampolines, spawns it in
    // its OWN VSpace/CNode/TCB (FSD-class descriptor — NO device caps) with a fault EP, and runs its
    // REAL DriverEntry (which IoCreateDevice(\Device\NamedPipe) + fills the MajorFunction[] table)
    // fault-contained. This is the reusable dynamic path (NT IoLoadDriver / SCM driver-start) — any
    // .sys becomes launchable at runtime; the existing bespoke spawners are follow-on migrations.
    if let Some(fs) = exec_fs() {
        print_str(b"[driver-launch] launching npfs.sys (FSD, isolated) via the general dynamic path\n");
        if let Some(dc) = load_driver(&fs, b"reactos\\system32\\drivers\\npfs.sys", DriverClass::Fsd)
        {
            register_npfs(&dc);
            // C1 checks: the general dynamic path loaded npfs isolated + ran its DriverEntry.
            check(b"npfs_driver_entry_entered", (dc.verdict & V_ENTERED) != 0, &mut passed);
            check(
                b"npfs_device_created",
                (dc.verdict & V_DEVICE) != 0 && dc.devobj != 0,
                &mut passed,
            );
            check(b"npfs_driver_entry_success", (dc.verdict & V_SUCCESS) != 0, &mut passed);
            check(b"npfs_major_function_table", (dc.verdict & V_MJ) != 0, &mut passed);
            // Isolation proof: npfs runs in its OWN VSpace (a distinct PML4 cap != the executive's).
            check(b"npfs_isolated_vspace", dc.pml4 != 0 && dc.pml4 != CAP_INIT_THREAD_VSPACE, &mut passed);
            if dc.finished && (dc.verdict & V_MJ) != 0 {
                // C2 round-trip: dispatch a REAL IRP_MJ_CREATE_NAMED_PIPE (major 1) to the live
                // component with a private probe pipe (UTF-16 "\ntstest") — exercising npfs's REAL
                // NpFsdCreateNamedPipe through a real FILE_OBJECT + IO_STACK_LOCATION. Proves the
                // routing path is real without consuming the live SCM `\ntsvcs` server instance.
                let name16: [u8; 16] = *b"\\\0n\0t\0s\0t\0e\0s\0t\0";
                let mut out = [0u8; 16];
                let r = npfs_dispatch_irp(1 /* IRP_MJ_CREATE_NAMED_PIPE */, 0, 0, &name16, &mut out);
                if let Some((st, info)) = r {
                    let srv_fid = driver_launch::npfs_last_file_id();
                    print_str(b"[npfs-svc] C2 dispatch IRP_MJ_CREATE_NAMED_PIPE(\\ntstest) -> status=0x");
                    print_hex(st as u32);
                    print_str(b" info=");
                    print_u64(info);
                    print_str(b" fsctx=0x");
                    print_hex(srv_fid as u32);
                    print_str(b"\n");
                    check(b"npfs_dispatch_roundtrip", true, &mut passed);
                    // C-a: NpFsdCreateNamedPipe COMPLETED — SUCCESS + FILE_CREATED(2) + a real CCB-backed
                    // FsContext. The VCB prefix-tree/ERESOURCE/security trampolines ran for real.
                    check(
                        b"npfs_create_named_pipe_complete",
                        st == 0 && info == 2 && srv_fid != 0,
                        &mut passed,
                    );
                    // C-a: create-then-CONNECT — a client IRP_MJ_CREATE(\ntstest) must find the FCB via the
                    // real prefix tree and return a connected client-end FILE_OBJECT (proves Insert+Find work).
                    let mut cout = [0u8; 16];
                    if let Some((cst, _cinfo)) =
                        npfs_dispatch_irp(0 /* IRP_MJ_CREATE */, 0, 0, &name16, &mut cout)
                    {
                        let cli_fid = driver_launch::npfs_last_file_id();
                        print_str(b"[npfs-svc] C-a connect IRP_MJ_CREATE(\\ntstest) -> status=0x");
                        print_hex(cst as u32);
                        print_str(b" fsctx=0x");
                        print_hex(cli_fid as u32);
                        print_str(b"\n");
                        check(b"npfs_client_connect_finds_fcb", cst == 0 && cli_fid != 0, &mut passed);
                        if cst == 0 && cli_fid != 0 {
                            let pipe_info = [1u8, 0, 0, 0, 0, 0, 0, 0];
                            let mut set_out = [];
                            if let Some((sst, sinfo)) = npfs_dispatch_irp(
                                6 /* IRP_MJ_SET_INFORMATION */,
                                23 /* FilePipeInformation */,
                                cli_fid,
                                &pipe_info,
                                &mut set_out,
                            ) {
                                print_str(b"[npfs-svc] C-b IRP_MJ_SET_INFORMATION(FilePipeInformation) -> status=0x");
                                print_hex(sst as u32);
                                print_str(b" info=");
                                print_u64(sinfo);
                                print_str(b"\n");
                                check(b"npfs_set_pipe_information", sst == 0 && sinfo == 0, &mut passed);
                            }
                        }
                    }
                }
            }
        } else {
            print_str(b"[driver-launch] npfs.sys launch returned None (not staged / load failed)\n");
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
                // OUR Rust ntdll IS `\reactos\system32\ntdll.dll` (make_image stages ours under that
                // name; the real ReactOS ntdll is NOT on the image). So the ntdll bytes the storage
                // host read into NTDLLBUF are OURS — no separate load, no flag, no fallback. We DERIVE
                // LdrpInitialize's RVA from the loaded ntdll's export table (never hardcode — it drifts
                // across builds) and pass it to the spawn trampoline so it calls OUR loader entry.
                if let Ok(ntdll_pe) = nt_pe_loader::PeFile::parse(ntdll_bytes) {
                    // Relocate ntdll for its load at NTDLL_BASE — its .data list heads etc. hold
                    // absolute self-pointers at the preferred base otherwise.
                    apply_relocations_to_buf(&ntdll_pe, NTDLLBUF_VADDR, NTDLL_BASE);
                    // Derive OUR LdrpInitialize RVA from the (single, ours) ntdll export table.
                    let smss_ldrp_rva = ntdll_pe
                        .exports()
                        .ok()
                        .and_then(|es| {
                            es.into_iter()
                                .find(|e| e.name == "LdrpInitialize")
                                .map(|e| e.rva as u64)
                        })
                        .unwrap_or(0);
                    // Publish it so EVERY hosted SEC_IMAGE spawn (csrss/winlogon/services/lsass, all
                    // spawned in service_sec_image.rs) calls OUR LdrpInitialize + uses the native
                    // transport — our ntdll is the ntdll for all of them, not just smss.
                    img_spawn::OUR_LDRP_RVA.store(smss_ldrp_rva, Ordering::Relaxed);
                    print_str(b"[ntos-exec] ntdll = OUR Rust ntdll, LdrpInitialize RVA=0x");
                    print_hex(smss_ldrp_rva as u32);
                    print_str(b"\n");
                    let smss_ntdll_pe: &nt_pe_loader::PeFile = &ntdll_pe;
                    // setup_env=true: a PEB + process params + trampoline so smss's entry gets a
                    // non-null PEB in RCX and runs its real startup (past the RtlAssert/null-deref).
                    let pml4 = spawn_sec_image(0, &pe, si_fault_c, NTDLL_BASE, true, 100, 0x0000_0100_1074_0000, SMSS_STACK_MIRROR_VA, SMSS_HEAP_MIRROR_VA, 0, b"\\SystemRoot\\System32\\smss.exe", b"smss.exe", smss_ldrp_rva);
                    // Demand-fault scratch: each filled image/ntdll page keeps a persistent
                    // executive mapping (indexed by fill order, for syscall copy-out to smss pages),
                    // so the region grows one page per fault. BATCH 22: smss now uses its own 64 MiB
                    // demand-scratch window (SMSS_SCRATCH_BASE) with 16 pre-mapped PTs, matching the
                    // widened per-process layout — clear of every other executive mapping.
                    const SCRATCH_BASE: u64 = SMSS_SCRATCH_BASE;
                    map_demand_scratch_pts(SCRATCH_BASE);
                    // The demand-fault router fills ntdll's pages from THIS PE — pass OUR ntdll when
                    // substituting so smss's ntdll pages (incl. OUR LdrpInitialize .text) fault in
                    // from OUR DLL's bytes; otherwise the real ntdll (fallback).
                    let (heap_verdict, sfaults, sfirst, sstop, ntfaults, sssn) = service_sec_image(
                        si_fault,
                        pml4,
                        &pe,
                        SCRATCH_BASE,
                        Some((NTDLL_BASE, smss_ntdll_pe)),
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
                    // P5 — winlogon's InitKeyboardLayouts fallback reached its layout key: the
                    // paint-safe MACHINE_ROOT sentinel let RegOpenKeyExW(HKLM\...\Keyboard
                    // Layouts\00000409) SUCCEED (the previously-fatal open), so winlogon runs past
                    // InitKeyboardLayouts toward StartRpcServer/StartServicesManager.
                    check(
                        b"exec_kbd_layout_opened",
                        KBD_LAYOUT_KEY_OPENED.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    // P5 — winlogon ran PAST InitKeyboardLayouts into StartRpcServer: rpcrt4's
                    // ncacn_np server created \pipe\winreg (NtCreateNamedPipeFile modeled). It then
                    // walls in RpcServerListen (its RPC listener thread needs a real TEB — the
                    // hosted-process multi-threading fork).
                    check(
                        b"exec_winlogon_rpc_pipe",
                        NAMED_PIPE_CREATED.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    // C-b: the LIVE pipe syscalls (services' SCM \pipe\ntsvcs create + its FSCTL_LISTEN)
                    // are ROUTED THROUGH the isolated npfs FSD (real NpFsdCreateNamedPipe / IRP dispatch),
                    // not the modeled-fake path. Proven by the routed-IRP counter.
                    check(
                        b"exec_pipe_syscalls_routed_through_npfs",
                        NPFS_ROUTED_IRPS.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    check(
                        b"exec_npfs_flush_pending",
                        NT_FLUSH_BUFFERS_FILE_PENDING_COUNT.load(Ordering::Relaxed) >= 2,
                        &mut passed,
                    );
                    // C-c: the N-threads-per-process fault-multiplex. services' SCM RPC listener thread
                    // (rpcrt4 io_thread) is a REAL seL4 thread SPAWNED + RESUMED into the SAME service
                    // loop as its main thread, with a distinct fault-EP badge (SVC_LISTENER_BADGE) that
                    // sub-selects (pi 3, listener) → the listener's OWN stack mirror/TEB. This is the
                    // reusable mechanism (lsass + any multi-thread process). Proven: its real TCB exists
                    // (mechanism live) — with it + the real npfs pipe, rpcrt4 gets PAST the 0x2c8 deref
                    // and the SCM RPC server goes live (the boot advances to winlogon's StartLsass).
                    check(
                        b"exec_svc_rpc_listener_multiplex",
                        SVC_LISTENER_TCB.load(Ordering::Relaxed) > 1
                            && SVC_LISTENER_TID.load(Ordering::Relaxed) != 0,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] C-c N-threads multiplex: svc-listener tcb=0x");
                    print_hex(SVC_LISTENER_TCB.load(Ordering::Relaxed) as u32);
                    print_str(b" tid=");
                    print_u64(SVC_LISTENER_TID.load(Ordering::Relaxed));
                    print_str(b" listener-faults-serviced=");
                    print_u64(SVC_LISTENER_FAULTS.load(Ordering::Relaxed));
                    print_str(b"\n");
                    // SERVICE 10 step 2 increment 1: lsass' LSA server thread runs through the SAME
                    // N-threads multiplex (badge LSASS_LISTENER_BADGE, its own stack mirror/TEB) — a real
                    // seL4 thread spawned + resumed into the service loop, its faults serviced (proving
                    // lsass' server threads advance past the tcb=30 stack-fault wall).
                    check(
                        b"exec_lsass_lsa_server_thread_multiplex",
                        LSASS_LISTENER_TCB.load(Ordering::Relaxed) > 1
                            && LSASS_LISTENER_TID.load(Ordering::Relaxed) != 0,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] lsass N-threads multiplex: lsass-listener tcb=0x");
                    print_hex(LSASS_LISTENER_TCB.load(Ordering::Relaxed) as u32);
                    print_str(b" tid=");
                    print_u64(LSASS_LISTENER_TID.load(Ordering::Relaxed));
                    print_str(b" listener-faults-serviced=");
                    print_u64(LSASS_LISTENER_FAULTS.load(Ordering::Relaxed));
                    print_str(b"\n");
                    // ★ GENERAL NtCreateThread (real service): winlogon's RPC listener thread is a REAL
                    // seL4-thread-backed nt-process ETHREAD — its NtCreateThread popped a pool ETHREAD,
                    // bound the RPC listener StartRoutine, mapped a real TEB, and minted a typed Thread
                    // handle (`exec_general_nt_create_thread`). The main thread then read that thread's
                    // real TEB/ClientId via NtQueryInformationThread(ThreadBasicInformation), so
                    // kernel32's RPC listener setup no longer NULL-derefs an absent TEB
                    // (`exec_rpc_listener_thread_real`) → StartRpcServer runs past the wall.
                    check(
                        b"exec_general_nt_create_thread",
                        PM_GENERAL_THREADS_CREATED.load(Ordering::Relaxed) >= 1
                            && WL_LISTENER_TCB.load(Ordering::Relaxed) > 1
                            && PM_LISTENER_TID.load(Ordering::Relaxed) != 0,
                        &mut passed,
                    );
                    check(
                        b"exec_rpc_listener_thread_real",
                        WL_LISTENER_TEB_QUERIED.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    // nt-process convergence (first increment): the real Process Manager backs the 3
                    // hosted processes with EPROCESS objects. `exec_process_manager_up` = 3 EPROCESSes
                    // exist; `exec_eprocess_backs_badges` = each pi's EPROCESS names its hosted binary
                    // with a distinct pid (identity is real, not a scalar); `exec_eprocess_lookup_by_badge`
                    // = the live service loop resolved a fault badge → its EPROCESS through the manager.
                    check(
                        b"exec_process_manager_up",
                        PM_PROC_COUNT.load(Ordering::Relaxed) == 5,
                        &mut passed,
                    );
                    check(
                        b"exec_eprocess_backs_badges",
                        PM_IDENTITY_OK.load(Ordering::Relaxed) == 0b11111,
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
                        PM_MAIN_THREADS_OK.load(Ordering::Relaxed) == 0b11111,
                        &mut passed,
                    );
                    check(
                        b"exec_main_thread_bound_at_spawn",
                        PM_THREAD_BINDS.load(Ordering::Relaxed) >= 5,
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
                    // csrss (bit 1), services (bit 3), and lsass (bit 4) self-exit;
                    // smss/winlogon (bits 0/2) do not.
                    let term_state = PM_TERMINATE_THREAD_STATE.load(Ordering::Relaxed);
                    check(
                        b"exec_live_terminate_thread_routed",
                        PM_TERMINATE_THREAD_LIVE.load(Ordering::Relaxed) >= 3
                            && (term_state & 0b010) != 0
                            && (term_state & 0b1000) != 0
                            && (term_state & 0b1_0000) != 0
                            && (term_state & 0b101) == 0,
                        &mut passed,
                    );
                    check(
                        b"exec_live_terminate_thread_tcb_reclaimed",
                        PM_TERMINATE_THREAD_TCB_RECLAIMED.load(Ordering::Relaxed) >= 3,
                        &mut passed,
                    );
                    let terminated_badges = PM_TERMINATE_THREAD_BADGES.load(Ordering::Relaxed);
                    let continued_badges = PM_POST_TERM_CONTINUED_BADGES.load(Ordering::Relaxed);
                    check(
                        b"exec_live_terminate_thread_no_reply",
                        PM_TERMINATE_THREAD_NO_REPLY.load(Ordering::Relaxed) >= 3,
                        &mut passed,
                    );
                    check(
                        b"exec_live_terminate_thread_unrelated_continued",
                        continued_badges & !terminated_badges != 0,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] item2a live-terminate-thread: count=0x");
                    print_hex(PM_TERMINATE_THREAD_LIVE.load(Ordering::Relaxed) as u32);
                    print_str(b" ethread-terminated-bits=0x");
                    print_hex(PM_TERMINATE_THREAD_STATE.load(Ordering::Relaxed) as u32);
                    print_str(b" nt-terminate-process-calls=0x");
                    print_hex(PM_TERMINATE_CALLS.load(Ordering::Relaxed) as u32);
                    print_str(b" tcb-reclaimed=0x");
                    print_hex(PM_TERMINATE_THREAD_TCB_RECLAIMED.load(Ordering::Relaxed) as u32);
                    print_str(b" no-reply=0x");
                    print_hex(PM_TERMINATE_THREAD_NO_REPLY.load(Ordering::Relaxed) as u32);
                    print_str(b" term-badges=0x");
                    print_hex(terminated_badges as u32);
                    print_str(b" continued-badges=0x");
                    print_hex(continued_badges as u32);
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
                        PM_EXEC_LINK_OK.load(Ordering::Relaxed) == 0b11111,
                        &mut passed,
                    );
                    // ★ MILESTONE — services.exe is the 4th hosted process: winlogon's Win32
                    // CreateProcessW (StartServicesManager → NtCreateProcessEx) spawned it (badge 6, pi
                    // 3) via spawn_sec_image, and its REAL ntdll loader ran (demand-faulted its image +
                    // ntdll + DLLs, resolved BY PATH from the FS pool). `exec_services_spawned` = the
                    // spawn fired; `exec_services_loader_running` = its loader demand-faulted pages.
                    check(
                        b"exec_services_spawned",
                        SERVICES_SPAWNED.load(Ordering::Relaxed) == 1,
                        &mut passed,
                    );
                    check(
                        b"exec_services_loader_running",
                        SERVICES_FAULTS.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    // ★ MILESTONE (SERVICE 10) — lsass.exe is the 5th hosted process: winlogon's
                    // StartLsass (CreateProcessW(L"lsass.exe") → NtCreateProcessEx) spawned it (badge 8,
                    // pi 4) via spawn_sec_image, and its REAL ntdll loader ran. NtWaitForSingleObject
                    // still returns immediately (winlogon's WaitForLsass) — real blocking is step 2.
                    check(
                        b"exec_lsass_spawned",
                        LSASS_SPAWNED.load(Ordering::Relaxed) == 1,
                        &mut passed,
                    );
                    check(
                        b"exec_lsass_loader_running",
                        LSASS_FAULTS.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    // SERVICE 10 step 2 (checkpoint A): lsasrv.dll + samsrv.dll are registered, so
                    // lsass's loader resolves them, reaches its real LSA entry, and runs
                    // LsapInitLsa → LsapRmInitializeServer, whose NtConnectPort(\SeRmCommandPort) we
                    // model-accept. This proves lsass advanced PAST the lsasrv DLL_NOT_FOUND wall into
                    // its genuine SRM/LSA-database bring-up.
                    check(
                        b"exec_lsass_lsa_init_running",
                        LSASS_SRM_CONNECTED.load(Ordering::Relaxed) == 1,
                        &mut passed,
                    );
                    // ★★ CHECKPOINT B (the LSA/wait milestone) — lsass runs its full LsarStartRpcServer
                    // and SIGNALS LSA_RPC_SERVER_ACTIVE (SetEvent, lsarpc.c:105). Proves lsass reached
                    // its signal point (past the RpcServerListen/pipe setup).
                    check(
                        b"exec_lsass_signals_lsa_rpc_active",
                        LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) == 1,
                        &mut passed,
                    );
                    // ★★ CHECKPOINT B — REAL reply-cap parking: a waiter (services' ScmWaitForLsa /
                    // winlogon's WaitForLsass, both WaitForSingleObject(LSA_RPC_SERVER_ACTIVE, INFINITE))
                    // genuinely BLOCKED on the unsignaled event (parked — the loop kept receiving) and
                    // was WOKEN by lsass' NtSetEvent. This is the block-then-wake proof: the immediate-
                    // return NtWaitForSingleObject stub is REPLACED by a real event-state wait for named
                    // events with a live signaler. parked>=1 && woken>=1.
                    check(
                        b"exec_wait_reply_cap_park_wake",
                        WAIT_PARKED_COUNT.load(Ordering::Relaxed) >= 1
                            && WAIT_WOKEN_COUNT.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    // ★ SERVICE 10 step 2 (Part 2) — winlogon's rpcrt4 server WORKER thread is
                    // MULTIPLEXED (badge WINLOGON_WORKER_BADGE) and actually RUNS (not suspended): it
                    // executes its wait array (NtWaitForMultipleObjects) through the N-threads loop.
                    // WL_WORKER_FAULTS>=1 proves the worker was scheduled + serviced at least once.
                    check(
                        b"exec_winlogon_worker_multiplex",
                        WL_WORKER_FAULTS.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] winlogon rpcrt4 worker multiplex events=0x");
                    print_hex(WL_WORKER_FAULTS.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
                    print_str(b"[ntos-exec] Checkpoint B: LSA_RPC_SERVER_ACTIVE signalled=0x");
                    print_hex(LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) as u32);
                    print_str(b" waiters parked=0x");
                    print_hex(WAIT_PARKED_COUNT.load(Ordering::Relaxed) as u32);
                    print_str(b" woken=0x");
                    print_hex(WAIT_WOKEN_COUNT.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
                    print_str(b"[ntos-exec] lsass spawned=0x");
                    print_hex(LSASS_SPAWNED.load(Ordering::Relaxed) as u32);
                    print_str(b" faults=0x");
                    print_hex(LSASS_FAULTS.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
                    // ★ GENERAL per-process CSR client-connect: services.exe (pi 3) connected to
                    // csrss's \Windows\ApiPort through the SAME mechanism winlogon (pi 2) uses — its own
                    // CSR heap-view + static-server-data mapped into ITS VSpace, the real
                    // CsrApiRequestThread accept. Both bits set (0b1100) proves the CSR connect is a
                    // per-process service, not winlogon-specific.
                    check(
                        b"exec_services_csr_connect",
                        CSR_CONNECTED_MASK.load(Ordering::Relaxed) & (1 << 3) != 0,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] CSR per-process connect mask=0x");
                    print_hex(CSR_CONNECTED_MASK.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
                    // ★ MILESTONE — services.exe is the 3rd win32k GUI client: its user32 DllMain
                    // NtUserProcessConnect (SSN 0x10FA) was routed to the win32k component (badge 6 /
                    // pi 3, the KeStackAttachProcess w32_client_attach re-point + the pi-keyed CSR heap
                    // RO-map) and returned STATUS_SUCCESS — bit 3 set. csrss (pi 1) + winlogon (pi 2)
                    // connects still work (the counted desktop paint below proves win32k still serves
                    // them). Three win32k clients coexist through the one parked win32k component.
                    check(
                        b"exec_services_win32k_connect",
                        W32_CONNECTED_MASK.load(Ordering::Relaxed) & (1 << 3) != 0,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] win32k per-process connect mask=0x");
                    print_hex(W32_CONNECTED_MASK.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
                    // ★ SERVICE 8 — services' SCM creates REAL named events in \BaseNamedObjects
                    // (SCM_START_EVENT / SC_AutoStartComplete / LSA_RPC_SERVER_ACTIVE / …) via
                    // NtCreateEvent: the named-event object is registered + the handle written back
                    // (was: no out-handle → CreateEventW returned NULL → wall). And ntdll's named-object
                    // path (NtQueryDirectoryObject enumerating \BaseNamedObjects) is serviced — the SSN
                    // 152 wall is gone. Past both, the SCM advances through CreateEventW(SCM_START/
                    // AUTOSTARTCOMPLETE) → ScmCreateServiceDatabase → RPC-server startup
                    // (NtCreateNamedPipeFile \pipe\ntsvcs). Waits still return immediately (no deadlock).
                    check(
                        b"exec_services_named_events",
                        SERVICES_NAMED_EVENTS.load(Ordering::Relaxed) >= 2,
                        &mut passed,
                    );
                    check(
                        b"exec_services_query_dir_object",
                        SERVICES_QUERY_DIR_OBJECT.load(Ordering::Relaxed) >= 1,
                        &mut passed,
                    );
                    print_str(b"[ntos-exec] SERVICE 8: services named-events=0x");
                    print_hex(SERVICES_NAMED_EVENTS.load(Ordering::Relaxed) as u32);
                    print_str(b" query-dir-object=0x");
                    print_hex(SERVICES_QUERY_DIR_OBJECT.load(Ordering::Relaxed) as u32);
                    print_str(b"\n");
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

        // BATCH 10 — RIP-instrument the winlogon user32-init spin. winlogon (pi 2) is PARKED at its
        // busy-spin by the time the specs run (its ntdll loader quiesced with no faults/syscalls).
        // Sample its saved RIP twice via seL4_TCB_ReadRegisters and classify against the known
        // module bases so we can decide (a) OUR ntdll CS bug vs (b) a user32/kernel32 shared-value
        // poll. If the two samples land in different functions it's a genuine loop; identical = a
        // tight self-loop. Module bases (from the DEMAND-LOAD log): user32=0x80150000,
        // kernel32=0x803a0000, gdi32=0x800f0000, advapi32=0x80280000, winsrv=0x80080000,
        // ntdll=NTDLL_BASE(0x100_0080_0000), winlogon.exe=PE_LOAD_BASE(0x100_0056_0000).
        let wl_tcb = PM_MAIN_TCBS[2].load(Ordering::Relaxed);
        if wl_tcb > 1 {
            for s in 0..3u64 {
                let rip = unsafe { crate::win32k_glue::tcb_read_rip(wl_tcb) };
                print_str(b"[batch10] winlogon parked RIP sample #");
                print_u64(s);
                print_str(b" = 0x");
                print_hex((rip >> 32) as u32);
                print_hex(rip as u32);
                // Classify + emit the module-relative RVA.
                let (name, base): (&[u8], u64) = if rip >= NTDLL_BASE && rip < NTDLL_BASE + 0x20_0000 {
                    (b"ntdll", NTDLL_BASE)
                } else if rip >= PE_LOAD_BASE && rip < PE_LOAD_BASE + 0x20_0000 {
                    (b"winlogon.exe", PE_LOAD_BASE)
                } else if rip >= 0x803a0000 && rip < 0x803a0000 + 0x2b0000 {
                    (b"kernel32", 0x803a0000)
                } else if rip >= 0x80150000 && rip < 0x80150000 + 0x130000 {
                    (b"user32", 0x80150000)
                } else if rip >= 0x80280000 && rip < 0x80280000 + 0x80000 {
                    (b"advapi32", 0x80280000)
                } else if rip >= 0x800f0000 && rip < 0x800f0000 + 0x60000 {
                    (b"gdi32", 0x800f0000)
                } else if rip >= 0x80080000 && rip < 0x80080000 + 0x70000 {
                    (b"winsrv", 0x80080000)
                } else if rip >= 0x80690000 && rip < 0x80690000 + 0x100000 {
                    (b"msvcrt", 0x80690000)
                } else {
                    (b"?", 0)
                };
                print_str(b" (");
                print_str(name);
                if base != 0 {
                    print_str(b"+0x");
                    print_hex((rip - base) as u32);
                }
                print_str(b")\n");
            }
        } else {
            print_str(b"[batch10] winlogon TCB not available for RIP sample\n");
        }
    }

    // SELF-CONTAINED delay specs: exercise the `nt_delay_execution` PUBLIC interface directly
    // (the deadline arithmetic + the park/wake queue), rather than depending on a hosted process
    // incidentally issuing NtDelayExecution during boot. The old runtime-counter assertions were
    // trajectory-fragile — they went red when winlogon's worker started deadlocking earlier (before
    // any delay fired). The counters below remain as a diagnostic of whether the LIVE path was hit.
    let delay_park_wake_ok = {
        use nt_delay_execution::{due_time, Due, Queue, Waiter};
        // Deadline arithmetic: interval 0 fires immediately; a relative (negative) interval parks
        // at now + |interval| on the monotonic clock.
        let immediate = matches!(due_time(0, 1000, 2000), Due::Immediate);
        let future = matches!(due_time(-500, 1000, 2000), Due::Monotonic100ns(1500));
        // Park/wake: a waiter is NOT due before its deadline (parked) and pops exactly at/after it
        // (woken), leaving the queue empty.
        let mut q = Queue::<4>::new();
        let w = Waiter {
            deadline_100ns: 1500,
            sequence: 0,
            reply_cap: 1,
            resume_ip: 0,
            resume_sp: 0,
            resume_flags: 0,
            thread_id: 7,
            badge: 3,
        };
        let inserted = q.insert(w).is_ok();
        let parked = q.next_deadline() == Some(1500) && q.pop_due(1499).is_none();
        let woken = q.pop_due(1500).map(|x| x.thread_id) == Some(7) && q.len() == 0;
        immediate && future && inserted && parked && woken
    };
    check(b"exec_delay_execution_park_wake", delay_park_wake_ok, &mut passed);
    let delay_multiplex_ok = {
        use nt_delay_execution::{Queue, Waiter};
        let mk = |deadline_100ns: u64, thread_id: u64, badge: u64| Waiter {
            deadline_100ns,
            sequence: 0,
            reply_cap: 1,
            resume_ip: 0,
            resume_sp: 0,
            resume_flags: 0,
            thread_id,
            badge,
        };
        // Multiplex property: waiters from DIFFERENT badges park concurrently, so while one badge
        // is parked the loop can still progress another. Wakes happen in deadline order regardless
        // of badge (the earlier-deadline badge-5 waiter wakes before the badge-3 one).
        let mut q = Queue::<4>::new();
        let ins1 = q.insert(mk(2000, 1, 3)).is_ok();
        let ins2 = q.insert(mk(1000, 2, 5)).is_ok();
        let cross = q.has_badge_other_than(3) && q.has_badge_other_than(5);
        let first = q.pop_due(1000).map(|w| (w.thread_id, w.badge)) == Some((2, 5));
        let second_not_yet = q.pop_due(1500).is_none();
        let second = q.pop_due(2000).map(|w| (w.thread_id, w.badge)) == Some((1, 3));
        ins1 && ins2 && cross && first && second_not_yet && second
    };
    check(b"exec_delay_execution_multiplex", delay_multiplex_ok, &mut passed);
    print_str(b"[ntos-exec] delay calls=0x");
    print_hex(DELAY_TRACE_COUNT.load(Ordering::Relaxed) as u32);
    print_str(b" parked=0x");
    print_hex(DELAY_PARKED_COUNT.load(Ordering::Relaxed) as u32);
    print_str(b" woken=0x");
    print_hex(DELAY_WOKEN_COUNT.load(Ordering::Relaxed) as u32);
    print_str(b" multiplex=0x");
    print_hex(DELAY_OTHER_BADGE_PROGRESS.load(Ordering::Relaxed) as u32);
    print_str(b"\n");

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
    print_str(b"/98 executive->isolated-service checks passed]\n");
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
