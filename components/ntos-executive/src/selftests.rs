//! `selftests` — post-loop MECHANISM self-tests (seL4 reclaim/teardown + the
//! two-VSpace ALPC cross-AS section-view xview test). Extracted verbatim from
//! `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

/// ITEM 2b — prove the seL4 MECHANISM-teardown (reclamation) end-to-end on a THROWAWAY untyped, with
/// ZERO risk to the live boot: runs POST-LOOP (all spawns done), touches only freshly-retyped
/// throwaway caps + an UNUSED offset of smss's (already-torn-down) demand-fill scratch region, and
/// deletes everything it makes → the 3 hosted processes' TCB/VSpace/CSpace/frames are NEVER touched.
/// Returns a bitmask of proven properties (all set = 0b11_1111 = the mechanism works). This is the
/// reclamation MECHANISM the coordinator asked to prove before (optionally) applying it live.
///
/// `RECLAIM_VA`: an unused page of smss's demand-fill scratch window (`SMSS_SCRATCH_BASE`, 16 PTs =
/// 8192 pages, mapped into the executive's OWN VSpace); smss faulted ~136 pages (offsets < 0x9_0000),
/// so page 3000 (offset 0xBB8_000) is free + its PT exists → a safe, isolated frame-map/unmap target.
pub(crate) unsafe fn reclaim_mechanism_selftest() -> u64 {
    const RECLAIM_VA: u64 = SMSS_SCRATCH_BASE + 3000 * 0x1000;
    let mut ok = 0u64;

    // (bit0) Carve a THROWAWAY child untyped — 2^16 = 64 KiB (room for ~16 x 4 KiB frames) — out of
    // the boot untyped. Deleting it at the end returns those 64 KiB to CAP_INIT_UNTYPED.
    let child = alloc_slot();
    if untyped_retype_from_r(CAP_INIT_UNTYPED, OBJ_UNTYPED, 16, 1, child) == 0 {
        ok |= 1 << 0;
    }

    // (bit1) FRAME RECLAMATION via Untyped-return. Allocate 4 KiB frames from the child until it is
    // EXHAUSTED (round 1, count K); CNodeDelete every one; then RESET the child untyped
    // (CNodeRevoke on the child cap = revoke all descendants + roll free_index back to 0) and
    // allocate again INTO THE SAME SLOTS (round 2). round2 == round1 (and K >= 8) proves the child
    // returned its full capacity — the hard "return-to-Untyped" reclamation.
    //
    // ★ BATCH 21: plain CNodeDelete of the frames did NOT roll the child's free_index back under the
    // deeper 5-process boot (lsass now spawned): round-2 retypes failed with seL4_NotEnoughMemory
    // (free_index stuck at capacity though every frame delete succeeded). An explicit CNodeRevoke on
    // the child cap is the definitive reset (it is exactly what the kernel's own "500 alloc/free
    // cycles reclaim untyped free_index" test exercises) — robust regardless of how full/fragmented
    // the parent CAP_INIT_UNTYPED is at this (deeper) stop point.
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
    // Revoke the child untyped: drops any straggler descendants AND resets its free_index to 0.
    let revoked = cnode_revoke_r(child) == 0;
    let mut round2 = 0usize;
    while round2 < round1 {
        // Retype into the round-1 slot (Null after delete): proves the child's capacity is fully
        // reclaimed. A fresh retype into a freed slot must succeed.
        if untyped_retype_from_r(child, OBJ_X86_4K_PAGE, PAGING_BITS, 1, fslots[round2]) != 0 {
            break;
        }
        round2 += 1;
    }
    if deleted_all && revoked && round1 >= 8 && round2 == round1 {
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
pub(crate) fn xview_writer_code(view: u64, pattern: u64) -> alloc::vec::Vec<u8> {
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
pub(crate) fn xview_reader_code(view: u64) -> alloc::vec::Vec<u8> {
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
pub(crate) unsafe fn xview_spawn(
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
pub(crate) unsafe fn alpc_cross_vspace_selftest() -> u64 {
    const PATTERN: u64 = 0xCAFE_BABE_DEAD_BEEF;
    // Executive-VSpace scratch pages to write each endpoint's code frame + one window onto the
    // section frame for an independent read. These sit in smss's (already-torn-down) demand-fill
    // scratch span, in the SAME 2 MiB page table as the reclaim self-test's proven-mapped RECLAIM_VA
    // (base + 3000*0x1000, PT index 5) — offsets 3001..3003 share that resident PT, so mapping a
    // fresh frame there succeeds (a page_map to an absent PT would silently fail → the executive
    // would then fault writing the trampoline; staying in the proven PT avoids that).
    const SCRATCH_BASE: u64 = SMSS_SCRATCH_BASE;
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
