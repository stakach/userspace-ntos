//! `img_spawn` — PE image build/spawn + SEC_IMAGE spawn (spawn_sec_image) +
//! the smss/csrss cross-AS memory access helpers (smss_stack_*/smss_copyin/out/
//! csrss_out_write/scratch_for) + reloc/rva helpers. Extracted verbatim from
//! `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

/// Build a PE32+/x86_64 image. `sections` = (name8, va, chars, data); `dirs` = (index, rva,
/// size). Mirrors nt-pe-loader's own test builder (crates/nt-pe-loader/tests/parse.rs).
pub(crate) unsafe fn build_pe(
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
pub(crate) unsafe fn build_import_table() -> alloc::vec::Vec<u8> {
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
pub(crate) unsafe fn build_pe_text() -> alloc::vec::Vec<u8> {
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
pub(crate) unsafe fn build_sec_image_text() -> alloc::vec::Vec<u8> {
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
pub(crate) unsafe fn spawn_pe_thread(mapped: &nt_pe_loader::MappedImage, fault_ep_c: u64, sysarg_c: u64) -> u64 {
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
pub(crate) unsafe fn page_rights(pe: &nt_pe_loader::PeFile, rva: u32) -> u64 {
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
pub(crate) unsafe fn fill_image_page(pe: &nt_pe_loader::PeFile, rva: u32, dst: u64) -> u64 {
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
pub(crate) unsafe fn spawn_sec_image(
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
        // Build the KUSER page via a scratch mapping so we can populate the fields the Win32 create
        // path reads. KUSER_SHARED_DATA.ImageNumberLow(@0x260)/ImageNumberHigh(@0x262) bound the
        // machine types kernel32's CreateProcessInternalW allows (proc.c:3474 —
        // ImageInformation.Machine outside [Low,High] → NtRaiseHardError STATUS_IMAGE_MACHINE_TYPE_
        // MISMATCH_EXE). A zeroed page → [0,0] → rejects our AMD64 (0x8664) EXEs. Set the authentic x64
        // range 0x014c (i386) .. 0x8664 (amd64) so services.exe (and any hosted create target) passes.
        // Offsets are the ReactOS KUSER_SHARED_DATA layout: ImageNumberLow@0x2c, ImageNumberHigh@0x2e.
        let kuser_f = alloc_frame();
        let kscr = scr + 0x6000; // next free page in the env-scratch window (past env at +0x4000/+0x5000)
        let _ = page_map(kuser_f, kscr, RW_NX, CAP_INIT_THREAD_VSPACE);
        core::ptr::write_volatile((kscr + 0x2c) as *mut u16, 0x014c); // ImageNumberLow  (IMAGE_FILE_MACHINE_I386)
        core::ptr::write_volatile((kscr + 0x2e) as *mut u16, 0x8664); // ImageNumberHigh (IMAGE_FILE_MACHINE_AMD64)
        let _ = page_map(copy_cap(kuser_f), KUSER_VA, RW_NX, pml4);
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
    if (pi as usize) < MAX_PI {
        PM_MAIN_TCBS[pi as usize].store(tcb, Ordering::Relaxed);
    }
    let _ = tcb_resume(tcb);
    pml4
}

/// Read a u64 from a SEC_IMAGE process's stack VA (a syscall's pointer arg) via the executive's
/// stack mirror. Returns 0 if the VA isn't in the mirrored stack range.
pub(crate) unsafe fn smss_stack_read(stack_va: u64) -> u64 {
    let base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    if stack_va >= base && stack_va + 8 <= base + size {
        let mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
        core::ptr::read_volatile((mirror + (stack_va - base)) as *const u64)
    } else {
        0
    }
}
/// Translate a SEC_IMAGE process VA to its executive mirror VA (stack or heap window), or None if
/// the range isn't covered by a mirror. The executive's copyin/copyout base: a userspace broker
/// can't walk smss's page tables, so it reaches smss memory through the same frames it mapped.
pub(crate) unsafe fn smss_mirror(va: u64, len: u64) -> Option<u64> {
    let stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    if va >= stack_base && va + len <= stack_base + stack_size {
        Some(ACTIVE_STACK_MIRROR.load(Ordering::Relaxed) + (va - stack_base))
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
pub(crate) unsafe fn smss_copyin(va: u64, dst: &mut [u8]) -> bool {
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
pub(crate) unsafe fn smss_copyout(va: u64, src: &[u8]) -> bool {
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
pub(crate) unsafe fn scratch_for(va: u64, filled_pages: &[u64], nfilled: usize, scratch_base: u64) -> Option<u64> {
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
pub(crate) unsafe fn csrss_out_write(
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
pub(crate) unsafe fn smss_read_unicode(buffer_va: u64, byte_len: u16) -> alloc::vec::Vec<u16> {
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
pub(crate) unsafe fn smss_read_ustr(ustr_va: u64) -> alloc::vec::Vec<u16> {
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
pub(crate) unsafe fn smss_read_objattr_name(oa_va: u64) -> alloc::vec::Vec<u16> {
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
pub(crate) unsafe fn smss_stack_write(stack_va: u64, v: u64) {
    let base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    if stack_va >= base && stack_va + 8 <= base + size {
        let mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
        core::ptr::write_volatile((mirror + (stack_va - base)) as *mut u64, v);
    }
}

/// Write a 32-bit value to a stack VA (via the mirror). Use for DWORD out-params (e.g. an
/// NtProtectVirtualMemory *OldProtect) — an 8-byte write would clobber the adjacent local.
pub(crate) unsafe fn smss_stack_write32(stack_va: u64, v: u32) {
    let base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    if stack_va >= base && stack_va + 4 <= base + size {
        let mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
        core::ptr::write_volatile((mirror + (stack_va - base)) as *mut u32, v);
    }
}

/// Write a 16-bit value to a stack VA (via the mirror). Use for the PORT_MESSAGE u2.s2.Type field
/// (a CSHORT) when modeling an LPC reply in place — a wider write would clobber the adjacent
/// DataInfoOffset / u1 length fields.
pub(crate) unsafe fn smss_stack_write16(stack_va: u64, v: u16) {
    let base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    if stack_va >= base && stack_va + 2 <= base + size {
        let mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
        core::ptr::write_volatile((mirror + (stack_va - base)) as *mut u16, v);
    }
}

/// Write an ASCII string as a NUL-terminated UTF-16LE buffer at an executive scratch VA (for building
/// the CSR shared static server data's WCHAR name buffers before they are mapped into winlogon).
pub(crate) unsafe fn write_wstr(exec_va: u64, s: &str) {
    let mut off = 0u64;
    for u in s.encode_utf16() {
        core::ptr::write_volatile((exec_va + off) as *mut u16, u);
        off += 2;
    }
    core::ptr::write_volatile((exec_va + off) as *mut u16, 0);
}

/// The file byte at image RVA `rva` (translated via the section table). For reading a faulting
/// instruction's opcode from the mapped PE.
pub(crate) unsafe fn pe_byte_at_rva(pe: &nt_pe_loader::PeFile, rva: u32) -> Option<u8> {
    for s in pe.sections() {
        if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
            let off = (s.pointer_to_raw_data + (rva - s.virtual_address)) as usize;
            return pe.bytes().get(off).copied();
        }
    }
    None
}

/// File offset of image RVA `rva`, via the section table.
pub(crate) unsafe fn rva_to_file(pe: &nt_pe_loader::PeFile, rva: u32) -> Option<u64> {
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
pub(crate) unsafe fn apply_relocations_to_buf(pe: &nt_pe_loader::PeFile, buf: u64, load_base: u64) {
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
pub(crate) unsafe fn image_extent(pe: &nt_pe_loader::PeFile) -> u64 {
    let mut ext = 0u32;
    for s in pe.sections() {
        let e = s.virtual_address.wrapping_add(s.virtual_size);
        if e > ext {
            ext = e;
        }
    }
    ((ext + 0xFFF) & !0xFFF) as u64
}
