//! An isolated **storage** driver host (P2). A separate VSpace/CSpace granted ONLY the AHCI
//! BAR + a DMA frame + a shared word by the executive (Tier-1 broker). It brings up the AHCI
//! controller, validates GPT, and reads real files from the Simpleboot EFI System Partition
//! entirely from isolation — a fault or rogue DMA is contained here, not in the executive.
//! The executive already enabled PCI Bus Master; this host has no PCI-config access.
//!
//! Cap layout (all in this host's own VSpace):
//!   * `AHCI_VADDR`           — the AHCI ABAR MMIO (granted BAR frame)
//!   * `AHCI_DMA_VADDR`       — the DMA frame (command list + FIS + command table + data)
//!   * `STORAGE_SHARED_VADDR` — dma_paddr in @0; verdict @8,
//!     import table at page-0 offset, generated hive at page-1 offset

use crate::*;

#[no_mangle]
#[link_section = ".text.storage_host_entry"]
pub unsafe extern "C" fn storage_host_entry(heap_frames: u64) -> ! {
    if !unsafe { allocator::initialize_mapped_heap(heap_frames) } {
        park();
    }
    // The executive left the DMA frame's physical address in the shared word — this host has
    // no X86PageGetAddress path of its own (least privilege).
    let dma_paddr = core::ptr::read_volatile(STORAGE_SHARED_VADDR as *const u64);
    print_str(b"[storage-host] START: driving AHCI from isolation (dma_paddr=0x");
    print_hex((dma_paddr >> 32) as u32);
    print_hex(dma_paddr as u32);
    print_str(b")\n");

    // The entire storage stack — AHCI bring-up, GPT validation, ESP/FAT32 mount, root-dir
    // listing, initrd.tar proof, and the SYSTEM.DAT registry hive read — runs here in the
    // isolated host's VSpace. The generated hive uses page 1 of the shared run so it cannot
    // overlap the page-0 metadata or IMPORTS.BIN table.
    let (
        verdict,
        hive_size,
        smss_size,
        imports_size,
        ntdll_size,
        nls_ansi_size,
        nls_oem_size,
        nls_case_size,
    ) = storage_probe(
        AHCI_VADDR,
        AHCI_DMA_VADDR,
        dma_paddr,
        STORAGE_SHARED_VADDR + STORAGE_HIVE_IMAGE_OFFSET,
        FILEBUF_VADDR,
        STORAGE_SHARED_VADDR + STORAGE_IMPORTS_IMAGE_OFFSET,
        NTDLLBUF_VADDR,
        SRVBUF_VADDR,
        WIN32BUF_VADDR,
        NLS_ANSI_VADDR,
        NLS_OEM_VADDR,
        NLS_CASE_VADDR,
        NLS_20127_VADDR,
        WIN32KBUF_VADDR,
        WINLOGONBUF_VADDR,
    );

    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 8) as *mut u32, verdict);
    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x18) as *mut u32, hive_size);
    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x20) as *mut u32, smss_size);
    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x24) as *mut u32, imports_size);
    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x28) as *mut u32, ntdll_size);
    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x2c) as *mut u32, nls_ansi_size);
    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x30) as *mut u32, nls_oem_size);
    core::ptr::write_volatile((STORAGE_SHARED_VADDR + 0x34) as *mut u32, nls_case_size);
    print_str(b"[storage-host] done: verdict bits=0x");
    print_hex(verdict);
    print_str(b"\n");
    let _ = syscall5(SYS_SEND, CT_RESULT_NTFN, 0, 0, 0, 0);
    park();
}
