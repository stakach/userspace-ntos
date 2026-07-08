//! An isolated PnP **driver host** (P1 capstone). A separate VSpace/CSpace that, at
//! START, receives a real NT `CM_RESOURCE_LIST` (MMIO + interrupt) plus a VT-d-confined
//! common DMA buffer, and drives the real e1000e NIC entirely from isolation — an MMIO
//! register read + a confined DMA transmit. This is the seL4 analogue of a KMDF driver's
//! `EvtDevicePrepareHardware` / `IRP_MN_START_DEVICE`: the executive (Tier-1 PnP + HAL)
//! grants the host ONLY the resources it needs (the BAR pages, the IRQ notification, and
//! one DMA frame confined to a single IOVA), so a fault or a rogue DMA is contained here
//! and can't touch the rest of the system.
//!
//! Resource layout the executive hands us (all in this host's own VSpace):
//!   * `RESLIST_VADDR`         — CM_RESOURCE_LIST (memory + interrupt descriptors)
//!   * `RESLIST_VADDR + 0x100` — common-buffer descriptor: cpu_va(u64), iova(u64), len(u64)
//!   * `RESLIST_VADDR + 0x200` — where we write our 1-byte verdict for the executive
//!   * the NIC BAR + the common buffer are mapped at the vaddrs named in those descriptors

use crate::*;
use nt_cm_resources::{decode_memory_interrupt_list, MEMORY_INTERRUPT_LIST_SIZE};

#[no_mangle]
#[link_section = ".text.driver_host_entry"]
pub unsafe extern "C" fn driver_host_entry() -> ! {
    let mut verdict = 0u8;

    // 1. Parse the CM_RESOURCE_LIST handed at START — exactly the bytes a WDK driver
    //    reads from Parameters.StartDevice.AllocatedResourcesTranslated.
    let reslist = core::slice::from_raw_parts(RESLIST_VADDR as *const u8, MEMORY_INTERRUPT_LIST_SIZE);
    if let Some((mem, int)) = decode_memory_interrupt_list(reslist) {
        print_str(b"[driver-host] START: parsed CM_RESOURCE_LIST (MMIO + interrupt)\n");
        // Must have a real MMIO window + the expected interrupt vector wired.
        let res_ok = mem.length != 0 && int.vector == NIC_MSI_VECTOR as u32;
        let mmio = mem.start;

        // 2. Common-buffer descriptor — the DMA adapter's AllocateCommonBuffer analogue:
        //    a CPU virtual address we write through and a device logical address (IOVA)
        //    we program the NIC with. VT-d maps the IOVA to this frame and NOTHING else.
        let cpu_va = core::ptr::read_volatile((RESLIST_VADDR + 0x100) as *const u64);
        let iova = core::ptr::read_volatile((RESLIST_VADDR + 0x108) as *const u64);

        // 3. MMIO: read a live NIC register (STATUS @ 0x08) through the granted BAR.
        let status = core::ptr::read_volatile((mmio + 0x08) as *const u32);
        let mmio_ok = status != 0xFFFF_FFFF && status != 0;

        // 4. Confined DMA transmit. Build a legacy TX descriptor in the common buffer
        //    (ring @ offset 0, packet @ 0x200) and program the NIC to address memory by
        //    IOVA — the CPU writes via cpu_va, the device DMAs via the IOVA.
        for i in 0..64u64 {
            core::ptr::write_volatile((cpu_va + 0x200 + i) as *mut u8, 0x5A);
        }
        core::ptr::write_volatile(cpu_va as *mut u64, iova + 0x200); // buffer addr = IOVA
        core::ptr::write_volatile((cpu_va + 8) as *mut u16, 64); // length
        core::ptr::write_volatile((cpu_va + 10) as *mut u8, 0); // CSO
        core::ptr::write_volatile((cpu_va + 11) as *mut u8, 0x09); // CMD = EOP | RS
        core::ptr::write_volatile((cpu_va + 12) as *mut u8, 0); // STA (NIC writes DD)
        core::ptr::write_volatile((cpu_va + 13) as *mut u8, 0); // CSS
        core::ptr::write_volatile((cpu_va + 14) as *mut u16, 0); // special

        // e1000e TX registers (offsets from the BAR base): TDBAL 0x3800, TDBAH 0x3804,
        // TDLEN 0x3808, TDH 0x3810, TDT 0x3818, TCTL 0x0400, TARC0 0x3840.
        core::ptr::write_volatile((mmio + 0x3800) as *mut u32, iova as u32);
        core::ptr::write_volatile((mmio + 0x3804) as *mut u32, (iova >> 32) as u32);
        core::ptr::write_volatile((mmio + 0x3808) as *mut u32, 128);
        core::ptr::write_volatile((mmio + 0x3810) as *mut u32, 0);
        core::ptr::write_volatile((mmio + 0x3818) as *mut u32, 0);
        core::ptr::write_volatile((mmio + 0x0400) as *mut u32, 0x0004_00F3); // EN|PSP|CT|COLD
        let tarc = core::ptr::read_volatile((mmio + 0x3840) as *const u32);
        core::ptr::write_volatile((mmio + 0x3840) as *mut u32, tarc | (1 << 10)); // engine enable
        core::ptr::write_volatile((mmio + 0x3818) as *mut u32, 1); // TDT: hand off descriptor 0

        let mut dd = 0u8;
        for _ in 0..2_000_000u64 {
            dd = core::ptr::read_volatile((cpu_va + 12) as *const u8);
            if dd & 0x1 != 0 {
                break;
            }
            yield_now();
        }
        if res_ok && mmio_ok && (dd & 0x1 != 0) {
            verdict = 1;
            print_str(b"[driver-host] drove the NIC from isolation: MMIO read + confined DMA (DD)\n");
        }
    }

    // Report the verdict into the shared resource frame, then signal the executive.
    core::ptr::write_volatile((RESLIST_VADDR + 0x200) as *mut u8, verdict);
    let _ = syscall5(SYS_SEND, CT_RESULT_NTFN, 0, 0, 0, 0);
    loop {
        yield_now();
    }
}
