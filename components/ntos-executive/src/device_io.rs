//! `device_io` — the P2 storage/device probe + low-level IO/PCI primitives
//! (storage_probe, iopt_map, map_io, io_in32, pci_read32/write32).
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

/// The whole P2 storage stack, callable from an isolated host: bring up AHCI port 0, read
/// sector 0 (MBR), parse the FAT32 volume, list the root directory, read BOOTBOOT/INITRD, and
/// read the registry hive `SYSTEM.DAT` into `hive_dest`. Returns (verdict, initrd_cluster,
/// initrd_size, hive_size). Verdict bits: 1 = port present + MBR (0xAA55), 2 = FAT32 BPB ok,
/// 4 = root lists EFI+BOOTBOOT, 8 = INITRD read, 0x10 = SYSTEM.DAT read. READ ONLY. AHCI BAR
/// @ `ahci_vaddr`, DMA @ `dma_vaddr` (device addr `dma_paddr`) — all in the caller's VSpace.
pub(crate) unsafe fn storage_probe(
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
            (b"reactos\\Fonts\\arial.ttf".as_slice(), b"ARIAL   TTF", win32k_subsystem::FONTBUF_VADDR, win32k_subsystem::FONTBUF_FRAMES, 0x90u64),
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
pub(crate) unsafe fn iopt_map(iopt_cap: u64, io_space_cap: u64, io_address: u64) -> u64 {
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
pub(crate) unsafe fn map_io(frame_cap: u64, io_space_cap: u64, rights: u64, io_address: u64) -> u64 {
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

pub(crate) unsafe fn io_in32(ioport: u64, port: u16) -> u32 {
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
pub(crate) unsafe fn pci_read32(ioport: u64, bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((reg as u32) & 0xFC);
    io_out32(ioport, PCI_CONFIG_ADDR, addr);
    io_in32(ioport, PCI_CONFIG_DATA)
}

/// Write a 32-bit PCI configuration register.
pub(crate) unsafe fn pci_write32(ioport: u64, bus: u8, dev: u8, func: u8, reg: u8, value: u32) {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((reg as u32) & 0xFC);
    io_out32(ioport, PCI_CONFIG_ADDR, addr);
    io_out32(ioport, PCI_CONFIG_DATA, value);
}
