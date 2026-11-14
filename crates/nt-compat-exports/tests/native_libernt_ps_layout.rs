//! The hosted Ps layout against the pinned LiberNT release's own code.
//!
//! `nt_kernel_abi::ps_hosted_x64::PINNED_LAYOUT` cites the headers. This test checks the same
//! offsets against the instructions of the released ntoskrnl.exe accessors (the reference
//! implementation of each field) and against the places where win32k.sys reads a field itself
//! instead of calling an accessor. The images are not in the repository; the check runs
//! wherever the verified release tree is cached.

use std::fs;
use std::path::PathBuf;

use nt_kernel_abi::ps_hosted_x64 as abi;

const SOURCE_REVISION: &str = "source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d";

/// (image, RVA of the instruction, object, field, what executes there).
const FIELD_SITES: &[(&str, u64, &str, &str, &str)] = &[
    ("ntoskrnl.exe", 0x124b70, "EPROCESS", "UniqueProcessId", "PsGetProcessId"),
    ("ntoskrnl.exe", 0x124cc0, "EPROCESS", "Win32Process", "PsGetProcessWin32Process"),
    ("ntoskrnl.exe", 0x124c60, "EPROCESS", "SectionBaseAddress", "PsGetProcessSectionBaseAddress"),
    ("ntoskrnl.exe", 0x124e00, "EPROCESS", "Win32WindowStation", "PsGetProcessWin32WindowStation"),
    ("ntoskrnl.exe", 0x125160, "EPROCESS", "Win32WindowStation", "PsSetProcessWindowStation"),
    ("ntoskrnl.exe", 0x124c00, "EPROCESS", "Peb", "PsGetProcessPeb"),
    ("ntoskrnl.exe", 0x124b80, "EPROCESS", "ImageFileName", "PsGetProcessImageFileName"),
    ("ntoskrnl.exe", 0x0d62b9, "KTHREAD", "ThreadFlags", "KeSetKernelStackSwapEnable"),
    ("ntoskrnl.exe", 0x098619, "KTHREAD", "ApcState.Process", "IoGetCurrentProcess"),
    ("ntoskrnl.exe", 0x13bfa0, "KTHREAD", "Teb", "PsGetThreadTeb"),
    ("ntoskrnl.exe", 0x13bfd0, "KTHREAD", "Win32Thread", "PsGetThreadWin32Thread"),
    ("ntoskrnl.exe", 0x13bf30, "KTHREAD", "Process", "PsGetThreadProcess"),
    ("ntoskrnl.exe", 0x049479, "KTHREAD", "PreviousMode", "ExGetPreviousMode"),
    ("ntoskrnl.exe", 0x0d0009, "KTHREAD", "ApcStateIndex", "KeIsAttachedProcess"),
    ("ntoskrnl.exe", 0x13bf60, "ETHREAD", "Cid.UniqueProcess", "PsGetThreadProcessId"),
    ("ntoskrnl.exe", 0x13bf00, "ETHREAD", "Cid.UniqueThread", "PsGetThreadId"),
    ("ntoskrnl.exe", 0x098e60, "ETHREAD", "DeviceToVerify", "IoSetDeviceToVerify"),
    ("ntoskrnl.exe", 0x13c0e0, "ETHREAD", "CrossThreadFlags", "PsIsSystemThread"),
    // win32k.sys reading the object itself.
    ("win32k.sys", 0x022d13, "EPROCESS", "UniqueProcessId", "AllocW32Process (main.c:94)"),
    ("win32k.sys", 0x07f624, "EPROCESS", "Win32Process", "NtUserWaitForInputIdle (message.c:3927)"),
    ("win32k.sys", 0x080eb7, "EPROCESS", "Win32Process", "NtUserGetGuiResources (misc.c:555)"),
    ("win32k.sys", 0x0242b3, "EPROCESS", "SectionBaseAddress", "IntIsGuiImage (main.c:570)"),
    ("win32k.sys", 0x023cb4, "EPROCESS", "SectionBaseAddress", "InitThreadCallback (main.c:701)"),
    ("win32k.sys", 0x0af43e, "EPROCESS", "Win32WindowStation", "UserGetShellWindow (window.c:3958)"),
    ("win32k.sys", 0x0af567, "EPROCESS", "Win32WindowStation", "NtUserSetShellWindowEx (window.c:4008)"),
    ("win32k.sys", 0x05f443, "EPROCESS", "Win32WindowStation", "NtUserSetWindowsHookEx (hook.c:1559)"),
    ("win32k.sys", 0x073fa5, "EPROCESS", "Win32WindowStation", "UserCreateMenu (menu.c:5152)"),
    ("win32k.sys", 0x0ab3cf, "EPROCESS", "Peb", "IntFixWindowCoordinates (window.c:1928)"),
    ("win32k.sys", 0x050c45, "EPROCESS", "ImageFileName", "IntSetThreadDesktop (desktop.c:3619)"),
    ("win32k.sys", 0x07cfb6, "KTHREAD", "Win32Thread", "NtUserPostThreadMessage (message.c:2764)"),
    ("win32k.sys", 0x0aab37, "KTHREAD", "Win32Thread", "NtUserBuildHwndList (window.c:1674)"),
    ("win32k.sys", 0x09ca97, "KTHREAD", "Win32Thread", "NtUserCallNoParam (simplecall.c:105)"),
    ("win32k.sys", 0x0856e6, "KTHREAD", "SuspendCount", "hung-window test (msgqueue.c:2307)"),
    ("win32k.sys", 0x0861b1, "KTHREAD", "SuspendCount", "hung-window test (msgqueue.c:2307)"),
    ("win32k.sys", 0x0b01eb, "ETHREAD", "Cid.UniqueProcess", "NtUserQueryWindow (window.c:4578)"),
    ("win32k.sys", 0x05839f, "ETHREAD", "Cid.UniqueProcess", "IntNotifyWinEvent (event.c:214)"),
    ("win32k.sys", 0x0582fa, "ETHREAD", "Cid.UniqueThread", "IntNotifyWinEvent (event.c:200)"),
    ("win32k.sys", 0x08f8c2, "ETHREAD", "Cid.UniqueThread", "NtUserGetPointerInfoList (ntstubs.c:1113)"),
];

/// (RVA of `mov dword ptr [rsp+0x28], imm32` before `ObCreateObject`, body size, caller).
const BODY_SIZE_SITES: &[(u64, usize, &str)] = &[
    (0x13aba5, abi::ETHREAD_BODY_BYTES, "PspCreateThread"),
    (0x123385, abi::EPROCESS_BYTES, "PspCreateProcess"),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn raw_offset(bytes: &[u8], rva: u64) -> usize {
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(&bytes[pe..pe + 4], b"PE\0\0");
    let count = u16::from_le_bytes(bytes[pe + 6..pe + 8].try_into().unwrap()) as usize;
    let optional = u16::from_le_bytes(bytes[pe + 20..pe + 22].try_into().unwrap()) as usize;
    for index in 0..count {
        let section = pe + 24 + optional + index * 40;
        let base = u32::from_le_bytes(bytes[section + 12..section + 16].try_into().unwrap()) as u64;
        let size = u32::from_le_bytes(bytes[section + 8..section + 12].try_into().unwrap()) as u64;
        if (base..base + size).contains(&rva) {
            return u32::from_le_bytes(bytes[section + 20..section + 24].try_into().unwrap())
                as usize
                + (rva - base) as usize;
        }
    }
    panic!("RVA 0x{rva:x} is outside the image");
}

fn pinned_offset(object: &str, field: &str) -> usize {
    abi::PINNED_LAYOUT
        .iter()
        .find(|row| row.object == object && row.name == field)
        .unwrap_or_else(|| panic!("{object}.{field} is not in the layout table"))
        .pinned
}

/// The instruction at `site` addresses memory with exactly this displacement. One x64
/// instruction is at most fifteen bytes; opcode, ModRM and SIB precede the displacement.
fn displaces_by(image: &[u8], site: usize, offset: usize) -> bool {
    let instruction = &image[site..site + 12];
    if offset < 0x80 {
        return instruction[1..5].contains(&(offset as u8));
    }
    let wanted = (offset as u32).to_le_bytes();
    instruction[1..].windows(4).take(4).any(|window| window == wanted)
}

#[test]
fn every_site_cites_a_field_of_the_layout_table() {
    for &(_, _, object, field, _) in FIELD_SITES {
        pinned_offset(object, field);
    }
}

#[test]
fn released_images_keep_each_field_where_the_layout_table_says() {
    if let Ok(manifest) = fs::read_to_string(root().join("rust-micro/vendor/libernt/manifest.txt")) {
        assert!(manifest.lines().any(|line| line == SOURCE_REVISION));
    }
    let system32 = root().join("rust-micro/.tmp/libernt/tree/Windows/system32");
    let (Ok(kernel), Ok(win32k)) =
        (fs::read(system32.join("ntoskrnl.exe")), fs::read(system32.join("win32k.sys")))
    else {
        // The pinned release tree is absent on CI.
        return;
    };
    for &(image, rva, object, field, what) in FIELD_SITES {
        let bytes = if image == "win32k.sys" { &win32k } else { &kernel };
        let offset = pinned_offset(object, field);
        assert!(
            displaces_by(bytes, raw_offset(bytes, rva), offset),
            "{image}+0x{rva:x} {what}: {object}.{field} is not at 0x{offset:x}"
        );
    }
    for &(rva, size, what) in BODY_SIZE_SITES {
        let site = raw_offset(&kernel, rva);
        // c7 44 24 28 imm32
        assert_eq!(&kernel[site..site + 4], &[0xc7, 0x44, 0x24, 0x28], "{what}");
        assert_eq!(
            u32::from_le_bytes(kernel[site + 4..site + 8].try_into().unwrap()) as usize,
            size,
            "{what}"
        );
    }
}
