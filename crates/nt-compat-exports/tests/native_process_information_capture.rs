//! Captured ZwQueryInformationProcess data for the pinned LiberNT win32k callsites.
//! The executive owns caller handles and admitted image identity; a native adapter later copies
//! these bytes through a bounded packet into win32k's own address space.

#[path = "../../../components/ntos-executive/src/process_information_capture.rs"]
mod process_information_capture;

use nt_exe_image::{HostedImageCatalog, HostedImageRoot, HostedProcessImageRef, HostedProcessRole};
use nt_process::{HandleObject, ProcessManager, PROCESS_QUERY_INFORMATION};
use process_information_capture::{capture_process_information, ProcessImageEvidence};

const MISMATCH: u32 = 0xC000_0004;

fn fixture() -> (
    ProcessManager,
    u32,
    u32,
    u64,
    HostedImageCatalog<'static, 2>,
) {
    let mut pm = ProcessManager::new();
    let caller = pm.create_process("caller.exe", None, None);
    let target = pm.create_process("Chosen.EXE", None, None);
    let handle = u64::from(
        pm.insert_handle(
            caller,
            HandleObject::Process(target),
            PROCESS_QUERY_INFORMATION,
        )
        .unwrap(),
    );
    let mut catalog = HostedImageCatalog::new();
    catalog
        .register(HostedProcessImageRef {
            pi: 7,
            top_badge: 29,
            generation: 7,
            leaf: b"Chosen.EXE",
            process_name: "Chosen.EXE",
            role: HostedProcessRole::Application,
            observation: None,
            nt_image_path: b"\\SystemRoot\\System32\\Chosen.EXE",
            command_line: b"Chosen.EXE",
            image_root: HostedImageRoot::System32,
            probe_fragment: b"",
        })
        .unwrap();
    catalog
        .register(HostedProcessImageRef {
            pi: 8,
            top_badge: 30,
            generation: 8,
            leaf: b"caller.exe",
            process_name: "caller.exe",
            role: HostedProcessRole::Application,
            observation: None,
            nt_image_path: b"\\SystemRoot\\System32\\caller.exe",
            command_line: b"caller.exe",
            image_root: HostedImageRoot::System32,
            probe_fragment: b"",
        })
        .unwrap();
    (pm, caller, target, handle, catalog)
}

fn captured(
    pm: &ProcessManager,
    caller: u32,
    target: u32,
    handle: u64,
    class: u32,
    output_address: u64,
    output_length: u32,
    image: Option<HostedProcessImageRef<'_>>,
    image_information: [u8; 0x40],
) -> process_information_capture::CapturedProcessInformation {
    capture_process_information(
        pm,
        caller,
        handle,
        class,
        output_address,
        output_length,
        b"C:\\Windows",
        |resolved| {
            (resolved == target).then_some(ProcessImageEvidence {
                process_id: target,
                image: image?,
                image_information,
            })
        },
    )
}

#[test]
fn class_43_reports_required_length_then_captures_admitted_dos_name() {
    let (pm, caller, _, _, catalog) = fixture();
    let image = catalog.get_by_pi(8).unwrap();
    let path = r"C:\Windows\System32\caller.exe";
    let utf16: Vec<u16> = path.encode_utf16().collect();
    let required = 0x10 + (utf16.len() + 1) * 2;

    // The pinned callsite first asks with zero bytes, then retries with ReturnLength.
    let short = captured(
        &pm,
        caller,
        caller,
        u64::MAX,
        43,
        0,
        0,
        Some(image),
        [0; 0x40],
    );
    assert_eq!(
        (short.status, short.return_length, short.bytes.len()),
        (MISMATCH, required as u32, 0)
    );

    let output_address = 0x7000;
    let result = captured(
        &pm,
        caller,
        caller,
        u64::MAX,
        43,
        output_address,
        required as u32,
        Some(image),
        [0; 0x40],
    );
    assert_eq!(
        (result.status, result.return_length, result.bytes.len()),
        (0, required as u32, required)
    );
    assert_eq!(
        u16::from_le_bytes(result.bytes[0..2].try_into().unwrap()),
        (utf16.len() * 2) as u16
    );
    assert_eq!(
        u16::from_le_bytes(result.bytes[2..4].try_into().unwrap()),
        ((utf16.len() + 1) * 2) as u16
    );
    assert_eq!(
        u64::from_le_bytes(result.bytes[8..16].try_into().unwrap()),
        output_address + 0x10
    );
    let actual: Vec<u16> = result.bytes[0x10..required - 2]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    assert_eq!(actual, utf16);
    assert_eq!(&result.bytes[required - 2..required], &[0, 0]);
}

#[test]
fn class_37_copies_exact_image_information_for_real_query_handle() {
    let (pm, caller, target, handle, catalog) = fixture();
    let image = catalog.get_by_pi(7).unwrap();
    // Distinct captured PE fields make substitution by a constant image-info template visible.
    let mut image_information = [0u8; 0x40];
    image_information[0..8].copy_from_slice(&0x1400_1234u64.to_le_bytes());
    image_information[0x10..0x18].copy_from_slice(&0x280000u64.to_le_bytes());
    image_information[0x18..0x20].copy_from_slice(&0x9000u64.to_le_bytes());
    image_information[0x20..0x24].copy_from_slice(&2u32.to_le_bytes());
    image_information[0x38..0x3c].copy_from_slice(&0x5a000u32.to_le_bytes());

    let short = captured(
        &pm,
        caller,
        target,
        handle,
        37,
        0x8000,
        0x3f,
        Some(image),
        image_information,
    );
    assert_eq!(
        (short.status, short.return_length, short.bytes.len()),
        (MISMATCH, 0x40, 0)
    );
    let result = captured(
        &pm,
        caller,
        target,
        handle,
        37,
        0x8000,
        0x40,
        Some(image),
        image_information,
    );
    assert_eq!((result.status, result.return_length), (0, 0x40));
    assert_eq!(result.bytes.as_slice(), &image_information);
}

#[test]
fn invalid_access_handle_or_unadmitted_image_never_publishes_query_bytes() {
    let (mut pm, caller, target, handle, catalog) = fixture();
    let image = catalog.get_by_pi(7).unwrap();
    let denied = u64::from(
        pm.insert_handle(caller, HandleObject::Process(target), 0)
            .unwrap(),
    );
    for (query_handle, query_image, expected) in [
        (0xdead, Some(image), nt_process::STATUS_INVALID_HANDLE),
        (denied, Some(image), nt_process::STATUS_ACCESS_DENIED),
        (handle, None, nt_process::STATUS_INVALID_HANDLE),
    ] {
        let result = captured(
            &pm,
            caller,
            target,
            query_handle,
            43,
            0x9000,
            0x200,
            query_image,
            [0; 0x40],
        );
        assert_eq!(result.status, expected);
        assert!(result.bytes.is_empty());
        assert_eq!(result.return_length, 0);
    }
}
