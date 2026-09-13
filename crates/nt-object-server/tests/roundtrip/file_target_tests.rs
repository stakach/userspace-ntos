use super::*;
use core::mem::size_of;
use nt_object_abi::{opcode, ObLookupPathRequest};
use nt_object_client::FilePathTarget;
use nt_types::ObjAttrFlags;

fn units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn request(path: &str) -> Vec<u8> {
    let path = units(path);
    let req = ObLookupPathRequest {
        abi_size: size_of::<ObLookupPathRequest>() as u16,
        flags: ObjAttrFlags::CASE_INSENSITIVE.bits() as u16,
        path_offset: size_of::<ObLookupPathRequest>() as u32,
        path_len_bytes: (path.len() * 2) as u32,
    };
    let mut bytes = bytemuck::bytes_of(&req).to_vec();
    bytes.extend(path.iter().flat_map(|unit| unit.to_le_bytes()));
    bytes
}

#[test]
fn target_wire_roundtrip_binds_two_devices_aliases_and_raw_suffixes() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut c = client(&mut server, cid);
    let first = c
        .create_device("\\Device\\First", 0x494f, 17, true)
        .unwrap();
    let second = c
        .create_device("\\Device\\Second", 0x494f, 18, true)
        .unwrap();
    c.create_symbolic_link("\\??\\FirstAlias", "\\Device\\First", true)
        .unwrap();
    c.create_symbolic_link("\\??\\SecondAlias", "\\Device\\Second\\Parent\\", true)
        .unwrap();
    c.create_symbolic_link("\\??\\Nested", "\\??\\SecondAlias", true)
        .unwrap();
    for (name, device, suffix) in [
        ("\\Device\\First", first, ""),
        ("\\Device\\First\\", first, "\\"),
        ("\\??\\FirstAlias\\\\Leaf\\", first, "\\\\Leaf\\"),
        ("\\??\\Nested\\MiXeD\\", second, "\\Parent\\MiXeD\\"),
        ("\\device\\SECOND\\MiXeD", second, "\\MiXeD"),
    ] {
        assert_eq!(
            c.resolve_file_target(&units(name), true),
            Ok(FilePathTarget {
                device_object: device,
                remaining_name: units(suffix),
            })
        );
    }
    assert_eq!(
        c.resolve_file_target(&units("\\??\\firstalias\\Leaf"), false),
        Err(NtStatus::OBJECT_PATH_NOT_FOUND)
    );
    assert_eq!(
        c.resolve_file_target(&units("\\??\\FirstAlias\\Leaf"), false)
            .unwrap()
            .device_object,
        first
    );
    c.create_symbolic_link("\\??\\WrongCase", "\\device\\Second", true)
        .unwrap();
    assert_eq!(
        c.resolve_file_target(&units("\\??\\WrongCase\\Leaf"), false),
        Err(NtStatus::OBJECT_PATH_NOT_FOUND)
    );
    assert_eq!(
        c.resolve_file_target(&units("\\??\\WrongCase\\Leaf"), true)
            .unwrap()
            .device_object,
        second
    );
}

#[test]
fn target_wire_rejects_malformed_headers_ranges_and_retired_opcode() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let original = request("\\Device\\Absent");
    for kind in 0..6 {
        let mut bytes = original.clone();
        let mut req: ObLookupPathRequest =
            bytemuck::pod_read_unaligned(&bytes[..size_of::<ObLookupPathRequest>()]);
        match kind {
            0 => req.abi_size -= 1,
            1 => req.flags |= 1,
            2 => req.path_offset = 0,
            3 => req.path_offset += 1,
            4 => req.path_len_bytes -= 1,
            5 => req.path_len_bytes = u32::MAX - 1,
            _ => unreachable!(),
        }
        bytes[..size_of::<ObLookupPathRequest>()].copy_from_slice(bytemuck::bytes_of(&req));
        let mut output = [0xa5; 64];
        let reply = server.dispatch(cid, opcode::OB_OP_RESOLVE_FILE_TARGET, &bytes, &mut output);
        assert_eq!(NtStatus(reply.status), NtStatus::INVALID_PARAMETER);
        assert_eq!(reply.information, 0);
        assert_eq!(reply.detail0, 0);
        assert_eq!(output, [0xa5; 64]);
    }
    let mut output = [0xa5; 64];
    let reply = server.dispatch(cid, 0x2033, &original, &mut output);
    assert!(NtStatus(reply.status).is_error());
    assert_eq!(output, [0xa5; 64]);
}

#[test]
fn target_wire_short_output_never_partially_publishes_suffix_or_identity() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    client(&mut server, cid)
        .create_device("\\Device\\Volume", 0x494f, 17, true)
        .unwrap();
    let mut output = [0xa5; 3];
    let reply = server.dispatch(
        cid,
        opcode::OB_OP_RESOLVE_FILE_TARGET,
        &request("\\Device\\Volume\\Leaf"),
        &mut output,
    );
    assert_eq!(NtStatus(reply.status), NtStatus::INSUFFICIENT_RESOURCES);
    assert_eq!(reply.information, 0);
    assert_eq!(reply.detail0, 0);
    assert_eq!(reply.detail1, 0);
    assert_eq!(output, [0xa5; 3]);
}
