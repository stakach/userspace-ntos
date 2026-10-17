use super::*;
use alloc::vec;

fn read_image(image: &[u8], address: u64, out: &mut [u8]) -> bool {
    let Some(end) = (address as usize).checked_add(out.len()) else { return false };
    let Some(bytes) = image.get(address as usize..end) else { return false };
    out.copy_from_slice(bytes);
    true
}

fn caller() -> NativeCaller {
    NativeCaller { process: 4, thread: 8, generation: 12, badge: 16, tcb: 20 }
}

#[test]
fn send_capture_owns_message_and_attributes_after_guest_mutation() {
    let mut image = [0u8; 512];
    image[64..66].copy_from_slice(&4u16.to_le_bytes());
    image[66..68].copy_from_slice(&44u16.to_le_bytes());
    image[104..108].copy_from_slice(b"ping");
    image[160..164].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    image[164..168].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    let args = [77, 0, 64, 160, 0, 0, 0, 0];
    let captured = capture_send_wait_receive(args, |p, b| read_image(&image, p, b), |_, _| true).unwrap();
    image[104] = b'X';
    image[160] = 0xff;
    assert_eq!(image[160], 0xff);
    assert_eq!(&captured.send_message.as_ref().unwrap()[40..], b"ping");
    assert_eq!(captured.send_attributes.as_ref().unwrap().allocated, 0x2000_0000);
    assert_eq!(captured.send_attributes.as_ref().unwrap().bytes[0], 0);
}

#[test]
fn malformed_message_and_unsupported_attributes_fail_before_effect() {
    let mut image = [0u8; 512];
    image[64..66].copy_from_slice(&4u16.to_le_bytes());
    image[66..68].copy_from_slice(&39u16.to_le_bytes());
    assert_eq!(capture_send_wait_receive([77, 0, 64, 0, 0, 0, 0, 0], |p,b| read_image(&image,p,b), |_,_| true), Err(STATUS_INVALID_PARAMETER));
    image[66..68].copy_from_slice(&44u16.to_le_bytes());
    image[160..164].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    image[164..168].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    assert_eq!(capture_send_wait_receive([77, 0, 64, 160, 0, 0, 0, 0], |p,b| read_image(&image,p,b), |_,_| true), Err(STATUS_NOT_SUPPORTED));
}

#[test]
fn receive_capture_requires_bounded_writable_output_and_size() {
    let mut image = [0u8; 512];
    image[32..40].copy_from_slice(&128u64.to_le_bytes());
    assert_eq!(capture_send_wait_receive([77, 0, 0, 0, 128, 32, 0, 0], |p,b| read_image(&image,p,b), |p,n| p == 128 && n == 128 || p == 32 && n == 8), Ok(CapturedSendWaitReceive { port: 77, flags: 0, send_message: None, send_attributes: None, receive: Some(ReceiveTarget { message: 128, capacity: 128, size_pointer: 32, attributes: None }), timeout: None }));
    image[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(capture_send_wait_receive([77, 0, 0, 0, 128, 32, 0, 0], |p,b| read_image(&image,p,b), |_,_| true), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn smss_receive_context_attribute_is_bounded_and_retained_before_effect() {
    let mut image = [0u8; 512];
    image[32..40].copy_from_slice(&128u64.to_le_bytes());
    image[256..260].copy_from_slice(&CONTEXT_ATTR.to_le_bytes());
    let captured = capture_send_wait_receive([77, 0, 0, 0, 128, 32, 256, 0],
        |p, b| read_image(&image, p, b),
        |p, n| (p == 128 && n == 128) || (p == 32 && n == 8) || (p == 256 && n == 40))
        .unwrap();
    assert_eq!(captured.receive.unwrap().attributes, Some((256, CONTEXT_ATTR)));
    image[256..260].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    assert_eq!(capture_send_wait_receive([77, 0, 0, 0, 128, 32, 256, 0],
        |p, b| read_image(&image, p, b), |_, _| true), Err(STATUS_NOT_SUPPORTED));
}

#[test]
fn owned_smss_receive_wire_preserves_context_attributes_after_target_transfer() {
    let mut image = [0u8; 512];
    image[32..40].copy_from_slice(&328u64.to_le_bytes());
    image[400..404].copy_from_slice(&CONTEXT_ATTR.to_le_bytes());
    let captured = capture_send_wait_receive([77, 0, 0, 0, 64, 32, 400, 0],
        |p, b| read_image(&image, p, b), |_, _| true).unwrap();
    let (wire, target) = captured.into_checked_wire_and_receive(caller(), (7, 12)).unwrap();
    let header: nt_alpc_abi::AlpcSendReceiveCheckedRequest = bytemuck::pod_read_unaligned(
        &wire[..core::mem::size_of::<nt_alpc_abi::AlpcSendReceiveCheckedRequest>()]);
    assert_eq!(target.capacity, 328);
    assert_eq!(target.attributes, Some((400, CONTEXT_ATTR)));
    assert_eq!(header.send_receive.flags, nt_alpc_abi::send_flag::RECV_ATTRIBUTES);
    assert_eq!(header.send_receive.valid_attributes, CONTEXT_ATTR);
}

#[test]
fn smss_reply_and_receive_captures_the_reply_with_context_output() {
    let mut image = [0u8; 512];
    image[32..40].copy_from_slice(&128u64.to_le_bytes());
    image[64..66].copy_from_slice(&2u16.to_le_bytes());
    image[66..68].copy_from_slice(&42u16.to_le_bytes());
    // SMSS reuses the request header; the flag, not the header type, marks a reply.
    image[68..70].copy_from_slice(&nt_alpc_abi::msg_type::REQUEST.to_le_bytes());
    image[104..106].copy_from_slice(b"OK");
    image[256..260].copy_from_slice(&CONTEXT_ATTR.to_le_bytes());
    let captured = capture_send_wait_receive(
        [77, u64::from(nt_alpc_abi::send_flag::REPLY_MESSAGE), 64, 0, 128, 32, 256, 0],
        |p, b| read_image(&image, p, b), |_, _| true,
    ).expect("SMSS sends its previous reply while receiving the next request");
    assert_eq!(captured.flags, nt_alpc_abi::send_flag::REPLY_MESSAGE);
    assert_eq!(captured.send_message.as_deref(), Some(&image[64..106]));
    assert_eq!(captured.receive.unwrap().attributes, Some((256, CONTEXT_ATTR)));
}

#[test]
fn smss_sync_request_owns_send_bytes_before_reusing_receive_buffer() {
    let mut image = [0u8; 512];
    image[32..40].copy_from_slice(&128u64.to_le_bytes());
    image[128..130].copy_from_slice(&4u16.to_le_bytes());
    image[130..132].copy_from_slice(&44u16.to_le_bytes());
    image[168..172].copy_from_slice(b"exec");
    let captured = capture_send_wait_receive(
        [77, 0x0002_0000, 128, 0, 128, 32, 0, 0],
        |p, b| read_image(&image, p, b), |_, _| true,
    ).expect("ALPC_MSGFLG_SYNC_REQUEST permits an in-place send and reply buffer");
    assert_eq!(captured.flags, 0x0002_0000);
    assert_eq!(captured.send_message.as_deref(), Some(&image[128..172]));
    assert_eq!(captured.receive.as_ref().unwrap().message, 128);
    assert_eq!(captured.receive.as_ref().unwrap().capacity, 128);
}

#[test]
fn connect_capture_owns_name_and_rejects_invalid_server_sid() {
    let mut image = [0u8; 512];
    image[64..66].copy_from_slice(&20u16.to_le_bytes());
    image[66..68].copy_from_slice(&22u16.to_le_bytes());
    image[72..80].copy_from_slice(&128u64.to_le_bytes());
    for (i, unit) in "\\SmApiPort".encode_utf16().enumerate() {
        image[128 + 2*i..130 + 2*i].copy_from_slice(&unit.to_le_bytes());
    }
    let captured = capture_connect_port([16,64,0,0,0,0,0,0,0,0,0], |p,b| read_image(&image,p,b), |p,n| p == 16 && n == 8).unwrap();
    image[128] = 0;
    assert_eq!(captured.name, "\\SmApiPort".encode_utf16().collect::<Vec<_>>());
    let authorized = captured.checked_wire_authorized(caller(), (7, 8), 91).unwrap();
    let head: nt_alpc_abi::AlpcConnectPortAuthorizedRequest =
        bytemuck::pod_read_unaligned(&authorized[..core::mem::size_of::<nt_alpc_abi::AlpcConnectPortAuthorizedRequest>()]);
    assert_eq!(head.target_listen_handle, 91);
    assert_eq!(head.access_granted, 1);
    assert_eq!(head.checked.connect.name_offset as usize,
        core::mem::size_of::<nt_alpc_abi::AlpcConnectPortAuthorizedRequest>());
    assert_eq!(capture_connect_port([16,64,0,0,0,256,0,0,0,0,0], |p,b| read_image(&image,p,b), |_,_| true), Err(0xC000_0078));
}

#[test]
fn smss_sync_connect_uses_32_bit_flags_from_native_argument_slot() {
    let mut image = [0u8; 512];
    image[64..66].copy_from_slice(&20u16.to_le_bytes());
    image[66..68].copy_from_slice(&22u16.to_le_bytes());
    image[72..80].copy_from_slice(&128u64.to_le_bytes());
    for (i, unit) in "\\SmApiPort".encode_utf16().enumerate() {
        image[128 + 2*i..130 + 2*i].copy_from_slice(&unit.to_le_bytes());
    }
    let captured = capture_connect_port(
        [16, 64, 0, 0, 0x0000_0100_0002_0000, 0, 0, 0, 0, 0, 0],
        |p, b| read_image(&image, p, b), |p, n| p == 16 && n == 8,
    ).expect("native ULONG flags use only their low 32 bits");
    assert_eq!(captured.connect_flags, nt_alpc_abi::connect_flag::SYNC_CONNECTION);
}

#[test]
fn libernt_csr_connect_retains_local_system_server_sid() {
    let mut image = [0u8; 512];
    image[64..66].copy_from_slice(&32u16.to_le_bytes());
    image[66..68].copy_from_slice(&34u16.to_le_bytes());
    image[72..80].copy_from_slice(&128u64.to_le_bytes());
    for (index, unit) in "\\Windows\\ApiPort".encode_utf16().enumerate() {
        image[128 + 2 * index..130 + 2 * index].copy_from_slice(&unit.to_le_bytes());
    }
    let sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    image[256..268].copy_from_slice(&sid);
    let captured = capture_connect_port(
        [16, 64, 0, 0, 0x0002_0000, 256, 0, 0, 0, 0, 0],
        |address, out| read_image(&image, address, out), |_, _| true,
    ).expect("LiberNT supplies an owned LocalSystem server SID");
    assert_eq!(captured.server_sid.as_deref(), Some(sid.as_slice()));
}

#[test]
fn smss_main_thread_badge_zero_keeps_exact_connect_and_reply_identity() {
    let mut main = caller();
    main.badge = 0;
    let captured = CapturedConnectPort {
        output: 16,
        name: "\\SmApiPort".encode_utf16().collect(),
        connect_flags: nt_alpc_abi::connect_flag::SYNC_CONNECTION,
        port_attributes: None,
        server_sid: None,
        message: None,
        message_target: None,
        send_attributes: None,
        timeout: None,
    };
    let wire = captured.checked_wire(main, (7, 13))
        .expect("badge zero is a valid physical SMSS thread badge");
    let retained = RetainedLater::new(main, (7, 13), 31, wire)
        .expect("reply ownership includes exact TCB, not a nonzero badge assumption");
    assert_eq!(retained.caller(), main);
    assert_eq!(retained.reply_cap(), 31);

    let mut missing_tcb = main;
    missing_tcb.tcb = 0;
    assert_eq!(captured.checked_wire(missing_tcb, (7, 14)), Err(STATUS_INVALID_PARAMETER));
    assert!(matches!(RetainedLater::new(missing_tcb, (7, 14), 32, vec![1]),
        Err(RetainedError::InvalidIdentity)));
}

#[test]
fn accept_capture_requires_connection_request_and_owned_output() {
    let mut image = [0u8; 512];
    image[64..66].copy_from_slice(&0u16.to_le_bytes());
    image[66..68].copy_from_slice(&40u16.to_le_bytes());
    image[68..70].copy_from_slice(&10u16.to_le_bytes());
    image[88..92].copy_from_slice(&59u32.to_le_bytes());
    let captured = capture_accept_connect([16,77,0,0,0,0,64,0,1], 59, |p,b| read_image(&image,p,b), |p,n| p == 16 && n == 8).unwrap();
    assert_eq!(captured.connection_id, 59);
    assert_eq!(captured.message, image[64..104]);
    image[64] = 0xff;
    assert_eq!(captured.message[0], 0);
    assert_eq!(capture_accept_connect([16,77,0,0,0,0,64,0,1], 60, |p,b| read_image(&image,p,b), |_,_| true), Err(STATUS_INVALID_PARAMETER));
    image[68..70].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(capture_accept_connect([16,77,0,0,0,0,64,0,1], 59, |p,b| read_image(&image,p,b), |_,_| true), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn libernt_csr_accept_uses_native_ulong_and_boolean_widths() {
    let mut image = [0u8; 256];
    image[64..66].copy_from_slice(&72u16.to_le_bytes());
    image[66..68].copy_from_slice(&112u16.to_le_bytes());
    image[68..70].copy_from_slice(&10u16.to_le_bytes());
    image[88..92].copy_from_slice(&59u32.to_le_bytes());
    let captured = capture_accept_connect(
        [16, 77, 0xfeed_face_0000_0000, 0, 0, 42, 64, 0, 0xfeed_face_0000_0001],
        59, |address, out| read_image(&image, address, out), |address, len| address == 16 && len == 8,
    ).expect("Windows ABI accepts only the ULONG flags and BOOLEAN low byte");
    assert!(captured.accept);
    assert_eq!(captured.connection_id, 59);
    assert_eq!(captured.port_context, 42);
    assert_eq!(capture_accept_connect(
        [16, 77, 0xfeed_face_0000_0001, 0, 0, 42, 64, 0, 1],
        59, |address, out| read_image(&image, address, out), |_, _| true,
    ), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(capture_accept_connect(
        [16, 77, 0, 0, 0, 42, 64, 0, 0xfeed_face_0000_0002],
        59, |address, out| read_image(&image, address, out), |_, _| true,
    ), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn connect_capture_retains_response_addresses_for_exact_copyout() {
    let mut image = [0u8; 512];
    image[64..66].copy_from_slice(&20u16.to_le_bytes());
    image[66..68].copy_from_slice(&22u16.to_le_bytes());
    image[72..80].copy_from_slice(&128u64.to_le_bytes());
    for (i, unit) in "\\SmApiPort".encode_utf16().enumerate() {
        image[128 + 2*i..130 + 2*i].copy_from_slice(&unit.to_le_bytes());
    }
    image[240..242].copy_from_slice(&5u16.to_le_bytes());
    image[242..244].copy_from_slice(&45u16.to_le_bytes());
    image[280..285].copy_from_slice(b"hello");
    image[300..308].copy_from_slice(&128u64.to_le_bytes());
    let captured = capture_connect_port([16,64,0,0,0,0,240,300,0,0,0],
        |p,b| read_image(&image,p,b), |_,_| true).unwrap();
    assert_eq!(captured.message_target, Some((240, 128, 300)));
    image[240] = 0xff;
    assert_eq!(image[240], 0xff);
    assert_eq!(captured.message.as_ref().unwrap()[0], 5);
    assert_eq!(&captured.message.as_ref().unwrap()[40..], b"hello");
}

#[test]
fn libernt_sm_connect_captures_sync_flag_message_and_qos_before_effect() {
    let mut image = [0u8; 512];
    image[64..66].copy_from_slice(&20u16.to_le_bytes());
    image[66..68].copy_from_slice(&22u16.to_le_bytes());
    image[72..80].copy_from_slice(&128u64.to_le_bytes());
    for (index, unit) in "\\SmApiPort".encode_utf16().enumerate() {
        image[128 + 2 * index..130 + 2 * index].copy_from_slice(&unit.to_le_bytes());
    }
    let attributes = AlpcPortAttributes {
        max_message_length: 512,
        security_qos: nt_alpc_abi::SecurityQualityOfService {
            length: 12, impersonation_level: 1, context_tracking_mode: 1,
            effective_only: 1, ..Default::default()
        },
        ..Default::default()
    };
    image[160..232].copy_from_slice(bytemuck::bytes_of(&attributes));
    image[240..242].copy_from_slice(&4u16.to_le_bytes());
    image[242..244].copy_from_slice(&44u16.to_le_bytes());
    image[280..284].copy_from_slice(b"SB!!");
    image[400..408].copy_from_slice(&128u64.to_le_bytes());
    let captured = capture_connect_port(
        [16, 64, 0, 160, 0x0002_0000, 0, 240, 400, 0, 0, 0],
        |address, out| read_image(&image, address, out), |_, _| true,
    ).expect("LiberNT SmConnectToSm sync connection is a supported owned input");
    let mut expected_attributes = [0u8; 72];
    expected_attributes.copy_from_slice(bytemuck::bytes_of(&attributes));
    assert_eq!(captured.port_attributes, Some(expected_attributes));
    assert_eq!(captured.message.as_deref(), Some(&image[240..284]));
    let wire = captured.checked_wire(caller(), (7, 11)).unwrap();
    let header: nt_alpc_abi::AlpcConnectPortCheckedRequest =
        bytemuck::pod_read_unaligned(&wire[..core::mem::size_of::<nt_alpc_abi::AlpcConnectPortCheckedRequest>()]);
    assert_eq!(header.connect.connect_flags, 0x0002_0000);
    assert_eq!(header.has_port_attributes, 1);
    assert_eq!(header.port_attributes, attributes);
    assert_eq!(capture_connect_port(
        [16, 64, 0, 160, 0x0004_0000, 0, 240, 400, 0, 0, 0],
        |address, out| read_image(&image, address, out), |_, _| true,
    ), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn uncertain_submission_retains_exact_reply_request_and_physical_caller() {
    let mut pending = RetainedLater::new(caller(), (7,9), 31, vec![1,2,3]).unwrap();
    pending.begin(41).unwrap();
    assert_eq!(pending.observe(41, caller()), Ok(None));
    let mut reused = caller();
    reused.tcb = 99;
    assert_eq!(pending.complete(41, reused, TerminalLater::service(0, 0, 0, 0, vec![])), Err(RetainedError::WrongCaller));
    assert_eq!(pending.complete(42, caller(), TerminalLater::service(0, 0, 0, 0, vec![])), Err(RetainedError::WrongRequest));
    assert_eq!(pending.reply_cap(), 31);
    assert_eq!(pending.request(), &[1,2,3]);
    assert!(pending.finish_after_reply(true).is_err());
}

#[test]
fn terminal_reply_failure_and_no_effect_keep_or_release_correctly() {
    let mut pending = RetainedLater::new(caller(), (7,9), 31, vec![1]).unwrap();
    pending.begin(41).unwrap();
    pending.complete(41, caller(), TerminalLater::service(0, 3, 55, 0, vec![4,5,6])).unwrap();
    assert_eq!(pending.observe(42, caller()), Err(RetainedError::WrongRequest));
    let pending = pending.finish_after_reply(false).err().unwrap();
    assert_eq!(pending.reply_cap(), 31);
    assert_eq!(pending.terminal().unwrap().output, vec![4,5,6]);
    assert_eq!(pending.terminal().unwrap().detail0, 55);
    assert!(pending.finish_after_reply(true).is_ok());

    let mut pending = RetainedLater::new(caller(), (7,10), 32, vec![2]).unwrap();
    pending.begin(42).unwrap();
    pending.no_effect(42, caller(), STATUS_INVALID_PARAMETER as i32).unwrap();
    assert_eq!(pending.terminal().unwrap().status, STATUS_INVALID_PARAMETER as i32);
    assert!(!pending.terminal().unwrap().service_effect_possible);
    assert!(pending.finish_after_reply(true).is_ok());
}

#[test]
fn retained_later_rejects_success_as_no_effect_and_attempts_reply_once() {
    let mut pending = RetainedLater::new(caller(), (7, 11), 33, vec![3]).unwrap();
    pending.begin(43).unwrap();
    assert_eq!(pending.no_effect(43, caller(), 0), Err(RetainedError::WrongPhase));
    assert_eq!(pending.observe(43, caller()), Ok(None));
    pending.complete(43, caller(), TerminalLater::service(0, 0, 0, 0, vec![])).unwrap();
    assert_eq!(pending.begin_reply(), Ok(()));
    assert_eq!(pending.begin_reply(), Err(RetainedError::WrongPhase));
    let pending = pending.finish_after_reply(false).err().unwrap();
    assert_eq!(pending.reply_cap(), 33);
    assert!(pending.finish_after_reply(true).is_ok());
}

#[test]
fn exact_pending_receive_can_poll_again_without_releasing_its_reply() {
    let mut pending = RetainedLater::new(caller(), (7, 12), 34, vec![4]).unwrap();
    pending.begin(44).unwrap();
    assert_eq!(pending.continue_pending(45, caller()), Err(RetainedError::WrongRequest));
    assert_eq!(pending.continue_pending(44, caller()), Ok(()));
    assert_eq!(pending.reply_cap(), 34);
    assert_eq!(pending.request(), &[4]);
    assert_eq!(pending.begin(45), Ok(()));
    assert_eq!(pending.observe(44, caller()), Err(RetainedError::WrongRequest));
    pending.complete(45, caller(), TerminalLater::service(0, 0, 0, 0, vec![])).unwrap();
    assert_eq!(pending.begin_reply(), Ok(()));
}

#[test]
fn checked_send_wire_carries_exact_owner_token_and_copied_payload() {
    use nt_alpc_abi::AlpcSendReceiveCheckedRequest;
    let captured = CapturedSendWaitReceive {
        port: 77, flags: 0, send_message: Some(vec![1,2,3,4]),
        send_attributes: None, receive: None, timeout: None,
    };
    let wire = captured.checked_wire(caller(), (7,9)).unwrap();
    let header: AlpcSendReceiveCheckedRequest = bytemuck::pod_read_unaligned(&wire[..80]);
    assert_eq!(header.send_receive.abi_size, 80);
    assert_eq!(header.send_receive.message_offset, 80);
    assert_eq!(header.invocation.owner_generation, 12);
    assert_eq!((header.invocation.invocation_hi, header.invocation.invocation_lo), (7,9));
    assert_eq!(&wire[80..], &[1,2,3,4]);
}

#[test]
fn checked_connect_and_accept_wires_bind_owner_and_connection() {
    use nt_alpc_abi::{AlpcAcceptConnectCheckedRequest, AlpcConnectPortCheckedRequest};
    let connect = CapturedConnectPort {
        output: 16, name: "\\SmApiPort".encode_utf16().collect(),
        connect_flags: 0,
        port_attributes: None, server_sid: None, message: None, message_target: None,
        send_attributes: None, timeout: None,
    };
    let wire = connect.checked_wire(caller(), (7,9)).unwrap();
    let header: AlpcConnectPortCheckedRequest = bytemuck::pod_read_unaligned(&wire[..160]);
    assert_eq!(header.connect.abi_size, 160);
    assert_eq!(header.connect.name_offset, 160);
    assert_eq!(header.invocation.owner_thread, 8);
    assert_eq!(header.has_port_attributes, 0);
    assert_eq!(wire.len(), 180);
    let accept = CapturedAcceptConnect {
        output: 16, listen_port: 77, connection_id: 59, port_context: 44, accept: true,
        message: vec![0; 40],
    };
    let wire = accept.checked_wire(caller(), (7,10)).unwrap();
    let header: AlpcAcceptConnectCheckedRequest = bytemuck::pod_read_unaligned(&wire[..80]);
    assert_eq!(header.accept.abi_size, 80);
    assert_eq!(header.accept.connection_id, 59);
    assert_eq!(header.listen_port, 77);
    assert_eq!(header.invocation.invocation_lo, 10);
    assert_eq!(header.message_offset, 80);
    assert_eq!(header.message_len_bytes, 40);
    assert_eq!(&wire[80..], &[0; 40]);
}

#[test]
fn checked_wire_rejects_unbound_owner_and_token_before_submission() {
    let captured = CapturedSendWaitReceive { port: 77, flags: 0, send_message: None,
        send_attributes: None, receive: None, timeout: None };
    assert_eq!(captured.checked_wire(caller(), (0,0)), Err(STATUS_INVALID_PARAMETER));
    let mut wrong = caller();
    wrong.tcb = 0;
    assert_eq!(captured.checked_wire(wrong, (7,9)), Err(STATUS_INVALID_PARAMETER));
}
