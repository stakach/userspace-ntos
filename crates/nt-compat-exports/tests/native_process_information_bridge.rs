//! Bounded native ZwQueryInformationProcess packet shared by win32k and the executive.

#[path = "../../../components/ntos-executive/src/process_information_bridge.rs"]
mod process_information_bridge;

use process_information_bridge::{
    decode_request, decode_response, encode_request, encode_response, packet_len_for,
    selected_effective_owner, ProcessQueryRequest, HEADER_SIZE, MAX_OUTPUT_BYTES,
};

fn request(output_length: u32) -> ProcessQueryRequest {
    ProcessQueryRequest {
        handle: 0x28,
        class: 37,
        output_address: 0x7fff_1000,
        output_length,
        return_length_requested: true,
    }
}

#[test]
fn bounded_packet_preserves_original_output_address_and_exact_result_length() {
    let req = request(0x40);
    let mut packet = vec![0; packet_len_for(req.output_length).unwrap()];
    encode_request(&mut packet, req).unwrap();
    assert_eq!(decode_request(&packet).unwrap(), req);
    let image_info: Vec<u8> = (0..0x40).collect();
    encode_response(&mut packet, req, 0, 0x40, &image_info).unwrap();
    let reply = decode_response(&packet, req).unwrap();
    assert_eq!(reply.status, 0);
    assert_eq!(reply.return_length, 0x40);
    assert_eq!(reply.bytes, image_info);
    assert_eq!(decode_request(&packet).unwrap().output_address, 0x7fff_1000);
}

#[test]
fn zero_length_probe_and_large_declared_buffer_have_bounded_packets() {
    let probe = request(0);
    let mut packet = vec![0; packet_len_for(0).unwrap()];
    assert_eq!(packet.len(), HEADER_SIZE);
    encode_request(&mut packet, probe).unwrap();
    encode_response(&mut packet, probe, 0xc000_0004, 0x40, &[]).unwrap();
    let reply = decode_response(&packet, probe).unwrap();
    assert_eq!((reply.status, reply.return_length, reply.bytes.len()), (0xc000_0004, 0x40, 0));
    assert_eq!(packet_len_for(u32::MAX), Some(HEADER_SIZE + MAX_OUTPUT_BYTES));
}

#[test]
fn forged_request_or_response_cannot_expand_copyout_or_change_query_identity() {
    let req = request(0x40);
    let mut packet = vec![0; packet_len_for(req.output_length).unwrap()];
    encode_request(&mut packet, req).unwrap();
    let mut malformed = packet.clone();
    malformed[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_request(&malformed).is_err());
    let mut malformed = packet.clone();
    malformed[6] = 0x80;
    assert!(decode_request(&malformed).is_err());
    assert!(encode_response(&mut packet, req, 0, 0x41, &[0; 0x41]).is_err());
    encode_response(&mut packet, req, 0, 0x40, &[0; 0x40]).unwrap();
    let other = ProcessQueryRequest { handle: 0x2c, ..req };
    assert!(decode_response(&packet, other).is_err());
    packet[40..44].copy_from_slice(&0x41u32.to_le_bytes());
    assert!(decode_response(&packet, req).is_err());
}

#[test]
fn attached_query_owner_requires_original_record_and_active_alias_agreement() {
    let original = (7u32, 11u64);
    let attached = (8u32, 12u64);
    assert_eq!(selected_effective_owner(original, None, Some(original)), Some(original));
    assert_eq!(selected_effective_owner(original, Some((original, attached, false)), Some(attached)), Some(attached));
    assert_eq!(selected_effective_owner(original, Some((original, attached, true)), Some(attached)), None);
    assert_eq!(selected_effective_owner(original, Some(((7, 10), attached, false)), Some(attached)), None);
    assert_eq!(selected_effective_owner(original, Some((original, attached, false)), Some(original)), None);
    assert_eq!(selected_effective_owner(original, None, Some(attached)), None);
}
