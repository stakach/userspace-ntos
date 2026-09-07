use super::*;
use core::num::NonZeroU32;

fn request(operation: u16, token: u64) -> CmHiveKeyCloseRequest {
    CmHiveKeyCloseRequest {
        abi_size: core::mem::size_of::<CmHiveKeyCloseRequest>() as u16,
        abi_version: CM_ABI_VERSION,
        operation,
        mount: hive_mount::SYSTEM,
        lease_token: token,
        ..CmHiveKeyCloseRequest::default()
    }
}

fn opened() -> (CmServer, u64) {
    let mut server = CmServer::new_for_incarnation(NonZeroU32::MIN);
    let token = server
        .system_key_leases
        .open(CellId(9), String::from("key"))
        .unwrap();
    (server, token)
}

#[test]
fn malformed_or_short_output_requests_do_not_release_a_lease() {
    let (mut server, token) = opened();
    let good = request(operation::PREPARE, token);
    let mut output = [0; core::mem::size_of::<CmHiveKeyCloseReply>()];
    let mut malformed = [good; 6];
    malformed[0].abi_size -= 1;
    malformed[1].abi_version += 1;
    malformed[2].mount = 0;
    malformed[3].receipt_generation = 1;
    malformed[4].lease_token = 0;
    malformed[5].operation = 999;
    for input in malformed {
        assert_eq!(
            server
                .op_system_hive_key_close(input.as_bytes(), &mut output)
                .status,
            STATUS_INVALID_PARAMETER
        );
        assert!(server.system_key_leases.get(token).is_some());
    }
    assert_eq!(
        server
            .op_system_hive_key_close(&good.as_bytes()[..39], &mut output)
            .status,
        STATUS_INVALID_PARAMETER
    );
    let mut extended = good.as_bytes().to_vec();
    extended.push(0);
    assert_eq!(
        server
            .op_system_hive_key_close(&extended, &mut output)
            .status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        server
            .op_system_hive_key_close(good.as_bytes(), &mut output[..39])
            .status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert!(server.system_key_leases.get(token).is_some());
}

#[test]
fn dispatched_receipts_replay_exactly_and_ack_reply_is_idempotent() {
    let (mut server, token) = opened();
    let begin = request(operation::PREPARE, token);
    let mut output = [0; core::mem::size_of::<CmHiveKeyCloseReply>()];
    let first = server.dispatch(
        opcode::CM_OP_SYSTEM_HIVE_KEY_CLOSE,
        begin.as_bytes(),
        &mut output,
    );
    assert_eq!(first.status, STATUS_SUCCESS);
    assert_eq!(first.information as usize, output.len());
    let receipt = CmHiveKeyCloseReply::from_bytes(&output).unwrap();
    assert_eq!(receipt.disposition, disposition::RETAINED);
    assert_eq!(receipt.lease_token, token);
    let saved = output;
    server.op_system_hive_key_close(begin.as_bytes(), &mut output);
    assert_eq!(output, saved);
    let ack = CmHiveKeyCloseRequest {
        receipt_bank: receipt.receipt_bank,
        receipt_slot: receipt.receipt_slot,
        receipt_generation: receipt.receipt_generation,
        ..request(operation::ACKNOWLEDGE, 0)
    };
    assert_eq!(
        server
            .op_system_hive_key_close(ack.as_bytes(), &mut output[..39])
            .status,
        STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(
        server
            .op_system_hive_key_close(ack.as_bytes(), &mut output)
            .status,
        STATUS_SUCCESS
    );
    assert_eq!(
        CmHiveKeyCloseReply::from_bytes(&output)
            .unwrap()
            .disposition,
        disposition::ACKNOWLEDGED
    );
    assert_eq!(
        server
            .op_system_hive_key_close(ack.as_bytes(), &mut output)
            .status,
        STATUS_SUCCESS
    );
    assert_eq!(
        CmHiveKeyCloseReply::from_bytes(&output)
            .unwrap()
            .disposition,
        disposition::ALREADY_ACKNOWLEDGED
    );
}
