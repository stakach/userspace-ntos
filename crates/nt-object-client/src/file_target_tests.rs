use super::*;

struct ReplyBackend {
    reply: ObReply,
    bytes: Vec<u8>,
}

impl Backend for ReplyBackend {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> ObReply {
        assert_eq!(opcode, opcode::OB_OP_RESOLVE_FILE_TARGET);
        let req: ObLookupPathRequest =
            bytemuck::pod_read_unaligned(&input[..size_of::<ObLookupPathRequest>()]);
        assert_eq!(req.abi_size as usize, size_of::<ObLookupPathRequest>());
        assert_eq!(req.path_offset as usize, size_of::<ObLookupPathRequest>());
        assert_eq!(
            req.path_len_bytes as usize,
            input.len() - req.path_offset as usize
        );
        output[..self.bytes.len()].copy_from_slice(&self.bytes);
        self.reply
    }
}

fn client(
    status: NtStatus,
    information: u32,
    device: u64,
    reserved: u64,
    bytes: &[u8],
) -> ObjectClient<ReplyBackend> {
    ObjectClient::new(ReplyBackend {
        reply: ObReply {
            status: status.raw(),
            information,
            detail0: device,
            detail1: reserved,
        },
        bytes: bytes.to_vec(),
    })
}

#[test]
fn target_reply_preserves_identity_and_exact_suffix() {
    let input = utf16("\\Device\\Volume\\");
    let suffix = [b'\\' as u16, b'\\' as u16, 0xd800, 0, 0xdc00, b'\\' as u16];
    let bytes: Vec<u8> = suffix.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    let mut c = client(NtStatus::SUCCESS, bytes.len() as u32, 0x1234, 0, &bytes);
    assert_eq!(
        c.resolve_file_target(&input, false),
        Ok(FilePathTarget {
            device_object: ObjectId(0x1234),
            remaining_name: suffix.to_vec(),
        })
    );
    let mut c = client(NtStatus::SUCCESS, 0, 0x1234, 0, &[]);
    assert_eq!(
        c.resolve_file_target(&input, true),
        Ok(FilePathTarget {
            device_object: ObjectId(0x1234),
            remaining_name: Vec::new(),
        })
    );
}

#[test]
fn target_reply_rejects_malformed_identity_length_and_suffix() {
    for (information, device, reserved, bytes) in [
        (0, 0, 0, &[][..]),
        (0, 1, 1, &[][..]),
        (1, 1, 0, &[b'\\'][..]),
        (4098, 1, 0, &[][..]),
        (u32::MAX, 1, 0, &[][..]),
        (2, 1, 0, &[b'A', 0][..]),
    ] {
        let mut c = client(NtStatus::SUCCESS, information, device, reserved, bytes);
        assert_eq!(
            c.resolve_file_target(&utf16("\\Device\\Volume"), true),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }
}

#[test]
fn target_reply_preserves_server_failure_without_interpreting_payload() {
    let mut c = client(NtStatus::OBJECT_PATH_NOT_FOUND, u32::MAX, 0, 1, &[]);
    assert_eq!(
        c.resolve_file_target(&utf16("\\Device\\Absent"), true),
        Err(NtStatus::OBJECT_PATH_NOT_FOUND)
    );
}
