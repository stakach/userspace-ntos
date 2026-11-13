use super::*;

struct ContendedTarget {
    submits: Vec<u16>,
    target_polls: usize,
    malformed_target: bool,
}

impl ContendedTarget {
    fn new(malformed_target: bool) -> Self {
        Self { submits: Vec::new(), target_polls: 0, malformed_target }
    }
}

impl Backend for ContendedTarget {
    fn call(&mut self, _: u16, _: &[u8], _: &mut [u8]) -> ObReply {
        panic!("owned namespace resolution must not use the synchronous Object Manager channel")
    }
}

impl OwnedBackend for ContendedTarget {
    fn call_owned(&mut self, op: u16, request: &[u8], _: &mut [u8]) -> OwnedCall {
        assert!(request.len() > size_of::<ObLookupPathRequest>());
        self.submits.push(op);
        match op {
            opcode::OB_OP_OPEN_DIRECTORY_HANDLE => OwnedCall::Indeterminate(41),
            opcode::OB_OP_RESOLVE_FILE_TARGET => OwnedCall::Indeterminate(42),
            _ => panic!("unexpected Object Manager operation"),
        }
    }

    fn poll_owned(&mut self, request_id: u64, output: &mut [u8]) -> Option<ObReply> {
        match request_id {
            41 => Some(ObReply { status: NtStatus::SUCCESS.raw(), information: 0,
                detail0: 91, detail1: 0 }),
            42 => {
                self.target_polls += 1;
                if self.target_polls == 1 { return None; }
                let suffix: Vec<u8> = r"\windows\system32\sfc.dll".encode_utf16()
                    .flat_map(u16::to_le_bytes).collect();
                output[..suffix.len()].copy_from_slice(&suffix);
                Some(ObReply { status: NtStatus::SUCCESS.raw(),
                    information: if self.malformed_target { 1 } else { suffix.len() as u32 },
                    detail0: 73, detail1: 0 })
            }
            _ => panic!("poll of wrong Object Manager request identity"),
        }
    }
}

#[test]
fn owned_file_target_waits_for_directory_owner_then_returns_exact_device_and_suffix() {
    let mut client = ObjectClient::new(ContendedTarget::new(false));
    let directory = UnicodeString::from_str("\\Device\\SharedChannel");
    let pending_directory = match client.open_directory_handle_owned(None, &directory,
        AccessMask::GENERIC_READ, ObjAttrFlags::CASE_INSENSITIVE) {
        DirectoryOwnedOutcome::Indeterminate(pending) => pending,
        _ => panic!("directory request must own the shared channel"),
    };
    let name = utf16(r"\??\C:\Windows\System32\sfc.dll");
    assert!(matches!(client.resolve_file_target_owned(&name, true),
        FileTargetOwnedOutcome::NoEffect(NtStatus::DEVICE_BUSY)));
    assert_eq!(client.backend_mut().submits,
        [opcode::OB_OP_OPEN_DIRECTORY_HANDLE],
        "busy before submission must not enqueue a second SQE");

    assert!(matches!(client.poll_directory_handle_owned(&pending_directory),
        Some(DirectoryOwnedTerminal::Success(_))));
    let pending_target = match client.resolve_file_target_owned(&name, true) {
        FileTargetOwnedOutcome::Indeterminate(pending) => pending,
        _ => panic!("released channel must submit one exact file-target lookup"),
    };
    assert_eq!(client.backend_mut().submits,
        [opcode::OB_OP_OPEN_DIRECTORY_HANDLE, opcode::OB_OP_RESOLVE_FILE_TARGET]);
    let mut other = ObjectClient::new(ContendedTarget::new(false));
    let foreign_target = match other.resolve_file_target_owned(&name, true) {
        FileTargetOwnedOutcome::Indeterminate(pending) => pending,
        _ => panic!("other client owns an independent request"),
    };
    assert!(client.poll_file_target_owned(&foreign_target).is_none(),
        "a different client's request identity cannot consume this reply");
    assert!(client.poll_file_target_owned(&pending_target).is_none());
    let target = match client.poll_file_target_owned(&pending_target) {
        Some(FileTargetOwnedTerminal::Success(target)) => target,
        _ => panic!("the exact terminal reply must resolve the file target"),
    };
    assert_eq!(target.device_object, ObjectId(73));
    assert_eq!(target.remaining_name, utf16(r"\windows\system32\sfc.dll"));
    assert!(client.poll_file_target_owned(&pending_target).is_none(),
        "late duplicate poll must not consume another completion");
    assert_eq!(client.backend_mut().submits.len(), 2, "no file-target replay");
}

#[test]
fn malformed_owned_file_target_terminal_quarantines_the_channel() {
    let name = utf16(r"\SystemRoot\System32\msgina.dll");
    let mut client = ObjectClient::new(ContendedTarget::new(true));
    let pending = match client.resolve_file_target_owned(&name, true) {
        FileTargetOwnedOutcome::Indeterminate(pending) => pending,
        _ => panic!("file-target lookup must be retained after submission"),
    };
    assert!(client.poll_file_target_owned(&pending).is_none());
    assert!(matches!(client.poll_file_target_owned(&pending),
        Some(FileTargetOwnedTerminal::Incoherent(_))));
    assert!(matches!(client.resolve_file_target_owned(&name, true),
        FileTargetOwnedOutcome::NoEffect(NtStatus::DEVICE_BUSY)),
        "malformed success cannot authorize channel reuse or request replay");
    assert_eq!(client.backend_mut().submits.len(), 1);
}
