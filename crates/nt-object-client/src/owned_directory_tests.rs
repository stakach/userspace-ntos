use super::*;
use nt_object_abi::ObReply;
use core::cell::Cell;

struct LegacyUncertain<'a> { submitted: &'a Cell<bool> }

impl Backend for LegacyUncertain<'_> {
    fn call(&mut self, op: u16, _: &[u8], _: &mut [u8]) -> ObReply {
        assert_eq!(op, opcode::OB_OP_CREATE_DIRECTORY_HANDLE);
        self.submitted.set(true);
        ObReply { status: NtStatus::UNSUCCESSFUL.raw(), information: 0,
            detail0: 0, detail1: 0 }
    }
}

struct LegacyOpenUncertain<'a> {
    submitted: &'a Cell<bool>,
}

impl Backend for LegacyOpenUncertain<'_> {
    fn call(&mut self, op: u16, _: &[u8], _: &mut [u8]) -> ObReply {
        assert_eq!(op, opcode::OB_OP_OPEN_DIRECTORY_HANDLE);
        self.submitted.set(true);
        ObReply {
            status: NtStatus::UNSUCCESSFUL.raw(),
            information: 0,
            detail0: 0,
            detail1: 0,
        }
    }
}

#[test]
fn synchronous_directory_open_collapses_submitted_uncertainty_to_status() {
    let submitted = Cell::new(false);
    let mut client = ObjectClient::new(LegacyOpenUncertain {
        submitted: &submitted,
    });
    let name = UnicodeString::from_str("\\Device\\OwnedOpenPending");
    let error = client
        .open_directory_handle(
            None,
            &name,
            AccessMask::GENERIC_READ,
            ObjAttrFlags::CASE_INSENSITIVE,
        )
        .unwrap_err();
    assert!(submitted.get());
    assert_eq!(error, NtStatus::UNSUCCESSFUL);
    // The old return value has no request identity; a remote handle may still be created.
}

#[test]
fn synchronous_directory_create_collapses_submitted_uncertainty_to_status() {
    let submitted = Cell::new(false);
    let mut client = ObjectClient::new(LegacyUncertain { submitted: &submitted });
    let name = UnicodeString::from_str("\\Device\\OwnedPending");
    let error = client.create_directory_handle(None, &name,
        AccessMask::GENERIC_ALL, ObjAttrFlags::CASE_INSENSITIVE).unwrap_err();
    assert!(submitted.get());
    assert_eq!(error, NtStatus::UNSUCCESSFUL);
    // The result contains no request identity and cannot safely authorize rollback or retry.
}

struct Uncertain {
    sent: usize,
    pending: bool,
    malformed: bool,
}

impl Backend for Uncertain {
    fn call(&mut self, _: u16, _: &[u8], _: &mut [u8]) -> ObReply {
        panic!("directory publication must use owned transport")
    }
}

impl OwnedBackend for Uncertain {
    fn call_owned(&mut self, op: u16, request: &[u8], _: &mut [u8])
        -> OwnedCall {
        assert_eq!(op, opcode::OB_OP_CREATE_DIRECTORY_HANDLE);
        assert!(request.len() > size_of::<ObDirectoryHandleRequest>());
        self.sent += 1;
        self.pending = true;
        OwnedCall::Indeterminate(31)
    }

    fn poll_owned(&mut self, id: u64, _: &mut [u8]) -> Option<ObReply> {
        assert_eq!(id, 31);
        if self.pending {
            self.pending = false;
            None
        } else {
            Some(ObReply { status: NtStatus::SUCCESS.raw(), information: 0,
                detail0: if self.malformed { 0 } else { 49 }, detail1: 1 })
        }
    }
}

#[test]
fn uncertain_directory_create_retains_exact_request_until_terminal_completion() {
    let mut client = ObjectClient::new(Uncertain { sent: 0, pending: false, malformed: false });
    let name = UnicodeString::from_str("\\Device\\OwnedPending");
    let pending = match client.create_directory_handle_owned(None, &name,
        AccessMask::GENERIC_ALL, ObjAttrFlags::CASE_INSENSITIVE) {
        DirectoryOwnedOutcome::Indeterminate(pending) => pending,
        _ => panic!("request must remain retained"),
    };
    assert_eq!(client.backend_mut().sent, 1);
    assert!(matches!(client.create_directory_handle_owned(None, &name,
        AccessMask::GENERIC_ALL, ObjAttrFlags::CASE_INSENSITIVE),
        DirectoryOwnedOutcome::NoEffect(NtStatus::DEVICE_BUSY)));
    let mut other = ObjectClient::new(Uncertain { sent: 0, pending: false, malformed: false });
    let other_pending = match other.create_directory_handle_owned(None, &name,
        AccessMask::GENERIC_ALL, ObjAttrFlags::CASE_INSENSITIVE) {
        DirectoryOwnedOutcome::Indeterminate(pending) => pending,
        _ => panic!("other request must be retained"),
    };
    assert!(other.poll_directory_handle_owned(&pending).is_none());
    assert!(client.poll_directory_handle_owned(&other_pending).is_none());
    assert!(client.poll_directory_handle_owned(&pending).is_none());
    assert_eq!(client.backend_mut().sent, 1);
    let result = match client.poll_directory_handle_owned(&pending).unwrap() {
        DirectoryOwnedTerminal::Success(result) => result,
        _ => panic!("exact late completion must decode as success"),
    };
    assert_eq!(result.handle, HandleValue(49));
    assert!(result.created);
    assert_eq!(client.backend_mut().sent, 1);
    assert!(client.poll_directory_handle_owned(&pending).is_none());
}

#[test]
fn incoherent_success_after_uncertain_create_remains_an_owned_effect() {
    let mut client = ObjectClient::new(Uncertain { sent: 0, pending: false, malformed: true });
    let name = UnicodeString::from_str("\\Device\\BadReply");
    let pending = match client.create_directory_handle_owned(None, &name,
        AccessMask::GENERIC_ALL, ObjAttrFlags::CASE_INSENSITIVE) {
        DirectoryOwnedOutcome::Indeterminate(pending) => pending,
        _ => panic!("request must remain retained"),
    };
    assert!(client.poll_directory_handle_owned(&pending).is_none());
    assert!(matches!(client.poll_directory_handle_owned(&pending),
        Some(DirectoryOwnedTerminal::Incoherent(_))));
    assert!(matches!(client.create_directory_handle_owned(None, &name,
        AccessMask::GENERIC_ALL, ObjAttrFlags::CASE_INSENSITIVE),
        DirectoryOwnedOutcome::NoEffect(NtStatus::DEVICE_BUSY)));
}

struct UncertainOpen {
    sent: usize,
    pending: bool,
    malformed: bool,
}

impl Backend for UncertainOpen {
    fn call(&mut self, _: u16, _: &[u8], _: &mut [u8]) -> ObReply {
        panic!("directory open must use owned transport")
    }
}

impl OwnedBackend for UncertainOpen {
    fn call_owned(&mut self, op: u16, request: &[u8], _: &mut [u8]) -> OwnedCall {
        assert_eq!(op, opcode::OB_OP_OPEN_DIRECTORY_HANDLE);
        assert!(request.len() > size_of::<ObDirectoryHandleRequest>());
        self.sent += 1;
        self.pending = true;
        OwnedCall::Indeterminate(37)
    }

    fn poll_owned(&mut self, id: u64, _: &mut [u8]) -> Option<ObReply> {
        assert_eq!(id, 37);
        if self.pending {
            self.pending = false;
            None
        } else {
            Some(ObReply {
                status: if self.malformed {
                    0x4000_0000
                } else {
                    NtStatus::SUCCESS.raw()
                },
                information: 0,
                detail0: 71,
                detail1: 0,
            })
        }
    }
}

#[test]
fn uncertain_directory_open_retains_request_and_blocks_create_until_exact_completion() {
    let mut client = ObjectClient::new(UncertainOpen {
        sent: 0,
        pending: false,
        malformed: false,
    });
    let name = UnicodeString::from_str("\\Device\\OwnedOpenPending");
    let pending = match client.open_directory_handle_owned(
        None,
        &name,
        AccessMask::GENERIC_READ,
        ObjAttrFlags::CASE_INSENSITIVE,
    ) {
        DirectoryOwnedOutcome::Indeterminate(pending) => pending,
        _ => panic!("open request must remain retained"),
    };
    assert!(matches!(
        client.create_directory_handle_owned(
            None,
            &name,
            AccessMask::GENERIC_ALL,
            ObjAttrFlags::CASE_INSENSITIVE
        ),
        DirectoryOwnedOutcome::NoEffect(NtStatus::DEVICE_BUSY)
    ));
    assert!(matches!(
        client.open_directory_handle_owned(
            None,
            &name,
            AccessMask::GENERIC_READ,
            ObjAttrFlags::CASE_INSENSITIVE
        ),
        DirectoryOwnedOutcome::NoEffect(NtStatus::DEVICE_BUSY)
    ));
    assert!(client.poll_directory_handle_owned(&pending).is_none());
    let result = match client.poll_directory_handle_owned(&pending).unwrap() {
        DirectoryOwnedTerminal::Success(result) => result,
        _ => panic!("late open completion must decode as success"),
    };
    assert_eq!(result.handle, HandleValue(71));
    assert_eq!(result.status, NtStatus::SUCCESS);
    assert!(!result.created);
    assert_eq!(client.backend_mut().sent, 1);
    assert!(client.poll_directory_handle_owned(&pending).is_none());
}

#[test]
fn malformed_late_open_success_is_quarantined() {
    let mut client = ObjectClient::new(UncertainOpen {
        sent: 0,
        pending: false,
        malformed: true,
    });
    let name = UnicodeString::from_str("\\Device\\BadOpenReply");
    let pending = match client.open_directory_handle_owned(
        None,
        &name,
        AccessMask::GENERIC_READ,
        ObjAttrFlags::CASE_INSENSITIVE,
    ) {
        DirectoryOwnedOutcome::Indeterminate(pending) => pending,
        _ => panic!("open request must remain retained"),
    };
    assert!(client.poll_directory_handle_owned(&pending).is_none());
    assert!(matches!(
        client.poll_directory_handle_owned(&pending),
        Some(DirectoryOwnedTerminal::Incoherent(_))
    ));
    assert!(matches!(
        client.open_directory_handle_owned(
            None,
            &name,
            AccessMask::GENERIC_READ,
            ObjAttrFlags::CASE_INSENSITIVE
        ),
        DirectoryOwnedOutcome::NoEffect(NtStatus::DEVICE_BUSY)
    ));
    assert_eq!(client.backend_mut().sent, 1);
}
