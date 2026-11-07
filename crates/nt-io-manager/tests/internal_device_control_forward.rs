use nt_io_manager::internal_device_control_forward::{
    InternalControlCapture, InternalControlError, InternalControlOutcome,
    InternalControlProgress,
};

#[test]
fn arbitrary_kernel_neither_control_retains_exact_output_until_terminal() {
    let request = InternalControlCapture::new(0x0f, 0, 0x7a12_3403, true, 0, 8).unwrap();
    assert_eq!(request.code(), 0x7a12_3403);
    assert_eq!(request.output_length(), 8);

    let mut progress = InternalControlProgress::new(request);
    assert_eq!(progress.enter(), Ok(()));
    assert_eq!(progress.enter(), Err(InternalControlError::AlreadyEntered));
    assert_eq!(progress.observe(InternalControlOutcome::Pending), Ok(None));
    assert_eq!(progress.enter(), Err(InternalControlError::AlreadyEntered));
    let result = progress.observe(InternalControlOutcome::Terminal {
        status: 0,
        information: 8,
        output: [1, 2, 3, 4, 5, 6, 7, 8],
    });
    assert!(result.unwrap().is_some());
    assert!(!progress.can_publish());
}

#[test]
fn uncertain_transport_and_stale_terminal_never_authorize_replay_or_publication() {
    let request = InternalControlCapture::new(0x0f, 0, 0x7a12_3403, true, 0, 8).unwrap();
    let mut progress = InternalControlProgress::new(request);
    progress.enter().unwrap();
    assert_eq!(progress.observe(InternalControlOutcome::Uncertain), Ok(None));
    assert_eq!(progress.enter(), Err(InternalControlError::AlreadyEntered));
    assert_eq!(
        progress.observe(InternalControlOutcome::Terminal {
            status: 0,
            information: 9,
            output: [0; 8],
        }),
        Err(InternalControlError::ExcessInformation),
    );
    assert!(!progress.can_publish());
}

#[test]
fn rejects_non_kernel_or_non_neither_request_without_entering_provider() {
    assert_eq!(
        InternalControlCapture::new(0x0e, 0, 0x7a12_3403, true, 0, 8),
        Err(InternalControlError::WrongMajor),
    );
    assert_eq!(
        InternalControlCapture::new(0x0f, 0, 0x7a12_3400, true, 0, 8),
        Err(InternalControlError::WrongMethod),
    );
    assert_eq!(
        InternalControlCapture::new(0x0f, 0, 0x7a12_3403, false, 0, 8),
        Err(InternalControlError::WrongMode),
    );
}
