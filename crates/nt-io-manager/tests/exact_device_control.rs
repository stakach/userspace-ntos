//! Host composition of File-less exact-device controls, transfer buffers, and retained completion.

use std::{cell::RefCell, rc::Rc};

use nt_io_abi::{ioctl, major};
use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceId, DeviceType, DispatchContext, DispatchOutcome,
    DriverCompletion, DriverDispatchBackend, ExternalDispatchResult, IoManager, IoParameters,
    IrpId, IrpProjection, MockObjectPort,
};
use nt_status::NtStatus;
use nt_types::{ClientId, NtPath};

const INPUT: &[u8] = b"input";
const WRITTEN: &[u8] = b"OUT";
const CAPACITY: usize = 8;
const BUFFER_OVERFLOW: NtStatus = NtStatus(0x8000_0005u32 as i32);

#[test]
fn observing_retained_completion_does_not_acknowledge_or_replay_the_request() {
    let mut f = Fixture::new();
    f.lower_state.borrow_mut().pending = true;
    let mut output = [0xa5; CAPACITY];
    let ExternalDispatchResult::Pending { irp_id } = f
        .dispatch(false, true, f.lower, ioctl::METHOD_BUFFERED, &mut output)
        .unwrap()
    else {
        panic!("expected retained control request");
    };
    assert_eq!(f.io.pump(), 1);
    for _ in 0..4 {
        assert_eq!(f.io.completed_irp(irp_id).unwrap().id, irp_id);
        assert_eq!(f.io.next_completed_irp().unwrap().id, irp_id);
        assert!(f.io.irp(irp_id).is_some());
        assert_eq!(f.lower_state.borrow().acknowledgements, 0);
    }
    f.lower_state.borrow_mut().refuse_ack = true;
    assert_eq!(
        f.io.acknowledge_completed_irp_strict(irp_id).unwrap_err(),
        NtStatus::UNSUCCESSFUL
    );
    for _ in 0..4 {
        assert_eq!(f.io.completed_irp(irp_id).unwrap().id, irp_id);
        assert_eq!(f.lower_state.borrow().acknowledgements, 1);
        assert_eq!(f.lower_state.borrow().calls.len(), 1);
    }
    f.lower_state.borrow_mut().refuse_ack = false;
    f.io.acknowledge_completed_irp_strict(irp_id).unwrap();
    assert_eq!(f.lower_state.borrow().acknowledgements, 2);
    assert_eq!(f.lower_state.borrow().calls.len(), 1);
    assert!(f.io.completed_irp(irp_id).is_none());
    assert!(f.io.irp(irp_id).is_none());
}

struct Observation {
    irp: IrpProjection,
    system: Vec<u8>,
    direct: Option<Vec<u8>>,
    type3: Option<Vec<u8>>,
    user: Option<Vec<u8>>,
}

struct State {
    calls: Vec<Observation>,
    pending: bool,
    status: NtStatus,
    information: u64,
    ready: Option<DriverCompletion>,
    retained: Option<(IrpId, Vec<u8>)>,
    refuse_ack: bool,
    acknowledgements: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            pending: false,
            status: NtStatus::SUCCESS,
            information: 3,
            ready: None,
            retained: None,
            refuse_ack: false,
            acknowledgements: 0,
        }
    }
}

struct Backend(Rc<RefCell<State>>);

impl DriverDispatchBackend for Backend {
    fn dispatch_irp(
        &mut self,
        mut ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let parameters = match &irp.parameters {
            IoParameters::DeviceControl(parameters)
            | IoParameters::InternalDeviceControl(parameters) => parameters,
            _ => panic!("File-less control must not create or close a File"),
        };
        let method = ioctl::method(parameters.ioctl_code);
        let mut state = self.0.borrow_mut();
        state.calls.push(Observation {
            irp: irp.clone(),
            system: ctx.system_buffer.to_vec(),
            direct: ctx.direct_buffer.as_deref().map(<[u8]>::to_vec),
            type3: ctx.type3_input_buffer.as_deref().map(<[u8]>::to_vec),
            user: ctx.user_buffer.as_deref().map(<[u8]>::to_vec),
        });
        assert_eq!(
            &ctx.ioctl_input_buffer(method)[..parameters.input_len as usize],
            INPUT
        );
        let output = ctx.ioctl_output_buffer_mut(method);
        output[..WRITTEN.len()].copy_from_slice(WRITTEN);
        if state.pending {
            state.retained = Some((irp.irp_id, output.to_vec()));
            state.ready = Some(DriverCompletion {
                irp_id: irp.irp_id,
                status: state.status,
                information: state.information,
                file_context: None,
            });
            Ok(DispatchOutcome::Pending)
        } else {
            Ok(DispatchOutcome::Completed {
                status: state.status,
                information: state.information,
                file_context: None,
            })
        }
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.0.borrow_mut().ready.take()
    }

    fn cancel_irp(&mut self, _: IrpId) -> Result<(), NtStatus> {
        panic!("control tests do not cancel");
    }

    fn copy_completion_output(
        &mut self,
        irp: IrpId,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, NtStatus> {
        let state = self.0.borrow();
        let (retained_irp, bytes) = state.retained.as_ref().ok_or(NtStatus::INVALID_PARAMETER)?;
        assert_eq!(*retained_irp, irp);
        let source = bytes
            .get(offset as usize..)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let copied = output.len().min(source.len());
        output[..copied].copy_from_slice(&source[..copied]);
        Ok(copied)
    }

    fn acknowledge_completion(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        let mut state = self.0.borrow_mut();
        state.acknowledgements += 1;
        if state.refuse_ack {
            return Err(NtStatus::UNSUCCESSFUL);
        }
        if let Some((retained, _)) = state.retained.as_ref() {
            assert_eq!(*retained, irp);
        }
        state.retained = None;
        Ok(())
    }
}

struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
    lower: DeviceId,
    upper: DeviceId,
    lower_state: Rc<RefCell<State>>,
    upper_state: Rc<RefCell<State>>,
}

impl Fixture {
    fn new() -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let lower_state = Rc::new(RefCell::new(State::default()));
        let upper_state = Rc::new(RefCell::new(State::default()));
        let mut add = |name: &str, state: Rc<RefCell<State>>| {
            let driver = io
                .create_driver(&NtPath::parse_str(name).unwrap(), Box::new(Backend(state)))
                .unwrap();
            io.create_device(
                driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap()
        };
        let lower = add(r"\Driver\ExactControlLower", lower_state.clone());
        let upper = add(r"\Driver\ExactControlUpper", upper_state.clone());
        io.attach_device_to_stack(upper, lower).unwrap();
        Self {
            io,
            client,
            lower,
            upper,
            lower_state,
            upper_state,
        }
    }

    fn dispatch(
        &mut self,
        internal: bool,
        exact: bool,
        target: DeviceId,
        method: u32,
        output: &mut [u8],
    ) -> Result<ExternalDispatchResult, NtStatus> {
        // No File or user handle exists, even though the CTL_CODE demands read and write access.
        let code = ioctl::ctl_code(
            0x22,
            0x800,
            method,
            ioctl::FILE_READ_ACCESS | ioctl::FILE_WRITE_ACCESS,
        );
        match (internal, exact) {
            (false, true) => {
                self.io
                    .device_control_exact_device(self.client, target, code, INPUT, output)
            }
            (true, true) => self.io.internal_device_control_exact_device(
                self.client,
                target,
                code,
                INPUT,
                output,
            ),
            (false, false) => {
                self.io
                    .device_control_device(self.client, target, code, INPUT, output)
            }
            (true, false) => {
                self.io
                    .internal_device_control_device(self.client, target, code, INPUT, output)
            }
        }
    }
}

fn expected_output() -> [u8; CAPACITY] {
    let mut output = [0xa5; CAPACITY];
    output[..WRITTEN.len()].copy_from_slice(WRITTEN);
    output
}

#[test]
fn exact_controls_support_all_transfer_methods_without_file_access_or_upper_dispatch() {
    for internal in [false, true] {
        for method in 0..=3 {
            let mut f = Fixture::new();
            let mut output = [0xa5; CAPACITY];
            assert_eq!(
                f.dispatch(internal, true, f.lower, method, &mut output),
                Ok(ExternalDispatchResult::Completed {
                    status: NtStatus::SUCCESS,
                    information: 3,
                    file_context: None,
                })
            );
            assert_eq!(output, expected_output());
            assert!(f.upper_state.borrow().calls.is_empty());
            let state = f.lower_state.borrow();
            assert_eq!(state.calls.len(), 1);
            let observed = &state.calls[0];
            assert_eq!(observed.irp.device_id, f.lower);
            assert_eq!(observed.irp.file_id, None);
            assert_eq!(
                observed.irp.major,
                if internal {
                    major::IRP_MJ_INTERNAL_DEVICE_CONTROL
                } else {
                    major::IRP_MJ_DEVICE_CONTROL
                }
            );
            match method {
                ioctl::METHOD_BUFFERED => {
                    assert_eq!(&observed.system[..INPUT.len()], INPUT);
                    assert!(
                        observed.direct.is_none()
                            && observed.type3.is_none()
                            && observed.user.is_none()
                    );
                }
                ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
                    assert_eq!(observed.system, INPUT);
                    assert_eq!(
                        observed.direct.as_deref(),
                        Some([0xa5; CAPACITY].as_slice())
                    );
                    assert!(observed.type3.is_none() && observed.user.is_none());
                }
                ioctl::METHOD_NEITHER => {
                    assert!(observed.system.is_empty() && observed.direct.is_none());
                    assert_eq!(observed.type3.as_deref(), Some(INPUT));
                    assert_eq!(observed.user.as_deref(), Some([0xa5; CAPACITY].as_slice()));
                }
                _ => unreachable!(),
            }
            assert_eq!(f.io.file_count(), 0);
            assert_eq!(f.io.irp_count(), 0);
        }
    }
}

#[test]
fn ordinary_device_controls_still_resolve_attached_top_instead_of_exact_lower() {
    for internal in [false, true] {
        let mut f = Fixture::new();
        f.dispatch(
            internal,
            false,
            f.lower,
            ioctl::METHOD_BUFFERED,
            &mut [0; CAPACITY],
        )
        .unwrap();
        assert!(f.lower_state.borrow().calls.is_empty());
        let state = f.upper_state.borrow();
        assert_eq!(state.calls.len(), 1);
        assert_eq!(state.calls[0].irp.device_id, f.upper);
        assert_eq!(state.calls[0].irp.file_id, None);
        assert_eq!(f.io.file_count(), 0);
    }
}

#[test]
fn raw_terminal_status_information_and_transfer_method_control_copyout() {
    let verify_required = NtStatus(0x8000_0016u32 as i32);
    for internal in [false, true] {
        for method in 0..=3 {
            for status in [
                NtStatus::SUCCESS,
                BUFFER_OVERFLOW,
                NtStatus::ACCESS_DENIED,
                verify_required,
            ] {
                for information in [0, 3, u64::MAX] {
                    let mut f = Fixture::new();
                    f.lower_state.borrow_mut().status = status;
                    f.lower_state.borrow_mut().information = information;
                    let mut output = [0xa5; CAPACITY];
                    assert_eq!(
                        f.dispatch(internal, true, f.lower, method, &mut output),
                        Ok(ExternalDispatchResult::Completed {
                            status,
                            information,
                            file_context: None,
                        })
                    );
                    let mut expected = [0xa5; CAPACITY];
                    if method != ioctl::METHOD_BUFFERED {
                        expected = expected_output();
                    } else if (status.raw() as u32 >> 30) != 3 && status != verify_required {
                        let staged = [b'O', b'U', b'T', b'u', b't', 0, 0, 0];
                        let copied = information.min(CAPACITY as u64) as usize;
                        expected[..copied].copy_from_slice(&staged[..copied]);
                    }
                    assert_eq!(
                        output, expected,
                        "method={method} status={status:?} information={information}"
                    );
                    assert_eq!(f.lower_state.borrow().calls.len(), 1);
                    assert!(f.upper_state.borrow().calls.is_empty());
                    assert_eq!(f.io.irp_count(), 0);
                }
            }
        }
    }
}

#[test]
fn pending_output_survives_failed_strict_ack_and_retry_without_redispatch() {
    for internal in [false, true] {
        for method in 0..=3 {
            for (status, information) in [(BUFFER_OVERFLOW, 3), (NtStatus::ACCESS_DENIED, 0)] {
                let mut f = Fixture::new();
                {
                    let mut state = f.lower_state.borrow_mut();
                    state.pending = true;
                    state.status = status;
                    state.information = information;
                }
                let mut output = [0xa5; CAPACITY];
                let ExternalDispatchResult::Pending { irp_id } = f
                    .dispatch(internal, true, f.lower, method, &mut output)
                    .unwrap()
                else {
                    panic!("expected retained request");
                };
                assert_eq!(output, [0xa5; CAPACITY]);
                f.io.pump();
                let completion = f.io.next_completed_irp().unwrap();
                assert_eq!(completion.id, irp_id);
                assert_eq!(completion.status, status);
                assert_eq!(completion.information, information);
                let copied =
                    f.io.copy_completed_device_control_output(irp_id, 0, &mut output)
                        .unwrap();
                let expected_len = if method != ioctl::METHOD_BUFFERED {
                    CAPACITY
                } else if (status.raw() as u32 >> 30) == 3 {
                    0
                } else {
                    3
                };
                assert_eq!(copied, expected_len);
                assert_eq!(
                    output,
                    if expected_len == 0 {
                        [0xa5; CAPACITY]
                    } else {
                        expected_output()
                    }
                );
                f.lower_state.borrow_mut().refuse_ack = true;
                assert_eq!(
                    f.io.acknowledge_completed_irp_strict(irp_id).unwrap_err(),
                    NtStatus::UNSUCCESSFUL
                );
                assert!(f.io.irp(irp_id).is_some());
                assert!(f.lower_state.borrow().retained.is_some());
                let mut retried = [0xa5; CAPACITY];
                assert_eq!(
                    f.io.copy_completed_device_control_output(irp_id, 0, &mut retried)
                        .unwrap(),
                    copied
                );
                assert_eq!(retried, output);
                f.lower_state.borrow_mut().refuse_ack = false;
                f.io.acknowledge_completed_irp_strict(irp_id).unwrap();
                assert_eq!(f.lower_state.borrow().calls.len(), 1);
                assert_eq!(f.lower_state.borrow().acknowledgements, 2);
                assert!(f.lower_state.borrow().retained.is_none());
                assert!(f.upper_state.borrow().calls.is_empty());
                assert_eq!(f.io.file_count(), 0);
                assert_eq!(f.io.irp_count(), 0);
            }
        }
    }
}

#[test]
fn invalid_or_delete_pending_exact_targets_never_enter_a_backend() {
    for internal in [false, true] {
        let mut f = Fixture::new();
        for target in [DeviceId::NULL, DeviceId(u64::MAX)] {
            assert_eq!(
                f.dispatch(
                    internal,
                    true,
                    target,
                    ioctl::METHOD_BUFFERED,
                    &mut [0xa5; CAPACITY]
                ),
                Err(NtStatus::INVALID_PARAMETER)
            );
        }
        assert_eq!(
            f.io.delete_device(f.lower).err(),
            Some(NtStatus::DELETE_PENDING)
        );
        assert_eq!(
            f.dispatch(
                internal,
                true,
                f.lower,
                ioctl::METHOD_BUFFERED,
                &mut [0xa5; CAPACITY]
            ),
            Err(NtStatus::DELETE_PENDING)
        );
        assert!(f.lower_state.borrow().calls.is_empty());
        assert!(f.upper_state.borrow().calls.is_empty());
        assert_eq!(f.io.file_count(), 0);
        assert_eq!(f.io.irp_count(), 0);
    }
}

fn forward_pending_completion(f: &mut Fixture, irp: IrpId, lower_method: u32) {
    let record = f.io.irp(irp).unwrap();
    let current = record.current_stack().unwrap();
    let caller = current.driver_id;
    let mut lower = record.stack[record.current_location as usize + 1].clone();
    lower.major = current.major;
    lower.minor = current.minor;
    lower.parameters = current.parameters.clone();
    match &mut lower.parameters {
        IoParameters::DeviceControl(parameters)
        | IoParameters::InternalDeviceControl(parameters) => {
            parameters.ioctl_code = (parameters.ioctl_code & !3) | lower_method;
        }
        _ => panic!("expected precomputed lower IOCTL stack"),
    }
    assert_eq!(
        f.io.handoff_irp_to_next_stack(irp, caller, lower)
            .unwrap()
            .1,
        f.lower
    );
    // Model the host forwarding the retained transport buffers to the authenticated lower
    // backend. Completion/copy/ACK now belong to that backend, not to the original filter.
    let mut upper = f.upper_state.borrow_mut();
    let mut lower = f.lower_state.borrow_mut();
    lower.retained = upper.retained.take();
    lower.ready = upper.ready.take();
}

#[test]
fn pending_copy_policy_keeps_original_method_when_forwarded_stack_changes_control_code() {
    for internal in [false, true] {
        for original_method in 0..=3 {
            for (status, information) in [(BUFFER_OVERFLOW, 3), (NtStatus::ACCESS_DENIED, 0)] {
                let mut f = Fixture::new();
                {
                    let mut state = f.upper_state.borrow_mut();
                    state.pending = true;
                    state.status = status;
                    state.information = information;
                }
                let mut output = [0xa5; CAPACITY];
                let ExternalDispatchResult::Pending { irp_id } = f
                    .dispatch(internal, false, f.lower, original_method, &mut output)
                    .unwrap()
                else {
                    panic!("expected retained filter request");
                };
                let lower_method = if original_method == ioctl::METHOD_BUFFERED {
                    ioctl::METHOD_NEITHER
                } else {
                    ioctl::METHOD_BUFFERED
                };
                forward_pending_completion(&mut f, irp_id, lower_method);
                f.io.pump();
                let completion = f.io.next_completed_irp().unwrap();
                assert_eq!(completion.id, irp_id);
                assert_eq!(completion.status, status);
                assert_eq!(completion.information, information);
                let expected = if original_method != ioctl::METHOD_BUFFERED {
                    CAPACITY
                } else if (status.raw() as u32 >> 30) == 3 {
                    0
                } else {
                    3
                };
                assert_eq!(
                    f.io.copy_completed_device_control_output(irp_id, 0, &mut output)
                        .unwrap(),
                    expected
                );
                assert_eq!(
                    output,
                    if expected == 0 {
                        [0xa5; CAPACITY]
                    } else {
                        expected_output()
                    }
                );
                f.io.acknowledge_completed_irp_strict(irp_id).unwrap();
                assert_eq!(f.upper_state.borrow().calls.len(), 1);
                assert_eq!(f.upper_state.borrow().acknowledgements, 0);
                assert_eq!(f.lower_state.borrow().acknowledgements, 1);
                assert!(f.lower_state.borrow().retained.is_none());
                assert_eq!(f.io.irp_count(), 0);
            }
        }
    }
}

#[test]
fn full_buffer_payload_requires_original_buffered_method_after_forwarding() {
    for internal in [false, true] {
        for original_method in 0..=3 {
            let mut f = Fixture::new();
            {
                let mut state = f.upper_state.borrow_mut();
                state.pending = true;
                state.status = NtStatus::ACCESS_DENIED;
                state.information = 0;
            }
            let mut output = [0xa5; CAPACITY];
            let ExternalDispatchResult::Pending { irp_id } = f
                .dispatch(internal, false, f.lower, original_method, &mut output)
                .unwrap()
            else {
                panic!("expected retained filter request");
            };
            let lower_method = if original_method == ioctl::METHOD_BUFFERED {
                ioctl::METHOD_OUT_DIRECT
            } else {
                ioctl::METHOD_BUFFERED
            };
            forward_pending_completion(&mut f, irp_id, lower_method);
            f.io.pump();
            let result =
                f.io.copy_completed_buffered_device_control_payload(irp_id, 0, &mut output);
            if original_method == ioctl::METHOD_BUFFERED {
                assert_eq!(result, Ok(CAPACITY));
                assert_eq!(output, [b'O', b'U', b'T', b'u', b't', 0, 0, 0]);
            } else {
                assert_eq!(result, Err(NtStatus::INVALID_PARAMETER));
                assert_eq!(output, [0xa5; CAPACITY]);
            }
            f.io.acknowledge_completed_irp_strict(irp_id).unwrap();
            assert_eq!(f.upper_state.borrow().calls.len(), 1);
            assert_eq!(f.upper_state.borrow().acknowledgements, 0);
            assert_eq!(f.lower_state.borrow().acknowledgements, 1);
            assert_eq!(f.io.irp_count(), 0);
        }
    }
}
