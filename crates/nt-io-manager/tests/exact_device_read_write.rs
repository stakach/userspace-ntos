//! File-less kernel-built READ/WRITE requests retain exact device and transfer ownership.

use std::{cell::RefCell, rc::Rc};

use nt_io_abi::major;
use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceId, DeviceType, DispatchContext, DispatchOutcome,
    DriverCompletion, DriverDispatchBackend, ExternalDispatchResult, IoManager, IoParameters,
    IrpId, IrpProjection, MockObjectPort,
};
use nt_status::NtStatus;
use nt_types::{ClientId, NtPath};

#[derive(Default)]
struct State {
    calls: Vec<(u8, DeviceId, Vec<u8>, u64)>,
    pending: bool,
    ready: Option<DriverCompletion>,
    retained: Option<(IrpId, Vec<u8>)>,
    acknowledgements: usize,
}

struct Backend(Rc<RefCell<State>>);

impl DriverDispatchBackend for Backend {
    fn dispatch_irp(
        &mut self,
        mut ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        assert_eq!(irp.file_id, None);
        let (length, offset) = match &irp.parameters {
            IoParameters::Read(p) | IoParameters::Write(p) => (p.length, p.offset),
            _ => panic!("expected READ or WRITE"),
        };
        let transfer = if !ctx.system_buffer.is_empty() {
            &mut *ctx.system_buffer
        } else if let Some(buffer) = ctx.direct_buffer.as_deref_mut() {
            buffer
        } else {
            ctx.user_buffer.as_deref_mut().expect("neither buffer")
        };
        assert_eq!(transfer.len(), length as usize);
        let input = transfer.to_vec();
        if irp.major == major::IRP_MJ_READ {
            transfer[..4].copy_from_slice(b"data");
        }
        let mut state = self.0.borrow_mut();
        state.calls.push((irp.major, irp.device_id, input, offset));
        if state.pending {
            state.retained = Some((irp.irp_id, transfer.to_vec()));
            state.ready = Some(DriverCompletion {
                irp_id: irp.irp_id,
                status: NtStatus::SUCCESS,
                information: 4,
                file_context: None,
            });
            Ok(DispatchOutcome::Pending)
        } else {
            Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 4,
                file_context: None,
            })
        }
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.0.borrow_mut().ready.take()
    }

    fn cancel_irp(&mut self, _: IrpId) -> Result<(), NtStatus> {
        panic!("not cancelled")
    }

    fn copy_completion_output(
        &mut self,
        irp_id: IrpId,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, NtStatus> {
        let state = self.0.borrow();
        let (retained_id, retained) = state.retained.as_ref().ok_or(NtStatus::INVALID_PARAMETER)?;
        assert_eq!(*retained_id, irp_id);
        let remaining = retained.get(offset as usize..).ok_or(NtStatus::INVALID_PARAMETER)?;
        let count = remaining.len().min(output.len());
        output[..count].copy_from_slice(&remaining[..count]);
        Ok(count)
    }

    fn acknowledge_completion(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
        let mut state = self.0.borrow_mut();
        assert_eq!(state.retained.as_ref().map(|(id, _)| *id), Some(irp_id));
        state.acknowledgements += 1;
        state.retained = None;
        Ok(())
    }
}

fn fixture(flags: DeviceFlags) -> (IoManager<MockObjectPort>, ClientId, DeviceId, DeviceId, Rc<RefCell<State>>, Rc<RefCell<State>>) {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let lower_state = Rc::new(RefCell::new(State::default()));
    let upper_state = Rc::new(RefCell::new(State::default()));
    let mut add = |name: &str, state: Rc<RefCell<State>>| {
        let driver = io
            .create_driver(&NtPath::parse_str(name).unwrap(), Box::new(Backend(state)))
            .unwrap();
        io.create_device(driver, None, DeviceType::UNKNOWN, DeviceCharacteristics::empty(), flags, 0)
            .unwrap()
    };
    let lower = add(r"\Driver\ExactReadWriteLower", lower_state.clone());
    let upper = add(r"\Driver\ExactReadWriteUpper", upper_state.clone());
    io.attach_device_to_stack(upper, lower).unwrap();
    (io, client, lower, upper, lower_state, upper_state)
}

#[test]
fn exact_read_and_write_use_the_target_transfer_model_without_a_file() {
    for flags in [DeviceFlags::BUFFERED_IO, DeviceFlags::DIRECT_IO, DeviceFlags::empty()] {
        let (mut io, client, lower, _upper, lower_state, upper_state) = fixture(flags);
        let mut output = [0; 8];
        assert_eq!(
            io.read_exact_device(client, lower, 0x1234, &mut output).unwrap(),
            ExternalDispatchResult::Completed {
                status: NtStatus::SUCCESS,
                information: 4,
                file_context: None,
            }
        );
        assert_eq!(&output[..4], b"data");
        assert_eq!(
            io.write_exact_device(client, lower, 0x5678, b"write").unwrap(),
            ExternalDispatchResult::Completed {
                status: NtStatus::SUCCESS,
                information: 4,
                file_context: None,
            }
        );
        assert_eq!(lower_state.borrow().calls, vec![
            (major::IRP_MJ_READ, lower, vec![0; 8], 0x1234),
            (major::IRP_MJ_WRITE, lower, b"write".to_vec(), 0x5678),
        ]);
        assert!(upper_state.borrow().calls.is_empty());
    }
}

#[test]
fn pending_exact_read_retains_output_until_terminal_and_strict_ack() {
    let (mut io, client, lower, _upper, lower_state, upper_state) = fixture(DeviceFlags::BUFFERED_IO);
    lower_state.borrow_mut().pending = true;
    let mut output = [0; 8];
    let ExternalDispatchResult::Pending { irp_id } =
        io.read_exact_device(client, lower, 0, &mut output).unwrap()
    else {
        panic!("expected pending read")
    };
    assert!(io.copy_completed_irp_output(irp_id, 0, &mut output).is_err());
    assert!(io.acknowledge_completed_irp_strict(irp_id).is_err());
    assert_eq!(io.pump(), 1);
    assert_eq!(io.completed_irp(irp_id).unwrap().information, 4);
    output.fill(0);
    assert_eq!(io.copy_completed_irp_output(irp_id, 0, &mut output).unwrap(), 4);
    assert_eq!(&output[..4], b"data");
    assert_eq!(lower_state.borrow().acknowledgements, 0);
    io.acknowledge_completed_irp_strict(irp_id).unwrap();
    assert!(io.irp(irp_id).is_none());
    assert_eq!(lower_state.borrow().acknowledgements, 1);
    assert_eq!(lower_state.borrow().calls.len(), 1);
    assert!(upper_state.borrow().calls.is_empty());
}
