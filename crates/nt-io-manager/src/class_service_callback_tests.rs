use super::*;
use crate::{
    hosted_forward_target::HostedForwardTarget,
    retained_connect_forward::{
        ConnectBufferAllocation, ConnectBufferSource, ConnectControl, ConnectDispatchReturn,
        ConnectPayloadIdentity, ConnectStackRange, RetainedConnectForward,
    },
    retained_query_path_forward::SourceIrpTicket,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpOwner},
    CompletionAcknowledgement, DeviceCharacteristics, DeviceFlags, DeviceType, IoManager,
    MockDriverBackend, MockObjectPort,
};
use alloc::boxed::Box;
use nt_status::NtStatus;
use nt_types::NtPath;

fn fixture(control: ConnectControl) -> (IoManager<MockObjectPort>, ClassServiceEndpoint) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io
        .create_driver(
            &NtPath::parse_str(r"\Driver\ClassCallback").unwrap(),
            Box::new(MockDriverBackend::new()),
        )
        .unwrap();
    let port = io
        .create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        )
        .unwrap();
    let class = io
        .create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        )
        .unwrap();
    let class_domain = io.register_hosted_domain();
    let port_domain = io.register_hosted_domain();
    io.bind_hosted_device_pointer(class_domain, 0x5000, port)
        .unwrap();
    let class_registration = io
        .bind_hosted_device_pointer(class_domain, 0x6000, class)
        .unwrap();
    io.bind_hosted_device_pointer(port_domain, 0x7000, port)
        .unwrap();
    let source = SourceIrpForwardIdentity::new(
        SourceIrpTicket::new(class_domain, 17, 3).unwrap(),
        SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(0),
            domain: class_domain,
            component_address: 0x8000,
            bytes: 0x100,
            stack_count: 3,
            pool_generation: 3,
        },
    )
    .unwrap();
    let mut forward = RetainedConnectForward::new(
        source,
        HostedForwardTarget::capture(&mut io, class_domain, 0x5000).unwrap(),
        control,
    );
    let mut snapshot = [0; 16];
    snapshot[..8].copy_from_slice(&class_registration.address().to_le_bytes());
    snapshot[8..].copy_from_slice(&0x9000_u64.to_le_bytes());
    let payload = ConnectPayloadIdentity {
        forward: forward.identity(),
        buffer: ConnectBufferSource::Stack(ConnectStackRange {
            domain: class_domain,
            thread: 7,
            base: 0xa000,
            bytes: 0x1000,
            generation: 4,
        }),
        input_pointer: 0xaff0,
        input_length: 16,
        snapshot,
        class_device: class_registration,
        class_service: 0x9000,
    };
    forward.capture_payload(&io, payload, class).unwrap();
    let forward_identity = forward.identity();
    forward.enter(&io, forward_identity).unwrap();
    forward
        .observe_dispatch(
            &io,
            forward_identity,
            ConnectDispatchReturn::Terminal(NtStatus::SUCCESS),
        )
        .unwrap();
    let mut class_target = HostedForwardTarget::capture(&mut io, class_domain, 0x6000).unwrap();
    let mut port_target = HostedForwardTarget::capture(&mut io, port_domain, 0x7000).unwrap();
    for bad_thunk in [
        ClassServiceThunk {
            domain: class_domain,
            address: 0x9008,
            generation: 5,
        },
        ClassServiceThunk {
            domain: class_domain,
            address: 0x9000,
            generation: 0,
        },
    ] {
        let (error, returned_class, returned_port) = ClassServiceEndpoint::bind(
            &io,
            &forward,
            payload,
            class_target,
            port_target,
            bad_thunk,
        )
        .unwrap_err();
        assert_eq!(error, ClassCallbackError::WrongIdentity);
        class_target = returned_class;
        port_target = returned_port;
    }
    let endpoint = ClassServiceEndpoint::bind(
        &io,
        &forward,
        payload,
        class_target,
        port_target,
        ClassServiceThunk {
            domain: class_domain,
            address: 0x9000,
            generation: 5,
        },
    )
    .unwrap();
    forward.consume_terminal(&io, forward_identity).unwrap();
    forward.retire_after_source_completion(&mut io).unwrap();
    (io, endpoint)
}

#[test]
fn callback_copies_bounded_records_and_consumed_count_never_exceeds_offered() {
    for (control, size) in [(ConnectControl::Keyboard, 12), (ConnectControl::Mouse, 24)] {
        let (mut io, endpoint) = fixture(control);
        let identity = endpoint.binding();
        let port_domain = identity.port.domain();
        let source = ConnectBufferAllocation {
            domain: port_domain,
            base: 0x10000,
            bytes: 2 * size as u64,
            generation: 9,
        };
        let mut port_bytes = alloc::vec![0x11; 2 * size];
        let mut request = endpoint
            .capture(&io, source, 0x10000, 0x10000 + 2 * size as u64, &port_bytes)
            .unwrap();
        port_bytes.fill(0x22);
        assert_eq!(request.bytes(), alloc::vec![0x11; 2 * size].as_slice());
        assert_eq!(request.offered(), 2);
        let observed = request.identity();
        assert_eq!(request.enter(&io, observed), Ok(()));
        assert_eq!(request.complete(&io, observed, 1), Ok(()));
        assert_eq!(
            request.enter(&io, observed),
            Err(ClassCallbackError::InvalidTransition)
        );
        assert_eq!(
            request.acknowledge(&io, observed, CompletionAcknowledgement::Acknowledged),
            Ok(1)
        );
        assert_eq!(
            request.acknowledge(&io, observed, CompletionAcknowledgement::Acknowledged),
            Err(ClassCallbackError::InvalidTransition)
        );
        assert_eq!(request.retire_after_ack(), Ok(1));
        assert_eq!(endpoint.validate(&io), Ok(()));
        let mut endpoint = endpoint;
        assert_eq!(endpoint.disconnect(&mut io), Ok(()));
    }
}

#[test]
fn oversized_consumed_count_is_an_uncertain_effect_and_blocks_release() {
    let (mut io, endpoint) = fixture(ConnectControl::Keyboard);
    let source = ConnectBufferAllocation {
        domain: endpoint.binding().port.domain(),
        base: 0x10000,
        bytes: 12,
        generation: 9,
    };
    let mut request = endpoint
        .capture(&io, source, 0x10000, 0x1000c, &[0; 12])
        .unwrap();
    let identity = request.identity();
    request.enter(&io, identity).unwrap();
    assert_eq!(
        request.complete(&io, identity, 2),
        Err(ClassCallbackError::ConsumedBeyondOffered)
    );
    assert_eq!(
        request.complete(&io, identity, 1),
        Err(ClassCallbackError::InvalidTransition)
    );
    assert_eq!(
        request.retire_after_ack(),
        Err(ClassCallbackError::InvalidTransition)
    );
    drop(request);
    let mut endpoint = endpoint;
    assert_eq!(
        endpoint.disconnect(&mut io),
        Err(ClassCallbackError::Outstanding)
    );
}

#[test]
fn completion_without_provider_ack_retains_input_and_endpoint() {
    let (mut io, endpoint) = fixture(ConnectControl::Mouse);
    let source = ConnectBufferAllocation {
        domain: endpoint.binding().port.domain(),
        base: 0x10000,
        bytes: 24,
        generation: 9,
    };
    let mut request = endpoint
        .capture(&io, source, 0x10000, 0x10018, &[0; 24])
        .unwrap();
    let identity = request.identity();
    request.enter(&io, identity).unwrap();
    request.complete(&io, identity, 1).unwrap();
    assert_eq!(
        request.acknowledge(
            &io,
            identity,
            CompletionAcknowledgement::Indeterminate {
                transport_status: NtStatus::DEVICE_NOT_CONNECTED
            }
        ),
        Err(ClassCallbackError::InvalidTransition)
    );
    assert_eq!(
        request.retire_after_ack(),
        Err(ClassCallbackError::InvalidTransition)
    );
    assert_eq!(request.bytes(), &[0; 24]);
    drop(request);
    let mut endpoint = endpoint;
    assert_eq!(
        endpoint.disconnect(&mut io),
        Err(ClassCallbackError::Outstanding)
    );
}

#[test]
fn input_bounds_alignment_and_registration_generations_are_exact() {
    let (mut io, endpoint) = fixture(ConnectControl::Mouse);
    let binding = endpoint.binding();
    let source = ConnectBufferAllocation {
        domain: binding.port.domain(),
        base: 0x10000,
        bytes: 48,
        generation: 9,
    };
    for (start, end, bytes) in [
        (0x10000, 0x1000c, 12), // wrong record width
        (0x10000, 0x10030, 24), // snapshot incomplete
        (0x10001, 0x10019, 24), // misaligned
        (0x10018, 0x10000, 24), // reversed
        (0x10030, 0x10048, 24), // outside pool
        (u64::MAX - 15, u64::MAX, 15),
    ] {
        assert!(endpoint
            .capture(&io, source, start, end, &alloc::vec![0; bytes])
            .is_err());
    }
    assert!(endpoint
        .capture(
            &io,
            ConnectBufferAllocation {
                generation: 0,
                ..source
            },
            0x10000,
            0x10018,
            &[0; 24]
        )
        .is_err());
    let oversized = alloc::vec![0; 1025 * 24];
    assert_eq!(
        endpoint
            .capture(
                &io,
                ConnectBufferAllocation {
                    base: 0x20000,
                    bytes: oversized.len() as u64,
                    ..source
                },
                0x20000,
                0x20000 + oversized.len() as u64,
                &oversized
            )
            .err(),
        Some(ClassCallbackError::InvalidInput)
    );
    let mut request = endpoint
        .capture(&io, source, 0x10000, 0x10018, &[0; 24])
        .unwrap();
    let observed = request.identity();
    let wrong = ClassCallbackIdentity {
        binding: ClassServiceBinding {
            thunk: ClassServiceThunk {
                generation: binding.thunk.generation + 1,
                ..binding.thunk
            },
            ..binding
        },
        ..observed
    };
    assert_eq!(
        request.enter(&io, wrong),
        Err(ClassCallbackError::WrongIdentity)
    );
    assert_eq!(
        request.enter(
            &io,
            ClassCallbackIdentity {
                binding: ClassServiceBinding {
                    class: binding.port,
                    ..binding
                },
                ..observed
            }
        ),
        Err(ClassCallbackError::WrongIdentity)
    );
    assert_eq!(request.enter(&io, observed), Ok(()));
    assert_eq!(request.complete(&io, observed, 0), Ok(()));
    assert_eq!(
        request.acknowledge(&io, observed, CompletionAcknowledgement::Acknowledged),
        Ok(0)
    );
    assert_eq!(request.retire_after_ack(), Ok(0));
    let mut endpoint = endpoint;
    endpoint.disconnect(&mut io).unwrap();
}

#[test]
fn uncertain_callback_cannot_replay_or_release_endpoint() {
    let (mut io, endpoint) = fixture(ConnectControl::Keyboard);
    let source = ConnectBufferAllocation {
        domain: endpoint.binding().port.domain(),
        base: 0x10000,
        bytes: 12,
        generation: 9,
    };
    let mut request = endpoint
        .capture(&io, source, 0x10000, 0x1000c, &[0; 12])
        .unwrap();
    let identity = request.identity();
    assert_eq!(request.enter(&io, identity), Ok(()));
    assert_eq!(request.mark_indeterminate(&io, identity), Ok(()));
    assert_eq!(
        request.enter(&io, identity),
        Err(ClassCallbackError::InvalidTransition)
    );
    assert_eq!(
        request.complete(&io, identity, 1),
        Err(ClassCallbackError::InvalidTransition)
    );
    assert_eq!(
        request.acknowledge(&io, identity, CompletionAcknowledgement::Acknowledged),
        Err(ClassCallbackError::InvalidTransition)
    );
    assert_eq!(
        request.retire_after_ack(),
        Err(ClassCallbackError::InvalidTransition)
    );
    assert_eq!(endpoint.validate(&io), Ok(()));
    // Even an accidentally dropped request leaves a permanent ownership gate.
    drop(request);
    let mut endpoint = endpoint;
    assert_eq!(
        endpoint.disconnect(&mut io),
        Err(ClassCallbackError::Outstanding)
    );
}
