use super::*;

#[test]
fn autoaccepted_connection_closure_retires_original_listen_object() {
    let mut core = PortCore::new();
    let name: Vec<u16> = "\\AutoLifetime".encode_utf16().collect();
    let listen = core.create_port(&name, PortApi::Lpc);
    let object_id = core.ports[0].object_id;
    let (client, id) = match core.connect(&name, PortApi::Lpc, 0, &[]).unwrap() {
        ConnectOutcome::Completed {
            client_handle,
            connection_id,
        } => (client_handle, connection_id),
        _ => panic!("automatic connection"),
    };
    core.send_message(client, b"queued", MessageAttrs::default())
        .unwrap();
    core.close_port_checked(client).unwrap();
    core.close_port_checked(listen).unwrap();
    assert!(
        !core.ports.iter().any(|port| port.object_id == object_id),
        "an implicit server endpoint has no public handle retaining a closed listen object"
    );
    assert_eq!(core.connection_pool_usage(id), Some(0));
}

#[test]
fn autoaccepted_listen_owner_drain_never_closes_phantom_zero_handle() {
    let mut core = PortCore::new();
    let name: Vec<u16> = "\\AutoDrain".encode_utf16().collect();
    core.create_port_with_owner(
        &name,
        PortApi::Lpc,
        ClientId {
            process: 42,
            thread: 43,
        },
    );
    let id = match core
        .connect_with_client_id(
            &name,
            PortApi::Lpc,
            0,
            &[],
            ClientId {
                process: 52,
                thread: 53,
            },
        )
        .unwrap()
    {
        ConnectOutcome::Completed { connection_id, .. } => connection_id,
        _ => panic!("automatic connection"),
    };
    assert_eq!(
        core.close_process_ports(42),
        Ok(1),
        "only the actual listen handle is present in the owner's user table"
    );
    assert_eq!(core.close_process_ports(42), Ok(0));
    assert_eq!(core.close_process_ports(52), Ok(1));
    assert!(core.ports.is_empty());
    assert_eq!(core.connection_pool_usage(id), Some(0));
}

#[test]
fn replacement_listen_port_cannot_receive_old_endpoint_datagram() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let name: Vec<u16> = "\\ReplacementOwner".encode_utf16().collect();
    let original = core.create_port(&name, PortApi::Lpc);
    let original_object = core.ports[0].object_id;
    let id = match core.connect(&name, PortApi::Lpc, 0, &[]).unwrap() {
        ConnectOutcome::Pending { connection_id } => connection_id,
        _ => panic!("manual connection"),
    };
    let server = core.accept(id, true, 0x1234).unwrap();
    let client = core.complete(id).unwrap().0;
    let retained = core.retain_communication_port(client).unwrap();
    core.send_retained_message(
        retained,
        b"old-owner",
        MessageAttrs::default(),
        ClientId {
            process: 42,
            thread: 43,
        },
    )
    .unwrap();
    core.close_port_checked(client).unwrap();
    assert!(core
        .release_port_object_with_lifetime(retained)
        .unwrap()
        .unwrap()
        .is_deleted());
    core.close_port_checked(original).unwrap();
    assert!(
        core.ports
            .iter()
            .any(|port| port.object_id == original_object),
        "the original server endpoint retains its receiving port object"
    );
    let replacement = core.create_port(&name, PortApi::Lpc);
    assert_ne!(replacement, original);
    assert!(
        core.receive_message(replacement).unwrap().is_none(),
        "same name does not authorize receiving an old port object's datagram"
    );
    let message = core.receive_message(server).unwrap().unwrap();
    assert_eq!(message.bytes, b"old-owner");
    assert_eq!(message.provenance.connection_id, id);
    assert_eq!(message.port_context, 0x1234);
    assert!(core.receive_message(server).unwrap().is_none());
    core.close_port_checked(server).unwrap();
    assert!(!core
        .ports
        .iter()
        .any(|port| port.object_id == original_object));
    assert_eq!(core.connection_pool_usage(id), Some(0));
    assert!(core.receive_message(replacement).unwrap().is_none());
}

fn connected() -> (PortCore, u64, u64, u64) {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let name: Vec<u16> = "\\Lifetime".encode_utf16().collect();
    core.create_port(&name, PortApi::Lpc);
    let id = match core
        .connect_with_client_id(
            &name,
            PortApi::Lpc,
            0,
            &[],
            ClientId {
                process: 42,
                thread: 43,
            },
        )
        .unwrap()
    {
        ConnectOutcome::Pending { connection_id } => connection_id,
        _ => panic!("manual connection"),
    };
    let server = core.accept(id, true, 0).unwrap();
    let client = core.complete(id).unwrap().0;
    (core, id, client, server)
}

#[test]
fn endpoint_deletion_is_independent_of_peer_handle_closure() {
    let (mut core, id, client, server) = connected();
    let server_before = core
        .communication_endpoint_lifetime(id, PortHandleEndpoint::ServerCommPort, 0)
        .unwrap();
    let closed = core.close_port_checked(client).unwrap().unwrap();
    assert!(closed.is_deleted());
    assert_eq!(closed.owner_process, 42);
    assert_eq!(
        core.communication_endpoint_lifetime(id, PortHandleEndpoint::ServerCommPort, 0)
            .unwrap(),
        server_before
    );
    assert!(core
        .close_port_checked(server)
        .unwrap()
        .unwrap()
        .is_deleted());
    assert_eq!(
        core.close_port_checked(client),
        Err(NtStatus::INVALID_PORT_HANDLE)
    );
}

#[test]
fn final_kernel_reference_not_user_close_deletes_client_endpoint() {
    let (mut core, id, client, server) = connected();
    let first = core.retain_communication_port(client).unwrap();
    let second = core.retain_communication_port(client).unwrap();
    assert_eq!(
        core.close_port_checked(first),
        Err(NtStatus::INVALID_PORT_HANDLE)
    );
    assert_eq!(
        core.communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 42)
            .unwrap()
            .kernel_references,
        2
    );
    let snapshot = core.close_port_checked(client).unwrap().unwrap();
    assert!(!snapshot.is_deleted());
    assert_eq!(snapshot.kernel_references, 2);
    let one = core
        .release_port_object_with_lifetime(first)
        .unwrap()
        .unwrap();
    assert!(!one.is_deleted());
    assert_eq!(one.kernel_references, 1);
    let before = core
        .communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 42)
        .unwrap();
    assert_eq!(
        core.release_port_object_with_lifetime(first),
        Err(NtStatus::INVALID_PORT_HANDLE)
    );
    assert_eq!(
        core.communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 42)
            .unwrap(),
        before
    );
    let last = core
        .release_port_object_with_lifetime(second)
        .unwrap()
        .unwrap();
    assert!(last.is_deleted());
    assert!(core.handle_info(server).is_some());
}

#[test]
fn endpoint_queries_refuse_foreign_connection_process_and_kind_without_mutation() {
    let (core, id, _, _) = connected();
    let before = core
        .communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 42)
        .unwrap();
    assert_eq!(
        core.communication_endpoint_lifetime(id + 1, PortHandleEndpoint::ClientCommPort, 42),
        Err(NtStatus::INVALID_PORT_HANDLE)
    );
    assert_eq!(
        core.communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 43),
        Err(NtStatus::INVALID_PORT_HANDLE)
    );
    assert_eq!(
        core.communication_endpoint_lifetime(id, PortHandleEndpoint::ListenPort, 42),
        Err(NtStatus::INVALID_PORT_HANDLE)
    );
    assert_eq!(
        core.communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 42)
            .unwrap(),
        before
    );
}

#[test]
fn pending_connector_has_construction_reference_before_its_user_handle_exists() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let name: Vec<u16> = "\\PendingLifetime".encode_utf16().collect();
    core.create_port(&name, PortApi::Lpc);
    let id = match core
        .connect_with_client_id(
            &name,
            PortApi::Lpc,
            0,
            &[],
            ClientId {
                process: 42,
                thread: 43,
            },
        )
        .unwrap()
    {
        ConnectOutcome::Pending { connection_id } => connection_id,
        _ => panic!("manual connection"),
    };
    let pending = core
        .communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 42)
        .unwrap();
    assert!(!pending.user_open);
    assert_eq!(pending.construction_references, 1);
    assert!(!pending.is_deleted());
    core.accept(id, false, 0).unwrap();
    let refused = core
        .communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 42)
        .unwrap();
    assert!(refused.is_deleted());
}

#[test]
fn process_user_handle_drain_is_idempotent_and_preserves_kernel_and_peer_owners() {
    let (mut core, id, client, server) = connected();
    let retained = core.retain_communication_port(client).unwrap();
    let listen = core.create_port_with_owner(
        &"\\OwnedListen".encode_utf16().collect::<Vec<_>>(),
        PortApi::Lpc,
        ClientId {
            process: 42,
            thread: 44,
        },
    );
    assert_eq!(
        core.close_process_ports(0),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert!(core.handle_info(client).is_some());
    assert_eq!(core.close_process_ports(42), Ok(2));
    assert!(core.handle_info(client).is_none());
    assert!(core.handle_info(listen).is_none());
    assert!(core.handle_info(server).is_some());
    assert!(!core
        .communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 42)
        .unwrap()
        .is_deleted());
    assert_eq!(core.close_process_ports(42), Ok(0));
    assert!(core
        .release_port_object_with_lifetime(retained)
        .unwrap()
        .unwrap()
        .is_deleted());
}

#[test]
fn process_exit_refuses_unpublished_connector_without_closing_server_endpoint() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let name: Vec<u16> = "\\UnpublishedExit".encode_utf16().collect();
    core.create_port(&name, PortApi::Lpc);
    let id = match core
        .connect_with_client_id(
            &name,
            PortApi::Lpc,
            0,
            &[],
            ClientId {
                process: 42,
                thread: 43,
            },
        )
        .unwrap()
    {
        ConnectOutcome::Pending { connection_id } => connection_id,
        _ => panic!("manual connection"),
    };
    let server = core.accept(id, true, 0).unwrap();
    assert_eq!(core.close_process_ports(42), Ok(0));
    assert!(core
        .communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, 42)
        .unwrap()
        .is_deleted());
    assert_eq!(core.complete(id), Err(NtStatus::INVALID_PARAMETER));
    assert!(core.handle_info(server).is_some());
    assert_eq!(core.close_process_ports(42), Ok(0));
}
