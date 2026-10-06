//! Retained LPC references for native ETHREAD termination messages.
use super::*;

pub(crate) unsafe fn register_native_thread_termination_port(
    handler: &mut ExecNtHandler,
    handle: u64,
) -> u32 {
    let _durable = crate::allocator::enter_durable();
    let tid = handler.current_tid as nt_process::ThreadId;
    let Some(lifetime) = handler.pm.thread_lifetime(tid) else {
        return nt_process::STATUS_INVALID_HANDLE;
    };
    let Some(process) = handler.capture_process_identity(handler.pi) else {
        return nt_process::STATUS_INVALID_HANDLE;
    };
    if lifetime.process_id() != process.pid {
        return nt_process::STATUS_INVALID_HANDLE;
    }
    let Some(lpc) = lpc_client() else {
        return 0xC000_0001;
    };
    let identity = match lpc.query_handle(handle) {
        Ok(identity) => identity,
        Err(status) => return status.raw() as u32,
    };
    let owner = match identity.endpoint {
        nt_lpc_abi::handle_endpoint::LISTEN_PORT
        | nt_lpc_abi::handle_endpoint::SERVER_COMM_PORT => identity.server_process,
        nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT => identity.client_process,
        _ => return nt_process::STATUS_INVALID_HANDLE,
    };
    if owner != u64::from(process.pid) {
        return nt_process::STATUS_INVALID_HANDLE;
    }
    // The broker currently retains listen and client communication objects. An actual server
    // communication object is not silently substituted by another endpoint.
    if identity.endpoint == nt_lpc_abi::handle_endpoint::SERVER_COMM_PORT {
        return 0xC000_00BB;
    }
    let ticket = match handler.pm.prepare_thread_termination_port(tid) {
        Ok(ticket) => ticket,
        Err(status) => return status,
    };
    if ticket.lifetime() != lifetime {
        let _ = handler.pm.cancel_thread_termination_port(&ticket);
        return nt_process::STATUS_INVALID_HANDLE;
    }
    let endpoint = match lpc.retain_port_object(handle) {
        Ok(endpoint) if endpoint != 0 => endpoint,
        // Without an effect classification, refusal/transport uncertainty cannot release the
        // reserved canonical owner or justify a second reference acquisition.
        Ok(_) => return 0xC000_0001,
        Err(status) => return status.raw() as u32,
    };
    // The reservation prevents lifetime reuse and preallocates its record; no policy reentry
    // may remove it while this exact native acquisition is outstanding.
    handler
        .pm
        .register_thread_termination_port(&ticket, endpoint)
        .expect("retained termination reference has its reserved exact ETHREAD owner");
    LPC_THREAD_TERMINATE_PORT_REGISTRATIONS.fetch_add(1, Ordering::Relaxed);
    0
}

pub(crate) unsafe fn notify_thread_termination_ports(tid: u64, handler: &mut ExecNtHandler) {
    use nt_process::ThreadTerminationPortPhase as Phase;
    loop {
        let snapshot = match handler
            .pm
            .peek_thread_termination_port(tid as nt_process::ThreadId)
        {
            Ok(Some(snapshot)) => snapshot,
            _ => break,
        };
        let Some(endpoint) = snapshot.endpoint else {
            break;
        };
        let ticket = &snapshot.ticket;
        let lifetime = ticket.lifetime();
        if !handler.pm.validate_thread_lifetime(lifetime) {
            break;
        }
        let Some(lpc) = lpc_client() else {
            break;
        };
        if snapshot.phase == Phase::Registered {
            let mut message = nt_lpc_abi::client_died_message(snapshot.create_time_100ns);
            message[8..16].copy_from_slice(&(lifetime.process_id() as u64).to_le_bytes());
            message[16..24].copy_from_slice(&(lifetime.thread_id() as u64).to_le_bytes());
            let csr_api_port = lpc
                .query_handle(endpoint)
                .is_ok_and(|identity| lpc_name_is(&identity.name, b"\\windows\\apiport"));
            if handler
                .pm
                .begin_thread_termination_port_delivery(ticket)
                .is_err()
            {
                break;
            }
            match lpc.retained_request_port_outcome(
                endpoint,
                &message,
                lifetime.process_id() as u64,
                lifetime.thread_id() as u64,
            ) {
                Ok(nt_lpc_client::RetainedRequestPortOutcome::Queued) => {
                    handler
                        .pm
                        .acknowledge_thread_termination_port_delivery(ticket)
                        .expect("exact entered termination delivery ACK");
                    LPC_THREAD_TERMINATE_PORT_DELIVERIES.fetch_add(1, Ordering::Relaxed);
                    handler.lpc_endpoint_progress = true;
                    if csr_api_port {
                        CSR_KERNEL_MESSAGES_PENDING.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(nt_lpc_client::RetainedRequestPortOutcome::Refused(status)) => {
                    handler
                        .pm
                        .acknowledge_thread_termination_port_refusal(ticket, status.raw() as u32)
                        .expect("exact checked termination delivery refusal");
                    LPC_THREAD_TERMINATE_PORT_DELIVERY_FAILURES.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[thread-term-port] retained delivery refused tid=");
                    print_u64(tid);
                    print_str(b" status=0x");
                    print_hex(status.raw() as u32);
                    print_str(b"\n");
                }
                Err(status) => {
                    LPC_THREAD_TERMINATE_PORT_DELIVERY_FAILURES.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[thread-term-port] retained delivery unresolved tid=");
                    print_u64(tid);
                    print_str(b" endpoint=0x");
                    print_hex_u64(endpoint);
                    print_str(b" status=0x");
                    print_hex(status.raw() as u32);
                    print_str(b"\n");
                    break;
                }
            }
        } else if !matches!(snapshot.phase, Phase::Delivered | Phase::Refused) {
            // Pending effects are sticky: later cleanup cannot resend or rerelease them.
            break;
        }
        if handler
            .pm
            .begin_thread_termination_port_release(ticket)
            .is_err()
        {
            break;
        }
        let receipt = match lpc.release_port_object_with_lifetime(endpoint) {
            Ok(receipt) => receipt,
            Err(status) => {
                print_str(b"[thread-term-port] retained release unresolved tid=");
                print_u64(tid);
                print_str(b" endpoint=0x");
                print_hex_u64(endpoint);
                print_str(b" status=0x");
                print_hex(status.raw() as u32);
                print_str(b"\n");
                break;
            }
        };
        handler
            .pm
            .acknowledge_thread_termination_port_release(ticket)
            .expect("exact entered termination reference release ACK");
        if let Some(receipt) = receipt {
            handler.retire_lpc_endpoint_release(receipt);
        }
    }
    let _ = crate::service_sec_image::lpc_endpoint_redrive_all(handler);
}
