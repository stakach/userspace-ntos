//! Authenticate retained worker resources before one-shot shared startup.

use super::*;

pub(crate) enum WorkerStartError {
    NotReady,
    InvalidWorker,
    UnknownPeer,
    Start(nt_component_suspension::PeerStartupError<sel4_rt::reply_binding::Error, u64>),
}

/// The physical owner must authenticate this live domain generation and retain the exact stopped
/// worker, including its scheduler and all capability aliases, through success or uncertainty.
/// No scheduler hook may reenter shared ingress while these borrows exist. Startup readiness and
/// pre-ready fault handling must use shared ingress; never enter the private component pump.
pub(crate) unsafe fn start_worker_peer<C, R, T>(
    route: PeerRoute,
    domain: u64,
    generation: u64,
    lanes: &mut ComponentSuspensionLanes<C, R, T>,
    worker: &crate::spawn_hosts::SpawnedComponentWorker,
) -> Result<(), WorkerStartError> {
    let endpoint = match worker.endpoint {
        crate::spawn_hosts::WorkerEndpoint::Shared(endpoint) => endpoint,
        crate::spawn_hosts::WorkerEndpoint::Private(_) => {
            return Err(WorkerStartError::InvalidWorker)
        }
    };
    if worker.sched_context == 0 || endpoint != route.endpoint() {
        return Err(WorkerStartError::InvalidWorker);
    }
    let owner = &mut *core::ptr::addr_of_mut!(SHARED_INGRESS);
    if !owner.ready {
        return Err(WorkerStartError::NotReady);
    }
    let installation = owner
        .installations
        .iter_mut()
        .find(|installation| installation.route() == route)
        .ok_or(WorkerStartError::UnknownPeer)?;
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    installation
        .start(
            owner.peers.as_ref().expect("initialized registry"),
            domain,
            generation,
            lanes,
            LaneBinding {
                executor_id: worker.tcb,
                receive_endpoint: endpoint,
                reply_object: worker.reply_cap,
            },
            nt_component_suspension::PeerSpaceBinding {
                executor: worker.tcb,
                cnode: worker.cnode,
                vspace: worker.pml4,
                fault_slot: crate::CT_FAULT,
            },
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            |tcb| {
                let status =
                    crate::spawn_hosts::resume_spawned_component_worker(tcb, worker.sched_context);
                if status == 0 {
                    Ok(())
                } else {
                    Err(status)
                }
            },
        )
        .map_err(WorkerStartError::Start)
}
