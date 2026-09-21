//! Retained physical attribution for hosted-driver shared ingress enrollment.
//!
//! Primary dispatch, arbitrary system-thread entry and dedicated IRQ protocol are distinct
//! sources. This module does not start executors, interpret messages or authorize Replies.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime::{
    self, PhysicalDomain, PhysicalSource, PhysicalSourceKind,
};
use nt_component_suspension::peer_registry::PeerRoute;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnrollmentPhase {
    Entered,
    Published,
    Failed,
    Retired,
}

#[derive(Clone, Copy)]
pub(crate) struct Enrollment {
    pub physical: PhysicalSource,
    pub cnode: u64,
    pub reply: u64,
    pub route: Option<PeerRoute>,
    pub phase: EnrollmentPhase,
    instance: usize,
}

#[derive(Debug)]
pub(crate) enum Error {
    PhysicalOwner,
    AlreadyAttempted,
    Capacity,
    Registration(runtime::Error),
}

static mut ENROLLMENTS: Vec<Enrollment> = Vec::new();

fn physical(instance_index: usize, kind: PhysicalSourceKind) -> Option<(PhysicalSource, u64)> {
    let inst = instance(instance_index)?;
    let domain = instance_domain_identity(inst)?;
    if inst.pml4 == 0 {
        return None;
    }
    let (tcb, cnode) = match kind {
        PhysicalSourceKind::Primary => {
            let thread = unsafe { (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_TABLES)) }
                .as_ref()?
                .get(instance_index)?
                .get(inst.main_thread_id)?;
            if thread.tcb != inst.tcb {
                return None;
            }
            (inst.tcb, inst.cnode)
        }
        PhysicalSourceKind::SystemThread { handle } => {
            let runtimes =
                unsafe { (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_RUNTIMES)).as_ref()? };
            let mut matching = runtimes.iter().filter(|row| {
                row.instance == instance_index && row.domain == domain && row.handle == handle
            });
            let row = matching.next()?;
            if matching.next().is_some() {
                return None;
            }
            let thread = unsafe { (&*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_TABLES)) }
                .as_ref()?
                .get(instance_index)?
                .get(handle)?;
            if thread.tcb != row.tcb || row.pml4 != inst.pml4 {
                return None;
            }
            (row.tcb, row.cnode)
        }
        PhysicalSourceKind::Interrupt(identity) => {
            if identity.domain_id != domain.domain_id.raw()
                || identity.domain_cookie != domain.cookie
                || identity.lane_generation == 0
            {
                return None;
            }
            let mut matching = unsafe { hosted_irq_lanes()? }.iter().filter(|row| {
                row.projection_instance == instance_index
                    && row.domain == domain
                    && row.identity == identity
            });
            let row = matching.next()?;
            if matching.next().is_some() || row.pml4 != inst.pml4 {
                return None;
            }
            (row.tcb, row.cnode)
        }
        // There is no separate ordinal-based dispatch worker owner in the hosted-driver catalog.
        PhysicalSourceKind::DispatchWorker { .. } => return None,
    };
    if tcb == 0 || cnode == 0 || cnode == crate::CAP_INIT_THREAD_CNODE {
        return None;
    }
    Some((
        PhysicalSource {
            domain: PhysicalDomain::Hosted(domain),
            kind,
            pml4: inst.pml4,
            tcb,
        },
        cnode,
    ))
}

/// Observational and allocation-free. Stopped/quarantined owners remain attributable for drain;
/// execution admission is separately controlled by the shared ingress installation lifecycle.
pub(crate) unsafe fn verify(source: PhysicalSource) -> bool {
    let mut matching = (&*core::ptr::addr_of!(ENROLLMENTS))
        .iter()
        .filter(|row| row.physical == source && row.phase != EnrollmentPhase::Retired);
    let Some(row) = matching.next() else {
        return false;
    };
    matching.next().is_none() && physical(row.instance, source.kind) == Some((source, row.cnode))
}

/// Snapshot even a failed enrollment. Its resources must not be deleted/reused until the shared
/// owner proves cancellation and drain; failure is deliberately not a retryable empty slot.
pub(crate) fn enrollment(source: PhysicalSource) -> Option<Enrollment> {
    unsafe {
        (&*core::ptr::addr_of!(ENROLLMENTS))
            .iter()
            .find(|row| row.physical == source)
            .copied()
    }
}

pub(crate) fn route_for(source: PhysicalSource) -> Option<PeerRoute> {
    let row = enrollment(source)?;
    if row.phase != EnrollmentPhase::Published || !unsafe { verify(source) } {
        return None;
    }
    row.route
}

/// A received badge only selects a retained source; exact physical validation still gates use.
pub(crate) fn caller_route(
    instance_index: usize,
    badge: u64,
) -> Option<(PhysicalSource, PeerRoute)> {
    let rows = unsafe { &*core::ptr::addr_of!(ENROLLMENTS) };
    let mut matching = rows.iter().filter(|row| {
        row.instance == instance_index
            && row.phase == EnrollmentPhase::Published
            && matches!(
                row.physical.kind,
                PhysicalSourceKind::Primary | PhysicalSourceKind::SystemThread { .. }
            )
            && row.route.is_some_and(|route| route.badge() == badge)
    });
    let row = matching.next()?;
    if matching.next().is_some() || !unsafe { verify(row.physical) } {
        return None;
    }
    Some((row.physical, row.route?))
}

pub(crate) fn system_thread_route(instance_index: usize, handle: u64) -> Option<PeerRoute> {
    let (source, _) = physical(instance_index, PhysicalSourceKind::SystemThread { handle })?;
    route_for(source)
}

pub(crate) fn thread_enrollment(instance_index: usize, handle: u64) -> Option<Enrollment> {
    let inst = instance(instance_index)?;
    let domain = PhysicalDomain::Hosted(instance_domain_identity(inst)?);
    unsafe {
        (&*core::ptr::addr_of!(ENROLLMENTS))
            .iter()
            .find(|row| {
                row.instance == instance_index
                    && row.physical.kind == PhysicalSourceKind::SystemThread { handle }
                    && row.physical.domain == domain
                    && row.physical.pml4 == inst.pml4
            })
            .copied()
    }
}

pub(super) fn primary_enrollment(instance_index: usize) -> Option<Enrollment> {
    let inst = instance(instance_index)?;
    let domain = PhysicalDomain::Hosted(instance_domain_identity(inst)?);
    unsafe {
        (&*core::ptr::addr_of!(ENROLLMENTS))
            .iter()
            .find(|row| {
                row.instance == instance_index
                    && row.physical.kind == PhysicalSourceKind::Primary
                    && row.physical.domain == domain
                    && row.physical.tcb == inst.tcb
                    && row.physical.pml4 == inst.pml4
            })
            .copied()
    }
}

pub(super) fn primary_route(instance_index: usize) -> Option<PeerRoute> {
    let (source, _) = physical(instance_index, PhysicalSourceKind::Primary)?;
    route_for(source)
}

/// Called only after shared retirement and all physical cleanup ACKs. Keep the source tombstone;
/// only its exhausted physical resource ownership ends, never its globally fresh attribution.
pub(super) unsafe fn finish_physical_retirement(source: PhysicalSource) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(ENROLLMENTS))
        .iter_mut()
        .find(|row| row.physical == source)
    else {
        return false;
    };
    row.phase = EnrollmentPhase::Retired;
    true
}

unsafe fn enroll(
    instance_index: usize,
    kind: PhysicalSourceKind,
    reply: u64,
) -> Result<PeerRoute, Error> {
    let (physical, cnode) = physical(instance_index, kind).ok_or(Error::PhysicalOwner)?;
    if reply == 0 {
        return Err(Error::PhysicalOwner);
    }
    let index = {
        let rows = &mut *core::ptr::addr_of_mut!(ENROLLMENTS);
        if rows.iter().any(|row| {
            row.phase != EnrollmentPhase::Retired
                && (row.physical == physical
                    || row.physical.tcb == physical.tcb
                    || (row.physical.domain == physical.domain
                        && row.physical.kind == physical.kind))
        }) {
            return Err(Error::AlreadyAttempted);
        }
        let _durable = crate::allocator::enter_durable();
        rows.try_reserve(1).map_err(|_| Error::Capacity)?;
        let index = rows.len();
        rows.push(Enrollment {
            physical,
            cnode,
            reply,
            route: None,
            phase: EnrollmentPhase::Entered,
            instance: instance_index,
        });
        index
    };
    // No catalog or enrollment reference crosses capability allocation/publication.
    let result = runtime::register(physical, reply, cnode, verify);
    let retained_route = runtime::retained_route(physical);
    let row = &mut (&mut *core::ptr::addr_of_mut!(ENROLLMENTS))[index];
    match result {
        Ok(route) => {
            row.route = Some(route);
            row.phase = EnrollmentPhase::Published;
            Ok(route)
        }
        Err(error) => {
            row.route = retained_route;
            row.phase = EnrollmentPhase::Failed;
            Err(Error::Registration(error))
        }
    }
}

/// The primary transport and attached main-thread receipt must already be retained, stopped.
pub(crate) unsafe fn enroll_primary(instance_index: usize) -> Result<PeerRoute, Error> {
    let inst = instance(instance_index).ok_or(Error::PhysicalOwner)?;
    enroll(instance_index, PhysicalSourceKind::Primary, inst.reply_cap)
}

/// Retain the attached thread/runtime before this call. `reply` is an owned empty Reply object,
/// not caller authentication. This arbitrary-entry thread has no dispatch-worker ready handshake.
pub(crate) unsafe fn enroll_system_thread(
    instance_index: usize,
    handle: u64,
    reply: u64,
) -> Result<PeerRoute, Error> {
    enroll(
        instance_index,
        PhysicalSourceKind::SystemThread { handle },
        reply,
    )
}

/// Publish the complete stopped lane in the canonical lane store before enrollment. Its dedicated
/// arena/token protocol is not a primary dispatch-worker ready handshake.
pub(crate) unsafe fn enroll_interrupt(
    identity: nt_hosted_runtime::HostedIrqLaneIdentity,
) -> Result<PeerRoute, Error> {
    let (instance_index, reply) = {
        let mut matching = hosted_irq_lanes()
            .ok_or(Error::PhysicalOwner)?
            .iter()
            .filter(|row| row.identity == identity);
        let lane = matching.next().ok_or(Error::PhysicalOwner)?;
        if matching.next().is_some()
            || lane.tcb_resumed
            || lane.state != HostedIrqLaneState::Booting
        {
            return Err(Error::PhysicalOwner);
        }
        (lane.projection_instance, lane.reply_cap)
    };
    enroll(
        instance_index,
        PhysicalSourceKind::Interrupt(identity),
        reply,
    )
}
