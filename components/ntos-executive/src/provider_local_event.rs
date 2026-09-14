//! Borrowed canonical provider-local Event operations shared by bootstrap and runtime.

use super::*;
use nt_kernel_exec::{EventObjectId, EventObjectOwner, EventObjectRegistry, EventStore};
use nt_provider_wait::ProviderDomainIdentity;

const INVALID_PARAMETER: u32 = 0xC000_000D;
const INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

pub(crate) struct LocalEventState<'a> {
    obj_ns: &'a mut Vec<ObjEntry>,
    anon_event_seq: &'a mut u32,
    events: &'a mut EventStore,
    event_objects: &'a mut EventObjectRegistry,
}

impl<'a> LocalEventState<'a> {
    pub(crate) fn new(
        obj_ns: &'a mut Vec<ObjEntry>,
        anon_event_seq: &'a mut u32,
        events: &'a mut EventStore,
        event_objects: &'a mut EventObjectRegistry,
    ) -> Self {
        Self {
            obj_ns,
            anon_event_seq,
            events,
            event_objects,
        }
    }

    // Provider identity is metadata supplied by a separately authenticated execution adapter.
    fn owner(provider: ProviderDomainIdentity, local: u64) -> Result<EventObjectOwner, u32> {
        if provider.domain == 0 || provider.generation == 0 || local == 0 {
            return Err(INVALID_PARAMETER);
        }
        Ok(EventObjectOwner::provider(
            provider.domain,
            provider.generation,
        ))
    }

    pub(crate) fn publish(
        &mut self,
        provider: ProviderDomainIdentity,
        local: u64,
        event_type: u32,
        initial_state: bool,
    ) -> Result<(EventObjectId, u64), u32> {
        let owner = Self::owner(provider, local)?;
        if event_type > 1 {
            return Err(INVALID_PARAMETER);
        }
        let _durable = allocator::enter_durable();
        let index = create_anonymous_event(
            self.obj_ns,
            self.anon_event_seq,
            self.events,
            event_type == 1,
            initial_state,
        )
        .ok_or(INSUFFICIENT_RESOURCES)?;
        let id = match self
            .event_objects
            .create_provider_local(owner, local, index as u64)
        {
            Ok(id) => id,
            Err(_) => {
                // Publication has not escaped; only this newly appended namespace entry exists.
                assert_eq!(index + 1, self.obj_ns.len());
                assert!(self.events.remove_existing(index as u64));
                self.obj_ns.pop();
                return Err(INSUFFICIENT_RESOURCES);
            }
        };
        trace(b"publish", provider, local, Some(id), index as u64);
        Ok((
            id,
            u64::from(event_type == 1) | (u64::from(initial_state) << 1),
        ))
    }

    pub(crate) fn identity(
        &self,
        provider: ProviderDomainIdentity,
        local: u64,
    ) -> Result<(EventObjectId, usize, EventKind, bool), u32> {
        let owner = Self::owner(provider, local)?;
        let id = self
            .event_objects
            .id_for_provider_local(owner, local)
            .ok_or(INVALID_PARAMETER)?;
        let snapshot = self
            .event_objects
            .snapshot(id)
            .map_err(|_| INVALID_PARAMETER)?;
        let index = usize::try_from(snapshot.native_identity).map_err(|_| INVALID_PARAMETER)?;
        let entry = self.obj_ns.get(index).ok_or(INVALID_PARAMETER)?;
        if !entry.is_live() || entry.kind != OBJ_KIND_EVENT {
            return Err(INVALID_PARAMETER);
        }
        let (kind, signaled) = self
            .events
            .query_existing(index as u64)
            .ok_or(INVALID_PARAMETER)?;
        Ok((id, index, kind, signaled))
    }

    pub(crate) fn reset(
        &mut self,
        provider: ProviderDomainIdentity,
        local: u64,
    ) -> Result<bool, u32> {
        let (_, index, _, _) = self.identity(provider, local)?;
        self.events
            .reset_existing(index as u64)
            .ok_or(INVALID_PARAMETER)
    }

    /// Bootstrap owns this borrow exclusively; no callout may admit observers before mutation.
    pub(crate) fn signal_unobserved(
        &mut self,
        provider: ProviderDomainIdentity,
        local: u64,
        mode: nt_kernel_exec::EventSignalMode,
    ) -> Result<(bool, bool), u32> {
        let owner = Self::owner(provider, local)?;
        let (id, index, _, _) = self.identity(provider, local)?;
        let result = nt_kernel_exec::signal_unobserved_provider_event(
            self.event_objects,
            self.events,
            id,
            owner,
            local,
            self.obj_ns[index].wait_references,
            mode,
        )
        .map_err(|error| match error {
            nt_kernel_exec::UnobservedEventSignalError::Observed => 0xC000_00BB,
            nt_kernel_exec::UnobservedEventSignalError::InvalidIdentity
            | nt_kernel_exec::UnobservedEventSignalError::InvalidBacking => INVALID_PARAMETER,
        })?;
        trace(
            match mode {
                nt_kernel_exec::EventSignalMode::Set => b"set-unobserved",
                nt_kernel_exec::EventSignalMode::Pulse => b"pulse-unobserved",
            },
            provider,
            local,
            Some(id),
            index as u64,
        );
        Ok(result)
    }

    pub(crate) fn clear(
        &mut self,
        provider: ProviderDomainIdentity,
        local: u64,
    ) -> Result<(), u32> {
        let (_, index, _, _) = self.identity(provider, local)?;
        self.events
            .clear_existing(index as u64)
            .then_some(())
            .ok_or(INVALID_PARAMETER)
    }

    pub(crate) fn read(&self, provider: ProviderDomainIdentity, local: u64) -> Result<bool, u32> {
        self.identity(provider, local)
            .map(|(_, _, _, signaled)| signaled)
    }

    pub(crate) fn retire(
        &mut self,
        provider: ProviderDomainIdentity,
        local: u64,
    ) -> Result<Option<EventObjectId>, u32> {
        let owner = Self::owner(provider, local)?;
        if let Some(id) = self
            .event_objects
            .pending_provider_local_reclaim(owner, local)
        {
            trace(b"retire-pending", provider, local, Some(id), 0);
            return Ok(Some(id));
        }
        let (id, index, _, _) = self.identity(provider, local)?;
        let snapshot = self
            .event_objects
            .snapshot(id)
            .map_err(|_| INVALID_PARAMETER)?;
        if snapshot.provider_body.is_some() || self.obj_ns[index].wait_references != 0 {
            return Err(INVALID_PARAMETER);
        }
        trace(b"retire", provider, local, Some(id), index as u64);
        match self
            .event_objects
            .request_delete(id)
            .map_err(|_| INVALID_PARAMETER)?
        {
            Some(retired) => {
                // All backing checks precede canonical retirement; this borrow prevents reuse.
                assert_eq!(retired.id, id);
                assert_eq!(retired.native_identity, index as u64);
                finalize_local_backing(self.obj_ns, self.events, retired);
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn ack(
        &mut self,
        provider: ProviderDomainIdentity,
        local: u64,
        id: EventObjectId,
    ) -> Result<(), u32> {
        let owner = Self::owner(provider, local)?;
        self.event_objects
            .complete_provider_local_reclaim(id, owner, local)
            .map_err(|_| INVALID_PARAMETER)?;
        trace(b"ack", provider, local, Some(id), 0);
        Ok(())
    }
}

/// A canonical retirement cannot be rolled back or reported complete without removing backing.
/// This is also used when the final retained wait lease drains after a local retirement request.
pub(crate) fn finalize_local_backing(
    obj_ns: &mut [ObjEntry],
    events: &mut EventStore,
    retired: nt_kernel_exec::RetiredEventObject,
) {
    assert!(matches!(retired.owner, EventObjectOwner::Provider { .. }));
    assert!(retired.provider_local_identity.is_some());
    assert!(retired.provider_body.is_none());
    let index = usize::try_from(retired.native_identity)
        .expect("retired provider-local Event native identity");
    let entry = obj_ns
        .get_mut(index)
        .expect("retired provider-local Event namespace backing");
    assert!(entry.is_live() && entry.kind == OBJ_KIND_EVENT);
    assert_eq!(entry.wait_references, 0);
    assert!(events.remove_existing(retired.native_identity));
    entry.unlink();
}

/// Anonymous namespace entries are append-only; their index is the native dispatcher identity.
pub(crate) fn create_anonymous_event(
    obj_ns: &mut Vec<ObjEntry>,
    anon_event_seq: &mut u32,
    events: &mut EventStore,
    auto_reset: bool,
    initial_state: bool,
) -> Option<usize> {
    let _durable = allocator::enter_durable();
    let n = *anon_event_seq;
    *anon_event_seq = anon_event_seq.wrapping_add(1);
    let name = [
        b'a',
        (n & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
    ];
    let index = ObjEntry::push_kind(
        obj_ns,
        &name,
        OBJ_PARENT_ANONYMOUS,
        OBJ_KIND_EVENT,
        &[],
        false,
    )?;
    if !events.try_initialize(
        index as u64,
        if auto_reset {
            EventKind::Synchronization
        } else {
            EventKind::Notification
        },
        initial_state,
    ) {
        obj_ns.pop();
        return None;
    }
    Some(index)
}

static TRACE_N: AtomicU64 = AtomicU64::new(0);

/// Both entry adapters authenticate the provider before calling this live-dispatcher operation.
/// The operation lease spans selection, any reply-cleanup reentry, and the final state readback.
pub(crate) unsafe fn signal(
    handler: &mut ExecNtHandler,
    provider: ProviderDomainIdentity,
    local: u64,
    mode: nt_kernel_exec::EventSignalMode,
) -> Result<(i32, u64, u64, u64), u32> {
    let _durable = allocator::enter_durable();
    let (id, index, _, _) = LocalEventState::new(
        &mut handler.obj_ns,
        &mut handler.anon_event_seq,
        &mut handler.events,
        &mut handler.event_objects,
    )
    .identity(provider, local)?;
    let lease = handler
        .event_objects
        .acquire_wait(id, nt_kernel_exec::EventLeaseKind::Operation)
        .map_err(|_| INSUFFICIENT_RESOURCES)?;
    let result = (|| {
        let previous = handler
            .events
            .set_existing(index as u64)
            .ok_or(INVALID_PARAMETER)?;
        if !previous {
            match mode {
                nt_kernel_exec::EventSignalMode::Set => {
                    crate::wait_wake_event_set(index, handler);
                }
                nt_kernel_exec::EventSignalMode::Pulse => {
                    crate::wait_wake_event_pulse(index, handler);
                }
            }
        } else if mode == nt_kernel_exec::EventSignalMode::Pulse {
            assert!(handler.events.clear_existing(index as u64));
        }
        let (_, current) = handler
            .events
            .query_existing(index as u64)
            .expect("pinned local Event lost its dispatcher backing");
        let current = if mode == nt_kernel_exec::EventSignalMode::Set {
            current
        } else {
            false
        };
        Ok((0, u64::from(previous), u64::from(current), 0))
    })();
    if let Some(retired) = handler
        .event_objects
        .release_wait(lease, nt_kernel_exec::EventLeaseKind::Operation)
        .expect("local Event operation lost its exact lease")
    {
        handler.finalize_retired_event_object(retired);
    }
    result
}

pub(crate) fn trace(
    op: &[u8],
    provider: ProviderDomainIdentity,
    local: u64,
    id: Option<EventObjectId>,
    native_identity: u64,
) {
    let n = TRACE_N.fetch_add(1, Ordering::Relaxed);
    if n >= 64 {
        return;
    }
    print_str(b"[provider-local-event] #");
    print_u64(n + 1);
    print_str(b" op=");
    print_str(op);
    print_str(b" provider=");
    print_u64(provider.domain);
    print_str(b"/");
    print_u64(provider.generation);
    print_str(b" local=0x");
    print_hex_u64(local);
    if let Some(id) = id {
        print_str(b" canonical=");
        print_u64(id.0.slot().saturating_add(1));
        print_str(b"/");
        print_u64(u64::from(id.0.generation().0));
    }
    if native_identity != 0 {
        print_str(b" native=");
        print_u64(native_identity);
    }
    print_str(b"\n");
}
