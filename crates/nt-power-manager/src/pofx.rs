//! Component activation ownership for registered PoFx devices.
//!
//! This is the policy core. The native boundary authenticates the caller,
//! validates/copies the driver's PO_FX_DEVICE description, retains callback
//! ownership, and delivers condition changes. No driver pointer enters here.

use alloc::vec::Vec;

/// An opaque registration identity. Values are never reused by one manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PofxHandle(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PofxError {
    InvalidRegistration,
    AlreadyRegistered,
    UnknownHandle,
    WrongOwner,
    InvalidComponent,
    AlreadyStarted,
    UnbalancedIdle,
    ReferenceOverflow,
    CallbacksPending,
    UnknownCallback,
    InsufficientResources,
}

/// A callback obligation produced by a count edge. The native boundary must
/// deliver it before claiming the condition change completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentEvent {
    None,
    BecameActive,
    BecameIdle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentSnapshot {
    pub references: u32,
    /// Logical active condition. Native integration still owes any callback
    /// announced by a `ComponentEvent` before hardware access is guaranteed.
    pub active: bool,
}

struct Registration {
    handle: PofxHandle,
    owner: u64,
    pdo: u64,
    started: bool,
    components: Vec<ComponentSnapshot>,
    callbacks: Vec<u64>,
}

/// One authority for PoFx registration identities and activation counts.
#[derive(Default)]
pub struct PofxManager {
    registrations: Vec<Registration>,
    next_handle: u64,
    next_callback: u64,
}

impl PofxManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        owner: u64,
        pdo: u64,
        component_count: u32,
    ) -> Result<PofxHandle, PofxError> {
        if owner == 0 || pdo == 0 || component_count == 0 {
            return Err(PofxError::InvalidRegistration);
        }
        if self.registrations.iter().any(|registration| registration.pdo == pdo) {
            return Err(PofxError::AlreadyRegistered);
        }
        let next = self
            .next_handle
            .checked_add(1)
            .ok_or(PofxError::InsufficientResources)?;
        let mut components = Vec::new();
        components
            .try_reserve_exact(component_count as usize)
            .map_err(|_| PofxError::InsufficientResources)?;
        components.resize(
            component_count as usize,
            ComponentSnapshot {
                references: 0,
                active: true,
            },
        );
        self.registrations
            .try_reserve(1)
            .map_err(|_| PofxError::InsufficientResources)?;
        let handle = PofxHandle(next);
        self.registrations.push(Registration {
            handle,
            owner,
            pdo,
            started: false,
            components,
            callbacks: Vec::new(),
        });
        self.next_handle = next;
        Ok(handle)
    }

    fn registration(&self, owner: u64, handle: PofxHandle) -> Result<&Registration, PofxError> {
        let registration = self
            .registrations
            .iter()
            .find(|registration| registration.handle == handle)
            .ok_or(PofxError::UnknownHandle)?;
        if registration.owner != owner {
            return Err(PofxError::WrongOwner);
        }
        Ok(registration)
    }

    fn registration_mut(
        &mut self,
        owner: u64,
        handle: PofxHandle,
    ) -> Result<&mut Registration, PofxError> {
        let registration = self
            .registrations
            .iter_mut()
            .find(|registration| registration.handle == handle)
            .ok_or(PofxError::UnknownHandle)?;
        if registration.owner != owner {
            return Err(PofxError::WrongOwner);
        }
        Ok(registration)
    }

    /// Begin runtime management. Unreferenced components become idle; the
    /// returned indexes each require the registered idle-condition callback.
    pub fn start(&mut self, owner: u64, handle: PofxHandle) -> Result<Vec<u32>, PofxError> {
        let registration = self.registration_mut(owner, handle)?;
        if registration.started {
            return Err(PofxError::AlreadyStarted);
        }
        let mut became_idle = Vec::new();
        became_idle
            .try_reserve_exact(registration.components.len())
            .map_err(|_| PofxError::InsufficientResources)?;
        for (index, component) in registration.components.iter_mut().enumerate() {
            if component.references == 0 {
                component.active = false;
                became_idle.push(index as u32);
            }
        }
        registration.started = true;
        Ok(became_idle)
    }

    pub fn activate(
        &mut self,
        owner: u64,
        handle: PofxHandle,
        component: u32,
    ) -> Result<ComponentEvent, PofxError> {
        let registration = self.registration_mut(owner, handle)?;
        let component = registration
            .components
            .get_mut(component as usize)
            .ok_or(PofxError::InvalidComponent)?;
        let next = component
            .references
            .checked_add(1)
            .ok_or(PofxError::ReferenceOverflow)?;
        let event = if registration.started && component.references == 0 {
            component.active = true;
            ComponentEvent::BecameActive
        } else {
            ComponentEvent::None
        };
        component.references = next;
        Ok(event)
    }

    pub fn idle(
        &mut self,
        owner: u64,
        handle: PofxHandle,
        component: u32,
    ) -> Result<ComponentEvent, PofxError> {
        let registration = self.registration_mut(owner, handle)?;
        let component = registration
            .components
            .get_mut(component as usize)
            .ok_or(PofxError::InvalidComponent)?;
        if component.references == 0 {
            return Err(PofxError::UnbalancedIdle);
        }
        component.references -= 1;
        if registration.started && component.references == 0 {
            component.active = false;
            Ok(ComponentEvent::BecameIdle)
        } else {
            Ok(ComponentEvent::None)
        }
    }

    pub fn component(
        &self,
        owner: u64,
        handle: PofxHandle,
        component: u32,
    ) -> Result<ComponentSnapshot, PofxError> {
        self.registration(owner, handle)?
            .components
            .get(component as usize)
            .copied()
            .ok_or(PofxError::InvalidComponent)
    }

    pub fn started(&self, owner: u64, handle: PofxHandle) -> Result<bool, PofxError> {
        Ok(self.registration(owner, handle)?.started)
    }

    /// A retained ticket precedes every native callback invocation. If its
    /// result is uncertain, the ticket stays outstanding and blocks rundown.
    pub fn begin_callback(&mut self, owner: u64, handle: PofxHandle) -> Result<u64, PofxError> {
        let next = self.next_callback.checked_add(1)
            .ok_or(PofxError::InsufficientResources)?;
        self.registration_mut(owner, handle)?.callbacks.try_reserve(1)
            .map_err(|_| PofxError::InsufficientResources)?;
        self.registration_mut(owner, handle)?.callbacks.push(next);
        self.next_callback = next;
        Ok(next)
    }

    pub fn complete_callback(
        &mut self,
        owner: u64,
        handle: PofxHandle,
        ticket: u64,
    ) -> Result<(), PofxError> {
        let registration = self.registration_mut(owner, handle)?;
        let position = registration.callbacks.iter().position(|&value| value == ticket)
            .ok_or(PofxError::UnknownCallback)?;
        registration.callbacks.remove(position);
        Ok(())
    }

    pub fn callback_quiesced(
        &self,
        owner: u64,
        handle: PofxHandle,
    ) -> Result<bool, PofxError> {
        Ok(self.registration(owner, handle)?.callbacks.is_empty())
    }

    pub fn callbacks_quiesced(&self, owner: u64) -> bool {
        self.registrations.iter().filter(|registration| registration.owner == owner)
            .all(|registration| registration.callbacks.is_empty())
    }

    /// Native integration must first quiesce every callback and prevent new
    /// calls from entering this record. Removal then revokes the handle.
    pub fn unregister(&mut self, owner: u64, handle: PofxHandle) -> Result<(), PofxError> {
        let position = self
            .registrations
            .iter()
            .position(|registration| registration.handle == handle)
            .ok_or(PofxError::UnknownHandle)?;
        if self.registrations[position].owner != owner {
            return Err(PofxError::WrongOwner);
        }
        if !self.registrations[position].callbacks.is_empty() {
            return Err(PofxError::CallbacksPending);
        }
        self.registrations.remove(position);
        Ok(())
    }
}
