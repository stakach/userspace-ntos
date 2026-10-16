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
}

/// One authority for PoFx registration identities and activation counts.
#[derive(Default)]
pub struct PofxManager {
    registrations: Vec<Registration>,
    next_handle: u64,
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
        self.registrations.remove(position);
        Ok(())
    }
}
