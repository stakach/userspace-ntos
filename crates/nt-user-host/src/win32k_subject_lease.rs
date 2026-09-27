//! Retained native caller subjects for exact win32k provider jobs.

use alloc::vec::Vec;
use nt_process::{
    native_handle::NativeHandleCaller, ProcessManager, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_HANDLE,
};
use nt_security::{CapturedSubjectTokens, TokenStore};

use crate::native_caller_subject::NativeCallerSubject;

/// Authenticated provider-job identity supplied by the native dispatch owner, not by win32k.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Win32kSubjectOwner<Route, Dispatch> {
    pub route: Route,
    pub dispatch: Dispatch,
    pub caller: NativeHandleCaller,
}

/// Expected provider-local addresses. Equality checks bind a request to a job, but these
/// addresses are never used as token authority; only the retained subject is authoritative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Win32kSubjectProjection {
    pub access_state: u64,
    pub primary_token: u64,
    pub client_token: u64,
}

struct SubjectLease<Route, Dispatch> {
    id: u64,
    owner: Win32kSubjectOwner<Route, Dispatch>,
    projection: Option<Win32kSubjectProjection>,
    subject: NativeCallerSubject,
}

/// Retains canonical token references while a win32k parse job calls back into the executive.
/// Lease IDs are never reused, including after release or dispatch retirement.
pub struct Win32kSubjectLeases<Route, Dispatch> {
    next_id: Option<u64>,
    leases: Vec<SubjectLease<Route, Dispatch>>,
}

impl<Route: Copy + Eq, Dispatch: Copy + Eq> Win32kSubjectLeases<Route, Dispatch> {
    pub const fn new() -> Self {
        Self {
            next_id: Some(1),
            leases: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    pub fn admit(
        &mut self,
        pm: &ProcessManager,
        tokens: &mut TokenStore,
        owner: Win32kSubjectOwner<Route, Dispatch>,
        projection: Option<Win32kSubjectProjection>,
    ) -> Result<u64, u32> {
        let id = self.next_id.ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        self.leases
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let subject = NativeCallerSubject::capture(pm, tokens, owner.caller)?;
        self.leases.push(SubjectLease {
            id,
            owner,
            projection,
            subject,
        });
        self.next_id = id.checked_add(1);
        Ok(id)
    }

    pub fn resolve<'a>(
        &'a self,
        tokens: &'a TokenStore,
        id: u64,
        owner: Win32kSubjectOwner<Route, Dispatch>,
        projection: Option<Win32kSubjectProjection>,
    ) -> Result<CapturedSubjectTokens<'a>, u32> {
        self.matching(id, owner, projection)?
            .subject
            .resolve(tokens)
    }

    pub fn release(
        &mut self,
        tokens: &mut TokenStore,
        id: u64,
        owner: Win32kSubjectOwner<Route, Dispatch>,
        projection: Option<Win32kSubjectProjection>,
    ) -> Result<(), u32> {
        let index = self.matching_index(id, owner, projection)?;
        self.leases[index].subject.release(tokens)?;
        self.leases.remove(index);
        Ok(())
    }

    /// The authenticated dispatch-retirement hook releases every lease for that exact route and
    /// dispatch. A failed release remains in the table so canonical-store cleanup can be retried.
    pub fn drain_dispatch(
        &mut self,
        tokens: &mut TokenStore,
        route: Route,
        dispatch: Dispatch,
    ) -> Result<usize, u32> {
        let mut released = 0;
        let mut index = 0;
        while index < self.leases.len() {
            if self.leases[index].owner.route == route
                && self.leases[index].owner.dispatch == dispatch
            {
                self.leases[index].subject.release(tokens)?;
                self.leases.remove(index);
                released += 1;
            } else {
                index += 1;
            }
        }
        Ok(released)
    }

    fn matching(
        &self,
        id: u64,
        owner: Win32kSubjectOwner<Route, Dispatch>,
        projection: Option<Win32kSubjectProjection>,
    ) -> Result<&SubjectLease<Route, Dispatch>, u32> {
        let index = self.matching_index(id, owner, projection)?;
        Ok(&self.leases[index])
    }

    fn matching_index(
        &self,
        id: u64,
        owner: Win32kSubjectOwner<Route, Dispatch>,
        projection: Option<Win32kSubjectProjection>,
    ) -> Result<usize, u32> {
        self.leases
            .iter()
            .position(|lease| {
                lease.id == id && lease.owner == owner && lease.projection == projection
            })
            .ok_or(STATUS_INVALID_HANDLE)
    }
}

impl<Route: Copy + Eq, Dispatch: Copy + Eq> Default for Win32kSubjectLeases<Route, Dispatch> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "win32k_subject_lease_tests.rs"]
mod tests;
