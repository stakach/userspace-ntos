//! Native x64 handle scope and counted Ps references over the existing process tables.
//!
//! The caller is structural authority, not an IPC credential or an access-check result. Native
//! adapters must authenticate their execution lane before capturing it. Attachment is deliberately
//! not exposed: the effective process is currently the exact thread's owning process.

use crate::{
    Handle, HandleFlags, HandleObject, InitialSystemIdentity, ProcessId, ProcessManager,
    ProcessState, ThreadLifetime, ThreadState, STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
};
use nt_types::AccessMode;

pub const KERNEL_HANDLE_TAG: u64 = 0xffff_ffff_8000_0000;
pub const OBJ_KERNEL_HANDLE: u32 = 0x200;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xc000_0024;
pub const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const OBJ_INHERIT: u32 = 2;
const OBJ_PROTECT_CLOSE: u32 = 1;
const MAX_RAW_HANDLE: u64 = 0x7fff_fffc;

/// Exact original thread plus a separately represented effective process. Neither is supplied
/// by an untrusted request; only ProcessManager can create this context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeHandleCaller {
    system: InitialSystemIdentity,
    original_thread: ThreadLifetime,
    effective_process: ProcessId,
    mode: AccessMode,
}

impl NativeHandleCaller {
    pub const fn original_thread(self) -> ThreadLifetime {
        self.original_thread
    }
    pub const fn effective_process(self) -> ProcessId {
        self.effective_process
    }
    pub const fn mode(self) -> AccessMode {
        self.mode
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeHandleScope {
    CurrentProcess,
    CurrentThread,
    Table {
        owner: ProcessId,
        handle: Handle,
        kernel: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PsHandleType {
    Process,
    Thread,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeHandleInformation {
    pub attributes: u32,
    /// None only for pseudo handles: canonical creation-time self grants are not yet stored.
    /// A native adapter requesting full OBJECT_HANDLE_INFORMATION must not substitute a mask.
    pub granted_access: Option<u32>,
}

/// One acquired pointer reference, independent of the source handle and caller lifetime.
/// There is intentionally no Clone or implicit Drop: rollback needs the canonical manager, and
/// a failed rollback must leave this owner available for retry. Do not discard an unpublished
/// reference. After successful output publication, `into_body` transfers it to the Ob caller.
#[must_use = "release on failed publication, or transfer the reference to the Ob caller"]
#[derive(Debug)]
pub struct NativeObjectReference {
    system: InitialSystemIdentity,
    object: HandleObject,
    thread: Option<ThreadLifetime>,
    body: u64,
    information: NativeHandleInformation,
    held: bool,
}

impl NativeObjectReference {
    pub const fn body(&self) -> u64 {
        self.body
    }
    pub const fn object(&self) -> HandleObject {
        self.object
    }
    pub const fn information(&self) -> NativeHandleInformation {
        self.information
    }
    pub const fn is_held(&self) -> bool {
        self.held
    }

    /// Consume the owner only after its body has been delivered successfully. The receiver must
    /// eventually invoke the existing counted Ob/Ps dereference path exactly once.
    pub fn into_body(self) -> Result<u64, u32> {
        if self.held {
            Ok(self.body)
        } else {
            Err(STATUS_INVALID_HANDLE)
        }
    }

    /// Validate exact manager and target before changing a count. Caller exit or handle close
    /// does not invalidate a reference already acquired for publication.
    pub fn release(&mut self, pm: &mut ProcessManager) -> Result<(), u32> {
        self.validate(pm)?;
        pm.release_kernel_object_pointer(self.body)?;
        self.held = false;
        Ok(())
    }

    fn validate(&self, pm: &ProcessManager) -> Result<(), u32> {
        if !self.held || !pm.has_initial_system_designation(self.system) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let exact = match self.object {
            HandleObject::Process(pid) => pm.process_kernel_object(pid) == Some(self.body),
            HandleObject::Thread(tid) => {
                pm.thread_kernel_object(tid) == Some(self.body)
                    && self
                        .thread
                        .is_some_and(|thread| pm.validate_thread_lifetime(thread))
            }
            _ => false,
        };
        if exact {
            Ok(())
        } else {
            Err(STATUS_INVALID_HANDLE)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePsHandlePublicationPhase {
    Bound,
    Published,
    Aborted,
}

/// Owns one exact, invisible handle-table reference until output publication or rollback.
/// This does not own the pointer reference used to prepare it. Dropping that pointer reference,
/// closing unrelated handles, or terminating the target cannot remove this bound table entry.
/// No implicit Drop can contact the manager; retain a failed transaction for explicit retry.
#[must_use = "publish or abort the exact bound handle reservation"]
#[derive(Debug)]
pub struct NativePsHandlePublication {
    system: InitialSystemIdentity,
    reservation: crate::HandleReservation,
    object: HandleObject,
    body: u64,
    thread: Option<ThreadLifetime>,
    granted_access: u32,
    flags: HandleFlags,
    value: u64,
    phase: NativePsHandlePublicationPhase,
}

impl NativePsHandlePublication {
    /// Value to write into the caller's output before acknowledging publication. Lookup still
    /// rejects this value while the transaction is Bound.
    pub const fn value(&self) -> u64 {
        self.value
    }

    pub const fn phase(&self) -> NativePsHandlePublicationPhase {
        self.phase
    }

    fn validate(&self, pm: &ProcessManager) -> Result<(), u32> {
        if self.phase != NativePsHandlePublicationPhase::Bound
            || !pm.has_initial_system_designation(self.system)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let table = &pm
            .process(self.reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?
            .handles;
        let slot = crate::handle_to_slot(self.reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        let exact = matches!(table.get(slot), Some(crate::HandleSlot::Bound { generation, entry })
            if *generation == self.reservation.generation
                && entry.object == self.object
                && entry.granted_access == self.granted_access
                && entry.flags == self.flags);
        let target = match self.object {
            HandleObject::Process(pid) => pm.process_kernel_object(pid) == Some(self.body),
            HandleObject::Thread(tid) => {
                pm.thread_kernel_object(tid) == Some(self.body)
                    && self
                        .thread
                        .is_some_and(|thread| pm.validate_thread_lifetime(thread))
            }
            _ => false,
        };
        if exact && target {
            Ok(())
        } else {
            Err(STATUS_INVALID_HANDLE)
        }
    }

    /// Acknowledges successful output delivery. Native adapters must authenticate the request
    /// before calling this method; it does not reconstruct a caller or validate an IPC channel.
    /// A terminated target remains referenceable, but a terminated table owner must be rolled
    /// back instead of receiving a new visible handle after its close-all pass.
    pub fn publish(&mut self, pm: &mut ProcessManager) -> Result<u64, u32> {
        self.validate(pm)?;
        let owner = pm
            .process(self.reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if owner.state != ProcessState::Running || owner.exit_status.is_some() {
            return Err(crate::STATUS_PROCESS_IS_TERMINATING);
        }
        pm.publish_reserved_handle(self.reservation)?;
        self.phase = NativePsHandlePublicationPhase::Published;
        Ok(self.value)
    }

    /// Roll back only the owned bound generation. Even an externally cancelled/reused slot is
    /// not an excuse to close another handle; failure leaves this transaction intact.
    pub fn abort(&mut self, pm: &mut ProcessManager) -> Result<(), u32> {
        self.validate(pm)?;
        let object = pm.cancel_bound_handle(self.reservation)?;
        debug_assert_eq!(object, self.object);
        self.phase = NativePsHandlePublicationPhase::Aborted;
        Ok(())
    }
}

impl ProcessManager {
    /// Capture an unattached caller after the native adapter has authenticated its live runtime.
    /// A caller from the initial System thread additionally requires its retained bootstrap root.
    pub fn capture_native_handle_caller(
        &self,
        thread: ThreadLifetime,
        mode: AccessMode,
    ) -> Result<NativeHandleCaller, u32> {
        let system = self
            .initial_system_identity()
            .ok_or(STATUS_INVALID_HANDLE)?;
        let caller = NativeHandleCaller {
            system,
            original_thread: thread,
            effective_process: thread.process_id(),
            mode,
        };
        self.validate_native_handle_caller(caller)?;
        Ok(caller)
    }

    pub fn validate_native_handle_caller(&self, caller: NativeHandleCaller) -> Result<(), u32> {
        if self.initial_system_identity() != Some(caller.system)
            || !self.initial_system_references_held()
            || !self.validate_thread_lifetime(caller.original_thread)
            || caller.effective_process != caller.original_thread.process_id()
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let process = self
            .process(caller.effective_process)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self
            .thread(caller.original_thread.thread_id())
            .ok_or(STATUS_INVALID_HANDLE)?;
        if process.state != ProcessState::Running
            || process.exit_status.is_some()
            || thread.exit_status.is_some()
            || matches!(
                thread.state,
                ThreadState::Initialized | ThreadState::Terminated
            )
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    /// Resolve scope without truncating native values. -1/-2 are pseudo handles, never entries
    /// in System's table. Untagged handles use the current effective process even in KernelMode.
    pub fn decode_native_handle(
        &self,
        caller: NativeHandleCaller,
        value: u64,
    ) -> Result<NativeHandleScope, u32> {
        self.validate_native_handle_caller(caller)?;
        match value {
            u64::MAX => return Ok(NativeHandleScope::CurrentProcess),
            value if value == u64::MAX - 1 => return Ok(NativeHandleScope::CurrentThread),
            _ => {}
        }
        let kernel = value & KERNEL_HANDLE_TAG == KERNEL_HANDLE_TAG;
        let raw_with_tags = if kernel {
            if caller.mode != AccessMode::KernelMode {
                return Err(STATUS_INVALID_HANDLE);
            }
            value & !KERNEL_HANDLE_TAG
        } else {
            value
        };
        if raw_with_tags > (MAX_RAW_HANDLE | 3) {
            return Err(STATUS_INVALID_HANDLE);
        }
        // EXHANDLE reserves its low two bits for application tags. Validate the full native
        // width before clearing them, so unrelated high bits never alias a valid table entry.
        let raw = raw_with_tags & !3;
        if raw == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(NativeHandleScope::Table {
            owner: if kernel {
                caller.system.process_id()
            } else {
                caller.effective_process
            },
            handle: raw as Handle,
            kernel,
        })
    }

    /// Reference a Process/Thread handle, including native pseudo handles. All fallible admission,
    /// type, grant and projection checks precede the single counted reference acquisition.
    pub fn reference_native_ps_handle(
        &mut self,
        caller: NativeHandleCaller,
        value: u64,
        expected: Option<PsHandleType>,
        desired_access: u32,
    ) -> Result<NativeObjectReference, u32> {
        let (object, information) = match self.decode_native_handle(caller, value)? {
            NativeHandleScope::CurrentProcess => (
                HandleObject::Process(caller.effective_process),
                NativeHandleInformation {
                    attributes: 0,
                    granted_access: None,
                },
            ),
            NativeHandleScope::CurrentThread => (
                HandleObject::Thread(caller.original_thread.thread_id()),
                NativeHandleInformation {
                    attributes: 0,
                    granted_access: None,
                },
            ),
            NativeHandleScope::Table { owner, handle, .. } => {
                let object = self
                    .lookup_handle(owner, handle)
                    .ok_or(STATUS_INVALID_HANDLE)?;
                let flags = self
                    .handle_flags(owner, handle)
                    .ok_or(STATUS_INVALID_HANDLE)?;
                (
                    object,
                    NativeHandleInformation {
                        attributes: u32::from(flags.inherit) * OBJ_INHERIT
                            | u32::from(flags.protect_from_close) * OBJ_PROTECT_CLOSE,
                        granted_access: Some(
                            self.handle_access(owner, handle)
                                .ok_or(STATUS_INVALID_HANDLE)?,
                        ),
                    },
                )
            }
        };
        let (kind, body, thread) = match object {
            HandleObject::Process(pid) => (
                PsHandleType::Process,
                self.process_kernel_object(pid)
                    .ok_or(STATUS_INVALID_HANDLE)?,
                None,
            ),
            HandleObject::Thread(tid) => (
                PsHandleType::Thread,
                self.thread_kernel_object(tid)
                    .ok_or(STATUS_INVALID_HANDLE)?,
                Some(self.thread_lifetime(tid).ok_or(STATUS_INVALID_HANDLE)?),
            ),
            _ => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        };
        if expected.is_some_and(|expected| expected != kind) {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if caller.mode == AccessMode::UserMode && desired_access != 0 {
            // NT computes pseudo-handle self grants at object creation. Until that state is
            // published canonically, do not promote the legacy maximum-access assumption.
            let granted = information.granted_access.ok_or(STATUS_NOT_SUPPORTED)?;
            if desired_access & !granted != 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
        }
        self.retain_kernel_object_pointer(body)?;
        Ok(NativeObjectReference {
            system: caller.system,
            object,
            thread,
            body,
            information,
            held: true,
        })
    }

    /// Low-level publication of an ALREADY AUTHORIZED grant; this is not ObOpenObjectByPointer's
    /// security policy. A retained target supplies stable identity, and its pointer reference is
    /// independent of the new handle's table-owned reference. Only KernelMode can select System's
    /// table. The original reference remains owned by the caller on every outcome.
    pub fn prepare_authorized_native_ps_handle(
        &mut self,
        caller: NativeHandleCaller,
        reference: &NativeObjectReference,
        granted_access: u32,
        attributes: u32,
    ) -> Result<NativePsHandlePublication, u32> {
        self.validate_native_handle_caller(caller)?;
        reference.validate(self)?;
        if attributes & !(OBJ_KERNEL_HANDLE | OBJ_INHERIT) != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let kernel = attributes & OBJ_KERNEL_HANDLE != 0;
        if kernel && caller.mode != AccessMode::KernelMode {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let owner = if kernel {
            caller.system.process_id()
        } else {
            caller.effective_process
        };
        let table = &self.process(owner).ok_or(STATUS_INVALID_HANDLE)?.handles;
        let next_slot = table
            .iter()
            .position(crate::HandleSlot::is_free)
            .unwrap_or(table.len());
        if next_slot >= (MAX_RAW_HANDLE / 4) as usize {
            return Err(crate::STATUS_INSUFFICIENT_RESOURCES);
        }
        let reservation = self.try_reserve_handle_slot(owner)?;
        if let Err(status) =
            self.bind_reserved_handle(reservation, reference.object, granted_access)
        {
            self.cancel_reserved_handle(reservation)?;
            return Err(status);
        }
        let flags = HandleFlags {
            inherit: attributes & OBJ_INHERIT != 0,
            protect_from_close: false,
        };
        let slot = crate::handle_to_slot(reservation.handle).expect("reserved native handle");
        let crate::HandleSlot::Bound { generation, entry } = &mut self
            .processes
            .get_mut(&owner)
            .expect("reserved table owner")
            .handles[slot]
        else {
            unreachable!("new native Ps reservation remains bound");
        };
        assert_eq!(*generation, reservation.generation);
        entry.flags = flags;
        Ok(NativePsHandlePublication {
            system: caller.system,
            reservation,
            object: reference.object,
            body: reference.body,
            thread: reference.thread,
            granted_access,
            flags,
            value: u64::from(reservation.handle) | if kernel { KERNEL_HANDLE_TAG } else { 0 },
            phase: NativePsHandlePublicationPhase::Bound,
        })
    }

    /// Synchronous convenience for already-authorized internal callers. Provider IPC output
    /// delivery must instead retain the prepare result until its explicit publish/abort decision.
    pub fn insert_authorized_native_ps_handle(
        &mut self,
        caller: NativeHandleCaller,
        reference: &NativeObjectReference,
        granted_access: u32,
        attributes: u32,
    ) -> Result<u64, u32> {
        let mut publication = self.prepare_authorized_native_ps_handle(
            caller,
            reference,
            granted_access,
            attributes,
        )?;
        match publication.publish(self) {
            Ok(handle) => Ok(handle),
            Err(status) => {
                publication
                    .abort(self)
                    .expect("uninterrupted native handle preparation remains owned");
                Err(status)
            }
        }
    }
}

#[cfg(test)]
mod tests;
