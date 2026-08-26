//! NT I/O completion-port objects and packet queues.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_VERIFY_REQUIRED: u32 = 0x8000_0016;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_NAME_TOO_LONG: u32 = 0xC000_0106;
pub const STATUS_QUOTA_EXCEEDED: u32 = 0xC000_0044;

pub const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: u32 = 0x0000_0001;
pub const FILE_SKIP_SET_EVENT_ON_HANDLE: u32 = 0x0000_0002;
pub const FILE_SKIP_SET_USER_EVENT_ON_FAST_IO: u32 = 0x0000_0004;
pub const FILE_IO_COMPLETION_NOTIFICATION_VALID_FLAGS: u32 = FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
    | FILE_SKIP_SET_EVENT_ON_HANDLE
    | FILE_SKIP_SET_USER_EVENT_ON_FAST_IO;

/// FILE_OBJECT I/O mode derived from the mutually-exclusive synchronous create options. Alertable
/// and non-alertable synchronous Files share the same serialization lock but differ when a waiter
/// is interrupted by a user APC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FileIoMode {
    #[default]
    Asynchronous,
    SynchronousAlertable,
    SynchronousNonAlertable,
}

impl FileIoMode {
    pub const fn from_create_flags(
        alertable: bool,
        nonalertable: bool,
        synchronize_access: bool,
    ) -> Result<Self, u32> {
        if alertable && nonalertable {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !alertable && !nonalertable {
            return Ok(Self::Asynchronous);
        }
        if !synchronize_access {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(if alertable {
            Self::SynchronousAlertable
        } else {
            Self::SynchronousNonAlertable
        })
    }

    pub const fn is_synchronous(self) -> bool {
        !matches!(self, Self::Asynchronous)
    }

    pub const fn is_alertable(self) -> bool {
        matches!(self, Self::SynchronousAlertable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileIoAcquireResult {
    /// Asynchronous Files do not use the FILE_OBJECT serialization lock.
    Bypassed,
    Acquired,
    Contended {
        alertable: bool,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileIoRelease {
    pub waiters: u32,
}

/// NT file I/O APIs let callers set the low bit of an overlapped event handle to suppress
/// completion-port notification. The event object itself is still the handle with that bit cleared.
pub const fn normalize_io_event_handle(handle: u64) -> Option<u64> {
    let untagged = handle & !1;
    if untagged == 0 {
        None
    } else {
        Some(untagged)
    }
}

pub const fn io_event_suppresses_completion_port(handle: u64) -> bool {
    handle & 1 != 0
}

/// Whether a returned I/O status owns caller-visible completion publication. Warnings are terminal
/// completions, but an error returned inline leaves the IOSB, event, APC, and completion port alone.
/// An error delivered after the operation returned pending is still a real completion.
pub const fn file_io_status_publishes_completion(status: u32, completed_inline: bool) -> bool {
    status & 0xC000_0000 != 0xC000_0000 || !completed_inline
}

/// Buffered output is copied for success and warning statuses, but never for an NT error.
pub const fn file_io_status_copies_output(status: u32) -> bool {
    status != STATUS_VERIFY_REQUIRED && status & 0xC000_0000 != 0xC000_0000
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileCompletionBinding {
    pub port_id: u32,
    pub key_context: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileReferenceRelease {
    pub cleanup_required: bool,
    pub close_required: bool,
    pub device_id: u64,
    pub port_id: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FileCompletionEntry {
    file_id: u64,
    device_id: u64,
    references: u32,
    handle_references: u32,
    handle_publication_reserved: bool,
    io_mode: FileIoMode,
    /// Thread owning the synchronous FILE_OBJECT Busy lock, or zero while unlocked.
    lock_owner_tid: u64,
    /// A promoted waiter owns Busy before it runs again. Its first acquisition consumes this grant;
    /// a genuinely re-entrant I/O from the same thread still contends like NT's Busy exchange.
    lock_grant_tid: u64,
    lock_waiters: u32,
    signaled: bool,
    cleanup_sent: bool,
    /// The final handle reference has become the close procedure's cleanup
    /// reference and must be released only after CLEANUP has drained.
    cleanup_reference_held: bool,
    /// A synchronous cleanup owner is ordered after every already-referenced
    /// ordinary waiter without masquerading as a user thread.
    cleanup_waiting: bool,
    cleanup_lifecycle_started: bool,
    notification_modes: u32,
    binding: Option<FileCompletionBinding>,
}

/// Fixed FILE_OBJECT-to-completion-port associations. Handles duplicated from the same file object
/// share one entry and one immutable completion binding. Pending operations retain the same entry,
/// so closing the last handle cannot tear down an association before its final completion packet.
pub struct FileCompletionTable<const FILES: usize> {
    entries: [FileCompletionEntry; FILES],
}

impl<const FILES: usize> FileCompletionTable<FILES> {
    const CLEANUP_LOCK_OWNER: u64 = u64::MAX;

    pub const fn new() -> Self {
        assert!(FILES > 0);
        Self {
            entries: [FileCompletionEntry {
                file_id: 0,
                device_id: 0,
                references: 0,
                handle_references: 0,
                handle_publication_reserved: false,
                io_mode: FileIoMode::Asynchronous,
                lock_owner_tid: 0,
                lock_grant_tid: 0,
                lock_waiters: 0,
                signaled: false,
                cleanup_sent: false,
                cleanup_reference_held: false,
                cleanup_waiting: false,
                cleanup_lifecycle_started: false,
                notification_modes: 0,
                binding: None,
            }; FILES],
        }
    }

    pub fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            *entry = FileCompletionEntry::default();
        }
    }

    pub fn insert_file(
        &mut self,
        file_id: u64,
        device_id: u64,
        synchronous: bool,
    ) -> Result<(), u32> {
        self.insert_file_with_mode(
            file_id,
            device_id,
            if synchronous {
                FileIoMode::SynchronousNonAlertable
            } else {
                FileIoMode::Asynchronous
            },
        )
    }

    pub fn insert_file_with_mode(
        &mut self,
        file_id: u64,
        device_id: u64,
        io_mode: FileIoMode,
    ) -> Result<(), u32> {
        if file_id == 0 || device_id == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        if let Some(entry) = self.entry_mut(file_id) {
            if entry.device_id != device_id
                || entry.io_mode != io_mode
                || entry.cleanup_sent
                || entry.handle_publication_reserved
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
            entry.references = entry
                .references
                .checked_add(1)
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            entry.handle_references = entry
                .handle_references
                .checked_add(1)
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            return Ok(());
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.references == 0)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        *entry = FileCompletionEntry {
            file_id,
            device_id,
            references: 1,
            handle_references: 1,
            handle_publication_reserved: false,
            io_mode,
            lock_owner_tid: 0,
            lock_grant_tid: 0,
            lock_waiters: 0,
            signaled: true,
            cleanup_sent: false,
            cleanup_reference_held: false,
            cleanup_waiting: false,
            cleanup_lifecycle_started: false,
            notification_modes: 0,
            binding: None,
        };
        Ok(())
    }

    /// Claim one fixed File-completion slot before dispatching CREATE. The reservation owns the
    /// future handle reference, but is not yet a user-visible handle and can be rolled back without
    /// generating CLEANUP/CLOSE completion policy.
    pub fn reserve_file_handle_publication(
        &mut self,
        file_id: u64,
        device_id: u64,
        synchronous: bool,
    ) -> Result<(), u32> {
        self.reserve_file_handle_publication_with_mode(
            file_id,
            device_id,
            if synchronous {
                FileIoMode::SynchronousNonAlertable
            } else {
                FileIoMode::Asynchronous
            },
        )
    }

    pub fn reserve_file_handle_publication_with_mode(
        &mut self,
        file_id: u64,
        device_id: u64,
        io_mode: FileIoMode,
    ) -> Result<(), u32> {
        if file_id == 0 || device_id == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        if self.entry(file_id).is_some() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.references == 0)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        *entry = FileCompletionEntry {
            file_id,
            device_id,
            references: 1,
            handle_references: 0,
            handle_publication_reserved: true,
            io_mode,
            lock_owner_tid: 0,
            lock_grant_tid: 0,
            lock_waiters: 0,
            signaled: true,
            cleanup_sent: false,
            cleanup_reference_held: false,
            cleanup_waiting: false,
            cleanup_lifecycle_started: false,
            notification_modes: 0,
            binding: None,
        };
        Ok(())
    }

    /// Convert an exact pre-CREATE reservation into the first real handle reference.
    pub fn commit_reserved_file_handle(&mut self, file_id: u64) -> Result<(), u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if !entry.handle_publication_reserved
            || entry.handle_references != 0
            || entry.references != 1
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.handle_publication_reserved = false;
        entry.handle_references = 1;
        Ok(())
    }

    /// Roll back an unpublished pre-CREATE reservation without manufacturing handle-close policy.
    pub fn cancel_reserved_file_handle(&mut self, file_id: u64) -> Result<(), u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if !entry.handle_publication_reserved
            || entry.handle_references != 0
            || entry.references != 1
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        *entry = FileCompletionEntry::default();
        Ok(())
    }

    pub fn retain_handle(&mut self, file_id: u64) -> Result<(), u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.cleanup_sent || entry.handle_publication_reserved {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.references = entry
            .references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        entry.handle_references = entry
            .handle_references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    pub fn retain_file(&mut self, file_id: u64) -> Result<(), u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.handle_publication_reserved {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.references = entry
            .references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    /// Drop one non-handle file-object reference, usually held by a pending I/O operation.
    pub fn release_file(&mut self, file_id: u64) -> Result<FileReferenceRelease, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.handle_publication_reserved {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.references -= 1;
        Ok(Self::finish_release(entry, false))
    }

    /// Drop one user-visible file handle reference. Cleanup is required when the last handle closes;
    /// that final handle reference transfers to the cleanup owner until the
    /// driver's CLEANUP/CLOSE lifecycle has drained.
    pub fn release_handle(&mut self, file_id: u64) -> Result<FileReferenceRelease, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.handle_references == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        entry.handle_references -= 1;
        let cleanup_required = entry.handle_references == 0 && !entry.cleanup_sent;
        if cleanup_required {
            entry.cleanup_sent = true;
            entry.cleanup_reference_held = true;
        } else {
            entry.references -= 1;
        }
        Ok(Self::finish_release(entry, cleanup_required))
    }

    /// Release the reference transferred from the final handle after the
    /// cleanup owner has finished the canonical driver lifecycle.
    pub fn release_cleanup_reference(&mut self, file_id: u64) -> Result<FileReferenceRelease, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if !entry.cleanup_reference_held
            || entry.handle_references != 0
            || entry.cleanup_waiting
            || entry.lock_owner_tid == Self::CLEANUP_LOCK_OWNER
            || !entry.cleanup_lifecycle_started
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.cleanup_reference_held = false;
        entry.cleanup_lifecycle_started = false;
        entry.references -= 1;
        Ok(Self::finish_release(entry, false))
    }

    pub fn cleanup_required_on_handle_close(&self, file_id: u64) -> Result<bool, u32> {
        let entry = self.entry(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(entry.handle_references == 1 && !entry.cleanup_sent)
    }

    pub fn associate(&mut self, file_id: u64, binding: FileCompletionBinding) -> Result<(), u32> {
        self.can_associate(file_id)?;
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        entry.binding = Some(binding);
        Ok(())
    }

    pub fn can_associate(&self, file_id: u64) -> Result<(), u32> {
        let entry = self.entry(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.io_mode.is_synchronous()
            || entry.binding.is_some()
            || entry.handle_publication_reserved
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    pub fn binding(&self, file_id: u64) -> Option<FileCompletionBinding> {
        self.entry(file_id).and_then(|entry| entry.binding)
    }

    pub fn set_notification_modes(&mut self, file_id: u64, flags: u32) -> Result<u32, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.io_mode.is_synchronous() && flags != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.notification_modes |= flags & FILE_IO_COMPLETION_NOTIFICATION_VALID_FLAGS;
        Ok(entry.notification_modes)
    }

    pub fn notification_modes(&self, file_id: u64) -> Result<u32, u32> {
        self.entry(file_id)
            .map(|entry| entry.notification_modes)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn is_synchronous(&self, file_id: u64) -> Result<bool, u32> {
        self.entry(file_id)
            .map(|entry| entry.io_mode.is_synchronous())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn io_mode(&self, file_id: u64) -> Result<FileIoMode, u32> {
        self.entry(file_id)
            .map(|entry| entry.io_mode)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Acquire the synchronous FILE_OBJECT Busy lock. Contention records one executive-owned
    /// waiter; the caller must either enqueue that waiter or immediately call `cancel_io_waiter`.
    pub fn begin_io(&mut self, file_id: u64, tid: u64) -> Result<FileIoAcquireResult, u32> {
        if tid == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if !entry.io_mode.is_synchronous() {
            if entry.cleanup_reference_held {
                return Err(STATUS_INVALID_HANDLE);
            }
            return Ok(FileIoAcquireResult::Bypassed);
        }
        if entry.cleanup_reference_held
            && !(entry.lock_owner_tid == tid && entry.lock_grant_tid == tid)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        if entry.lock_owner_tid == 0 {
            entry.lock_owner_tid = tid;
            return Ok(FileIoAcquireResult::Acquired);
        }
        if entry.lock_owner_tid == tid && entry.lock_grant_tid == tid {
            entry.lock_grant_tid = 0;
            return Ok(FileIoAcquireResult::Acquired);
        }
        entry.lock_waiters = entry
            .lock_waiters
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(FileIoAcquireResult::Contended {
            alertable: entry.io_mode.is_alertable(),
        })
    }

    /// Acquire Busy for the internal, non-alertable CLEANUP owner. A contended
    /// cleanup is held behind the ordinary waiter count and becomes eligible
    /// only after the final pre-existing operation releases Busy.
    pub fn begin_cleanup(&mut self, file_id: u64) -> Result<FileIoAcquireResult, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if !entry.cleanup_reference_held
            || entry.handle_references != 0
            || entry.cleanup_waiting
            || entry.lock_owner_tid == Self::CLEANUP_LOCK_OWNER
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !entry.io_mode.is_synchronous() {
            return Ok(FileIoAcquireResult::Bypassed);
        }
        if entry.lock_owner_tid == 0 && entry.lock_waiters == 0 {
            entry.lock_owner_tid = Self::CLEANUP_LOCK_OWNER;
            return Ok(FileIoAcquireResult::Acquired);
        }
        entry.cleanup_waiting = true;
        Ok(FileIoAcquireResult::Contended { alertable: false })
    }

    /// Undo a contention count when the executive could not publish or no longer needs a waiter.
    pub fn cancel_io_waiter(&mut self, file_id: u64) -> Result<u32, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.lock_waiters == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.lock_waiters -= 1;
        Ok(entry.lock_waiters)
    }

    /// Transfer an unlocked synchronous File to one exact FIFO waiter before waking it. The grant
    /// prevents a racing new caller from stealing Busy before the promoted syscall runs again.
    pub fn promote_io_waiter(&mut self, file_id: u64, tid: u64) -> Result<u32, u32> {
        if tid == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if !entry.io_mode.is_synchronous()
            || entry.lock_owner_tid != 0
            || entry.lock_grant_tid != 0
            || entry.lock_waiters == 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.lock_waiters -= 1;
        entry.lock_owner_tid = tid;
        entry.lock_grant_tid = tid;
        Ok(entry.lock_waiters)
    }

    pub fn promote_cleanup_if_ready(&mut self, file_id: u64) -> Result<bool, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if !entry.cleanup_waiting {
            return Ok(false);
        }
        if !entry.cleanup_reference_held || !entry.io_mode.is_synchronous() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if entry.lock_owner_tid != 0 || entry.lock_grant_tid != 0 || entry.lock_waiters != 0 {
            return Ok(false);
        }
        entry.cleanup_waiting = false;
        entry.lock_owner_tid = Self::CLEANUP_LOCK_OWNER;
        Ok(true)
    }

    /// Mark the canonical manager lifecycle active before crossing the driver
    /// boundary. Repeated callers observe the existing owner and must redrive it
    /// rather than dispatching a second cleanup generation.
    pub fn mark_cleanup_lifecycle_started(&mut self, file_id: u64) -> Result<bool, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if !entry.cleanup_reference_held || entry.handle_references != 0 || entry.cleanup_waiting {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if entry.io_mode.is_synchronous() && entry.lock_owner_tid != Self::CLEANUP_LOCK_OWNER {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if entry.cleanup_lifecycle_started {
            return Ok(false);
        }
        entry.cleanup_lifecycle_started = true;
        Ok(true)
    }

    /// Allocation-free enumeration of cleanup owners whose canonical manager
    /// lifecycle has started but whose transferred File reference is still live.
    pub fn active_cleanup_from(&self, start: usize) -> Option<(usize, u64)> {
        self.entries
            .iter()
            .enumerate()
            .skip(start)
            .find_map(|(slot, entry)| {
                (entry.references != 0
                    && entry.cleanup_reference_held
                    && entry.cleanup_lifecycle_started)
                    .then_some((slot, entry.file_id))
            })
    }

    /// Release a completed synchronous operation. The executive uses the returned waiter count to
    /// promote exactly one FIFO acquisition owner before making that thread runnable.
    pub fn release_io(&mut self, file_id: u64, tid: u64) -> Result<FileIoRelease, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if !entry.io_mode.is_synchronous()
            || entry.lock_owner_tid != tid
            || entry.lock_grant_tid != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.lock_owner_tid = 0;
        Ok(FileIoRelease {
            waiters: entry.lock_waiters,
        })
    }

    pub fn release_cleanup_io(&mut self, file_id: u64) -> Result<FileIoRelease, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.lock_owner_tid != Self::CLEANUP_LOCK_OWNER || entry.lock_grant_tid != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.lock_owner_tid = 0;
        Ok(FileIoRelease {
            waiters: entry.lock_waiters,
        })
    }

    /// Drop a promoted owner whose thread terminated before consuming its grant.
    pub fn cancel_promoted_io(&mut self, file_id: u64, tid: u64) -> Result<FileIoRelease, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.lock_owner_tid != tid || entry.lock_grant_tid != tid {
            return Err(STATUS_INVALID_PARAMETER);
        }
        entry.lock_owner_tid = 0;
        entry.lock_grant_tid = 0;
        Ok(FileIoRelease {
            waiters: entry.lock_waiters,
        })
    }

    pub fn io_lock_owner(&self, file_id: u64) -> Result<Option<u64>, u32> {
        self.entry(file_id)
            .map(|entry| (entry.lock_owner_tid != 0).then_some(entry.lock_owner_tid))
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn io_waiter_count(&self, file_id: u64) -> Result<u32, u32> {
        self.entry(file_id)
            .map(|entry| entry.lock_waiters)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn device_id(&self, file_id: u64) -> Result<u64, u32> {
        self.entry(file_id)
            .map(|entry| entry.device_id)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn set_signaled(&mut self, file_id: u64, signaled: bool) -> Result<(), u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        entry.signaled = signaled;
        Ok(())
    }

    pub fn is_signaled(&self, file_id: u64) -> Result<bool, u32> {
        self.entry(file_id)
            .map(|entry| entry.signaled)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn complete_file(&mut self, file_id: u64, status: u32) -> Result<bool, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if status == STATUS_SUCCESS && entry.notification_modes & FILE_SKIP_SET_EVENT_ON_HANDLE != 0
        {
            return Ok(false);
        }
        entry.signaled = true;
        Ok(true)
    }

    pub fn signal_on_completion_association(&mut self, file_id: u64) -> Result<bool, u32> {
        let entry = self.entry_mut(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if entry.notification_modes & FILE_SKIP_SET_EVENT_ON_HANDLE != 0 {
            return Ok(false);
        }
        entry.signaled = true;
        Ok(true)
    }

    pub fn should_queue_completion_packet(
        &self,
        file_id: u64,
        apc_context: u64,
        status: u32,
        completed_inline: bool,
        operation_suppressed: bool,
    ) -> Result<bool, u32> {
        let entry = self.entry(file_id).ok_or(STATUS_INVALID_HANDLE)?;
        if apc_context == 0 || operation_suppressed {
            return Ok(false);
        }
        if completed_inline
            && status == STATUS_SUCCESS
            && entry.notification_modes & FILE_SKIP_COMPLETION_PORT_ON_SUCCESS != 0
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn entry(&self, file_id: u64) -> Option<&FileCompletionEntry> {
        self.entries
            .iter()
            .find(|entry| entry.references != 0 && entry.file_id == file_id)
    }

    fn entry_mut(&mut self, file_id: u64) -> Option<&mut FileCompletionEntry> {
        self.entries
            .iter_mut()
            .find(|entry| entry.references != 0 && entry.file_id == file_id)
    }

    fn finish_release(
        entry: &mut FileCompletionEntry,
        cleanup_required: bool,
    ) -> FileReferenceRelease {
        let close_required = entry.references == 0;
        assert!(
            !close_required
                || (entry.lock_owner_tid == 0
                    && entry.lock_grant_tid == 0
                    && entry.lock_waiters == 0),
            "last File reference released while synchronous I/O still owns it"
        );
        let release = FileReferenceRelease {
            cleanup_required,
            close_required,
            device_id: entry.device_id,
            port_id: if close_required {
                entry.binding.map(|binding| binding.port_id)
            } else {
                None
            },
        };
        if close_required {
            *entry = FileCompletionEntry::default();
        }
        release
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompletionPacket {
    pub key_context: u64,
    pub apc_context: u64,
    pub status: u32,
    pub information: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportCompletion {
    pub request_id: u64,
    pub user_data: u64,
    pub status: i32,
    pub information: u64,
}

impl From<TransportCompletion> for CompletionPacket {
    fn from(completion: TransportCompletion) -> Self {
        Self {
            // SURT preserves `user_data` as the caller's opaque cookie. The NT adapter uses it as
            // the completion key and uses the stable request id as the APC/overlapped context.
            key_context: completion.user_data,
            apc_context: completion.request_id,
            status: completion.status as u32,
            information: completion.information,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveMode {
    Poll,
    Wait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveResult {
    Packet(CompletionPacket),
    Empty(u32),
}

pub const INFINITE_DEADLINE: u64 = u64::MAX;

/// Executive-owned state for one blocking `NtRemoveIoCompletion` call. Addresses are kept opaque;
/// the executive validates them before parking and writes them in the waiter's process on wake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompletionWaiter {
    pub port_id: u32,
    pub process_index: u8,
    pub _reserved: [u8; 3],
    pub reply_cap: u64,
    pub reply: nt_syscall_abi::ParkedSyscallReply,
    pub thread_id: u64,
    pub badge: u64,
    pub key_context_out: u64,
    pub apc_context_out: u64,
    pub io_status_block_out: u64,
    pub deadline_100ns: u64,
    sequence: u64,
}

/// Wait table shared by completion ports. Per-port release is LIFO, matching NT KQUEUE scheduling;
/// deadline and cancellation scans retain deterministic park order. Storage grows with real parked
/// waiter demand and reuses cleared rows so the crate does not impose an IOCP waiter ceiling.
pub struct CompletionWaiterTable {
    slots: Vec<Option<CompletionWaiter>>,
    next_sequence: u64,
    allocation_failures: u64,
    store_failures: u64,
}

impl CompletionWaiterTable {
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            next_sequence: 0,
            allocation_failures: 0,
            store_failures: 0,
        }
    }

    pub fn reset(&mut self, initial_reserve: usize) -> bool {
        self.slots.clear();
        if self.slots.capacity() < initial_reserve
            && self.slots.try_reserve(initial_reserve).is_err()
        {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            return false;
        }
        true
    }

    pub fn insert(&mut self, mut waiter: CompletionWaiter) -> Result<(), u32> {
        if waiter.reply_cap == 0
            || self
                .slots
                .iter()
                .flatten()
                .any(|existing| existing.reply_cap == waiter.reply_cap)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let index = if let Some(index) = self.slots.iter().position(|slot| slot.is_none()) {
            index
        } else {
            if self.slots.len() == self.slots.capacity() && self.slots.try_reserve(1).is_err() {
                self.allocation_failures = self.allocation_failures.saturating_add(1);
                self.store_failures = self.store_failures.saturating_add(1);
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            let index = self.slots.len();
            self.slots.push(None);
            index
        };
        waiter.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.slots[index] = Some(waiter);
        Ok(())
    }

    /// Release the newest waiter for `port_id`, matching NT KQUEUE/IOCP LIFO thread scheduling.
    /// Packet order remains FIFO in [`CompletionPortTable`].
    pub fn pop_port(&mut self, port_id: u32) -> Option<CompletionWaiter> {
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, waiter)| waiter.map(|waiter| (index, waiter)))
            .filter(|(_, waiter)| waiter.port_id == port_id)
            .max_by_key(|(_, waiter)| waiter.sequence)
            .map(|(index, _)| index)?;
        self.slots[index].take()
    }

    /// Remove the oldest waiter owned by a terminating thread.
    pub fn pop_thread(&mut self, thread_id: u64) -> Option<CompletionWaiter> {
        self.pop_oldest_matching(|waiter| waiter.thread_id == thread_id)
    }

    /// Remove the oldest waiter owned by a terminating process.
    pub fn pop_process(&mut self, process_index: u8) -> Option<CompletionWaiter> {
        self.pop_oldest_matching(|waiter| waiter.process_index == process_index)
    }

    /// Remove the earliest expired waiter. Equal deadlines retain park order.
    pub fn pop_due(&mut self, now_100ns: u64) -> Option<CompletionWaiter> {
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, waiter)| waiter.map(|waiter| (index, waiter)))
            .filter(|(_, waiter)| {
                waiter.deadline_100ns != INFINITE_DEADLINE && waiter.deadline_100ns <= now_100ns
            })
            .min_by_key(|(_, waiter)| (waiter.deadline_100ns, waiter.sequence))
            .map(|(index, _)| index)?;
        self.slots[index].take()
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .map(|waiter| waiter.deadline_100ns)
            .filter(|deadline| *deadline != INFINITE_DEADLINE)
            .min()
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn records(&self) -> usize {
        self.slots.len()
    }

    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    pub fn allocation_failures(&self) -> u64 {
        self.allocation_failures
    }

    pub fn store_failures(&self) -> u64 {
        self.store_failures
    }

    fn pop_oldest_matching(
        &mut self,
        predicate: impl Fn(&CompletionWaiter) -> bool,
    ) -> Option<CompletionWaiter> {
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, waiter)| waiter.map(|waiter| (index, waiter)))
            .filter(|(_, waiter)| predicate(waiter))
            .min_by_key(|(_, waiter)| waiter.sequence)
            .map(|(index, _)| index)?;
        self.slots[index].take()
    }
}

impl Default for CompletionWaiterTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateResult {
    pub id: u32,
    pub created: bool,
}

#[derive(Clone, Copy)]
struct CompletionPort<const PACKETS: usize, const NAME_UNITS: usize> {
    occupied: bool,
    references: u16,
    concurrency: u32,
    name_len: u16,
    name: [u16; NAME_UNITS],
    packets: [CompletionPacket; PACKETS],
    head: usize,
    len: usize,
}

impl<const PACKETS: usize, const NAME_UNITS: usize> CompletionPort<PACKETS, NAME_UNITS> {
    const fn empty() -> Self {
        Self {
            occupied: false,
            references: 0,
            concurrency: 0,
            name_len: 0,
            name: [0; NAME_UNITS],
            packets: [CompletionPacket {
                key_context: 0,
                apc_context: 0,
                status: 0,
                information: 0,
            }; PACKETS],
            head: 0,
            len: 0,
        }
    }

    fn name(&self) -> &[u16] {
        &self.name[..self.name_len as usize]
    }

    fn retain(&mut self) -> Result<(), u32> {
        self.references = self
            .references
            .checked_add(1)
            .ok_or(STATUS_QUOTA_EXCEEDED)?;
        Ok(())
    }

    fn reset(&mut self) {
        *self = Self::empty();
    }
}

pub struct CompletionPortTable<const PORTS: usize, const PACKETS: usize, const NAME_UNITS: usize> {
    ports: [CompletionPort<PACKETS, NAME_UNITS>; PORTS],
}

impl<const PORTS: usize, const PACKETS: usize, const NAME_UNITS: usize>
    CompletionPortTable<PORTS, PACKETS, NAME_UNITS>
{
    pub const fn new() -> Self {
        assert!(PORTS > 0);
        assert!(PACKETS > 0);
        Self {
            ports: [CompletionPort::empty(); PORTS],
        }
    }

    pub fn clear(&mut self) {
        for port in self.ports.iter_mut() {
            port.reset();
        }
    }

    pub fn create(
        &mut self,
        name: &[u16],
        concurrency: u32,
        case_insensitive: bool,
    ) -> Result<CreateResult, u32> {
        if name.len() > NAME_UNITS {
            return Err(STATUS_NAME_TOO_LONG);
        }
        if !name.is_empty() {
            if let Some(index) = self.find_name(name, case_insensitive) {
                self.ports[index].retain()?;
                return Ok(CreateResult {
                    id: index as u32,
                    created: false,
                });
            }
        }
        let index = self
            .ports
            .iter()
            .position(|port| !port.occupied)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let port = &mut self.ports[index];
        port.occupied = true;
        port.references = 1;
        port.concurrency = concurrency;
        port.name_len = name.len() as u16;
        port.name[..name.len()].copy_from_slice(name);
        Ok(CreateResult {
            id: index as u32,
            created: true,
        })
    }

    pub fn open(&mut self, name: &[u16], case_insensitive: bool) -> Result<u32, u32> {
        if name.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let index = self
            .find_name(name, case_insensitive)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        self.ports[index].retain()?;
        Ok(index as u32)
    }

    /// Hold an executive-internal reference while a blocking remove is parked.
    pub fn retain(&mut self, id: u32) -> Result<(), u32> {
        self.port_mut(id)?.retain()
    }

    pub fn release(&mut self, id: u32) -> Result<(), u32> {
        let port = self.port_mut(id)?;
        if port.references > 1 {
            port.references -= 1;
        } else {
            port.reset();
        }
        Ok(())
    }

    pub fn enqueue(&mut self, id: u32, packet: CompletionPacket) -> Result<(), u32> {
        let port = self.port_mut(id)?;
        if port.len == PACKETS {
            return Err(STATUS_QUOTA_EXCEEDED);
        }
        let tail = (port.head + port.len) % PACKETS;
        port.packets[tail] = packet;
        port.len += 1;
        Ok(())
    }

    pub fn enqueue_transport(
        &mut self,
        id: u32,
        completion: TransportCompletion,
    ) -> Result<(), u32> {
        self.enqueue(id, completion.into())
    }

    pub fn remove(&mut self, id: u32, mode: RemoveMode) -> Result<RemoveResult, u32> {
        let port = self.port_mut(id)?;
        if port.len == 0 {
            return Ok(RemoveResult::Empty(match mode {
                RemoveMode::Poll => STATUS_TIMEOUT,
                RemoveMode::Wait => STATUS_PENDING,
            }));
        }
        let packet = port.packets[port.head];
        port.head = (port.head + 1) % PACKETS;
        port.len -= 1;
        Ok(RemoveResult::Packet(packet))
    }

    pub fn depth(&self, id: u32) -> Result<u32, u32> {
        Ok(self.port(id)?.len as u32)
    }

    pub fn concurrency(&self, id: u32) -> Result<u32, u32> {
        Ok(self.port(id)?.concurrency)
    }

    fn port(&self, id: u32) -> Result<&CompletionPort<PACKETS, NAME_UNITS>, u32> {
        self.ports
            .get(id as usize)
            .filter(|port| port.occupied)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    fn port_mut(&mut self, id: u32) -> Result<&mut CompletionPort<PACKETS, NAME_UNITS>, u32> {
        self.ports
            .get_mut(id as usize)
            .filter(|port| port.occupied)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    fn find_name(&self, name: &[u16], case_insensitive: bool) -> Option<usize> {
        self.ports.iter().position(|port| {
            port.occupied
                && port.name().len() == name.len()
                && port.name().iter().zip(name).all(|(&left, &right)| {
                    if case_insensitive {
                        fold_ascii(left) == fold_ascii(right)
                    } else {
                        left == right
                    }
                })
        })
    }
}

impl<const PORTS: usize, const PACKETS: usize, const NAME_UNITS: usize> Default
    for CompletionPortTable<PORTS, PACKETS, NAME_UNITS>
{
    fn default() -> Self {
        Self::new()
    }
}

fn fold_ascii(unit: u16) -> u16 {
    if unit >= b'A' as u16 && unit <= b'Z' as u16 {
        unit + (b'a' - b'A') as u16
    } else {
        unit
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    type Ports = CompletionPortTable<2, 2, 16>;

    #[test]
    fn completion_publication_distinguishes_inline_errors_from_deferred_errors() {
        assert!(file_io_status_copies_output(STATUS_SUCCESS));
        assert!(file_io_status_copies_output(0x8000_0005));
        assert!(!file_io_status_copies_output(STATUS_VERIFY_REQUIRED));
        assert!(!file_io_status_copies_output(STATUS_INVALID_PARAMETER));
        assert!(file_io_status_publishes_completion(STATUS_SUCCESS, true));
        assert!(file_io_status_publishes_completion(0x8000_0005, true));
        assert!(file_io_status_publishes_completion(
            STATUS_VERIFY_REQUIRED,
            true
        ));
        assert!(!file_io_status_publishes_completion(
            STATUS_INVALID_PARAMETER,
            true
        ));
        assert!(file_io_status_publishes_completion(
            STATUS_INVALID_PARAMETER,
            false
        ));
    }

    fn packet(value: u64) -> CompletionPacket {
        CompletionPacket {
            key_context: value,
            apc_context: value + 1,
            status: value as u32,
            information: value + 2,
        }
    }

    fn waiter(port_id: u32, value: u64, deadline_100ns: u64) -> CompletionWaiter {
        CompletionWaiter {
            port_id,
            process_index: value as u8,
            reply_cap: value,
            thread_id: value + 100,
            key_context_out: value + 200,
            deadline_100ns,
            ..CompletionWaiter::default()
        }
    }

    #[test]
    fn create_tracks_concurrency_and_distinct_anonymous_objects() {
        let mut ports = Ports::new();
        let first = ports.create(&[], 4, false).unwrap();
        let second = ports.create(&[], 0, false).unwrap();
        assert!(first.created);
        assert!(second.created);
        assert_ne!(first.id, second.id);
        assert_eq!(ports.concurrency(first.id), Ok(4));
    }

    #[test]
    fn named_create_and_open_share_an_object() {
        let mut ports = Ports::new();
        let created = ports
            .create(
                &[b'P' as u16, b'o' as u16, b'r' as u16, b't' as u16],
                2,
                true,
            )
            .unwrap();
        let duplicate = ports
            .create(
                &[b'p' as u16, b'O' as u16, b'R' as u16, b'T' as u16],
                9,
                true,
            )
            .unwrap();
        assert!(!duplicate.created);
        assert_eq!(duplicate.id, created.id);
        assert_eq!(ports.concurrency(created.id), Ok(2));
        assert_eq!(
            ports.open(&[b'p' as u16, b'o' as u16, b'r' as u16, b't' as u16], true),
            Ok(created.id)
        );
    }

    #[test]
    fn case_sensitive_names_and_missing_opens_are_distinct() {
        let mut ports = Ports::new();
        let upper = [b'P' as u16];
        let lower = [b'p' as u16];
        let first = ports.create(&upper, 1, false).unwrap();
        let second = ports.create(&lower, 1, false).unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(
            ports.open(&[b'x' as u16], false),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn object_and_name_capacity_fail_truthfully() {
        let mut ports = Ports::new();
        assert_eq!(
            ports.create(&[b'x' as u16; 17], 1, false),
            Err(STATUS_NAME_TOO_LONG)
        );
        ports.create(&[], 1, false).unwrap();
        ports.create(&[], 1, false).unwrap();
        assert_eq!(
            ports.create(&[], 1, false),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
    }

    #[test]
    fn io_event_handles_strip_completion_port_suppression_bit() {
        assert_eq!(normalize_io_event_handle(0), None);
        assert_eq!(normalize_io_event_handle(1), None);
        assert_eq!(normalize_io_event_handle(0x40), Some(0x40));
        assert_eq!(normalize_io_event_handle(0x41), Some(0x40));
        assert!(!io_event_suppresses_completion_port(0x40));
        assert!(io_event_suppresses_completion_port(0x41));
    }

    #[test]
    fn packets_are_fifo_and_depth_is_exact() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        ports.enqueue(id, packet(10)).unwrap();
        ports.enqueue(id, packet(20)).unwrap();
        assert_eq!(ports.depth(id), Ok(2));
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Packet(packet(10)))
        );
        assert_eq!(
            ports.remove(id, RemoveMode::Wait),
            Ok(RemoveResult::Packet(packet(20)))
        );
        assert_eq!(ports.depth(id), Ok(0));
    }

    #[test]
    fn full_queue_is_reported_without_overwrite() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        ports.enqueue(id, packet(1)).unwrap();
        ports.enqueue(id, packet(2)).unwrap();
        assert_eq!(ports.enqueue(id, packet(3)), Err(STATUS_QUOTA_EXCEEDED));
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Packet(packet(1)))
        );
    }

    #[test]
    fn empty_remove_distinguishes_poll_from_blocking_wait() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Empty(STATUS_TIMEOUT))
        );
        assert_eq!(
            ports.remove(id, RemoveMode::Wait),
            Ok(RemoveResult::Empty(STATUS_PENDING))
        );
    }

    #[test]
    fn invalid_and_released_ids_are_rejected() {
        let mut ports = Ports::new();
        assert_eq!(ports.depth(99), Err(STATUS_INVALID_HANDLE));
        let id = ports.create(&[], 1, false).unwrap().id;
        ports.release(id).unwrap();
        assert_eq!(ports.enqueue(id, packet(1)), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn final_release_recycles_but_shared_reference_does_not() {
        let mut ports = Ports::new();
        let name = [b'x' as u16];
        let id = ports.create(&name, 1, false).unwrap().id;
        assert_eq!(ports.open(&name, false), Ok(id));
        ports.release(id).unwrap();
        assert_eq!(ports.depth(id), Ok(0));
        ports.release(id).unwrap();
        assert_eq!(ports.depth(id), Err(STATUS_INVALID_HANDLE));
        assert_eq!(ports.create(&[], 3, false).unwrap().id, id);
    }

    #[test]
    fn parked_waiter_reference_survives_last_handle_close() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        ports.retain(id).unwrap();
        ports.release(id).unwrap();
        assert_eq!(ports.depth(id), Ok(0));
        ports.enqueue(id, packet(1)).unwrap();
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Packet(packet(1)))
        );
        ports.release(id).unwrap();
        assert_eq!(ports.depth(id), Err(STATUS_INVALID_HANDLE));
        assert_eq!(ports.create(&[], 2, false).unwrap().id, id);
    }

    #[test]
    fn every_reference_path_reports_overflow_without_saturating() {
        let mut ports = Ports::new();
        let name = [b'x' as u16];
        let id = ports.create(&name, 1, false).unwrap().id;
        ports.ports[id as usize].references = u16::MAX;
        assert_eq!(ports.retain(id), Err(STATUS_QUOTA_EXCEEDED));
        assert_eq!(ports.open(&name, false), Err(STATUS_QUOTA_EXCEEDED));
        assert_eq!(ports.create(&name, 9, false), Err(STATUS_QUOTA_EXCEEDED));
        assert_eq!(ports.ports[id as usize].references, u16::MAX);
    }

    #[test]
    fn transport_adapter_maps_surt_fields_without_transport_dependency() {
        let mut ports = Ports::new();
        let id = ports.create(&[], 1, false).unwrap().id;
        ports
            .enqueue_transport(
                id,
                TransportCompletion {
                    request_id: 0x1111,
                    user_data: 0x2222,
                    status: -7,
                    information: 0x3333,
                },
            )
            .unwrap();
        assert_eq!(
            ports.remove(id, RemoveMode::Poll),
            Ok(RemoveResult::Packet(CompletionPacket {
                key_context: 0x2222,
                apc_context: 0x1111,
                status: (-7i32) as u32,
                information: 0x3333,
            }))
        );
    }

    #[test]
    fn file_completion_binding_is_shared_until_the_last_handle_closes() {
        let mut files = FileCompletionTable::<2>::new();
        files.insert_file(10, 77, false).unwrap();
        files.retain_handle(10).unwrap();
        files
            .associate(
                10,
                FileCompletionBinding {
                    port_id: 3,
                    key_context: 0x1234,
                },
            )
            .unwrap();
        assert_eq!(
            files.binding(10),
            Some(FileCompletionBinding {
                port_id: 3,
                key_context: 0x1234,
            })
        );
        assert_eq!(
            files.release_handle(10),
            Ok(FileReferenceRelease {
                cleanup_required: false,
                close_required: false,
                device_id: 77,
                port_id: None,
            })
        );
        assert_eq!(files.binding(10).unwrap().key_context, 0x1234);
        assert_eq!(
            files.release_handle(10),
            Ok(FileReferenceRelease {
                cleanup_required: true,
                close_required: false,
                device_id: 77,
                port_id: None,
            })
        );
        assert_eq!(files.binding(10).unwrap().port_id, 3);
        assert_eq!(files.begin_cleanup(10), Ok(FileIoAcquireResult::Bypassed));
        assert_eq!(files.mark_cleanup_lifecycle_started(10), Ok(true));
        assert_eq!(
            files.release_cleanup_reference(10),
            Ok(FileReferenceRelease {
                cleanup_required: false,
                close_required: true,
                device_id: 77,
                port_id: Some(3),
            })
        );
        assert_eq!(files.binding(10), None);
    }

    #[test]
    fn reserved_file_handle_publication_commits_or_rolls_back_exactly() {
        let mut files = FileCompletionTable::<1>::new();
        files
            .reserve_file_handle_publication(10, 77, false)
            .unwrap();
        assert_eq!(files.retain_file(10), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(files.retain_handle(10), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            files.insert_file(10, 77, false),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            files.reserve_file_handle_publication(20, 77, false),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );

        files.commit_reserved_file_handle(10).unwrap();
        assert_eq!(files.is_synchronous(10), Ok(false));
        assert_eq!(files.retain_file(10), Ok(()));
        assert_eq!(files.release_file(10).unwrap().close_required, false);
        assert_eq!(files.release_handle(10).unwrap().cleanup_required, true);
        assert_eq!(files.begin_cleanup(10), Ok(FileIoAcquireResult::Bypassed));
        files.mark_cleanup_lifecycle_started(10).unwrap();
        assert_eq!(
            files.release_cleanup_reference(10).unwrap().close_required,
            true
        );

        files.reserve_file_handle_publication(20, 88, true).unwrap();
        assert_eq!(files.cancel_reserved_file_handle(20), Ok(()));
        assert_eq!(files.is_synchronous(20), Err(STATUS_INVALID_HANDLE));
        files
            .reserve_file_handle_publication(30, 99, false)
            .unwrap();
    }

    #[test]
    fn pending_operation_keeps_binding_alive_after_last_handle_closes() {
        let mut files = FileCompletionTable::<1>::new();
        files.insert_file(10, 77, false).unwrap();
        files
            .associate(
                10,
                FileCompletionBinding {
                    port_id: 3,
                    key_context: 0x1234,
                },
            )
            .unwrap();
        files.retain_file(10).unwrap();
        assert_eq!(
            files.release_handle(10),
            Ok(FileReferenceRelease {
                cleanup_required: true,
                close_required: false,
                device_id: 77,
                port_id: None,
            })
        );
        assert_eq!(files.is_synchronous(10), Ok(false));
        assert_eq!(files.binding(10).unwrap().port_id, 3);
        assert_eq!(
            files.release_file(10),
            Ok(FileReferenceRelease {
                cleanup_required: false,
                close_required: false,
                device_id: 77,
                port_id: None,
            })
        );
        assert_eq!(files.binding(10).unwrap().port_id, 3);
        assert_eq!(files.begin_cleanup(10), Ok(FileIoAcquireResult::Bypassed));
        files.mark_cleanup_lifecycle_started(10).unwrap();
        assert_eq!(
            files.release_cleanup_reference(10).unwrap().close_required,
            true
        );
        assert_eq!(files.binding(10), None);
    }

    #[test]
    fn file_object_signal_state_tracks_pending_io() {
        let mut files = FileCompletionTable::<1>::new();
        files.insert_file(10, 77, false).unwrap();
        assert_eq!(files.is_signaled(10), Ok(true));

        assert_eq!(files.set_signaled(10, false), Ok(()));
        assert_eq!(files.is_signaled(10), Ok(false));

        assert_eq!(files.set_signaled(10, true), Ok(()));
        assert_eq!(files.is_signaled(10), Ok(true));
        assert_eq!(files.set_signaled(20, false), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn synchronous_file_mode_preserves_alertability() {
        let mut files = FileCompletionTable::<3>::new();
        files
            .insert_file_with_mode(10, 77, FileIoMode::Asynchronous)
            .unwrap();
        files
            .insert_file_with_mode(20, 77, FileIoMode::SynchronousAlertable)
            .unwrap();
        files
            .insert_file_with_mode(30, 77, FileIoMode::SynchronousNonAlertable)
            .unwrap();

        assert_eq!(files.io_mode(10), Ok(FileIoMode::Asynchronous));
        assert_eq!(files.is_synchronous(10), Ok(false));
        assert_eq!(files.io_mode(20), Ok(FileIoMode::SynchronousAlertable));
        assert_eq!(files.is_synchronous(20), Ok(true));
        assert_eq!(files.io_mode(30), Ok(FileIoMode::SynchronousNonAlertable));
        assert_eq!(
            FileIoMode::from_create_flags(true, false, true),
            Ok(FileIoMode::SynchronousAlertable)
        );
        assert_eq!(
            FileIoMode::from_create_flags(false, true, true),
            Ok(FileIoMode::SynchronousNonAlertable)
        );
        assert_eq!(
            FileIoMode::from_create_flags(false, false, false),
            Ok(FileIoMode::Asynchronous)
        );
        assert_eq!(
            FileIoMode::from_create_flags(true, true, true),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            FileIoMode::from_create_flags(true, false, false),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn synchronous_file_serializes_and_promotes_exactly_one_waiter() {
        let mut files = FileCompletionTable::<1>::new();
        files
            .insert_file_with_mode(10, 77, FileIoMode::SynchronousAlertable)
            .unwrap();

        assert_eq!(files.begin_io(10, 100), Ok(FileIoAcquireResult::Acquired));
        assert_eq!(files.io_lock_owner(10), Ok(Some(100)));
        assert_eq!(
            files.begin_io(10, 200),
            Ok(FileIoAcquireResult::Contended { alertable: true })
        );
        assert_eq!(
            files.begin_io(10, 300),
            Ok(FileIoAcquireResult::Contended { alertable: true })
        );
        assert_eq!(files.io_waiter_count(10), Ok(2));

        assert_eq!(files.release_io(10, 100), Ok(FileIoRelease { waiters: 2 }));
        assert_eq!(files.promote_io_waiter(10, 200), Ok(1));
        assert_eq!(files.io_lock_owner(10), Ok(Some(200)));
        assert_eq!(files.begin_io(10, 200), Ok(FileIoAcquireResult::Acquired));
        // A second operation from the same thread is not confused with the consumed promotion.
        assert_eq!(
            files.begin_io(10, 200),
            Ok(FileIoAcquireResult::Contended { alertable: true })
        );
        assert_eq!(files.cancel_io_waiter(10), Ok(1));
        assert_eq!(files.release_io(10, 200), Ok(FileIoRelease { waiters: 1 }));
        assert_eq!(files.promote_io_waiter(10, 300), Ok(0));
        assert_eq!(files.begin_io(10, 300), Ok(FileIoAcquireResult::Acquired));
        assert_eq!(files.release_io(10, 300), Ok(FileIoRelease { waiters: 0 }));
        assert_eq!(files.io_lock_owner(10), Ok(None));
    }

    #[test]
    fn last_handle_cleanup_follows_every_existing_synchronous_waiter() {
        let mut files = FileCompletionTable::<1>::new();
        files
            .insert_file_with_mode(10, 77, FileIoMode::SynchronousNonAlertable)
            .unwrap();
        files.begin_io(10, 100).unwrap();
        assert!(matches!(
            files.begin_io(10, 200),
            Ok(FileIoAcquireResult::Contended { .. })
        ));

        let release = files.release_handle(10).unwrap();
        assert!(release.cleanup_required);
        assert!(!release.close_required);
        assert_eq!(files.begin_io(10, 300), Err(STATUS_INVALID_HANDLE));
        assert!(matches!(
            files.begin_cleanup(10),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        ));
        assert_eq!(files.io_waiter_count(10), Ok(1));

        assert_eq!(files.release_io(10, 100).unwrap().waiters, 1);
        assert_eq!(files.promote_cleanup_if_ready(10), Ok(false));
        files.promote_io_waiter(10, 200).unwrap();
        files.begin_io(10, 200).unwrap();
        assert_eq!(files.release_io(10, 200).unwrap().waiters, 0);
        assert_eq!(files.promote_cleanup_if_ready(10), Ok(true));
        assert!(files.io_lock_owner(10).unwrap().is_some());
        assert_eq!(files.promote_cleanup_if_ready(10), Ok(false));
        assert_eq!(files.mark_cleanup_lifecycle_started(10), Ok(true));
        assert_eq!(files.mark_cleanup_lifecycle_started(10), Ok(false));
        assert_eq!(files.active_cleanup_from(0), Some((0, 10)));
        assert_eq!(files.release_cleanup_io(10).unwrap().waiters, 0);
        assert!(files.release_cleanup_reference(10).unwrap().close_required);
        assert_eq!(files.io_mode(10), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn asynchronous_cleanup_bypasses_busy_but_keeps_its_reference() {
        let mut files = FileCompletionTable::<1>::new();
        files.insert_file(10, 77, false).unwrap();
        assert!(files.release_handle(10).unwrap().cleanup_required);
        assert_eq!(files.begin_cleanup(10), Ok(FileIoAcquireResult::Bypassed));
        files.mark_cleanup_lifecycle_started(10).unwrap();
        assert!(files.release_cleanup_reference(10).unwrap().close_required);
    }

    #[test]
    fn asynchronous_file_bypasses_serialization() {
        let mut files = FileCompletionTable::<1>::new();
        files.insert_file(10, 77, false).unwrap();
        assert_eq!(files.begin_io(10, 100), Ok(FileIoAcquireResult::Bypassed));
        assert_eq!(files.begin_io(10, 200), Ok(FileIoAcquireResult::Bypassed));
        assert_eq!(files.io_lock_owner(10), Ok(None));
        assert_eq!(files.io_waiter_count(10), Ok(0));
        assert_eq!(files.release_io(10, 100), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn cancelled_waiter_and_unconsumed_promotion_are_generation_exact() {
        let mut files = FileCompletionTable::<1>::new();
        files
            .insert_file_with_mode(10, 77, FileIoMode::SynchronousNonAlertable)
            .unwrap();
        files.begin_io(10, 100).unwrap();
        assert_eq!(
            files.begin_io(10, 200),
            Ok(FileIoAcquireResult::Contended { alertable: false })
        );
        assert_eq!(files.cancel_io_waiter(10), Ok(0));
        assert_eq!(files.cancel_io_waiter(10), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(files.release_io(10, 100), Ok(FileIoRelease { waiters: 0 }));

        files.begin_io(10, 300).unwrap();
        files.begin_io(10, 400).unwrap();
        files.release_io(10, 300).unwrap();
        files.promote_io_waiter(10, 400).unwrap();
        assert_eq!(
            files.cancel_promoted_io(10, 300),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            files.cancel_promoted_io(10, 400),
            Ok(FileIoRelease { waiters: 0 })
        );
    }

    #[test]
    fn file_completion_notification_modes_are_sticky_and_reject_sync_files() {
        let mut files = FileCompletionTable::<2>::new();
        files.insert_file(10, 77, false).unwrap();
        files.insert_file(20, 77, true).unwrap();

        assert_eq!(files.notification_modes(10), Ok(0));
        assert_eq!(
            files.set_notification_modes(10, FILE_SKIP_SET_EVENT_ON_HANDLE),
            Ok(FILE_SKIP_SET_EVENT_ON_HANDLE)
        );
        assert_eq!(
            files.set_notification_modes(10, 0),
            Ok(FILE_SKIP_SET_EVENT_ON_HANDLE)
        );
        assert_eq!(
            files.set_notification_modes(
                10,
                FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_USER_EVENT_ON_FAST_IO | 0x100,
            ),
            Ok(FILE_SKIP_SET_EVENT_ON_HANDLE
                | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
                | FILE_SKIP_SET_USER_EVENT_ON_FAST_IO)
        );
        assert_eq!(
            files.set_notification_modes(20, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn file_completion_policy_controls_handle_signal_and_port_packets() {
        let mut files = FileCompletionTable::<1>::new();
        files.insert_file(10, 77, false).unwrap();
        files
            .set_notification_modes(
                10,
                FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS,
            )
            .unwrap();

        files.set_signaled(10, false).unwrap();
        assert_eq!(files.complete_file(10, STATUS_SUCCESS), Ok(false));
        assert_eq!(files.is_signaled(10), Ok(false));
        assert_eq!(
            files.should_queue_completion_packet(10, 1, STATUS_SUCCESS, true, false),
            Ok(false)
        );
        assert_eq!(
            files.should_queue_completion_packet(10, 1, STATUS_SUCCESS, false, false),
            Ok(true)
        );
        assert_eq!(
            files.should_queue_completion_packet(10, 1, STATUS_TIMEOUT, true, false),
            Ok(true)
        );
        assert_eq!(
            files.should_queue_completion_packet(10, 1, STATUS_TIMEOUT, true, true),
            Ok(false)
        );
        assert_eq!(
            files.should_queue_completion_packet(10, 0, STATUS_TIMEOUT, false, false),
            Ok(false)
        );

        assert_eq!(files.complete_file(10, STATUS_TIMEOUT), Ok(true));
        assert_eq!(files.is_signaled(10), Ok(true));
    }

    #[test]
    fn completion_port_packets_preserve_null_apc_context() {
        let mut ports = Ports::new();
        let port = ports.create(&[], 0, false).unwrap();
        let packet = CompletionPacket {
            key_context: 0x1234_5678,
            apc_context: 0,
            status: STATUS_SUCCESS,
            information: 72,
        };

        assert_eq!(ports.enqueue(port.id, packet), Ok(()));
        assert_eq!(
            ports.remove(port.id, RemoveMode::Poll),
            Ok(RemoveResult::Packet(packet))
        );
    }

    #[test]
    fn file_completion_binding_rejects_sync_rebind_and_capacity_overflow() {
        let mut files = FileCompletionTable::<2>::new();
        files.insert_file(10, 77, true).unwrap();
        assert_eq!(
            files.associate(10, FileCompletionBinding::default()),
            Err(STATUS_INVALID_PARAMETER)
        );
        files.insert_file(20, 77, false).unwrap();
        assert_eq!(
            files.associate(
                20,
                FileCompletionBinding {
                    port_id: 1,
                    key_context: 2,
                },
            ),
            Ok(())
        );
        assert_eq!(
            files.associate(20, FileCompletionBinding::default()),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(files.can_associate(20), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            files.insert_file(30, 77, false),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(files.retain_file(99), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn completion_packets_are_fifo_but_waiters_are_lifo_per_port() {
        let mut waiters = CompletionWaiterTable::new();
        waiters.insert(waiter(1, 10, INFINITE_DEADLINE)).unwrap();
        waiters.insert(waiter(2, 20, INFINITE_DEADLINE)).unwrap();
        waiters.insert(waiter(1, 30, INFINITE_DEADLINE)).unwrap();
        assert_eq!(waiters.pop_port(1).unwrap().reply_cap, 30);
        assert_eq!(waiters.pop_port(1).unwrap().reply_cap, 10);
        assert_eq!(waiters.pop_port(1), None);
        assert_eq!(waiters.pop_port(2).unwrap().reply_cap, 20);
        assert!(waiters.is_empty());
    }

    #[test]
    fn completion_waiter_reply_identity_and_dynamic_growth_are_enforced() {
        let mut waiters = CompletionWaiterTable::new();
        assert_eq!(
            waiters.insert(waiter(1, 0, INFINITE_DEADLINE)),
            Err(STATUS_INVALID_PARAMETER)
        );
        waiters.insert(waiter(1, 1, INFINITE_DEADLINE)).unwrap();
        assert_eq!(
            waiters.insert(waiter(2, 1, INFINITE_DEADLINE)),
            Err(STATUS_INVALID_PARAMETER)
        );
        waiters.insert(waiter(2, 2, INFINITE_DEADLINE)).unwrap();
        waiters.insert(waiter(3, 3, INFINITE_DEADLINE)).unwrap();
        assert_eq!(waiters.len(), 3);
        assert!(waiters.records() >= 3);
        assert!(waiters.capacity() >= waiters.records());
        assert_eq!(waiters.allocation_failures(), 0);
        assert_eq!(waiters.store_failures(), 0);
    }

    #[test]
    fn completion_waiter_deadlines_are_ordered_and_infinite_is_ignored() {
        let mut waiters = CompletionWaiterTable::new();
        waiters.insert(waiter(1, 1, INFINITE_DEADLINE)).unwrap();
        waiters.insert(waiter(1, 2, 200)).unwrap();
        waiters.insert(waiter(2, 3, 100)).unwrap();
        waiters.insert(waiter(3, 4, 100)).unwrap();
        assert_eq!(waiters.next_deadline(), Some(100));
        assert_eq!(waiters.pop_due(99), None);
        assert_eq!(waiters.pop_due(100).unwrap().reply_cap, 3);
        assert_eq!(waiters.pop_due(100).unwrap().reply_cap, 4);
        assert_eq!(waiters.next_deadline(), Some(200));
        assert_eq!(waiters.pop_due(200).unwrap().reply_cap, 2);
        assert_eq!(waiters.next_deadline(), None);
        assert_eq!(waiters.len(), 1);
    }

    #[test]
    fn completion_waiters_cancel_by_thread_without_disturbing_others() {
        let mut waiters = CompletionWaiterTable::new();
        waiters.insert(waiter(1, 1, INFINITE_DEADLINE)).unwrap();
        let mut second = waiter(1, 2, INFINITE_DEADLINE);
        second.thread_id = 101;
        waiters.insert(second).unwrap();
        waiters.insert(waiter(2, 3, INFINITE_DEADLINE)).unwrap();
        assert_eq!(waiters.pop_thread(101).unwrap().reply_cap, 1);
        assert_eq!(waiters.pop_thread(101).unwrap().reply_cap, 2);
        assert_eq!(waiters.pop_thread(101), None);
        assert_eq!(waiters.pop_port(2).unwrap().reply_cap, 3);
    }

    #[test]
    fn completion_waiters_cancel_by_process_without_disturbing_others() {
        let mut waiters = CompletionWaiterTable::new();
        let mut first = waiter(1, 1, INFINITE_DEADLINE);
        first.process_index = 2;
        waiters.insert(first).unwrap();
        let mut second = waiter(2, 2, INFINITE_DEADLINE);
        second.process_index = 3;
        waiters.insert(second).unwrap();
        let mut third = waiter(1, 3, INFINITE_DEADLINE);
        third.process_index = 2;
        waiters.insert(third).unwrap();
        assert_eq!(waiters.pop_process(2).unwrap().reply_cap, 1);
        assert_eq!(waiters.pop_process(2).unwrap().reply_cap, 3);
        assert_eq!(waiters.pop_process(2), None);
        assert_eq!(waiters.pop_port(2).unwrap().reply_cap, 2);
    }
}
