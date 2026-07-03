//! File object records + their lifecycle state machine (spec §12).

use nt_io_abi::{DeviceId, FileId};
use nt_types::{AccessMask, ClientId, NtPath, ObjectId};

bitflags::bitflags! {
    /// `FILE_SHARE_*` share access.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct ShareAccess: u32 {
        const READ = 0x0000_0001;
        const WRITE = 0x0000_0002;
        const DELETE = 0x0000_0004;
    }
}

bitflags::bitflags! {
    /// `FILE_*` create options.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct CreateOptions: u32 {
        const DIRECTORY_FILE = 0x0000_0001;
        const WRITE_THROUGH = 0x0000_0002;
        const SEQUENTIAL_ONLY = 0x0000_0004;
        const SYNCHRONOUS_IO_ALERT = 0x0000_0010;
        const SYNCHRONOUS_IO_NONALERT = 0x0000_0020;
        const NON_DIRECTORY_FILE = 0x0000_0040;
        const DELETE_ON_CLOSE = 0x0000_1000;
    }
}

bitflags::bitflags! {
    /// Internal `FO_*`-style file-object flags.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct FileFlags: u32 {
        const SYNCHRONOUS_IO = 0x0000_0001;
        const CLEANUP_COMPLETE = 0x0000_0002;
    }
}

/// File lifecycle (spec §12.2). `IRP_MJ_CREATE` must succeed (→ `Open`) before a
/// usable handle is returned; cleanup (handle release) and close (final deref)
/// are kept distinct even where a simple device collapses them.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum FileState {
    #[default]
    Allocated,
    CreateIrpDispatched,
    Open,
    CleanupPending,
    CleanupComplete,
    ClosePending,
    Closed,
}

impl FileState {
    /// Whether `self -> next` is an allowed transition (spec §12.2).
    pub fn can_transition_to(self, next: FileState) -> bool {
        use FileState::*;
        matches!(
            (self, next),
            (Allocated, CreateIrpDispatched)
                | (Allocated, Closed) // create never dispatched (early failure)
                | (CreateIrpDispatched, Open)
                | (CreateIrpDispatched, Closed) // create failed
                | (Open, CleanupPending)
                | (Open, ClosePending)
                | (CleanupPending, CleanupComplete)
                | (CleanupComplete, ClosePending)
                | (CleanupComplete, Closed)
                | (ClosePending, Closed)
        )
    }

    /// A usable (opened, not yet cleaned-up) file.
    pub fn is_open(self) -> bool {
        matches!(self, FileState::Open)
    }

    /// The file has been fully closed.
    pub fn is_closed(self) -> bool {
        matches!(self, FileState::Closed)
    }
}

/// Canonical I/O Manager file-object record (spec §12.1). A File is an open
/// instance of a Device. `object_id` points at the Object Manager `File` object;
/// the canonical handle lives in the Object Manager's per-client table.
///
/// Note: the spec's separate `cleanup_done`/`close_done` booleans are subsumed by
/// the [`FileState`] machine here, which keeps cleanup and close distinct.
pub struct FileRecord {
    pub id: FileId,
    pub object_id: ObjectId,
    pub client_id: ClientId,
    pub device_id: DeviceId,
    pub desired_access: AccessMask,
    pub share_access: ShareAccess,
    pub create_options: CreateOptions,
    pub flags: FileFlags,
    pub related_file: Option<FileId>,
    pub file_name: Option<NtPath>,
    pub state: FileState,
}

impl FileRecord {
    /// A freshly-allocated file record (id filled in by the store's caller).
    pub fn new(
        object_id: ObjectId,
        client_id: ClientId,
        device_id: DeviceId,
        desired_access: AccessMask,
        share_access: ShareAccess,
        create_options: CreateOptions,
        file_name: Option<NtPath>,
    ) -> Self {
        Self {
            id: FileId::NULL,
            object_id,
            client_id,
            device_id,
            desired_access,
            share_access,
            create_options,
            flags: FileFlags::empty(),
            related_file: None,
            file_name,
            state: FileState::Allocated,
        }
    }

    /// Advance the lifecycle state if the transition is allowed. Returns whether
    /// the transition was applied.
    pub fn transition(&mut self, next: FileState) -> bool {
        if self.state.can_transition_to(next) {
            self.state = next;
            true
        } else {
            false
        }
    }
}
