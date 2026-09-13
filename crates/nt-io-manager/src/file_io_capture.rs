//! A fresh authenticated handle capture owns a canonical File pointer before any callout.
//! This is not a handle reference: last-handle CLEANUP remains legal, while CLOSE waits for
//! retirement. Neither retirement nor its bounded retry invokes a driver backend.

use crate::{DeviceId, FileId, FileReference, IoManager};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_status::NtStatus;

static LAST_TABLE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIoCaptureIdentity {
    table: u64,
    slot: usize,
    generation: u64,
}

impl FileIoCaptureIdentity {
    pub const fn slot(self) -> usize {
        self.slot
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIoCaptureSnapshot {
    pub file_id: FileId,
    pub device_id: DeviceId,
    pub fs_context: u64,
    pub granted_access: u32,
}

/// Dropping the token cannot discard its table-owned reference. The caller must explicitly
/// retire it on every exit, normally using a native scope guard.
///
/// ```compile_fail
/// use nt_io_manager::file_io_capture::FileIoCapture;
/// fn duplicate(capture: FileIoCapture) { let _copy = capture.clone(); }
/// ```
#[derive(Debug)]
#[must_use = "retire a File capture after acquisition or an early return"]
pub struct FileIoCapture {
    identity: FileIoCaptureIdentity,
    snapshot: FileIoCaptureSnapshot,
    held: bool,
}

impl FileIoCapture {
    pub const fn identity(&self) -> FileIoCaptureIdentity {
        self.identity
    }
    pub const fn snapshot(&self) -> FileIoCaptureSnapshot {
        self.snapshot
    }
    pub const fn file_id(&self) -> FileId {
        self.snapshot.file_id
    }
    pub const fn device_id(&self) -> DeviceId {
        self.snapshot.device_id
    }
    pub const fn fs_context(&self) -> u64 {
        self.snapshot.fs_context
    }
    pub const fn granted_access(&self) -> u32 {
        self.snapshot.granted_access
    }
    pub const fn is_held(&self) -> bool {
        self.held
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIoCaptureView {
    pub snapshot: FileIoCaptureSnapshot,
    pub retiring: bool,
    pub last_error: Option<NtStatus>,
}

struct Row {
    generation: u64,
    reference: FileReference,
    view: FileIoCaptureView,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileIoCaptureRedrive {
    pub attempted: usize,
    pub released: usize,
    pub refused: usize,
}

pub struct FileIoCaptureTable {
    rows: Vec<Option<Row>>,
    identity: u64,
    next_generation: u64,
    cursor: usize,
}

impl Default for FileIoCaptureTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FileIoCaptureTable {
    pub const fn new() -> Self {
        Self {
            rows: Vec::new(),
            identity: 0,
            next_generation: 1,
            cursor: 0,
        }
    }

    /// The caller authenticates the handle and passes its granted access, not desired access.
    /// Route validation, snapshot and reference acquisition are memory-only and indivisible with
    /// respect to native callouts. Reserve all table storage before acquiring the reference.
    pub fn capture<P>(
        &mut self,
        io: &mut IoManager<P>,
        file: FileId,
        expected_device: DeviceId,
        granted_access: u32,
    ) -> Result<FileIoCapture, NtStatus> {
        let record = io.file(file).ok_or(NtStatus::INVALID_HANDLE)?;
        if expected_device == DeviceId::NULL
            || record.device_id != expected_device
            || !record.state.is_open()
        {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let snapshot = FileIoCaptureSnapshot {
            file_id: file,
            device_id: record.device_id,
            fs_context: record.driver_context.unwrap_or(0),
            granted_access,
        };
        let generation = self.next_generation;
        if generation == 0 {
            return Err(NtStatus::INSUFFICIENT_RESOURCES);
        }
        let slot = self
            .rows
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.rows.len());
        if slot == self.rows.len() {
            self.rows
                .try_reserve(1)
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        }
        if self.identity == 0 {
            self.identity = LAST_TABLE
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                    last.checked_add(1)
                })
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?
                + 1;
        }
        let reference = io.retain_file_reference(file)?;
        let identity = FileIoCaptureIdentity {
            table: self.identity,
            slot,
            generation,
        };
        self.next_generation = generation.checked_add(1).unwrap_or(0);
        let row = Some(Row {
            generation,
            reference,
            view: FileIoCaptureView {
                snapshot,
                retiring: false,
                last_error: None,
            },
        });
        if slot == self.rows.len() {
            self.rows.push(row);
        } else {
            self.rows[slot] = row;
        }
        Ok(FileIoCapture {
            identity,
            snapshot,
            held: true,
        })
    }

    fn row(&self, identity: FileIoCaptureIdentity) -> Option<&Row> {
        if identity.table == 0 || identity.table != self.identity {
            return None;
        }
        self.rows
            .get(identity.slot)?
            .as_ref()
            .filter(|row| row.generation == identity.generation)
    }

    pub fn get(&self, identity: FileIoCaptureIdentity) -> Option<FileIoCaptureView> {
        self.row(identity).map(|row| row.view)
    }

    /// Wrong-table and repeated retirement refuse without consuming the token.
    pub fn retire(&mut self, capture: &mut FileIoCapture) -> Result<(), NtStatus> {
        let row = self
            .row(capture.identity)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if !capture.held || row.view.retiring || row.view.snapshot != capture.snapshot {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.rows[capture.identity.slot]
            .as_mut()
            .unwrap()
            .view
            .retiring = true;
        capture.held = false;
        Ok(())
    }

    /// A refused canonical release retains the exact owner for retry, including wrong-manager
    /// calls. Successful final dereference only queues CLOSE for the normal outer I/O pump.
    pub fn release_retired<P>(
        &mut self,
        io: &mut IoManager<P>,
        identity: FileIoCaptureIdentity,
    ) -> Result<(), NtStatus> {
        if !self
            .row(identity)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .view
            .retiring
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let row = self.rows[identity.slot].as_mut().unwrap();
        match io.release_file_reference(&mut row.reference) {
            Ok(()) => {
                self.rows[identity.slot] = None;
                Ok(())
            }
            Err(status) => {
                row.view.last_error = Some(status);
                Err(status)
            }
        }
    }

    /// At most `budget` releases and one initial table-length scan. The persistent cursor keeps
    /// refusing owners from starving later rows. Active captures are never retired implicitly.
    pub fn redrive<P>(&mut self, io: &mut IoManager<P>, budget: usize) -> FileIoCaptureRedrive {
        let mut report = FileIoCaptureRedrive::default();
        let slots = self.rows.len();
        for _ in 0..slots {
            if report.attempted == budget {
                break;
            }
            let slot = self.cursor % slots;
            self.cursor = (slot + 1) % slots;
            let Some(row) = self.rows[slot].as_ref().filter(|row| row.view.retiring) else {
                continue;
            };
            let identity = FileIoCaptureIdentity {
                table: self.identity,
                slot,
                generation: row.generation,
            };
            report.attempted += 1;
            if self.release_retired(io, identity).is_ok() {
                report.released += 1;
            } else {
                report.refused += 1;
            }
        }
        report
    }

    pub fn is_empty(&self) -> bool {
        self.rows.iter().all(Option::is_none)
    }

    pub fn reset(&mut self) -> Result<(), NtStatus> {
        if !self.is_empty() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.rows.clear();
        self.cursor = 0;
        Ok(())
    }
}

#[cfg(test)]
#[path = "file_io_capture/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "file_io_capture/policy_tests.rs"]
mod policy_tests;
