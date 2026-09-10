//! Canonical File ownership without encoding filesystem domains into object-number bits.

use super::{PendingFileIo, PendingFileIoOperation};

/// Independent local FILE_OBJECT namespaces. Zero is a valid object number in each table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalFileObject {
    ReadonlyFile(u32),
    ReadonlyDirectory(u32),
    Overlay(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFileRoute {
    Hosted(u64),
    Local(LocalFileObject),
}

impl Default for PendingFileRoute {
    fn default() -> Self {
        Self::Hosted(0)
    }
}

impl PendingFileRoute {
    pub const fn hosted_file_id(self) -> Option<u64> {
        match self {
            Self::Hosted(file_id) => Some(file_id),
            Self::Local(_) => None,
        }
    }

    pub const fn local_file_object(self) -> Option<LocalFileObject> {
        match self {
            Self::Hosted(_) => None,
            Self::Local(file) => Some(file),
        }
    }

    pub(super) const fn is_valid(self) -> bool {
        !matches!(self, Self::Hosted(0))
    }
}

impl PendingFileIo {
    pub const fn hosted_file_id(self) -> Option<u64> {
        self.route.hosted_file_id()
    }

    pub const fn local_file_object(self) -> Option<LocalFileObject> {
        self.route.local_file_object()
    }

    pub(super) fn route_matches_operation(self) -> bool {
        use LocalFileObject::{Overlay, ReadonlyDirectory, ReadonlyFile};
        use PendingFileRoute::{Hosted, Local};
        match self.operation {
            PendingFileIoOperation::Transfer
            | PendingFileIoOperation::Create(_)
            | PendingFileIoOperation::SetFileName(_) => matches!(self.route, Hosted(_)),
            PendingFileIoOperation::LocalByteLock(_) => {
                matches!(self.route, Local(ReadonlyFile(_) | Overlay(_)))
            }
            PendingFileIoOperation::LocalDirectoryNotify(_) => {
                matches!(self.route, Local(ReadonlyDirectory(_) | Overlay(_)))
            }
            PendingFileIoOperation::LocalInline(_) => matches!(self.route, Local(_)),
            PendingFileIoOperation::LocalBuffered(_) => match self.major {
                nt_io_abi::major::IRP_MJ_READ => {
                    matches!(self.route, Local(ReadonlyFile(_) | Overlay(_)))
                }
                nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL => {
                    matches!(self.route, Local(ReadonlyDirectory(_) | Overlay(_)))
                }
                _ => false,
            },
            PendingFileIoOperation::LocalFlush(_) => matches!(self.route, Local(Overlay(_))),
        }
    }
}

#[cfg(test)]
#[path = "route/tests.rs"]
mod tests;
