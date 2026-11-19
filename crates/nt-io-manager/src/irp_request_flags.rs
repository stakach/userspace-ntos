//! Request-wide `IRP.Flags` chosen by the request's originator.
//!
//! Values are the WDK definitions (`wdm.h`; ReactOS `sdk/include/xdk/iotypes.h`). Two bit pairs
//! alias each other: `IRP_PAGING_IO == IRP_MOUNT_COMPLETION` and
//! `IRP_SYNCHRONOUS_PAGING_IO == IRP_INPUT_OPERATION`, so a raw word is meaningful only together
//! with its major function. This type names the originator's intent instead of a raw word, which
//! keeps paging bits off non-transfer majors and mount completion off ordinary I/O.
//!
//! Buffer-method bits (`IRP_BUFFERED_IO`, `IRP_DEALLOCATE_BUFFER`, `IRP_INPUT_OPERATION`) are not
//! request-wide: the Driver Host derives them from the target device's transfer method.

pub const IRP_NOCACHE: u32 = 0x0000_0001;
pub const IRP_PAGING_IO: u32 = 0x0000_0002;
pub const IRP_MOUNT_COMPLETION: u32 = 0x0000_0002;
pub const IRP_SYNCHRONOUS_API: u32 = 0x0000_0004;
pub const IRP_SYNCHRONOUS_PAGING_IO: u32 = 0x0000_0040;

const IRP_MN_MOUNT_VOLUME: u8 = 0x01;
const IRP_MN_VERIFY_VOLUME: u8 = 0x02;

/// The Memory Manager transfer that issued a paging IRP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingTransfer {
    /// `IoPageRead`: a page-in for a Section or image fault.
    Read,
    /// `IoSynchronousPageWrite`: `MmFlushSection` for NtFlushVirtualMemory, segment deletion and
    /// cache flush.
    SynchronousWrite,
    /// `IoAsynchronousPageWrite`: the mapped page writer's deferred writeback.
    AsynchronousWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    Ordinary { synchronous_api: bool, no_intermediate_buffering: bool },
    Paging(PagingTransfer),
    MountCompletion,
}

/// The request-wide part of `IRP.Flags`. Every value names a combination NT issues for some
/// major; [`admits`](Self::admits) rejects it for any other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrpRequestFlags(Origin);

impl Default for IrpRequestFlags {
    fn default() -> Self {
        Self::NONE
    }
}

impl IrpRequestFlags {
    pub const NONE: Self = Self(Origin::Ordinary {
        synchronous_api: false,
        no_intermediate_buffering: false,
    });

    /// An API request. `IRP_SYNCHRONOUS_API` marks an IRP the caller waits for on a local event;
    /// `IRP_NOCACHE` follows the File's `FO_NO_INTERMEDIATE_BUFFERING` on READ and WRITE
    /// (ReactOS iofunc.c NtReadFile/NtWriteFile).
    pub const fn api(synchronous_api: bool, no_intermediate_buffering: bool) -> Self {
        Self(Origin::Ordinary { synchronous_api, no_intermediate_buffering })
    }

    /// `IoPageRead`/`IoSynchronousPageWrite`/`IoAsynchronousPageWrite` (ReactOS iofunc.c,
    /// NT5 iosubs.c): paging I/O is never cached.
    pub const fn paging(transfer: PagingTransfer) -> Self {
        Self(Origin::Paging(transfer))
    }

    /// `IopMountVolume`/`IoVerifyVolume` (NT5 internal.c, iosubs.c).
    pub const fn mount_completion() -> Self {
        Self(Origin::MountCompletion)
    }

    pub const fn paging_transfer(self) -> Option<PagingTransfer> {
        match self.0 {
            Origin::Paging(transfer) => Some(transfer),
            _ => None,
        }
    }

    /// Paging I/O never moves `FILE_OBJECT.CurrentByteOffset` (ReactOS vfatfs rw.c,
    /// NT5 fastfat read.c/write.c).
    pub const fn is_paging_io(self) -> bool {
        matches!(self.0, Origin::Paging(_))
    }

    pub const fn bits(self) -> u32 {
        match self.0 {
            Origin::Ordinary { synchronous_api, no_intermediate_buffering } => {
                (if synchronous_api { IRP_SYNCHRONOUS_API } else { 0 })
                    | if no_intermediate_buffering { IRP_NOCACHE } else { 0 }
            }
            Origin::Paging(PagingTransfer::Read | PagingTransfer::SynchronousWrite) => {
                IRP_PAGING_IO | IRP_NOCACHE | IRP_SYNCHRONOUS_PAGING_IO
            }
            Origin::Paging(PagingTransfer::AsynchronousWrite) => IRP_PAGING_IO | IRP_NOCACHE,
            Origin::MountCompletion => IRP_MOUNT_COMPLETION | IRP_SYNCHRONOUS_PAGING_IO,
        }
    }

    /// Whether NT issues this combination for `major`/`minor`.
    pub const fn admits(self, major: u8, minor: u8) -> bool {
        use nt_io_abi::major::{IRP_MJ_FILE_SYSTEM_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE};
        match self.0 {
            Origin::Ordinary { no_intermediate_buffering, .. } => {
                !no_intermediate_buffering || major == IRP_MJ_READ || major == IRP_MJ_WRITE
            }
            Origin::Paging(PagingTransfer::Read) => major == IRP_MJ_READ,
            Origin::Paging(_) => major == IRP_MJ_WRITE,
            Origin::MountCompletion => {
                major == IRP_MJ_FILE_SYSTEM_CONTROL
                    && (minor == IRP_MN_MOUNT_VOLUME || minor == IRP_MN_VERIFY_VOLUME)
            }
        }
    }

    /// Decode a transported word. Exactly the words [`bits`](Self::bits) produces for an
    /// admitted origin are accepted; the major function disambiguates the aliased bits.
    pub fn from_wire(major: u8, minor: u8, bits: u32) -> Option<Self> {
        let candidates = [
            Self::api(false, false),
            Self::api(true, false),
            Self::api(false, true),
            Self::api(true, true),
            Self::paging(PagingTransfer::Read),
            Self::paging(PagingTransfer::SynchronousWrite),
            Self::paging(PagingTransfer::AsynchronousWrite),
            Self::mount_completion(),
        ];
        candidates
            .into_iter()
            .find(|candidate| candidate.admits(major, minor) && candidate.bits() == bits)
    }
}

#[cfg(test)]
#[path = "irp_request_flags_tests.rs"]
mod tests;
