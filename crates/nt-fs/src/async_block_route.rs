//! Shared physical block route for the mounted FAT reader and snapshot reserve.
//!
//! This is a pure request owner. It calls neither a driver nor the completion pump: a native
//! operation enters here before dispatch, then its exact completion is fed back by a top-level
//! continuation. The executive owns the actual buffers, SRBs, Replies and route proof.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockSource {
    Fat,
    Snapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOperation {
    Read { lba: u64, sectors: u32 },
    Write { lba: u64, sectors: u32 },
    Flush,
}

impl BlockOperation {
    fn transfer_bytes(self) -> u64 {
        match self {
            Self::Read { sectors, .. } | Self::Write { sectors, .. } => u64::from(sectors) * 512,
            Self::Flush => 0,
        }
    }

    fn valid(self, disk_sectors: u64) -> bool {
        match self {
            Self::Read { lba, sectors } | Self::Write { lba, sectors } => {
                sectors != 0
                    && lba
                        .checked_add(u64::from(sectors))
                        .is_some_and(|end| end <= disk_sectors)
            }
            Self::Flush => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockSourceKind {
    Boot,
    Draining,
    Native,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRouteError {
    InvalidMount,
    InvalidGeometry,
    InvalidRoute,
    WrongMount,
    WrongPhase,
    NativeIoOutstanding,
    WrongTicket,
    Incomplete,
    IdExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBlockTicket {
    pub mount: u64,
    pub route: u64,
    pub sequence: u64,
    pub source: BlockSource,
    pub operation: BlockOperation,
}

/// One physical disk and mount identity. The FAT and snapshot backends must share this owner.
/// The controller's `PciDmaHandoff` is the sole authority for direct boot AHCI commands and
/// their `BootIoTicket`s; this owner fences new mount calls and retains native requests only.
pub struct BlockRouteOwner {
    mount: u64,
    disk_sectors: u64,
    phase: BlockSourceKind,
    native_route: Option<u64>,
    native_io: Option<NativeBlockTicket>,
    native_entered: bool,
    next_sequence: u64,
}

impl BlockRouteOwner {
    pub fn new(mount: u64, disk_sectors: u64) -> Result<Self, BlockRouteError> {
        if mount == 0 {
            return Err(BlockRouteError::InvalidMount);
        }
        if disk_sectors == 0 {
            return Err(BlockRouteError::InvalidGeometry);
        }
        Ok(Self {
            mount,
            disk_sectors,
            phase: BlockSourceKind::Boot,
            native_route: None,
            native_io: None,
            native_entered: false,
            next_sequence: 1,
        })
    }

    pub const fn source_kind(&self) -> BlockSourceKind {
        self.phase
    }
    pub const fn native_route(&self) -> Option<u64> {
        self.native_route
    }
    pub const fn pending_native(&self) -> Option<NativeBlockTicket> {
        self.native_io
    }

    fn check_mount(&self, mount: u64) -> Result<(), BlockRouteError> {
        if self.mount == mount {
            Ok(())
        } else {
            Err(BlockRouteError::WrongMount)
        }
    }

    fn sequence(&mut self) -> Result<u64, BlockRouteError> {
        let current = self.next_sequence;
        self.next_sequence = current.checked_add(1).ok_or(BlockRouteError::IdExhausted)?;
        Ok(current)
    }

    /// Guard either mounted backend before it enters direct AHCI. The actual command and its
    /// retirement are tracked once, by `PciDmaHandoff::BootIoTicket` at the controller boundary.
    /// The executive serializes mount calls on its service loop, so a drain cannot race a call
    /// that already passed this guard; the controller ledger still fences all in-flight commands.
    pub fn admit_boot(
        &self,
        mount: u64,
        _source: BlockSource,
        operation: BlockOperation,
    ) -> Result<(), BlockRouteError> {
        self.check_mount(mount)?;
        if self.phase != BlockSourceKind::Boot {
            return Err(BlockRouteError::WrongPhase);
        }
        if !operation.valid(self.disk_sectors) {
            return Err(BlockRouteError::InvalidGeometry);
        }
        Ok(())
    }

    /// Fence both FAT and snapshot entry paths. The controller ledger separately drains and
    /// proves retirement of every direct boot command before native controller startup.
    pub fn begin_drain(&mut self, mount: u64) -> Result<(), BlockRouteError> {
        self.check_mount(mount)?;
        if self.phase != BlockSourceKind::Boot {
            return Err(BlockRouteError::WrongPhase);
        }
        self.phase = BlockSourceKind::Draining;
        Ok(())
    }

    /// Record an externally authenticated native block route under the *same* mount identity.
    /// Callers must first prove the native PDO and disk through the storage handoff owner.
    pub fn commit_native(&mut self, mount: u64, route: u64) -> Result<(), BlockRouteError> {
        self.check_mount(mount)?;
        if self.phase != BlockSourceKind::Draining {
            return Err(BlockRouteError::WrongPhase);
        }
        if route == 0 {
            return Err(BlockRouteError::InvalidRoute);
        }
        self.native_route = Some(route);
        self.phase = BlockSourceKind::Native;
        Ok(())
    }

    /// Reserve a native request before dispatch. The request and its buffer remain owned by the
    /// caller while the top-level completion pump runs on a later turn.
    pub fn enter_native(
        &mut self,
        mount: u64,
        source: BlockSource,
        operation: BlockOperation,
    ) -> Result<NativeBlockTicket, BlockRouteError> {
        self.check_mount(mount)?;
        if self.phase != BlockSourceKind::Native {
            return Err(BlockRouteError::WrongPhase);
        }
        if !operation.valid(self.disk_sectors) {
            return Err(BlockRouteError::InvalidGeometry);
        }
        if self.native_io.is_some() {
            return Err(BlockRouteError::NativeIoOutstanding);
        }
        let route = self.native_route.ok_or(BlockRouteError::InvalidRoute)?;
        let ticket = NativeBlockTicket {
            mount,
            route,
            sequence: self.sequence()?,
            source,
            operation,
        };
        self.native_io = Some(ticket);
        self.native_entered = false;
        Ok(ticket)
    }

    /// Undo a reservation only when the transport proves the provider was never entered.
    /// Once entry is possible, the exact ticket remains retained until terminal completion.
    pub fn cancel_unentered_native(
        &mut self,
        ticket: NativeBlockTicket,
    ) -> Result<(), BlockRouteError> {
        if self.native_io != Some(ticket) {
            return Err(BlockRouteError::WrongTicket);
        }
        if self.native_entered {
            return Err(BlockRouteError::WrongPhase);
        }
        self.native_io = None;
        Ok(())
    }

    pub fn lose_native(&mut self, ticket: NativeBlockTicket) -> Result<(), BlockRouteError> {
        if self.native_io != Some(ticket) {
            return Err(BlockRouteError::WrongTicket);
        }
        // The retained ticket is the fence; only its exact late completion may resolve it.
        self.native_entered = true;
        Ok(())
    }

    /// A late exact completion resolves an uncertain request. Neither an ACK nor a timeout
    /// permits replay; the caller must authenticate the original driver completion first.
    pub fn complete_native(
        &mut self,
        ticket: NativeBlockTicket,
        transferred_bytes: u64,
    ) -> Result<(), BlockRouteError> {
        if self.native_io != Some(ticket) {
            return Err(BlockRouteError::WrongTicket);
        }
        if !self.native_entered {
            return Err(BlockRouteError::WrongPhase);
        }
        if transferred_bytes != ticket.operation.transfer_bytes() {
            return Err(BlockRouteError::Incomplete);
        }
        self.native_io = None;
        self.native_entered = false;
        Ok(())
    }

    /// Retire an entered command whose exact provider terminal and acknowledgement report
    /// failure. The operation fails to its caller; this only releases the physical route.
    pub fn complete_native_failure(
        &mut self,
        ticket: NativeBlockTicket,
    ) -> Result<(), BlockRouteError> {
        if self.native_io != Some(ticket) {
            return Err(BlockRouteError::WrongTicket);
        }
        if !self.native_entered {
            return Err(BlockRouteError::WrongPhase);
        }
        self.native_io = None;
        self.native_entered = false;
        Ok(())
    }
}
