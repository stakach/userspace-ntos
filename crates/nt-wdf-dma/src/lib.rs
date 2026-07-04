//! # `nt-wdf-dma` — WDF DMA objects
//!
//! The three WDF DMA wrappers (spec: NT KMDF Hardware Extensions, §8-§10) over the existing
//! `nt-dma-manager` + `nt-mdl` substrate:
//!
//! - **WDFDMAENABLER** — a bus-master DMA adapter with a profile + maximum length (§8).
//! - **WDFCOMMONBUFFER** — a CPU buffer + a **fake logical address** from the DMA Manager
//!   (never a host physical address, §9.4). A device DMAs only to a buffer mapped for it.
//! - **WDFDMATRANSACTION** — a one-segment map → `EvtProgramDma` → complete state machine
//!   over a request MDL (§10.3).
//!
//! `WdfDmaManager` owns an `nt_dma_manager::DmaManager` + `nt_mdl::MdlRegistry` and keys the
//! WDF objects by their handle value (`WdfHandle.0`), so the runtime allocates the handle and
//! this crate holds the DMA-specific record. `no_std` + `alloc`; logical addresses are
//! allocator-controlled fakes, no raw driver pointers beyond opaque address integers.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use nt_dma_manager::{DmaError, DmaManager, DmaOwner};
use nt_mdl::MdlRegistry;

/// `WDF_DMA_PROFILE` (spec §8.2). v0.2 accepts all but uses only the common-buffer path.
pub const WDF_DMA_PROFILE_PACKET: u32 = 0;
pub const WDF_DMA_PROFILE_SCATTER_GATHER: u32 = 1;
pub const WDF_DMA_PROFILE_PACKET64: u32 = 2;
pub const WDF_DMA_PROFILE_SCATTER_GATHER64: u32 = 3;

/// Why a WDF DMA operation was rejected.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WdfDmaError {
    /// No such enabler / common buffer / transaction for this handle.
    StaleHandle,
    /// The transaction is not in the right state for this call (spec §10).
    BadState,
    /// The DMA Manager rejected the operation.
    Dma(DmaError),
    /// A length / range parameter is invalid.
    OutOfRange,
}

impl From<DmaError> for WdfDmaError {
    fn from(e: DmaError) -> Self {
        WdfDmaError::Dma(e)
    }
}

struct Enabler {
    handle: u64,
    owner: DmaOwner,
    adapter_id: u64,
    profile: u32,
    maximum_length: u64,
}

struct CommonBuffer {
    handle: u64,
    owner: DmaOwner,
    virtual_address: u64,
    logical_address: u64,
    length: u64,
}

/// A WDFDMATRANSACTION's state (spec §10.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransactionState {
    Created,
    Initialized,
    Executing,
    Completed,
}

struct Transaction {
    handle: u64,
    owner: DmaOwner,
    request: u64,
    mdl_id: u64,
    direction: u32,
    total_length: u64,
    backing_va: u64,
    bytes_transferred: u64,
    mapping_id: u64,
    logical_address: u64,
    evt_program_dma: u64,
    state: TransactionState,
}

/// The result of executing a transaction — what the Driver Host feeds `EvtProgramDma`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DmaExecution {
    pub logical_address: u64,
    pub length: u64,
    pub evt_program_dma: u64,
}

/// The canonical WDF DMA state for one Driver Host.
#[derive(Default)]
pub struct WdfDmaManager {
    dma: DmaManager,
    mdl: MdlRegistry,
    enablers: Vec<Enabler>,
    common_buffers: Vec<CommonBuffer>,
    transactions: Vec<Transaction>,
}

impl WdfDmaManager {
    pub fn new() -> Self {
        Self {
            dma: DmaManager::new(),
            mdl: MdlRegistry::new(),
            enablers: Vec::new(),
            common_buffers: Vec::new(),
            transactions: Vec::new(),
        }
    }

    /// Direct access to the underlying MDL registry (the Driver Host registers request MDLs).
    pub fn mdl_registry(&mut self) -> &mut MdlRegistry {
        &mut self.mdl
    }

    // --- WDFDMAENABLER (§8) ---------------------------------------------------

    /// `WdfDmaEnablerCreate` — acquire a DMA adapter (via the DMA Manager) for the device.
    pub fn create_enabler(
        &mut self,
        handle: u64,
        owner: DmaOwner,
        profile: u32,
        maximum_length: u64,
    ) {
        let sg = matches!(
            profile,
            WDF_DMA_PROFILE_SCATTER_GATHER | WDF_DMA_PROFILE_SCATTER_GATHER64
        );
        let dma64 = matches!(
            profile,
            WDF_DMA_PROFILE_PACKET64 | WDF_DMA_PROFILE_SCATTER_GATHER64
        );
        let adapter_id = self.dma.register_adapter(owner, sg, maximum_length, dma64);
        self.enablers.push(Enabler {
            handle,
            owner,
            adapter_id,
            profile,
            maximum_length,
        });
    }

    fn enabler(&self, handle: u64) -> Result<&Enabler, WdfDmaError> {
        self.enablers
            .iter()
            .find(|e| e.handle == handle)
            .ok_or(WdfDmaError::StaleHandle)
    }

    /// `WdfDmaEnablerGetMaximumLength`.
    pub fn enabler_maximum_length(&self, handle: u64) -> Option<u64> {
        self.enablers
            .iter()
            .find(|e| e.handle == handle)
            .map(|e| e.maximum_length)
    }
    pub fn enabler_profile(&self, handle: u64) -> Option<u32> {
        self.enablers
            .iter()
            .find(|e| e.handle == handle)
            .map(|e| e.profile)
    }

    // --- WDFCOMMONBUFFER (§9) -------------------------------------------------

    /// `WdfCommonBufferCreate` — allocate a common buffer (real backing `virtual_address`
    /// from the Driver Host) + a fake logical address from the DMA Manager (§9.4).
    pub fn create_common_buffer(
        &mut self,
        handle: u64,
        enabler_handle: u64,
        length: u64,
        virtual_address: u64,
    ) -> Result<u64, WdfDmaError> {
        let (owner, adapter_id) = {
            let e = self.enabler(enabler_handle)?;
            (e.owner, e.adapter_id)
        };
        let grant = self
            .dma
            .alloc_common_buffer(owner, adapter_id, length, virtual_address)?;
        self.common_buffers.push(CommonBuffer {
            handle,
            owner,
            virtual_address,
            logical_address: grant.logical_base,
            length,
        });
        Ok(grant.logical_base)
    }

    fn common_buffer(&self, handle: u64) -> Option<&CommonBuffer> {
        self.common_buffers.iter().find(|c| c.handle == handle)
    }

    /// `WdfCommonBufferGetAlignedVirtualAddress`.
    pub fn common_buffer_virtual_address(&self, handle: u64) -> Option<u64> {
        self.common_buffer(handle).map(|c| c.virtual_address)
    }
    /// `WdfCommonBufferGetAlignedLogicalAddress` (the fake DMA logical address).
    pub fn common_buffer_logical_address(&self, handle: u64) -> Option<u64> {
        self.common_buffer(handle).map(|c| c.logical_address)
    }
    /// `WdfCommonBufferGetLength`.
    pub fn common_buffer_length(&self, handle: u64) -> Option<u64> {
        self.common_buffer(handle).map(|c| c.length)
    }

    /// Decode a device logical address to its backing Driver-Host address (the IOMMU-facade
    /// lookup a simulated DMA device uses, spec §9.4).
    pub fn decode_logical(&self, logical: u64, length: u64) -> Result<u64, WdfDmaError> {
        Ok(self.dma.decode_logical(logical, length)?)
    }

    /// Delete a common buffer (`FreeCommonBuffer`, revoke the logical address, §9.5).
    pub fn free_common_buffer(&mut self, handle: u64) -> Result<(), WdfDmaError> {
        let (owner, logical, length) = {
            let c = self.common_buffer(handle).ok_or(WdfDmaError::StaleHandle)?;
            (c.owner, c.logical_address, c.length)
        };
        self.dma.free_common_buffer(owner, logical, length)?;
        self.common_buffers.retain(|c| c.handle != handle);
        Ok(())
    }

    // --- WDFDMATRANSACTION (§10) ----------------------------------------------

    /// `WdfDmaTransactionCreate`.
    pub fn create_transaction(
        &mut self,
        handle: u64,
        enabler_handle: u64,
    ) -> Result<(), WdfDmaError> {
        let owner = self.enabler(enabler_handle)?.owner;
        self.transactions.push(Transaction {
            handle,
            owner,
            request: 0,
            mdl_id: 0,
            direction: 0,
            total_length: 0,
            backing_va: 0,
            bytes_transferred: 0,
            mapping_id: 0,
            logical_address: 0,
            evt_program_dma: 0,
            state: TransactionState::Created,
        });
        Ok(())
    }

    fn transaction_mut(&mut self, handle: u64) -> Result<&mut Transaction, WdfDmaError> {
        self.transactions
            .iter_mut()
            .find(|t| t.handle == handle)
            .ok_or(WdfDmaError::StaleHandle)
    }

    /// `WdfDmaTransactionInitializeUsingRequest` — bind the transaction to a request's MDL
    /// (backed by `backing_va`), the transfer direction, and the total length (§10.3).
    #[allow(clippy::too_many_arguments)]
    pub fn init_transaction_using_request(
        &mut self,
        handle: u64,
        request: u64,
        backing_va: u64,
        total_length: u64,
        direction: u32,
        evt_program_dma: u64,
    ) -> Result<(), WdfDmaError> {
        // Register an MDL over the request buffer so a map has something to validate.
        let mdl_id = self.mdl.allocate(backing_va, total_length as u32);
        let _ = self.mdl.build_for_nonpaged(mdl_id);
        let t = self.transaction_mut(handle)?;
        if t.state != TransactionState::Created {
            return Err(WdfDmaError::BadState);
        }
        t.request = request;
        t.mdl_id = mdl_id;
        t.backing_va = backing_va;
        t.total_length = total_length;
        t.direction = direction;
        t.evt_program_dma = evt_program_dma;
        t.state = TransactionState::Initialized;
        Ok(())
    }

    /// `WdfDmaTransactionExecute` — map the request buffer to a fresh logical address and
    /// return what the Driver Host feeds `EvtProgramDma` (§10.4). One segment in v0.2.
    pub fn execute_transaction(&mut self, handle: u64) -> Result<DmaExecution, WdfDmaError> {
        let (owner, adapter_owner, backing_va, total_length, evt) = {
            let t = self.transaction_mut(handle)?;
            if t.state != TransactionState::Initialized {
                return Err(WdfDmaError::BadState);
            }
            (
                t.owner,
                t.owner,
                t.backing_va,
                t.total_length,
                t.evt_program_dma,
            )
        };
        // Use the owner's adapter (registered by its enabler).
        let adapter_id = self
            .enablers
            .iter()
            .find(|e| e.owner == adapter_owner)
            .ok_or(WdfDmaError::StaleHandle)?
            .adapter_id;
        let grant = self
            .dma
            .map_transfer(owner, adapter_id, backing_va, total_length)?;
        let t = self.transaction_mut(handle)?;
        t.mapping_id = grant.mapping_id;
        t.logical_address = grant.logical_base;
        t.state = TransactionState::Executing;
        Ok(DmaExecution {
            logical_address: grant.logical_base,
            length: grant.mapped_length,
            evt_program_dma: evt,
        })
    }

    pub fn transaction_state(&self, handle: u64) -> Option<TransactionState> {
        self.transactions
            .iter()
            .find(|t| t.handle == handle)
            .map(|t| t.state)
    }
    pub fn transaction_logical_address(&self, handle: u64) -> Option<u64> {
        self.transactions
            .iter()
            .find(|t| t.handle == handle)
            .map(|t| t.logical_address)
    }
    pub fn transaction_bytes_transferred(&self, handle: u64) -> Option<u64> {
        self.transactions
            .iter()
            .find(|t| t.handle == handle)
            .map(|t| t.bytes_transferred)
    }

    /// `WdfDmaTransactionDmaCompletedFinal` — release the DMA mapping, record the bytes
    /// transferred, mark complete. Returns `true` (transaction complete, §10.5).
    pub fn complete_transaction_final(
        &mut self,
        handle: u64,
        final_length: u64,
    ) -> Result<bool, WdfDmaError> {
        let mapping_id = {
            let t = self.transaction_mut(handle)?;
            if t.state != TransactionState::Executing {
                return Err(WdfDmaError::BadState);
            }
            t.mapping_id
        };
        self.dma.free_mapping(mapping_id)?;
        let t = self.transaction_mut(handle)?;
        t.bytes_transferred = final_length;
        t.state = TransactionState::Completed;
        Ok(true)
    }

    /// `WdfDmaTransactionRelease` / delete — drop the transaction + its MDL.
    pub fn release_transaction(&mut self, handle: u64) {
        if let Some(t) = self.transactions.iter().find(|t| t.handle == handle) {
            let mdl_id = t.mdl_id;
            let _ = self.mdl.free(mdl_id);
        }
        self.transactions.retain(|t| t.handle != handle);
    }

    /// Fault / remove cleanup — revoke everything owned by `owner` (spec §13.3, §7 remove).
    pub fn revoke_owner(&mut self, owner: DmaOwner) {
        self.dma.revoke_owner(owner);
        self.common_buffers.retain(|c| c.owner != owner);
        self.transactions.retain(|t| t.owner != owner);
        self.enablers.retain(|e| e.owner != owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> DmaOwner {
        DmaOwner::new(1, 10)
    }

    #[test]
    fn enabler_and_common_buffer_roundtrip() {
        let mut m = WdfDmaManager::new();
        m.create_enabler(0xE1, owner(), WDF_DMA_PROFILE_PACKET64, 4096);
        assert_eq!(m.enabler_maximum_length(0xE1), Some(4096));
        // Common buffer: real VA + fake logical.
        let logical = m.create_common_buffer(0xCB, 0xE1, 4096, 0x1_0000).unwrap();
        assert_eq!(m.common_buffer_virtual_address(0xCB), Some(0x1_0000));
        assert_eq!(m.common_buffer_logical_address(0xCB), Some(logical));
        assert_eq!(m.common_buffer_length(0xCB), Some(4096));
        // The sim device decodes the logical address to the backing VA.
        assert_eq!(m.decode_logical(logical + 64, 8), Ok(0x1_0000 + 64));
        // Free revokes the logical address.
        m.free_common_buffer(0xCB).unwrap();
        assert_eq!(
            m.decode_logical(logical, 4),
            Err(WdfDmaError::Dma(DmaError::LogicalViolation))
        );
    }

    #[test]
    fn transaction_execute_and_complete() {
        let mut m = WdfDmaManager::new();
        m.create_enabler(0xE1, owner(), WDF_DMA_PROFILE_PACKET, 4096);
        m.create_transaction(0x71, 0xE1).unwrap();
        assert_eq!(m.transaction_state(0x71), Some(TransactionState::Created));
        m.init_transaction_using_request(0x71, 0xE90, 0x2_0000, 256, 0, 0xE10)
            .unwrap();
        assert_eq!(
            m.transaction_state(0x71),
            Some(TransactionState::Initialized)
        );
        let exec = m.execute_transaction(0x71).unwrap();
        assert_eq!(exec.length, 256);
        assert_eq!(exec.evt_program_dma, 0xE10);
        // The mapped logical address decodes to the request buffer.
        assert_eq!(m.decode_logical(exec.logical_address, 256), Ok(0x2_0000));
        assert_eq!(m.transaction_state(0x71), Some(TransactionState::Executing));
        // Complete releases the mapping.
        assert_eq!(m.complete_transaction_final(0x71, 256), Ok(true));
        assert_eq!(m.transaction_bytes_transferred(0x71), Some(256));
        assert_eq!(
            m.decode_logical(exec.logical_address, 4),
            Err(WdfDmaError::Dma(DmaError::LogicalViolation))
        );
    }

    #[test]
    fn transaction_state_guards() {
        let mut m = WdfDmaManager::new();
        m.create_enabler(0xE1, owner(), WDF_DMA_PROFILE_PACKET, 4096);
        m.create_transaction(0x71, 0xE1).unwrap();
        // Execute before init is rejected.
        assert_eq!(m.execute_transaction(0x71), Err(WdfDmaError::BadState));
        // Complete before execute is rejected.
        assert_eq!(
            m.complete_transaction_final(0x71, 0),
            Err(WdfDmaError::BadState)
        );
    }
}
