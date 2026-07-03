//! The driver-local pool (spec §13): `ExAllocatePoolWithTag` / `ExFreePoolWithTag`
//! backed by the arena, with double-free / unknown-pointer traps and leak
//! reporting on unload.

use alloc::vec::Vec;

use nt_kernel_abi::GuestAddr;

use crate::arena::Arena;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PoolError {
    /// The arena is exhausted.
    OutOfMemory,
    /// The pointer was already freed.
    DoubleFree,
    /// The pointer is not a live pool allocation.
    UnknownPointer,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PoolBlock {
    pub addr: GuestAddr,
    pub size: usize,
    pub tag: u32,
    pub freed: bool,
}

/// The driver's pool-allocation tracker.
#[derive(Default)]
pub struct Pool {
    blocks: Vec<PoolBlock>,
}

impl Pool {
    pub fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    /// Allocate `size` bytes tagged `tag` (`ExAllocatePoolWithTag`).
    pub fn allocate(
        &mut self,
        arena: &mut Arena,
        size: usize,
        tag: u32,
    ) -> Result<GuestAddr, PoolError> {
        let addr = arena.alloc(size, 16).ok_or(PoolError::OutOfMemory)?;
        self.blocks.push(PoolBlock {
            addr,
            size,
            tag,
            freed: false,
        });
        Ok(addr)
    }

    /// Free a pool allocation (`ExFreePoolWithTag`). A double-free or unknown
    /// pointer is trapped (spec §13).
    pub fn free(&mut self, addr: GuestAddr) -> Result<(), PoolError> {
        match self.blocks.iter_mut().find(|b| b.addr == addr) {
            Some(b) if b.freed => Err(PoolError::DoubleFree),
            Some(b) => {
                b.freed = true;
                Ok(())
            }
            None => Err(PoolError::UnknownPointer),
        }
    }

    /// True if `addr` is a live (unfreed) pool allocation.
    pub fn is_live(&self, addr: GuestAddr) -> bool {
        self.blocks.iter().any(|b| b.addr == addr && !b.freed)
    }

    /// The unfreed allocations (leaks), reported on driver unload.
    pub fn leaks(&self) -> impl Iterator<Item = &PoolBlock> + '_ {
        self.blocks.iter().filter(|b| !b.freed)
    }

    /// The number of live allocations.
    pub fn live_count(&self) -> usize {
        self.blocks.iter().filter(|b| !b.freed).count()
    }
}
