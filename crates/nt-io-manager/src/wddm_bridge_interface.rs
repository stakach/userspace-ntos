//! The WDDM bridge interface that dxgkrnl returns to win32k for
//! `IOCTL_WDDM_BRIDGE_QUERY_INTERFACE` (win32ss/drivers/wddm/wddm_bridge.c).
//!
//! The 0x270-byte output is a version/size header followed by 77 function pointers into the
//! completing provider's image. Those addresses exist only in that provider's address space, so
//! they must never reach a caller in another domain. The root rewrites each slot to an entry in
//! the caller's domain and records the provider's exact identity in a [`BridgeBindings`] row:
//!
//! - A routed slot's entry asks the root to call the recorded provider RVA, and the root resolves
//!   it only through a binding whose provider identity is still live.
//! - Every other slot's entry is a fail-fast trap that names the slot. The pinned LiberNT win32k
//!   never calls those slots (it only checks them for NULL), so no argument shape can be proven
//!   for them; forwarding raw arguments would hand caller pointers to the provider.
//!
//! win32k rejects NULL slots, so an entry is always non-NULL. A slot absent at the negotiated
//! version stays NULL.

use alloc::vec::Vec;

/// CTL_CODE(FILE_DEVICE_VIDEO, 0x200, METHOD_BUFFERED, FILE_ANY_ACCESS).
pub const IOCTL_WDDM_BRIDGE_QUERY_INTERFACE: u32 = 0x0023_0800;
pub const WDDM_BRIDGE_INTERFACE_LEN: usize = 0x270;
/// First function-pointer slot after the 8-byte header.
pub const WDDM_BRIDGE_FIRST_SLOT: usize = 0x8;
pub const WDDM_BRIDGE_SLOT_COUNT: usize =
    (WDDM_BRIDGE_INTERFACE_LEN - WDDM_BRIDGE_FIRST_SLOT) / 8;
/// The version-8 `SendIoctl` slot (offset 0x268), which WddmBridgeSendIoctl prefers over IRP
/// dispatch.
pub const WDDM_BRIDGE_SEND_IOCTL_SLOT: usize = (0x268 - WDDM_BRIDGE_FIRST_SLOT) / 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeSlotRoute {
    /// The slot's argument shape is known and its entry calls the provider through the root.
    Routed,
    /// The slot's entry stops the caller with the slot index.
    Unrouted,
}

/// Slots win32k actually calls. win32k's only indirect call through its copy of the table is
/// `WddmBridgeSendIoctl`'s (win32k VMA 0x16526d).
pub const fn bridge_slot_route(slot: usize) -> BridgeSlotRoute {
    if slot == WDDM_BRIDGE_SEND_IOCTL_SLOT {
        BridgeSlotRoute::Routed
    } else {
        BridgeSlotRoute::Unrouted
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BridgeProjectionError {
    Length,
    /// A non-NULL slot is not executable code of the completing provider.
    SlotOutsideProvider { slot: usize },
}

/// The provider RVA behind each present slot of one projected interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeProjection {
    rvas: [Option<u64>; WDDM_BRIDGE_SLOT_COUNT],
}

impl BridgeProjection {
    pub fn provider_rva(&self, slot: usize) -> Option<u64> {
        self.rvas.get(slot).copied().flatten()
    }

    pub fn present_slots(&self) -> usize {
        self.rvas.iter().filter(|rva| rva.is_some()).count()
    }
}

/// Rewrite every non-NULL slot of a completed bridge interface for the calling domain.
///
/// `run_va..run_va + image_len` is the completing provider's image in its own domain and
/// `executable(rva)` says whether an RVA lies in its code. Every slot is proven before any is
/// rewritten; `entry(slot, route)` supplies the caller-domain address for each present slot.
pub fn project_bridge_interface(
    output: &mut [u8],
    run_va: u64,
    image_len: u64,
    executable: impl Fn(u64) -> bool,
    mut entry: impl FnMut(usize, BridgeSlotRoute) -> u64,
) -> Result<BridgeProjection, BridgeProjectionError> {
    if output.len() != WDDM_BRIDGE_INTERFACE_LEN {
        return Err(BridgeProjectionError::Length);
    }
    let slot_word = |output: &[u8], slot: usize| {
        let offset = WDDM_BRIDGE_FIRST_SLOT + slot * 8;
        u64::from_le_bytes(output[offset..offset + 8].try_into().unwrap())
    };
    let mut rvas = [None; WDDM_BRIDGE_SLOT_COUNT];
    for (slot, rva) in rvas.iter_mut().enumerate() {
        let target = slot_word(output, slot);
        if target == 0 {
            continue;
        }
        let provider_rva = target
            .checked_sub(run_va)
            .filter(|rva| *rva < image_len && executable(*rva))
            .ok_or(BridgeProjectionError::SlotOutsideProvider { slot })?;
        *rva = Some(provider_rva);
    }
    for (slot, rva) in rvas.iter().enumerate() {
        if rva.is_some() {
            let offset = WDDM_BRIDGE_FIRST_SLOT + slot * 8;
            output[offset..offset + 8]
                .copy_from_slice(&entry(slot, bridge_slot_route(slot)).to_le_bytes());
        }
    }
    Ok(BridgeProjection { rvas })
}

/// The exact caller domain a projection was published to (win32k's provider-domain identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeCallerIdentity {
    pub domain: u64,
    pub generation: u64,
}

/// The exact provider publication whose code a projection names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeProviderIdentity {
    pub instance: usize,
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub publication_cookie: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeCallTarget {
    pub provider: BridgeProviderIdentity,
    pub provider_rva: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeResolveError {
    /// The caller holds no projection, or its projection was dropped.
    NoBinding,
    /// The slot has no route; its entry never asks the root.
    Unrouted,
    /// The slot was NULL at the negotiated version.
    AbsentSlot,
    /// The recorded provider publication is no longer the live one.
    ProviderRetired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeBindingError {
    NoMemory,
}

#[derive(Clone, Copy)]
struct BridgeBinding {
    caller: BridgeCallerIdentity,
    provider: BridgeProviderIdentity,
    projection: BridgeProjection,
}

/// The root's record of every published bridge projection. A caller domain holds one table (a
/// new query replaces win32k's copy), so it holds at most one binding.
#[derive(Default)]
pub struct BridgeBindings {
    rows: Vec<BridgeBinding>,
}

impl BridgeBindings {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Make room for one more caller before a projection rewrites its interface, so that a
    /// rewritten interface can always be published.
    pub fn reserve(&mut self) -> Result<(), BridgeBindingError> {
        self.rows.try_reserve(1).map_err(|_| BridgeBindingError::NoMemory)
    }

    pub fn publish(
        &mut self,
        caller: BridgeCallerIdentity,
        provider: BridgeProviderIdentity,
        projection: BridgeProjection,
    ) -> Result<(), BridgeBindingError> {
        let row = BridgeBinding { caller, provider, projection };
        if let Some(existing) = self.rows.iter_mut().find(|row| row.caller == caller) {
            *existing = row;
            return Ok(());
        }
        self.rows.try_reserve(1).map_err(|_| BridgeBindingError::NoMemory)?;
        self.rows.push(row);
        Ok(())
    }

    /// Resolve a routed slot for the exact caller. `is_live(provider)` says whether the recorded
    /// provider publication is still the registered one; a binding whose publication is gone is
    /// dropped rather than redirected.
    pub fn resolve(
        &mut self,
        caller: BridgeCallerIdentity,
        slot: usize,
        is_live: impl Fn(BridgeProviderIdentity) -> bool,
    ) -> Result<BridgeCallTarget, BridgeResolveError> {
        if slot >= WDDM_BRIDGE_SLOT_COUNT || bridge_slot_route(slot) != BridgeSlotRoute::Routed {
            return Err(BridgeResolveError::Unrouted);
        }
        let index = self
            .rows
            .iter()
            .position(|row| row.caller == caller)
            .ok_or(BridgeResolveError::NoBinding)?;
        let row = self.rows[index];
        if !is_live(row.provider) {
            self.rows.swap_remove(index);
            return Err(BridgeResolveError::ProviderRetired);
        }
        let provider_rva = row.projection.provider_rva(slot).ok_or(BridgeResolveError::AbsentSlot)?;
        Ok(BridgeCallTarget { provider: row.provider, provider_rva })
    }

    /// Drop every binding into a retiring provider domain. Returns how many were dropped.
    pub fn retire_provider(&mut self, domain_id: u64, domain_cookie: u64) -> usize {
        let before = self.rows.len();
        self.rows.retain(|row| {
            row.provider.domain_id != domain_id || row.provider.domain_cookie != domain_cookie
        });
        before - self.rows.len()
    }
}
