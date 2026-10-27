//! WMI GUID provider registration and kernel data-block object ownership.
//!
//! This crate does not invent firmware data or dispatch driver code. A query
//! yields exact registered provider identities for the native broker to invoke.

#![no_std]

extern crate alloc;

pub mod reginfo;
pub mod event;

use alloc::vec::Vec;

pub const WMIGUID_QUERY: u32 = 0x0001;
pub const WMIGUID_SET: u32 = 0x0002;
pub const WMIGUID_NOTIFICATION: u32 = 0x0004;
pub const WMIGUID_EXECUTE: u32 = 0x0010;
pub const STATUS_WMI_GUID_NOT_FOUND: u32 = 0xc000_0295;
pub const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
pub const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
pub const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;
const VALID_ACCESS: u32 = WMIGUID_QUERY | WMIGUID_SET | WMIGUID_NOTIFICATION | WMIGUID_EXECUTE;

/// The 16 bytes of an NT GUID in native memory order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmiGuid(pub [u8; 16]);

/// Exact registered provider incarnation; numeric driver IDs alone can be reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmiProviderOwner {
    pub domain: u64,
    pub generation: u64,
}

/// A canonical hosted device address within its authenticated driver incarnation.
/// The native broker must verify this identity before registering it here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmiDeviceIdentity {
    pub domain: u64,
    pub generation: u64,
    pub device_object: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmiProviderId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmiBlockId(u64);

struct Provider {
    id: WmiProviderId,
    owner: WmiProviderOwner,
    guid: WmiGuid,
    access: u32,
}

struct Block {
    id: WmiBlockId,
    guid: WmiGuid,
    access: u32,
    references: u32,
}

struct DeviceProvider {
    identity: WmiDeviceIdentity,
    id: u32,
    live: bool,
    guids: Vec<(WmiGuid, u32)>,
}

/// A successful WMI event transfers a normal pool allocation to WMI. A traced
/// event leaves the input allocation with its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WmiEventOwnership {
    TransferPoolOnSuccess,
    RetainCaller,
}

/// IDs are monotonically allocated and never reused, even after slot reuse.
/// Native callers serialize this store with provider registration and queries.
pub struct WmiRegistry {
    next_id: u64,
    next_device_provider_id: u64,
    providers: Vec<Provider>,
    blocks: Vec<Block>,
    device_providers: Vec<DeviceProvider>,
}

impl WmiRegistry {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            next_device_provider_id: 1,
            providers: Vec::new(),
            blocks: Vec::new(),
            device_providers: Vec::new(),
        }
    }

    /// Assign the 32-bit provider identity used by `IoWMIDeviceObjectToProviderId`.
    /// Repeated registration of one live device is idempotent. An address cannot
    /// be reused by a new generation until the old registration is retired.
    pub fn register_device(&mut self, identity: WmiDeviceIdentity) -> Result<u32, u32> {
        if identity.domain == 0 || identity.generation == 0 || identity.device_object == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Some(entry) = self.device_providers.iter_mut().find(|entry| {
            entry.identity.domain == identity.domain
                && entry.identity.device_object == identity.device_object
        }) {
            if identity.generation < entry.identity.generation
                || (identity.generation == entry.identity.generation && !entry.live)
                || (identity.generation > entry.identity.generation && entry.live)
            {
                return Err(STATUS_INVALID_HANDLE);
            }
            if identity.generation == entry.identity.generation {
                return Ok(entry.id);
            }
            let id = u32::try_from(self.next_device_provider_id)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            self.next_device_provider_id += 1;
            entry.identity = identity;
            entry.id = id;
            entry.live = true;
            entry.guids.clear();
            return Ok(id);
        }
        self.device_providers
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let id = u32::try_from(self.next_device_provider_id)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.next_device_provider_id += 1;
        self.device_providers.push(DeviceProvider {
            identity,
            id,
            live: true,
            guids: Vec::new(),
        });
        Ok(id)
    }

    /// Resolve only an exact live device incarnation, never an address alone.
    pub fn device_provider_id(&self, identity: WmiDeviceIdentity) -> Result<u32, u32> {
        self.device_providers
            .iter()
            .find(|entry| entry.live && entry.identity == identity)
            .map(|entry| entry.id)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Publish the GUIDs returned by an authenticated device's REGINFO IRP.
    /// All entries are prepared before publication so a failed update leaves
    /// the prior registration intact.
    pub fn publish_device_guids(
        &mut self,
        identity: WmiDeviceIdentity,
        guids: &[(WmiGuid, u32)],
    ) -> Result<(), u32> {
        let entry = self
            .device_providers
            .iter_mut()
            .find(|entry| entry.live && entry.identity == identity)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve(guids.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for &(guid, access) in guids {
            if access == 0 || access & !VALID_ACCESS != 0
                || replacement.iter().any(|(existing, _)| *existing == guid)
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
            replacement.push((guid, access));
        }
        entry.guids = replacement;
        Ok(())
    }

    /// Admit a submitted event only for a live provider and a GUID that its
    /// completed REGINFO advertised for notification. The native broker must
    /// copy/deliver or consume the allocation before returning success.
    pub fn plan_device_event(
        &self,
        provider_id: u32,
        guid: WmiGuid,
        flags: u32,
    ) -> Result<(WmiDeviceIdentity, WmiEventOwnership), u32> {
        let entry = self
            .device_providers
            .iter()
            .find(|entry| entry.live && entry.id == provider_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if !entry
            .guids
            .iter()
            .any(|(registered, access)| *registered == guid && *access & WMIGUID_NOTIFICATION != 0)
        {
            return Err(STATUS_WMI_GUID_NOT_FOUND);
        }
        let ownership = if flags & WNODE_FLAG_TRACED_GUID != 0 {
            WmiEventOwnership::RetainCaller
        } else {
            WmiEventOwnership::TransferPoolOnSuccess
        };
        Ok((entry.identity, ownership))
    }

    /// Keep a tombstone so an old generation cannot register after address reuse.
    pub fn unregister_device(&mut self, identity: WmiDeviceIdentity) -> Result<(), u32> {
        let entry = self
            .device_providers
            .iter_mut()
            .find(|entry| entry.live && entry.identity == identity)
            .ok_or(STATUS_INVALID_HANDLE)?;
        entry.live = false;
        Ok(())
    }

    fn id(&mut self) -> Result<u64, u32> {
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(id)
    }

    /// Register a provider under its authenticated native owner identity.
    /// Multiple providers may publish instances for the same GUID.
    pub fn register_provider(
        &mut self,
        owner: WmiProviderOwner,
        guid: WmiGuid,
        access: u32,
    ) -> Result<WmiProviderId, u32> {
        if owner.domain == 0 || owner.generation == 0 || access == 0 || access & !VALID_ACCESS != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.providers
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let id = WmiProviderId(self.id()?);
        self.providers.push(Provider {
            id,
            owner,
            guid,
            access,
        });
        Ok(id)
    }

    /// The caller must serialize this with execution of any issued query plan.
    pub fn unregister_provider(
        &mut self,
        owner: WmiProviderOwner,
        id: WmiProviderId,
    ) -> Result<(), u32> {
        let index = self
            .providers
            .iter()
            .position(|entry| entry.id == id && entry.owner == owner)
            .ok_or(STATUS_INVALID_HANDLE)?;
        self.providers.remove(index);
        Ok(())
    }

    /// Opening creates a counted WmiGuid object only when a registered provider
    /// supports every requested operation. It does not create an empty success.
    pub fn open_block(&mut self, guid: WmiGuid, desired_access: u32) -> Result<WmiBlockId, u32> {
        if desired_access == 0 || desired_access & !VALID_ACCESS != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut exists = false;
        let mut supported = 0;
        for provider in &self.providers {
            if provider.guid == guid {
                exists = true;
                supported |= provider.access;
            }
        }
        if !exists {
            return Err(STATUS_WMI_GUID_NOT_FOUND);
        }
        if supported & desired_access != desired_access {
            return Err(STATUS_ACCESS_DENIED);
        }
        self.blocks
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let id = WmiBlockId(self.id()?);
        self.blocks.push(Block {
            id,
            guid,
            access: desired_access,
            references: 1,
        });
        Ok(id)
    }

    pub fn reference_block(&mut self, id: WmiBlockId) -> Result<(), u32> {
        let block = self
            .blocks
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        block.references = block
            .references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    pub fn dereference_block(&mut self, id: WmiBlockId) -> Result<(), u32> {
        let index = self
            .blocks
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let block = &mut self.blocks[index];
        block.references -= 1;
        if block.references == 0 {
            self.blocks.remove(index);
        }
        Ok(())
    }

    /// Identify every current provider for an authorized GUID query. The native
    /// broker must keep registration serialized until their results are collected.
    pub fn query_all_data_providers(&self, id: WmiBlockId) -> Result<Vec<WmiProviderId>, u32> {
        let block = self
            .blocks
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if block.access & WMIGUID_QUERY == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        let mut result = Vec::new();
        for provider in &self.providers {
            if provider.guid == block.guid && provider.access & WMIGUID_QUERY != 0 {
                result
                    .try_reserve(1)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                result.push(provider.id);
            }
        }
        if result.is_empty() {
            return Err(STATUS_WMI_GUID_NOT_FOUND);
        }
        Ok(result)
    }
}

impl Default for WmiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: WmiGuid = WmiGuid([1; 16]);
    const OWNER: WmiProviderOwner = WmiProviderOwner {
        domain: 7,
        generation: 1,
    };

    #[test]
    fn absent_provider_cannot_create_block_and_existing_provider_is_counted() {
        let mut registry = WmiRegistry::new();
        assert_eq!(
            registry.open_block(GUID, WMIGUID_QUERY),
            Err(STATUS_WMI_GUID_NOT_FOUND)
        );
        let provider = registry
            .register_provider(OWNER, GUID, WMIGUID_QUERY)
            .unwrap();
        let block = registry.open_block(GUID, WMIGUID_QUERY).unwrap();
        registry.reference_block(block).unwrap();
        assert_eq!(
            registry.query_all_data_providers(block),
            Ok(alloc::vec![provider])
        );
        registry.dereference_block(block).unwrap();
        assert_eq!(
            registry.query_all_data_providers(block),
            Ok(alloc::vec![provider])
        );
        registry.dereference_block(block).unwrap();
        assert_eq!(
            registry.query_all_data_providers(block),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn stale_ids_and_wrong_provider_owner_cannot_retarget_reused_slots() {
        let mut registry = WmiRegistry::new();
        let first = registry
            .register_provider(OWNER, GUID, WMIGUID_QUERY)
            .unwrap();
        assert_eq!(
            registry.unregister_provider(
                WmiProviderOwner {
                    generation: 2,
                    ..OWNER
                },
                first
            ),
            Err(STATUS_INVALID_HANDLE)
        );
        let old_block = registry.open_block(GUID, WMIGUID_QUERY).unwrap();
        registry.dereference_block(old_block).unwrap();
        let fresh_block = registry.open_block(GUID, WMIGUID_QUERY).unwrap();
        assert_ne!(old_block, fresh_block);
        assert_eq!(
            registry.reference_block(old_block),
            Err(STATUS_INVALID_HANDLE)
        );
        registry.unregister_provider(OWNER, first).unwrap();
        assert_eq!(
            registry.query_all_data_providers(fresh_block),
            Err(STATUS_WMI_GUID_NOT_FOUND)
        );
    }
}
