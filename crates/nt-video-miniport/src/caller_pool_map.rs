//! Exact, page-granular pool ownership for a provider-created video shadow.

const PAGE: u64 = 0x1000;

/// A provider VA can overlap numerically with another VSpace's arena. Select
/// the backing only after both independent owners have granted exact pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackingSelection { Pool, Projection, Missing, Ambiguous }

impl BackingSelection {
    pub const fn from_pins(pool: bool, projection: bool) -> Self {
        match (pool, projection) {
            (true, false) => Self::Pool,
            (false, true) => Self::Projection,
            (false, false) => Self::Missing,
            (true, true) => Self::Ambiguous,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolMapIdentity {
    pub device: u64,
    pub provider_domain: u64,
    pub provider_generation: u64,
    pub pool_base: u64,
    pub pool_frames: u64,
    pub pool_frame_base: u64,
    pub allocation_base: u64,
    pub allocation_capacity: u64,
    pub allocation_generation: u64,
    pub provider_pointer: u64,
    pub length: u64,
    pub caller_domain: u64,
    pub caller_generation: u64,
    pub caller_vspace: u64,
    pub alias_page: u64,
    pub alias_limit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMapError {
    InvalidIdentity,
    InvalidExtent,
    WrongPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolMapPlan {
    identity: PoolMapIdentity,
    pages: u64,
    alias_pointer: u64,
    first_pool_page: u64,
}

impl PoolMapPlan {
    pub fn new(identity: PoolMapIdentity) -> Result<Self, PoolMapError> {
        if identity.device == 0
            || identity.provider_domain == 0
            || identity.provider_generation == 0
            || identity.pool_frame_base == 0
            || identity.allocation_generation == 0
            || identity.caller_domain == 0
            || identity.caller_generation == 0
            || identity.caller_vspace == 0
        {
            return Err(PoolMapError::InvalidIdentity);
        }
        if identity.pool_base == 0
            || identity.pool_frames == 0
            || identity.allocation_base & (PAGE - 1) != 0
            || identity.allocation_capacity == 0
            || identity.allocation_capacity & (PAGE - 1) != 0
            || identity.alias_page == 0
            || identity.alias_page & (PAGE - 1) != 0
            || identity.alias_limit & (PAGE - 1) != 0
            || identity.alias_page >= identity.alias_limit
            || identity.provider_pointer < identity.allocation_base
            || identity.length == 0
        {
            return Err(PoolMapError::InvalidExtent);
        }
        let pool_end = identity
            .pool_frames
            .checked_mul(PAGE)
            .and_then(|bytes| identity.pool_base.checked_add(bytes))
            .ok_or(PoolMapError::InvalidExtent)?;
        let allocation_end = identity
            .allocation_base
            .checked_add(identity.allocation_capacity)
            .ok_or(PoolMapError::InvalidExtent)?;
        let pointer_end = identity
            .provider_pointer
            .checked_add(identity.length)
            .ok_or(PoolMapError::InvalidExtent)?;
        if identity.allocation_base < identity.pool_base
            || allocation_end > pool_end
            || pointer_end > allocation_end
        {
            return Err(PoolMapError::InvalidExtent);
        }
        let offset = identity.provider_pointer & (PAGE - 1);
        let pages = offset
            .checked_add(identity.length)
            .and_then(|bytes| bytes.checked_add(PAGE - 1))
            .map(|bytes| bytes / PAGE)
            .ok_or(PoolMapError::InvalidExtent)?;
        let alias_end = pages
            .checked_mul(PAGE)
            .and_then(|bytes| identity.alias_page.checked_add(bytes))
            .ok_or(PoolMapError::InvalidExtent)?;
        let first_pool_page = (identity.provider_pointer & !(PAGE - 1))
            .checked_sub(identity.pool_base)
            .ok_or(PoolMapError::InvalidExtent)? / PAGE;
        if alias_end > identity.alias_limit
            || first_pool_page.checked_add(pages).is_none_or(|end| end > identity.pool_frames)
            || identity.pool_frame_base.checked_add(first_pool_page)
                .and_then(|base| base.checked_add(pages)).is_none()
        {
            return Err(PoolMapError::InvalidExtent);
        }
        Ok(Self {
            identity,
            pages,
            alias_pointer: identity.alias_page + offset,
            first_pool_page,
        })
    }

    pub const fn identity(self) -> PoolMapIdentity { self.identity }
    pub const fn pages(self) -> u64 { self.pages }
    pub const fn alias_pointer(self) -> u64 { self.alias_pointer }
    pub fn frame_slot(self, index: u64) -> Option<u64> {
        (index < self.pages).then(|| self.identity.pool_frame_base + self.first_pool_page + index)
    }
    pub fn page_va(self, index: u64) -> Option<u64> {
        (index < self.pages).then(|| self.identity.alias_page + index * PAGE)
    }
    pub fn translate_alias_range(self, address: u64, bytes: u64) -> Option<u64> {
        if bytes == 0 || address < self.alias_pointer {
            return None;
        }
        let offset = address.checked_sub(self.alias_pointer)?;
        if offset.checked_add(bytes)? > self.identity.length {
            return None;
        }
        self.identity.provider_pointer.checked_add(offset)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMapPhase {
    ProviderOwned,
    Pinned,
    MapInFlight,
    Ready,
    Published,
    UnmapClaimed,
    AliasRevoked,
    PinReleased,
    ProviderUnmapInFlight,
    Retired,
    Quarantined,
}

pub struct PoolMapTransaction {
    plan: PoolMapPlan,
    phase: PoolMapPhase,
    mapped: u64,
    owned_next: bool,
}

impl PoolMapTransaction {
    pub const fn new(plan: PoolMapPlan) -> Self {
        Self { plan, phase: PoolMapPhase::ProviderOwned, mapped: 0, owned_next: false }
    }
    pub const fn plan(&self) -> PoolMapPlan { self.plan }
    pub const fn phase(&self) -> PoolMapPhase { self.phase }
    pub const fn mapped(&self) -> u64 { self.mapped }
    pub fn pin_allocation(&mut self) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::ProviderOwned { return Err(PoolMapError::WrongPhase); }
        self.phase = PoolMapPhase::Pinned;
        Ok(())
    }
    pub fn own_frame_cap(&mut self, page: u64) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::Pinned || self.owned_next || page != self.mapped || page >= self.plan.pages {
            return Err(PoolMapError::WrongPhase);
        }
        self.owned_next = true;
        Ok(())
    }
    pub fn begin_map(&mut self, page: u64) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::Pinned || !self.owned_next || page != self.mapped {
            return Err(PoolMapError::WrongPhase);
        }
        self.phase = PoolMapPhase::MapInFlight;
        Ok(())
    }
    pub fn ack_map(&mut self, page: u64) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::MapInFlight || page != self.mapped { return Err(PoolMapError::WrongPhase); }
        self.mapped += 1;
        self.owned_next = false;
        self.phase = PoolMapPhase::Pinned;
        Ok(())
    }
    pub fn unknown_map_effect(&mut self) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::MapInFlight { return Err(PoolMapError::WrongPhase); }
        self.phase = PoolMapPhase::Quarantined;
        Ok(())
    }
    pub fn commit(&mut self) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::Pinned || self.owned_next || self.mapped != self.plan.pages {
            return Err(PoolMapError::WrongPhase);
        }
        self.phase = PoolMapPhase::Ready;
        Ok(())
    }
    pub const fn publishable(&self) -> bool { matches!(self.phase, PoolMapPhase::Ready) }
    pub fn publish(&mut self) -> Result<(), PoolMapError> {
        if !self.publishable() { return Err(PoolMapError::WrongPhase); }
        self.phase = PoolMapPhase::Published;
        Ok(())
    }
    pub fn claim_unmap(&mut self) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::Published { return Err(PoolMapError::WrongPhase); }
        self.phase = PoolMapPhase::UnmapClaimed;
        Ok(())
    }
    pub fn revoke_alias(&mut self) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::UnmapClaimed { return Err(PoolMapError::WrongPhase); }
        self.phase = PoolMapPhase::AliasRevoked;
        Ok(())
    }
    pub fn release_pin(&mut self) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::AliasRevoked { return Err(PoolMapError::WrongPhase); }
        self.phase = PoolMapPhase::PinReleased;
        Ok(())
    }
    pub const fn provider_unmap_admissible(&self) -> bool { matches!(self.phase, PoolMapPhase::PinReleased) }
    pub fn begin_provider_unmap(&mut self) -> Result<(), PoolMapError> {
        if !self.provider_unmap_admissible() { return Err(PoolMapError::WrongPhase); }
        self.phase = PoolMapPhase::ProviderUnmapInFlight;
        Ok(())
    }
    pub fn ack_provider_unmap(&mut self) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::ProviderUnmapInFlight { return Err(PoolMapError::WrongPhase); }
        self.phase = PoolMapPhase::Retired;
        Ok(())
    }
    pub fn unknown_provider_unmap(&mut self) -> Result<(), PoolMapError> {
        if self.phase != PoolMapPhase::ProviderUnmapInFlight { return Err(PoolMapError::WrongPhase); }
        self.phase = PoolMapPhase::Quarantined;
        Ok(())
    }
    /// A native effect without a reliable acknowledgement retains every physical owner.
    pub fn quarantine(&mut self) {
        if self.phase != PoolMapPhase::Retired { self.phase = PoolMapPhase::Quarantined; }
    }
}
