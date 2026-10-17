//! HAL's retained ACPI PCI route query registration.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciRouteCallback {
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub vspace: u64,
    pub image_base: u64,
    pub image_len: u64,
    pub image_generation: u64,
    pub callback: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciRouteCallbackError { Invalid, Conflict, Foreign }

#[derive(Default)]
pub struct PciRouteCallbackLedger { current: Option<PciRouteCallback> }

impl PciRouteCallbackLedger {
    pub fn new() -> Self { Self::default() }
    pub fn register(&mut self, entry: PciRouteCallback) -> Result<(), PciRouteCallbackError> {
        if entry.domain_id == 0 || entry.domain_cookie == 0 || entry.vspace == 0
            || entry.image_base == 0 || entry.image_len == 0 || entry.image_generation == 0
            || entry.callback < entry.image_base
            || entry.image_base.checked_add(entry.image_len).is_none_or(|end| entry.callback >= end)
        { return Err(PciRouteCallbackError::Invalid); }
        match self.current {
            Some(current) if current == entry => Ok(()),
            Some(_) => Err(PciRouteCallbackError::Conflict),
            None => { self.current = Some(entry); Ok(()) }
        }
    }
    pub fn current(&self) -> Option<PciRouteCallback> { self.current }
    pub fn unregister(&mut self, domain_id: u64, domain_cookie: u64, vspace: u64)
        -> Result<(), PciRouteCallbackError> {
        match self.current {
            Some(current) if current.domain_id == domain_id
                && current.domain_cookie == domain_cookie && current.vspace == vspace => {
                self.current = None;
                Ok(())
            }
            None => Ok(()),
            Some(_) => Err(PciRouteCallbackError::Foreign),
        }
    }
    pub fn blocks_retirement(&self, domain_id: u64, domain_cookie: u64, vspace: u64) -> bool {
        self.current.is_some_and(|entry| entry.domain_id == domain_id
            && entry.domain_cookie == domain_cookie && entry.vspace == vspace)
    }
}
