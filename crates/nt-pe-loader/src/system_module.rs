//! Exact system-image ownership. A returned module handle is not an image address.
//! Native mapping/capability resources stay owned even when unload cannot be performed safely.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemImageIdentity {
    pub provider_domain: u64,
    pub provider_generation: u64,
    pub vspace: u64,
    pub image_owner: u64,
    pub base: u64,
    pub size: u32,
    pub entry_rva: u32,
    pub export_rva: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemModuleHandleIdentity {
    pub address: u64,
    pub allocation_id: u64,
    pub allocation_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemModuleError {
    InvalidIdentity,
    IdentityMismatch,
    ReferenceOverflow,
    NoLoadReference,
    TeardownUnsupported,
}

#[derive(Debug)]
pub struct SystemModule<R> {
    image: SystemImageIdentity,
    handle: SystemModuleHandleIdentity,
    load_references: u64,
    backing: R,
}

impl<R> SystemModule<R> {
    pub fn new(
        image: SystemImageIdentity,
        handle: SystemModuleHandleIdentity,
        backing: R,
    ) -> Result<Self, (SystemModuleError, R)> {
        let end = image.base.checked_add(u64::from(image.size));
        if image.provider_domain == 0
            || image.provider_generation == 0
            || image.vspace == 0
            || image.image_owner == 0
            || image.base == 0
            || image.size == 0
            || image.entry_rva >= image.size
            || image.export_rva >= image.size
            || end.is_none()
            || handle.address == 0
            || handle.allocation_generation == 0
            || end.is_some_and(|end| (image.base..end).contains(&handle.address))
        {
            return Err((SystemModuleError::InvalidIdentity, backing));
        }
        Ok(Self {
            image,
            handle,
            load_references: 0,
            backing,
        })
    }

    pub fn image(&self) -> SystemImageIdentity {
        self.image
    }
    pub fn handle(&self) -> SystemModuleHandleIdentity {
        self.handle
    }
    pub fn backing(&self) -> &R {
        &self.backing
    }
    pub fn load_references(&self) -> u64 {
        self.load_references
    }

    pub fn retain_load(
        &mut self,
        image: SystemImageIdentity,
        handle: SystemModuleHandleIdentity,
    ) -> Result<u64, SystemModuleError> {
        if image != self.image || handle != self.handle {
            return Err(SystemModuleError::IdentityMismatch);
        }
        let count = self
            .load_references
            .checked_add(1)
            .ok_or(SystemModuleError::ReferenceOverflow)?;
        self.load_references = count;
        Ok(count)
    }

    pub fn request_unload(
        &mut self,
        handle: SystemModuleHandleIdentity,
    ) -> Result<(), SystemModuleError> {
        if handle != self.handle {
            return Err(SystemModuleError::IdentityMismatch);
        }
        if self.load_references == 0 {
            return Err(SystemModuleError::NoLoadReference);
        }
        // A ref decrement is not an unload: callbacks, exception readers and native mappings
        // must have an exact retirement transaction before any backing can be relinquished.
        Err(SystemModuleError::TeardownUnsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> SystemImageIdentity {
        SystemImageIdentity {
            provider_domain: 1,
            provider_generation: 2,
            vspace: 3,
            image_owner: 4,
            base: 0x10000,
            size: 0x2000,
            entry_rva: 0x100,
            export_rva: 0x800,
        }
    }
    fn handle() -> SystemModuleHandleIdentity {
        SystemModuleHandleIdentity {
            address: 0x30000,
            allocation_id: 5,
            allocation_generation: 6,
        }
    }

    #[test]
    fn module_handle_is_a_real_distinct_allocation_not_image_base() {
        let module = SystemModule::new(image(), handle(), [7u64, 8, 9]).unwrap();
        assert_eq!(module.handle(), handle());
        assert_eq!(module.backing(), &[7, 8, 9]);
        assert_eq!(module.load_references(), 0);
        assert!(SystemModule::new(
            image(),
            SystemModuleHandleIdentity {
                address: image().base,
                ..handle()
            },
            ()
        )
        .is_err());
    }

    #[test]
    fn load_admission_requires_exact_domain_image_and_handle_generation() {
        let mut module = SystemModule::new(image(), handle(), [7u64]).unwrap();
        assert_eq!(module.retain_load(image(), handle()), Ok(1));
        assert_eq!(module.retain_load(image(), handle()), Ok(2));
        assert_eq!(
            module.retain_load(
                SystemImageIdentity {
                    provider_generation: 3,
                    ..image()
                },
                handle()
            ),
            Err(SystemModuleError::IdentityMismatch)
        );
        assert_eq!(
            module.retain_load(
                image(),
                SystemModuleHandleIdentity {
                    allocation_generation: 7,
                    ..handle()
                }
            ),
            Err(SystemModuleError::IdentityMismatch)
        );
        assert_eq!(module.load_references(), 2);
    }

    #[test]
    fn unsupported_unload_preserves_load_refs_and_all_backing() {
        let mut module = SystemModule::new(image(), handle(), [7u64, 8, 9]).unwrap();
        assert_eq!(
            module.request_unload(handle()),
            Err(SystemModuleError::NoLoadReference)
        );
        module.retain_load(image(), handle()).unwrap();
        assert_eq!(
            module.request_unload(handle()),
            Err(SystemModuleError::TeardownUnsupported)
        );
        assert_eq!(module.load_references(), 1);
        assert_eq!(module.backing(), &[7, 8, 9]);
        assert_eq!(
            module.request_unload(SystemModuleHandleIdentity {
                allocation_id: 9,
                ..handle()
            }),
            Err(SystemModuleError::IdentityMismatch)
        );
    }

    #[test]
    fn invalid_native_extents_return_ownership_to_caller() {
        let (_, backing) = SystemModule::new(
            SystemImageIdentity {
                entry_rva: 0x2000,
                ..image()
            },
            handle(),
            [42u64],
        )
        .unwrap_err();
        assert_eq!(backing, [42]);
        assert!(SystemModule::new(
            SystemImageIdentity {
                provider_generation: 0,
                ..image()
            },
            handle(),
            ()
        )
        .is_err());
        assert!(SystemModule::new(
            SystemImageIdentity {
                base: u64::MAX - 0x1000,
                ..image()
            },
            handle(),
            ()
        )
        .is_err());
    }
}
