use crate::ProviderWaitOwner;

pub const PROVIDER_WAIT_ABI_MAGIC: u32 = u32::from_le_bytes(*b"PWT1");
pub const PROVIDER_WAIT_ABI_VERSION: u16 = 1;
pub const PROVIDER_WAIT_SHARED_MAGIC: u32 = u32::from_le_bytes(*b"PWS1");
pub const PROVIDER_WAIT_MAX_OBJECTS: usize = 64;
pub const PROVIDER_WAIT_OBJECT_FLAG_NONE: u32 = 0;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitType {
    All = 0,
    Any = 1,
}

impl ProviderWaitType {
    fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::All),
            1 => Some(Self::Any),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitMode {
    Kernel = 0,
    User = 1,
}

impl ProviderWaitMode {
    fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Kernel),
            1 => Some(Self::User),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitTimeoutKind {
    Infinite = 0,
    Poll = 1,
    Relative = 2,
    Absolute = 3,
}

impl ProviderWaitTimeoutKind {
    fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Infinite),
            1 => Some(Self::Poll),
            2 => Some(Self::Relative),
            3 => Some(Self::Absolute),
            _ => None,
        }
    }

    fn accepts(self, timeout_100ns: i64) -> bool {
        match self {
            Self::Infinite | Self::Poll => timeout_100ns == 0,
            Self::Relative => timeout_100ns < 0,
            Self::Absolute => timeout_100ns > 0,
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitObjectType {
    Event = 1,
    Semaphore = 2,
    Timer = 3,
    Process = 4,
    Thread = 5,
    File = 6,
}

impl ProviderWaitObjectType {
    fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Event),
            2 => Some(Self::Semaphore),
            3 => Some(Self::Timer),
            4 => Some(Self::Process),
            5 => Some(Self::Thread),
            6 => Some(Self::File),
            _ => None,
        }
    }
}

/// Canonical dispatcher-object identity. Provider virtual addresses never cross this boundary.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderWaitObject {
    pub object_type: u32,
    pub flags: u32,
    pub object_id: u64,
    pub object_generation: u64,
}

impl ProviderWaitObject {
    pub const EMPTY: Self = Self {
        object_type: 0,
        flags: 0,
        object_id: 0,
        object_generation: 0,
    };

    pub const fn new(
        object_type: ProviderWaitObjectType,
        object_id: u64,
        object_generation: u64,
    ) -> Self {
        Self {
            object_type: object_type as u32,
            flags: PROVIDER_WAIT_OBJECT_FLAG_NONE,
            object_id,
            object_generation,
        }
    }

    pub fn typed(&self) -> Option<ProviderWaitObjectType> {
        ProviderWaitObjectType::from_wire(self.object_type)
    }

    const fn is_empty(self) -> bool {
        self.object_type == 0
            && self.flags == 0
            && self.object_id == 0
            && self.object_generation == 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderWaitHeader {
    pub magic: u32,
    pub version: u16,
    pub header_size: u16,
    pub request_size: u32,
    pub object_count: u32,
    pub wait_type: u32,
    pub wait_mode: u32,
    pub alertable: u32,
    pub timeout_kind: u32,
    pub reserved: u32,
    pub timeout_100ns: i64,
    pub wait_id: u64,
    pub provider_domain: u64,
    pub provider_generation: u64,
    pub client_pi: u32,
    pub owner_reserved: u32,
    pub client_generation: u64,
    pub client_tid: u64,
    pub client_badge: u64,
    pub dispatch_id: u64,
}

impl ProviderWaitHeader {
    pub const EMPTY: Self = Self {
        magic: 0,
        version: 0,
        header_size: 0,
        request_size: 0,
        object_count: 0,
        wait_type: 0,
        wait_mode: 0,
        alertable: 0,
        timeout_kind: 0,
        reserved: 0,
        timeout_100ns: 0,
        wait_id: 0,
        provider_domain: 0,
        provider_generation: 0,
        client_pi: 0,
        owner_reserved: 0,
        client_generation: 0,
        client_tid: 0,
        client_badge: 0,
        dispatch_id: 0,
    };

    pub const fn owner(self) -> ProviderWaitOwner {
        ProviderWaitOwner {
            provider_domain: self.provider_domain,
            provider_generation: self.provider_generation,
            client_pi: self.client_pi,
            client_generation: self.client_generation,
            client_tid: self.client_tid,
            client_badge: self.client_badge,
            dispatch_id: self.dispatch_id,
        }
    }
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderWaitRequest {
    pub header: ProviderWaitHeader,
    pub objects: [ProviderWaitObject; PROVIDER_WAIT_MAX_OBJECTS],
}

const _: () = assert!(core::mem::size_of::<ProviderWaitRequest>() <= 0x1000);
const _: () = assert!(core::mem::align_of::<ProviderWaitRequest>() == 8);

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderWaitSharedControl {
    pub magic: u32,
    pub version: u16,
    pub control_size: u16,
    pub page_size: u32,
    pub reserved: u32,
    pub provider_domain: u64,
    pub provider_generation: u64,
}

impl ProviderWaitSharedControl {
    pub const EMPTY: Self = Self {
        magic: 0,
        version: 0,
        control_size: 0,
        page_size: 0,
        reserved: 0,
        provider_domain: 0,
        provider_generation: 0,
    };

    pub const fn published(identity: crate::ProviderDomainIdentity) -> Self {
        Self {
            magic: PROVIDER_WAIT_SHARED_MAGIC,
            version: PROVIDER_WAIT_ABI_VERSION,
            control_size: core::mem::size_of::<Self>() as u16,
            page_size: core::mem::size_of::<ProviderWaitSharedPage>() as u32,
            reserved: 0,
            provider_domain: identity.domain,
            provider_generation: identity.generation,
        }
    }

    pub const fn identity(self) -> Option<crate::ProviderDomainIdentity> {
        let identity = crate::ProviderDomainIdentity {
            domain: self.provider_domain,
            generation: self.provider_generation,
        };
        if self.magic == PROVIDER_WAIT_SHARED_MAGIC
            && self.version == PROVIDER_WAIT_ABI_VERSION
            && self.control_size as usize == core::mem::size_of::<Self>()
            && self.page_size as usize == core::mem::size_of::<ProviderWaitSharedPage>()
            && self.reserved == 0
            && identity.is_valid()
        {
            Some(identity)
        } else {
            None
        }
    }
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderWaitSharedPage {
    pub control: ProviderWaitSharedControl,
    pub request: ProviderWaitRequest,
}

impl ProviderWaitSharedPage {
    pub const fn empty() -> Self {
        Self {
            control: ProviderWaitSharedControl::EMPTY,
            request: ProviderWaitRequest::empty(),
        }
    }
}

const _: () = assert!(core::mem::size_of::<ProviderWaitSharedPage>() <= 0x1000);
const _: () = assert!(core::mem::align_of::<ProviderWaitSharedPage>() == 8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderWaitRequestMetadata {
    pub wait_id: u64,
    pub owner: ProviderWaitOwner,
    pub wait_type: ProviderWaitType,
    pub wait_mode: ProviderWaitMode,
    pub alertable: bool,
    pub timeout_kind: ProviderWaitTimeoutKind,
    pub timeout_100ns: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitAbiError {
    InvalidHeader,
    InvalidIdentity,
    InvalidObjectCount,
    InvalidWaitType,
    InvalidWaitMode,
    InvalidAlertable,
    InvalidTimeout,
    InvalidObject,
    DuplicateObject,
    DirtyTail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedProviderWait<'a> {
    pub wait_id: u64,
    pub owner: ProviderWaitOwner,
    pub wait_type: ProviderWaitType,
    pub wait_mode: ProviderWaitMode,
    pub alertable: bool,
    pub timeout_kind: ProviderWaitTimeoutKind,
    pub timeout_100ns: i64,
    pub objects: &'a [ProviderWaitObject],
}

impl ProviderWaitRequest {
    pub const fn empty() -> Self {
        Self {
            header: ProviderWaitHeader::EMPTY,
            objects: [ProviderWaitObject::EMPTY; PROVIDER_WAIT_MAX_OBJECTS],
        }
    }

    pub fn begin(
        &mut self,
        metadata: ProviderWaitRequestMetadata,
        objects: &[ProviderWaitObject],
    ) -> Result<(), ProviderWaitAbiError> {
        if objects.is_empty() || objects.len() > PROVIDER_WAIT_MAX_OBJECTS {
            return Err(ProviderWaitAbiError::InvalidObjectCount);
        }

        *self = Self::empty();
        self.header = ProviderWaitHeader {
            magic: PROVIDER_WAIT_ABI_MAGIC,
            version: PROVIDER_WAIT_ABI_VERSION,
            header_size: core::mem::size_of::<ProviderWaitHeader>() as u16,
            request_size: (core::mem::size_of::<ProviderWaitHeader>()
                + objects.len() * core::mem::size_of::<ProviderWaitObject>())
                as u32,
            object_count: objects.len() as u32,
            wait_type: metadata.wait_type as u32,
            wait_mode: metadata.wait_mode as u32,
            alertable: u32::from(metadata.alertable),
            timeout_kind: metadata.timeout_kind as u32,
            reserved: 0,
            timeout_100ns: metadata.timeout_100ns,
            wait_id: metadata.wait_id,
            provider_domain: metadata.owner.provider_domain,
            provider_generation: metadata.owner.provider_generation,
            client_pi: metadata.owner.client_pi,
            owner_reserved: 0,
            client_generation: metadata.owner.client_generation,
            client_tid: metadata.owner.client_tid,
            client_badge: metadata.owner.client_badge,
            dispatch_id: metadata.owner.dispatch_id,
        };
        self.objects[..objects.len()].copy_from_slice(objects);
        self.validate().map(|_| ())
    }

    pub fn validate(&self) -> Result<ValidatedProviderWait<'_>, ProviderWaitAbiError> {
        let header_size = core::mem::size_of::<ProviderWaitHeader>();
        if self.header.magic != PROVIDER_WAIT_ABI_MAGIC
            || self.header.version != PROVIDER_WAIT_ABI_VERSION
            || self.header.header_size as usize != header_size
            || self.header.reserved != 0
            || self.header.owner_reserved != 0
        {
            return Err(ProviderWaitAbiError::InvalidHeader);
        }
        let count = self.header.object_count as usize;
        if count == 0 || count > PROVIDER_WAIT_MAX_OBJECTS {
            return Err(ProviderWaitAbiError::InvalidObjectCount);
        }
        let request_size = header_size
            .checked_add(count * core::mem::size_of::<ProviderWaitObject>())
            .ok_or(ProviderWaitAbiError::InvalidHeader)?;
        if self.header.request_size as usize != request_size {
            return Err(ProviderWaitAbiError::InvalidHeader);
        }
        if self.header.wait_id == 0 || !self.header.owner().is_valid() {
            return Err(ProviderWaitAbiError::InvalidIdentity);
        }
        let wait_type = ProviderWaitType::from_wire(self.header.wait_type)
            .ok_or(ProviderWaitAbiError::InvalidWaitType)?;
        let wait_mode = ProviderWaitMode::from_wire(self.header.wait_mode)
            .ok_or(ProviderWaitAbiError::InvalidWaitMode)?;
        let alertable = match self.header.alertable {
            0 => false,
            1 => true,
            _ => return Err(ProviderWaitAbiError::InvalidAlertable),
        };
        let timeout_kind = ProviderWaitTimeoutKind::from_wire(self.header.timeout_kind)
            .ok_or(ProviderWaitAbiError::InvalidTimeout)?;
        if !timeout_kind.accepts(self.header.timeout_100ns) {
            return Err(ProviderWaitAbiError::InvalidTimeout);
        }

        let objects = &self.objects[..count];
        for (index, object) in objects.iter().enumerate() {
            if object.typed().is_none()
                || object.flags != PROVIDER_WAIT_OBJECT_FLAG_NONE
                || object.object_id == 0
                || object.object_generation == 0
            {
                return Err(ProviderWaitAbiError::InvalidObject);
            }
            if objects[..index].iter().any(|candidate| {
                candidate.object_id == object.object_id
                    && candidate.object_generation == object.object_generation
            }) {
                return Err(ProviderWaitAbiError::DuplicateObject);
            }
        }
        if self.objects[count..]
            .iter()
            .any(|object| !object.is_empty())
        {
            return Err(ProviderWaitAbiError::DirtyTail);
        }

        Ok(ValidatedProviderWait {
            wait_id: self.header.wait_id,
            owner: self.header.owner(),
            wait_type,
            wait_mode,
            alertable,
            timeout_kind,
            timeout_100ns: self.header.timeout_100ns,
            objects,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> ProviderWaitOwner {
        ProviderWaitOwner {
            provider_domain: 9,
            provider_generation: 3,
            client_pi: 2,
            client_generation: 4,
            client_tid: 24,
            client_badge: 7,
            dispatch_id: 11,
        }
    }

    fn metadata() -> ProviderWaitRequestMetadata {
        ProviderWaitRequestMetadata {
            wait_id: 1,
            owner: owner(),
            wait_type: ProviderWaitType::Any,
            wait_mode: ProviderWaitMode::Kernel,
            alertable: false,
            timeout_kind: ProviderWaitTimeoutKind::Relative,
            timeout_100ns: -10_000,
        }
    }

    #[test]
    fn single_and_maximum_object_requests_round_trip_without_pointers() {
        let mut request = ProviderWaitRequest::empty();
        request
            .begin(
                metadata(),
                &[ProviderWaitObject::new(ProviderWaitObjectType::Event, 4, 2)],
            )
            .unwrap();
        let validated = request.validate().unwrap();
        assert_eq!(validated.objects.len(), 1);
        assert_eq!(validated.owner, owner());

        let mut objects = [ProviderWaitObject::EMPTY; PROVIDER_WAIT_MAX_OBJECTS];
        for (index, object) in objects.iter_mut().enumerate() {
            *object =
                ProviderWaitObject::new(ProviderWaitObjectType::Semaphore, index as u64 + 1, 5);
        }
        request.begin(metadata(), &objects).unwrap();
        assert_eq!(request.validate().unwrap().objects.len(), 64);
        assert!(core::mem::size_of::<ProviderWaitRequest>() <= 0x1000);
    }

    #[test]
    fn malformed_header_and_stale_tail_fail_closed() {
        let object = ProviderWaitObject::new(ProviderWaitObjectType::Event, 4, 2);
        let mut request = ProviderWaitRequest::empty();
        request.begin(metadata(), &[object]).unwrap();
        request.header.request_size += 1;
        assert_eq!(request.validate(), Err(ProviderWaitAbiError::InvalidHeader));

        request.begin(metadata(), &[object]).unwrap();
        request.objects[1] = ProviderWaitObject::new(ProviderWaitObjectType::Timer, 5, 1);
        assert_eq!(request.validate(), Err(ProviderWaitAbiError::DirtyTail));
    }

    #[test]
    fn duplicate_or_untyped_objects_fail_closed() {
        let object = ProviderWaitObject::new(ProviderWaitObjectType::Event, 4, 2);
        let mut request = ProviderWaitRequest::empty();
        assert_eq!(
            request.begin(metadata(), &[object, object]),
            Err(ProviderWaitAbiError::DuplicateObject)
        );

        let invalid = ProviderWaitObject {
            object_type: 99,
            ..object
        };
        assert_eq!(
            request.begin(metadata(), &[invalid]),
            Err(ProviderWaitAbiError::InvalidObject)
        );
    }

    #[test]
    fn timeout_forms_are_exact() {
        let object = ProviderWaitObject::new(ProviderWaitObjectType::Event, 4, 2);
        let mut request = ProviderWaitRequest::empty();
        for (kind, value) in [
            (ProviderWaitTimeoutKind::Infinite, 0),
            (ProviderWaitTimeoutKind::Poll, 0),
            (ProviderWaitTimeoutKind::Relative, -1),
            (ProviderWaitTimeoutKind::Absolute, 1),
        ] {
            let mut meta = metadata();
            meta.timeout_kind = kind;
            meta.timeout_100ns = value;
            request.begin(meta, &[object]).unwrap();
        }

        let mut meta = metadata();
        meta.timeout_kind = ProviderWaitTimeoutKind::Relative;
        meta.timeout_100ns = 1;
        assert_eq!(
            request.begin(meta, &[object]),
            Err(ProviderWaitAbiError::InvalidTimeout)
        );
    }

    #[test]
    fn owner_and_boolean_wire_values_are_validated() {
        let object = ProviderWaitObject::new(ProviderWaitObjectType::File, 8, 1);
        let mut request = ProviderWaitRequest::empty();
        request.begin(metadata(), &[object]).unwrap();
        request.header.provider_generation = 0;
        assert_eq!(
            request.validate(),
            Err(ProviderWaitAbiError::InvalidIdentity)
        );

        request.begin(metadata(), &[object]).unwrap();
        request.header.alertable = 2;
        assert_eq!(
            request.validate(),
            Err(ProviderWaitAbiError::InvalidAlertable)
        );
    }

    #[test]
    fn shared_control_rejects_unpublished_or_stale_layouts() {
        let identity = crate::ProviderDomainIdentity {
            domain: 4,
            generation: 2,
        };
        let mut page = ProviderWaitSharedPage::empty();
        assert_eq!(page.control.identity(), None);
        page.control = ProviderWaitSharedControl::published(identity);
        assert_eq!(page.control.identity(), Some(identity));
        page.control.provider_generation = 0;
        assert_eq!(page.control.identity(), None);
        page.control = ProviderWaitSharedControl::published(identity);
        page.control.page_size -= 1;
        assert_eq!(page.control.identity(), None);
    }
}
