use crate::{PdoProperties, PropertyBlobState};

impl PdoProperties {
    /// Return only resources whose assignment is already known for a raw PDO START.
    pub fn raw_start_resource_bytes(&self) -> Option<(&[u8], &[u8])> {
        match (&self.allocated_resources_raw, &self.allocated_resources_translated) {
            (PropertyBlobState::KnownNone, PropertyBlobState::KnownNone) => Some((&[], &[])),
            (PropertyBlobState::Present(raw), PropertyBlobState::Present(translated)) => {
                Some((raw, translated))
            }
            (PropertyBlobState::Unqueried, PropertyBlobState::Unqueried)
                if self.boot_resources_raw == PropertyBlobState::KnownNone
                    && self.boot_resources_translated == PropertyBlobState::KnownNone
                    && self.resource_requirements == PropertyBlobState::KnownNone =>
            {
                // The bus has positively reported no boot resources or requirements. The
                // PDO-only stack needs no arbiter assignment before its real START IRP.
                Some((&[], &[]))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_no_boot_resources_and_no_requirements_admit_empty_raw_start() {
        let properties = PdoProperties::from_bus_queries(
            None,
            None,
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
        );
        assert_eq!(properties.raw_start_resource_bytes(), Some((&[][..], &[][..])));
    }

    #[test]
    fn unknown_or_unassigned_hardware_resources_are_not_empty_resources() {
        let mut properties = PdoProperties::from_bus_queries(
            None,
            None,
            PropertyBlobState::Unqueried,
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
        );
        assert_eq!(properties.raw_start_resource_bytes(), None);
        properties.boot_resources_raw = PropertyBlobState::Present(alloc::vec![1]);
        assert_eq!(properties.raw_start_resource_bytes(), None);
        properties.allocated_resources_raw = PropertyBlobState::Present(alloc::vec![2]);
        properties.allocated_resources_translated = PropertyBlobState::Present(alloc::vec![3]);
        assert_eq!(properties.raw_start_resource_bytes(), Some((&[2][..], &[3][..])));
    }
}
