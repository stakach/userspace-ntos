//! Select process initialization or thread attachment from captured loader-entry state.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoaderEntry {
    InitializeProcess { image_base: u64 },
    InitializeThread,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoaderEntryError {
    MissingPeb,
    MissingImage,
    MissingNtdll,
}

pub fn select_loader_entry(
    peb: u64,
    image_base: u64,
    loader_data: u64,
    ntdll_base: u64,
    _system_argument2: u64,
) -> Result<LoaderEntry, LoaderEntryError> {
    if peb == 0 {
        return Err(LoaderEntryError::MissingPeb);
    }
    if loader_data != 0 {
        return Ok(LoaderEntry::InitializeThread);
    }
    if image_base == 0 {
        return Err(LoaderEntryError::MissingImage);
    }
    if ntdll_base == 0 {
        return Err(LoaderEntryError::MissingNtdll);
    }
    Ok(LoaderEntry::InitializeProcess { image_base })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_process_uses_peb_image_when_reserved_argument_is_zero() {
        assert_eq!(
            select_loader_entry(0x1000, 0x400000, 0, 0x700000, 0),
            Ok(LoaderEntry::InitializeProcess {
                image_base: 0x400000
            })
        );
    }

    #[test]
    fn reserved_argument_cannot_override_peb_image_identity() {
        assert_eq!(
            select_loader_entry(0x1000, 0x400000, 0, 0x700000, 0x900000),
            Ok(LoaderEntry::InitializeProcess {
                image_base: 0x400000
            })
        );
    }

    #[test]
    fn missing_entry_authority_fails_instead_of_skipping_process_initialization() {
        assert_eq!(
            select_loader_entry(0, 0x400000, 0, 0x700000, 0x900000),
            Err(LoaderEntryError::MissingPeb)
        );
        assert_eq!(
            select_loader_entry(0x1000, 0, 0, 0x700000, 0x900000),
            Err(LoaderEntryError::MissingImage)
        );
        assert_eq!(
            select_loader_entry(0x1000, 0x400000, 0, 0, 0x900000),
            Err(LoaderEntryError::MissingNtdll)
        );
    }

    #[test]
    fn initialized_process_routes_thread_attachment_without_reserved_image_argument() {
        assert_eq!(
            select_loader_entry(0x1000, 0x400000, 0x2000, 0x700000, 0),
            Ok(LoaderEntry::InitializeThread)
        );
        assert_eq!(
            select_loader_entry(0x1000, 0x400000, 0x2000, 0x700000, 0x900000),
            Ok(LoaderEntry::InitializeThread)
        );
    }

    #[test]
    fn initialized_loader_requires_peb_but_not_process_initialization_arguments() {
        assert_eq!(
            select_loader_entry(0, 0x400000, 0x2000, 0x700000, 0),
            Err(LoaderEntryError::MissingPeb)
        );
        assert_eq!(
            select_loader_entry(0x1000, 0x400000, 0x2000, 0, 0),
            Ok(LoaderEntry::InitializeThread)
        );
    }
}
