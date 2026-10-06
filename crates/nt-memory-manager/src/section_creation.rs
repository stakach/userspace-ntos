//! Public NtCreateSection validation, before user pointer capture.

const SEC_BASED: u32 = 0x0020_0000;
const SEC_NO_CHANGE: u32 = 0x0040_0000;
const SEC_IMAGE: u32 = 0x0100_0000;
const SEC_RESERVE: u32 = 0x0400_0000;
const SEC_COMMIT: u32 = 0x0800_0000;
const SEC_NOCACHE: u32 = 0x1000_0000;
const STATUS_INVALID_PARAMETER_6: u32 = 0xc000_00f4;
const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xc000_0045;

/// NT5 creasect.c: allocation flags and forbidden protection bits precede
/// SectionHandle/MaximumSize probes. Full protection-mask validation happens
/// later in MmCreateSection; zero/composite masks must not change fault precedence.
pub fn validate_section_creation_parameters(attributes: u32, protection: u32) -> Result<(), u32> {
    let allowed = SEC_COMMIT | SEC_RESERVE | SEC_BASED | SEC_IMAGE | SEC_NOCACHE | SEC_NO_CHANGE;
    if attributes & !allowed != 0
        || attributes & (SEC_COMMIT | SEC_RESERVE | SEC_IMAGE) == 0
        || (attributes & SEC_IMAGE != 0
            && attributes & (SEC_COMMIT | SEC_RESERVE | SEC_NOCACHE | SEC_NO_CHANGE) != 0)
        || attributes & (SEC_COMMIT | SEC_RESERVE) == (SEC_COMMIT | SEC_RESERVE)
    {
        return Err(STATUS_INVALID_PARAMETER_6);
    }
    if protection & (0x01 | 0x100 | 0x200) != 0 {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    Ok(())
}
