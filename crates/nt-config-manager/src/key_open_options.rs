//! Options accepted by `NtOpenKeyEx` before any registry handle or key is acquired.

const REG_OPTION_BACKUP_RESTORE: u32 = 0x4;
const REG_OPTION_OPEN_LINK: u32 = 0x8;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// Return whether backup/restore access applies. Registry links need their own object identity;
/// rejecting them here prevents an ordinary target open from silently following a link.
pub fn validate_key_open_options(options: u32) -> Result<bool, u32> {
    if options & !(REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK) != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if options & REG_OPTION_OPEN_LINK != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok(options & REG_OPTION_BACKUP_RESTORE != 0)
}
