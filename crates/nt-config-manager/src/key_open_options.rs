//! Options accepted by `NtOpenKeyEx` before any registry handle or key is acquired.

const REG_OPTION_BACKUP_RESTORE: u32 = 0x4;
const REG_OPTION_OPEN_LINK: u32 = 0x8;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// The `NtOpenKeyEx` options that change how the open proceeds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyOpenOptions {
    /// REG_OPTION_BACKUP_RESTORE: grant by backup/restore privilege instead of the key's DACL.
    pub backup: bool,
    /// REG_OPTION_OPEN_LINK: open a final symbolic link key itself (as OBJ_OPENLINK does).
    pub open_link: bool,
}

pub fn validate_key_open_options(options: u32) -> Result<KeyOpenOptions, u32> {
    if options & !(REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK) != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(KeyOpenOptions {
        backup: options & REG_OPTION_BACKUP_RESTORE != 0,
        open_link: options & REG_OPTION_OPEN_LINK != 0,
    })
}
