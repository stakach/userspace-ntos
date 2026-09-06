//! I/O-manager access admission for file-buffer flushing.

/// Generic grants remain accepted until the handle table normalizes generic access at creation.
pub fn file_flush_access_allowed(granted: u32, named_pipe: bool) -> bool {
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_APPEND_DATA: u32 = 0x0000_0004;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    // APPEND_DATA aliases CREATE_PIPE_INSTANCE, which does not authorize pipe flushing.
    let append = if named_pipe { 0 } else { FILE_APPEND_DATA };
    granted & (FILE_WRITE_DATA | append | GENERIC_WRITE | GENERIC_ALL) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_file_accepts_write_or_append_grants() {
        for access in [2, 4, 6, 0x4000_0000, 0x1000_0000] {
            assert!(file_flush_access_allowed(access, false));
        }
    }

    #[test]
    fn pipe_instance_creation_does_not_authorize_flush() {
        assert!(!file_flush_access_allowed(4, true));
        for access in [2, 6, 0x4000_0000, 0x1000_0000] {
            assert!(file_flush_access_allowed(access, true));
        }
    }

    #[test]
    fn read_metadata_and_synchronize_grants_do_not_authorize_flush() {
        for access in [0, 1, 0x8000_0000, 0x0010_0189] {
            assert!(!file_flush_access_allowed(access, false));
            assert!(!file_flush_access_allowed(access, true));
        }
    }
}
