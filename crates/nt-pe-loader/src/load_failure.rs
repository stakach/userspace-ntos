//! Stable failure classification for checked system-image admission.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadFailure {
    FileMissing,
    InvalidImage,
    MissingExport,
    InsufficientResources,
    NativeFailure,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn load_failures_preserve_distinct_ntstatus() {
        assert_eq!(LoadFailure::FileMissing.ntstatus() as u32, 0xc000_0135);
        assert_eq!(LoadFailure::InvalidImage.ntstatus() as u32, 0xc000_007b);
        assert_eq!(LoadFailure::MissingExport.ntstatus() as u32, 0xc000_007a);
        assert_eq!(
            LoadFailure::InsufficientResources.ntstatus() as u32,
            0xc000_009a
        );
        assert_eq!(LoadFailure::NativeFailure.ntstatus() as u32, 0xc000_0001);
        assert_eq!(
            LoadFailure::from_native_error(10),
            LoadFailure::InsufficientResources
        );
        assert_eq!(
            LoadFailure::from_native_error(4),
            LoadFailure::NativeFailure
        );
    }
}

impl LoadFailure {
    pub const fn ntstatus(self) -> i32 {
        (match self {
            Self::FileMissing => 0xc000_0135u32,
            Self::InvalidImage => 0xc000_007b,
            Self::MissingExport => 0xc000_007a,
            Self::InsufficientResources => 0xc000_009a,
            Self::NativeFailure => 0xc000_0001,
        }) as i32
    }
    /// seL4 error 10 is NotEnoughMemory; other acknowledged native failures are not file absence.
    pub const fn from_native_error(error: u64) -> Self {
        if error == 10 {
            Self::InsufficientResources
        } else {
            Self::NativeFailure
        }
    }
}
