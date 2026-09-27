use crate::{ProcessIdentity, STATUS_INVALID_HANDLE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedImageMappingIdentity {
    pub pi: u64,
    pub process: ProcessIdentity,
    pub page: u64,
}

impl SharedImageMappingIdentity {
    pub const fn empty() -> Self {
        Self {
            pi: 0,
            process: ProcessIdentity::empty(),
            page: 0,
        }
    }

    pub fn new(pi: u64, process: ProcessIdentity, page: u64) -> Result<Self, u32> {
        if !process.is_valid() {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(Self { pi, process, page })
    }

    /// A foreign generation at the same slot and page is not an absent mapping.
    pub fn admit(self, pi: u64, process: ProcessIdentity, page: u64) -> Result<bool, u32> {
        if !process.is_valid() {
            return Err(STATUS_INVALID_HANDLE);
        }
        if self.pi != pi || self.page != page {
            return Ok(false);
        }
        if self.process != process {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProcessGeneration;

    #[test]
    fn reused_slot_cannot_take_or_replace_an_old_mapping() {
        let old = ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(1),
        };
        let new = ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(2),
        };
        let retained = SharedImageMappingIdentity::new(7, old, 0x1000).unwrap();
        let mut native_effects = 0;
        let admission = retained.admit(7, new, 0x1000).map(|found| {
            if found {
                native_effects += 1;
            }
        });
        assert_eq!(admission, Err(STATUS_INVALID_HANDLE));
        assert_eq!(native_effects, 0);
        assert_eq!(retained.admit(7, old, 0x1000), Ok(true));
        assert_eq!(retained.admit(7, new, 0x2000), Ok(false));
    }
}
