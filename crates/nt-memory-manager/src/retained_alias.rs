//! Checked retirement of a mapped copy capability. The owner must retain this record on error.

#[derive(Debug, PartialEq, Eq)]
enum State {
    Live,
    RetiringMapped,
    RetiringUnmapped,
    Released,
}

/// A single alias owner, deliberately neither `Copy` nor `Clone`.
#[derive(Debug)]
pub struct RetainedAlias {
    cap: u64,
    state: State,
}

pub trait AliasRetirementIo {
    fn unmap(&mut self, cap: u64) -> Result<(), u32>;
    /// Delete the capability and recycle its slot only after successful deletion.
    fn delete(&mut self, cap: u64) -> Result<(), u32>;
}

impl RetainedAlias {
    /// Adopt an already mapped, non-null capability.
    pub fn new(cap: u64) -> Option<Self> {
        (cap != 0).then_some(Self {
            cap,
            state: State::Live,
        })
    }

    /// Ownership-inclusive capability, not permission to reuse a retiring mapping.
    pub fn cap(&self) -> u64 {
        self.cap
    }

    pub fn is_live(&self) -> bool {
        self.state == State::Live
    }

    /// Make the alias unavailable immediately, retaining successful cleanup progress on failure.
    pub fn retire(&mut self, io: &mut impl AliasRetirementIo) -> Result<(), u32> {
        if self.state == State::Live {
            self.state = State::RetiringMapped;
        }
        if self.state == State::RetiringMapped {
            io.unmap(self.cap)?;
            self.state = State::RetiringUnmapped;
        }
        if self.state == State::RetiringUnmapped {
            io.delete(self.cap)?;
            self.cap = 0;
            self.state = State::Released;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[derive(Default)]
    struct Io {
        fail_unmap: bool,
        fail_delete: bool,
        calls: Vec<(&'static str, u64)>,
    }
    impl AliasRetirementIo for Io {
        fn unmap(&mut self, cap: u64) -> Result<(), u32> {
            self.calls.push(("unmap", cap));
            if self.fail_unmap {
                Err(1)
            } else {
                Ok(())
            }
        }
        fn delete(&mut self, cap: u64) -> Result<(), u32> {
            self.calls.push(("delete", cap));
            if self.fail_delete {
                Err(2)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn rejects_null_capability() {
        assert!(RetainedAlias::new(0).is_none());
    }

    #[test]
    fn successful_retirement_is_idempotent() {
        let mut alias = RetainedAlias::new(42).unwrap();
        let mut io = Io::default();
        assert!(alias.is_live());
        assert_eq!(alias.cap(), 42);
        alias.retire(&mut io).unwrap();
        assert!(!alias.is_live());
        assert_eq!(alias.cap(), 0);
        alias.retire(&mut io).unwrap();
        assert_eq!(io.calls, vec![("unmap", 42), ("delete", 42)]);
    }

    #[test]
    fn failed_unmap_retains_cap_without_delete_or_live_projection() {
        let mut alias = RetainedAlias::new(42).unwrap();
        let mut io = Io {
            fail_unmap: true,
            ..Io::default()
        };
        assert_eq!(alias.retire(&mut io), Err(1));
        assert!(!alias.is_live());
        assert_eq!(alias.cap(), 42);
        assert_eq!(io.calls, vec![("unmap", 42)]);
        io.fail_unmap = false;
        alias.retire(&mut io).unwrap();
        assert_eq!(io.calls, vec![("unmap", 42), ("unmap", 42), ("delete", 42)]);
    }

    #[test]
    fn failed_delete_retains_cap_and_does_not_replay_successful_unmap() {
        let mut alias = RetainedAlias::new(97).unwrap();
        let mut io = Io {
            fail_delete: true,
            ..Io::default()
        };
        assert_eq!(alias.retire(&mut io), Err(2));
        assert!(!alias.is_live());
        assert_eq!(alias.cap(), 97);
        assert_eq!(alias.retire(&mut io), Err(2));
        io.fail_delete = false;
        alias.retire(&mut io).unwrap();
        assert_eq!(alias.cap(), 0);
        assert_eq!(
            io.calls,
            vec![
                ("unmap", 97),
                ("delete", 97),
                ("delete", 97),
                ("delete", 97)
            ]
        );
    }
}
