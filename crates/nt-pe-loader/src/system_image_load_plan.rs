//! Acquisition order for a system image whose bytes arrive through mounted File I/O.

use crate::module_namespace::{self, module_leaf};
use alloc::{string::String, vec::Vec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadAction {
    ReadMountedFile(String),
    Map(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadPlanError {
    InvalidName,
    WrongCompletion,
    Cycle,
    NoCapacity,
}

/// Search the driver directory only when System32 lookup established absence. Invalid names
/// and other failures remain terminal, preserving the original error.
pub const fn retry_driver_path(status: u32) -> bool {
    matches!(status, 0xc000_0034 | 0xc000_003a)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    NeedRead,
    Reading,
    NeedMap,
    Mapping,
    Mapped,
}

struct Frame {
    name: String,
    phase: Phase,
}

/// Depth first dependency acquisition; no image is mapped until every declared dependency has
/// been acquired and mapped. The caller owns file bytes and exact native I/O completion records.
pub struct SystemImageLoadPlan {
    frames: Vec<Frame>,
    mapped: Vec<String>,
}

impl SystemImageLoadPlan {
    pub fn new(root: &str) -> Result<Self, LoadPlanError> {
        let name = module_leaf(root).map_err(|_| LoadPlanError::InvalidName)?;
        Ok(Self {
            frames: alloc::vec![Frame {
                name,
                phase: Phase::NeedRead
            }],
            mapped: Vec::new(),
        })
    }

    pub fn next(&mut self) -> Option<LoadAction> {
        loop {
            let frame = self.frames.last_mut()?;
            match frame.phase {
                Phase::NeedRead => {
                    frame.phase = Phase::Reading;
                    return Some(LoadAction::ReadMountedFile(frame.name.clone()));
                }
                Phase::NeedMap => {
                    frame.phase = Phase::Mapping;
                    return Some(LoadAction::Map(frame.name.clone()));
                }
                Phase::Mapped => {
                    self.frames.pop();
                }
                Phase::Reading | Phase::Mapping => return None,
            }
        }
    }

    pub fn file_ready(
        &mut self,
        completed: &str,
        dependencies: &[&str],
    ) -> Result<(), LoadPlanError> {
        let frame = self.frames.last().ok_or(LoadPlanError::WrongCompletion)?;
        if frame.phase != Phase::Reading || frame.name != completed {
            return Err(LoadPlanError::WrongCompletion);
        }
        let mut children = Vec::new();
        children
            .try_reserve(dependencies.len())
            .map_err(|_| LoadPlanError::NoCapacity)?;
        for dependency in dependencies {
            let name = module_leaf(dependency).map_err(|_| LoadPlanError::InvalidName)?;
            if module_namespace::core_role(&name).is_some()
                || name == "win32k.sys"
                || self.mapped.contains(&name)
                || children.contains(&name)
            {
                continue;
            }
            if self.frames.iter().any(|frame| frame.name == name) {
                return Err(LoadPlanError::Cycle);
            }
            children.push(name);
        }
        self.frames
            .try_reserve(children.len())
            .map_err(|_| LoadPlanError::NoCapacity)?;
        self.frames.last_mut().unwrap().phase = Phase::NeedMap;
        for name in children.into_iter().rev() {
            self.frames.push(Frame {
                name,
                phase: Phase::NeedRead,
            });
        }
        Ok(())
    }

    pub fn mapped(&mut self, completed: &str) -> Result<(), LoadPlanError> {
        let frame = self
            .frames
            .last_mut()
            .ok_or(LoadPlanError::WrongCompletion)?;
        if frame.phase != Phase::Mapping || frame.name != completed {
            return Err(LoadPlanError::WrongCompletion);
        }
        self.mapped
            .try_reserve(1)
            .map_err(|_| LoadPlanError::NoCapacity)?;
        self.mapped.push(frame.name.clone());
        frame.phase = Phase::Mapped;
        Ok(())
    }

    /// Import preflight may discover a forwarded target after direct imports have been read.
    /// Reenter mapping only after the newly discovered module reaches a terminal map.
    pub fn require_dependency(
        &mut self,
        parent: &str,
        dependency: &str,
    ) -> Result<(), LoadPlanError> {
        let name = module_leaf(dependency).map_err(|_| LoadPlanError::InvalidName)?;
        let frame = self.frames.last().ok_or(LoadPlanError::WrongCompletion)?;
        if frame.phase != Phase::Mapping || frame.name != parent {
            return Err(LoadPlanError::WrongCompletion);
        }
        if self.frames.iter().any(|frame| frame.name == name) {
            return Err(LoadPlanError::Cycle);
        }
        if self.mapped.contains(&name) {
            return Err(LoadPlanError::WrongCompletion);
        }
        self.frames
            .try_reserve(1)
            .map_err(|_| LoadPlanError::NoCapacity)?;
        self.frames.last_mut().unwrap().phase = Phase::NeedMap;
        self.frames.push(Frame {
            name,
            phase: Phase::NeedRead,
        });
        Ok(())
    }

    pub fn skip_loaded(&mut self, name: &str) -> Result<(), LoadPlanError> {
        let frame = self
            .frames
            .last_mut()
            .ok_or(LoadPlanError::WrongCompletion)?;
        if frame.phase != Phase::Reading || frame.name != name {
            return Err(LoadPlanError::WrongCompletion);
        }
        self.mapped
            .try_reserve(1)
            .map_err(|_| LoadPlanError::NoCapacity)?;
        self.mapped.push(frame.name.clone());
        frame.phase = Phase::Mapped;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_handoff_image_load_waits_for_transitive_dependencies_before_mapping() {
        let mut plan = SystemImageLoadPlan::new("cdd.dll").unwrap();
        assert_eq!(
            plan.next(),
            Some(LoadAction::ReadMountedFile("cdd.dll".into()))
        );
        plan.file_ready("cdd.dll", &["helper.dll"]).unwrap();
        assert_eq!(
            plan.next(),
            Some(LoadAction::ReadMountedFile("helper.dll".into()))
        );
        plan.file_ready("helper.dll", &["forward.dll"]).unwrap();
        assert_eq!(
            plan.next(),
            Some(LoadAction::ReadMountedFile("forward.dll".into()))
        );
        plan.file_ready("forward.dll", &[]).unwrap();
        assert_eq!(plan.next(), Some(LoadAction::Map("forward.dll".into())));
        plan.mapped("forward.dll").unwrap();
        assert_eq!(plan.next(), Some(LoadAction::Map("helper.dll".into())));
        plan.mapped("helper.dll").unwrap();
        assert_eq!(plan.next(), Some(LoadAction::Map("cdd.dll".into())));
        plan.mapped("cdd.dll").unwrap();
        assert_eq!(plan.next(), None);
    }

    #[test]
    fn dependency_cycle_and_wrong_completion_fail_closed() {
        let mut plan = SystemImageLoadPlan::new("a.dll").unwrap();
        assert_eq!(
            plan.file_ready("b.dll", &[]),
            Err(LoadPlanError::WrongCompletion)
        );
        assert_eq!(
            plan.next(),
            Some(LoadAction::ReadMountedFile("a.dll".into()))
        );
        plan.file_ready("a.dll", &["b.dll"]).unwrap();
        assert_eq!(
            plan.next(),
            Some(LoadAction::ReadMountedFile("b.dll".into()))
        );
        assert_eq!(
            plan.file_ready("b.dll", &["a.dll"]),
            Err(LoadPlanError::Cycle)
        );
    }

    #[test]
    fn forwarded_target_discovered_during_import_preflight_blocks_map_effect() {
        let mut plan = SystemImageLoadPlan::new("cdd.dll").unwrap();
        assert_eq!(
            plan.next(),
            Some(LoadAction::ReadMountedFile("cdd.dll".into()))
        );
        plan.file_ready("cdd.dll", &[]).unwrap();
        assert_eq!(plan.next(), Some(LoadAction::Map("cdd.dll".into())));
        plan.require_dependency("cdd.dll", "forward.dll").unwrap();
        assert_eq!(
            plan.next(),
            Some(LoadAction::ReadMountedFile("forward.dll".into()))
        );
        plan.file_ready("forward.dll", &[]).unwrap();
        assert_eq!(plan.next(), Some(LoadAction::Map("forward.dll".into())));
        plan.mapped("forward.dll").unwrap();
        assert_eq!(plan.next(), Some(LoadAction::Map("cdd.dll".into())));
        plan.mapped("cdd.dll").unwrap();
        assert_eq!(plan.next(), None);
    }

    #[test]
    fn invalid_name_does_not_trigger_driver_directory_fallback() {
        assert!(retry_driver_path(0xc000_0034));
        assert!(retry_driver_path(0xc000_003a));
        assert!(!retry_driver_path(0xc000_0033));
        assert!(!retry_driver_path(0xc000_009a));
    }
}
