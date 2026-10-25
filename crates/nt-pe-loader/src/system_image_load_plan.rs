//! Acquisition order for a system image whose bytes arrive through mounted File I/O.

use alloc::{string::String, vec::Vec};
use crate::module_namespace::{self, module_leaf};

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { NeedRead, Reading, NeedMap, Mapping, Mapped }

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
        Ok(Self { frames: alloc::vec![Frame { name, phase: Phase::NeedRead }], mapped: Vec::new() })
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
                Phase::Mapped => { self.frames.pop(); }
                Phase::Reading | Phase::Mapping => return None,
            }
        }
    }

    pub fn file_ready(&mut self, completed: &str, dependencies: &[&str]) -> Result<(), LoadPlanError> {
        let frame = self.frames.last().ok_or(LoadPlanError::WrongCompletion)?;
        if frame.phase != Phase::Reading || frame.name != completed {
            return Err(LoadPlanError::WrongCompletion);
        }
        let mut children = Vec::new();
        children.try_reserve(dependencies.len()).map_err(|_| LoadPlanError::NoCapacity)?;
        for dependency in dependencies {
            let name = module_leaf(dependency).map_err(|_| LoadPlanError::InvalidName)?;
            if module_namespace::core_role(&name).is_some() || name == "win32k.sys"
                || self.mapped.contains(&name) || children.contains(&name) {
                continue;
            }
            if self.frames.iter().any(|frame| frame.name == name) {
                return Err(LoadPlanError::Cycle);
            }
            children.push(name);
        }
        self.frames.try_reserve(children.len()).map_err(|_| LoadPlanError::NoCapacity)?;
        self.frames.last_mut().unwrap().phase = Phase::NeedMap;
        for name in children.into_iter().rev() {
            self.frames.push(Frame { name, phase: Phase::NeedRead });
        }
        Ok(())
    }

    pub fn mapped(&mut self, completed: &str) -> Result<(), LoadPlanError> {
        let frame = self.frames.last_mut().ok_or(LoadPlanError::WrongCompletion)?;
        if frame.phase != Phase::Mapping || frame.name != completed {
            return Err(LoadPlanError::WrongCompletion);
        }
        self.mapped.try_reserve(1).map_err(|_| LoadPlanError::NoCapacity)?;
        self.mapped.push(frame.name.clone());
        frame.phase = Phase::Mapped;
        Ok(())
    }

    pub fn skip_loaded(&mut self, name: &str) -> Result<(), LoadPlanError> {
        let frame = self.frames.last_mut().ok_or(LoadPlanError::WrongCompletion)?;
        if frame.phase != Phase::Reading || frame.name != name {
            return Err(LoadPlanError::WrongCompletion);
        }
        self.mapped.try_reserve(1).map_err(|_| LoadPlanError::NoCapacity)?;
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
        assert_eq!(plan.next(), Some(LoadAction::ReadMountedFile("cdd.dll".into())));
        plan.file_ready("cdd.dll", &["helper.dll"]).unwrap();
        assert_eq!(plan.next(), Some(LoadAction::ReadMountedFile("helper.dll".into())));
        plan.file_ready("helper.dll", &["forward.dll"]).unwrap();
        assert_eq!(plan.next(), Some(LoadAction::ReadMountedFile("forward.dll".into())));
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
        assert_eq!(plan.file_ready("b.dll", &[]), Err(LoadPlanError::WrongCompletion));
        assert_eq!(plan.next(), Some(LoadAction::ReadMountedFile("a.dll".into())));
        plan.file_ready("a.dll", &["b.dll"]).unwrap();
        assert_eq!(plan.next(), Some(LoadAction::ReadMountedFile("b.dll".into())));
        assert_eq!(plan.file_ready("b.dll", &["a.dll"]), Err(LoadPlanError::Cycle));
    }
}
