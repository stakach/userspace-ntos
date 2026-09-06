//! Explicit handoff of retired section resources to their owning mechanism.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionRetirementResource {
    Frame(u64),
    Backing(GenericSectionBacking),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionRetirement {
    section_index: usize,
    generation: u64,
    page_epoch: u64,
    pub resource: SectionRetirementResource,
}

pub trait SectionRetirementIo {
    /// Revoke all derived mappings and unmap the owner before recycling its physical frame.
    fn release_frame(&mut self, frame: u64) -> Result<(), u32>;
    /// Release the section's object reference, not an open handle reference.
    fn release_backing(&mut self, backing: GenericSectionBacking) -> Result<(), u32>;
}

/// Frames whose page-in failed before publication still need checked physical release.
pub struct PendingSectionFrames {
    frames: Vec<u64>,
}

impl PendingSectionFrames {
    pub const fn new() -> Self {
        Self { frames: Vec::new() }
    }

    /// Reserve the failure path before acquiring a frame; deferral must not allocate under failure.
    pub fn reserve(&mut self) -> bool {
        self.frames.try_reserve(1).is_ok()
    }

    pub fn release_or_defer(&mut self, frame: u64, io: &mut impl SectionRetirementIo) {
        assert!(frame != 0 && !self.frames.contains(&frame));
        assert!(
            self.frames.len() < self.frames.capacity(),
            "page-in reserves its cleanup owner"
        );
        if io.release_frame(frame).is_err() {
            self.frames.push(frame);
        }
    }

    pub fn drain(&mut self, io: &mut impl SectionRetirementIo) -> Result<(), u32> {
        while let Some(frame) = self.frames.last().copied() {
            io.release_frame(frame)?;
            self.frames.pop();
        }
        Ok(())
    }
}

impl Default for PendingSectionFrames {
    fn default() -> Self {
        Self::new()
    }
}

impl GenericSectionTable {
    pub fn next_retirement(&self) -> Option<SectionRetirement> {
        let (section_index, section) = self
            .sections
            .iter()
            .enumerate()
            .find(|(_, section)| !section.live && section.backing.is_live())?;
        let page = self
            .pages
            .iter()
            .find(|page| page.live && page.section_index == section_index);
        Some(SectionRetirement {
            section_index,
            generation: section.generation,
            page_epoch: page.map_or(0, |page| page.dirty_epoch),
            resource: page.map_or(
                SectionRetirementResource::Backing(section.backing),
                |page| SectionRetirementResource::Frame(page.frame),
            ),
        })
    }

    /// Acknowledge only the current exact-generation handoff after the mechanism succeeded.
    pub fn complete_retirement(&mut self, ticket: SectionRetirement) -> bool {
        if self.next_retirement() != Some(ticket) {
            return false;
        }
        match ticket.resource {
            SectionRetirementResource::Frame(frame) => {
                let Some(page) = self.pages.iter_mut().find(|page| {
                    page.live
                        && page.section_index == ticket.section_index
                        && page.frame == frame
                        && page.dirty_epoch == ticket.page_epoch
                }) else {
                    return false;
                };
                *page = GenericSectionPage::empty();
            }
            SectionRetirementResource::Backing(_) => {
                self.sections[ticket.section_index] = GenericSection::empty();
            }
        }
        true
    }

    /// Resource release is ordered: all frames before their file-object reference. Failure leaves
    /// the failed resource and every later resource owned, without replaying completed releases.
    pub fn drain_retired(&mut self, io: &mut impl SectionRetirementIo) -> Result<(), u32> {
        while let Some(ticket) = self.next_retirement() {
            match ticket.resource {
                SectionRetirementResource::Frame(frame) => io.release_frame(frame)?,
                SectionRetirementResource::Backing(backing) => io.release_backing(backing)?,
            }
            assert!(
                self.complete_retirement(ticket),
                "serialized section retirement retains its generation"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "section_retirement_tests.rs"]
mod tests;
