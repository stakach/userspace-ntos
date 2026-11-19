//! Explicit handoff of retired section resources to their owning mechanism.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionRetirementResource {
    Frame(u64),
    Backing(GenericSectionBacking),
}

/// Exact section incarnation. A file identity may be shared by several sections, but each
/// section owns its own backing reference and must release it only once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionIdentity {
    pub(super) index: usize,
    pub(super) generation: u64,
}

impl SectionIdentity {
    pub const fn index(self) -> usize {
        self.index
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionRetirement {
    section_index: usize,
    generation: u64,
    control_area: u64,
    page_epoch: u64,
    pub resource: SectionRetirementResource,
}

impl SectionRetirement {
    pub const fn identity(self) -> SectionIdentity {
        SectionIdentity {
            index: self.section_index,
            generation: self.generation,
        }
    }
}

pub trait SectionRetirementIo {
    /// Revoke all derived mappings and unmap the owner before recycling its physical frame.
    fn release_frame(&mut self, frame: u64) -> Result<(), u32>;
    /// Release the section's object reference, not an open handle reference.
    fn release_backing(
        &mut self,
        identity: SectionIdentity,
        backing: GenericSectionBacking,
    ) -> Result<(), u32>;
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
            .find(|(index, section)| {
                let identity = SectionIdentity { index: *index, generation: section.generation };
                !section.live
                    && section.backing.is_live()
                    && !self.write_in_flight_via(identity)
                    && !self.needs_retained_writer(identity, section.control_area)
            })?;
        let page = if self.control_area_live(section.control_area) {
            None
        } else {
            self.pages
                .iter()
                .find(|page| page.control_area == section.control_area && self.page_releasable(page))
        };
        Some(SectionRetirement {
            section_index,
            generation: section.generation,
            control_area: section.control_area,
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
                        && page.control_area == ticket.control_area
                        && page.frame == frame
                        && page.dirty_epoch == ticket.page_epoch
                }) else {
                    return false;
                };
                *page = GenericSectionPage::empty();
            }
            SectionRetirementResource::Backing(_) => {
                self.sections[ticket.section_index] = GenericSection::empty();
                self.retire_control_area_if_unreferenced(ticket.control_area);
            }
        }
        true
    }

    /// Resource release is ordered: all frames before their file-object reference. Failure leaves
    /// the failed resource and every later resource owned, without replaying completed releases.
    /// A section waits only for a write in flight through its own FILE_OBJECT. When its file data
    /// still needs that FILE_OBJECT (an uncertain write, or released pages owing a write), the
    /// section retires into a page writer that keeps only the FILE_OBJECT and those pages.
    pub fn drain_retired(&mut self, io: &mut impl SectionRetirementIo) -> Result<(), u32> {
        for section_index in 0..self.sections.len() {
            let section = self.sections[section_index];
            let identity = SectionIdentity { index: section_index, generation: section.generation };
            if section.live || !section.backing.is_live() || self.write_in_flight_via(identity) {
                continue;
            }
            if !self.control_area_live(section.control_area) {
                self.release_settled_frames(section.control_area, io)?;
            }
            if self.needs_retained_writer(identity, section.control_area) {
                if self.retired_writers.try_reserve(1).is_err() {
                    continue; // The section stays whole and retries.
                }
                self.retired_writers.push(super::page_writes::RetiredPageWriter {
                    identity,
                    control_area: section.control_area,
                    backing: section.backing,
                });
                self.sections[section_index] = GenericSection::empty();
                continue;
            }
            io.release_backing(identity, section.backing)?;
            self.sections[section_index] = GenericSection::empty();
            self.retire_control_area_if_unreferenced(section.control_area);
        }
        self.drain_retired_writers(io)
    }
}

#[cfg(test)]
#[path = "section_retirement_tests.rs"]
mod tests;
