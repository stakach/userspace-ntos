//! Retained restoration of an existing transition frame; never acquires or zeroes backing.
use crate::private_page_installation::{InstallationCap, InstallationEffect};
use crate::working_set::PagefilePage;

pub trait TransitionRestorationIo<D> {
    fn map_frame(&mut self, descriptor: &D, source: PagefilePage) -> InstallationEffect;
    fn reserve_alias(&mut self, descriptor: &D) -> Result<InstallationCap, u32>;
    fn copy_alias(&mut self, source: PagefilePage, alias: InstallationCap) -> InstallationEffect;
    fn map_alias(&mut self, descriptor: &D, alias: InstallationCap) -> InstallationEffect;
    /// ACK transfers the original frame and any alias together into resident ownership.
    fn publish_resident(
        &mut self,
        descriptor: &D,
        source: PagefilePage,
        alias: Option<InstallationCap>,
    ) -> InstallationEffect;
    fn unmap(&mut self, cap: InstallationCap) -> InstallationEffect;
    fn delete_alias(&mut self, alias: InstallationCap) -> InstallationEffect;
    fn recycle_alias(&mut self, alias: InstallationCap, populated: bool) -> InstallationEffect;
    /// Called only after every accepted map/alias effect has been undone. ACK transfers backing.
    fn restore_available(&mut self, source: PagefilePage) -> InstallationEffect;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionRestorationOutcome {
    Published,
    Restored(u32),
    CleanupPending(u32),
    Quarantined(u32),
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Map,
    Reserve,
    Copy,
    AliasMap,
    Publish,
    Rollback,
    Published,
    Restored,
    Quarantined,
}

/// No Drop cleanup. The containing native owner must retain this value until ownership transfers.
#[must_use]
pub struct TransitionPageRestoration<D> {
    descriptor: D,
    source: PagefilePage,
    wants_alias: bool,
    frame_mapped: bool,
    alias: Option<InstallationCap>,
    alias_populated: bool,
    alias_mapped: bool,
    phase: Phase,
    failure: u32,
}

impl<D: Copy + Eq> TransitionPageRestoration<D> {
    pub fn new(descriptor: D, source: PagefilePage, wants_alias: bool) -> Result<Self, u32> {
        if !source.lifetime.is_valid() || source.backing == 0 || source.page & 4095 != 0 {
            return Err(crate::STATUS_INVALID_HANDLE);
        }
        Ok(Self {
            descriptor,
            source,
            wants_alias,
            frame_mapped: false,
            alias: None,
            alias_populated: false,
            alias_mapped: false,
            phase: Phase::Map,
            failure: 0,
        })
    }
    pub fn descriptor(&self) -> D {
        self.descriptor
    }
    pub fn source(&self) -> PagefilePage {
        self.source
    }
    pub fn is_settled(&self) -> bool {
        matches!(self.phase, Phase::Published | Phase::Restored)
    }
    pub fn owns_backing(&self, cap: u64) -> bool {
        !self.is_settled() && cap == self.source.backing
    }
    pub fn begin_retirement(&mut self, descriptor: &D) -> bool {
        if self.descriptor != *descriptor || self.is_settled() || self.phase == Phase::Quarantined {
            return false;
        }
        if self.failure == 0 {
            self.failure = crate::STATUS_INVALID_HANDLE;
        }
        self.phase = Phase::Rollback;
        true
    }
    fn enter(&mut self, effect: InstallationEffect) -> bool {
        match effect {
            InstallationEffect::Acknowledged => true,
            InstallationEffect::Refused(status) => {
                self.failure = status;
                self.phase = Phase::Rollback;
                false
            }
            InstallationEffect::Uncertain(status) => {
                self.failure = status;
                self.phase = Phase::Quarantined;
                false
            }
        }
    }
    fn cleanup(&mut self, effect: InstallationEffect) -> Result<(), TransitionRestorationOutcome> {
        match effect {
            InstallationEffect::Acknowledged => Ok(()),
            InstallationEffect::Refused(status) => {
                Err(TransitionRestorationOutcome::CleanupPending(status))
            }
            InstallationEffect::Uncertain(status) => {
                self.failure = status;
                self.phase = Phase::Quarantined;
                Err(TransitionRestorationOutcome::Quarantined(status))
            }
        }
    }
    pub fn advance(
        &mut self,
        io: &mut impl TransitionRestorationIo<D>,
    ) -> TransitionRestorationOutcome {
        use TransitionRestorationOutcome as Outcome;
        loop {
            match self.phase {
                Phase::Map => {
                    let effect = io.map_frame(&self.descriptor, self.source);
                    if self.enter(effect) {
                        self.frame_mapped = true;
                        self.phase = if self.wants_alias {
                            Phase::Reserve
                        } else {
                            Phase::Publish
                        };
                    }
                }
                Phase::Reserve => match io.reserve_alias(&self.descriptor) {
                    Ok(alias) => {
                        // A malformed alias can never confer ownership of the source frame itself.
                        if alias.cap == 0 || alias.cap == self.source.backing {
                            self.phase = Phase::Quarantined;
                            self.failure = crate::STATUS_INVALID_HANDLE;
                        } else {
                            self.alias = Some(alias);
                            self.phase = Phase::Copy;
                        }
                    }
                    Err(status) => {
                        self.failure = status;
                        self.phase = Phase::Rollback;
                    }
                },
                Phase::Copy => {
                    let effect = io.copy_alias(self.source, self.alias.unwrap());
                    if self.enter(effect) {
                        self.alias_populated = true;
                        self.phase = Phase::AliasMap;
                    }
                }
                Phase::AliasMap => {
                    let effect = io.map_alias(&self.descriptor, self.alias.unwrap());
                    if self.enter(effect) {
                        self.alias_mapped = true;
                        self.phase = Phase::Publish;
                    }
                }
                Phase::Publish => {
                    let effect = io.publish_resident(&self.descriptor, self.source, self.alias);
                    if self.enter(effect) {
                        self.phase = Phase::Published;
                    }
                }
                Phase::Rollback => {
                    if let Some(alias) = self.alias {
                        if self.alias_mapped {
                            let effect = io.unmap(alias);
                            if let Err(outcome) = self.cleanup(effect) {
                                return outcome;
                            }
                            self.alias_mapped = false;
                        }
                        if self.alias_populated {
                            let effect = io.delete_alias(alias);
                            if let Err(outcome) = self.cleanup(effect) {
                                return outcome;
                            }
                            self.alias_populated = false;
                        }
                        let effect = io.recycle_alias(alias, false);
                        if let Err(outcome) = self.cleanup(effect) {
                            return outcome;
                        }
                        self.alias = None;
                    }
                    if self.frame_mapped {
                        let effect = io.unmap(InstallationCap {
                            cap: self.source.backing,
                        });
                        if let Err(outcome) = self.cleanup(effect) {
                            return outcome;
                        }
                        self.frame_mapped = false;
                    }
                    let effect = io.restore_available(self.source);
                    if let Err(outcome) = self.cleanup(effect) {
                        return outcome;
                    }
                    self.phase = Phase::Restored;
                }
                Phase::Published => return Outcome::Published,
                Phase::Restored => return Outcome::Restored(self.failure),
                Phase::Quarantined => return Outcome::Quarantined(self.failure),
            }
        }
    }
}
