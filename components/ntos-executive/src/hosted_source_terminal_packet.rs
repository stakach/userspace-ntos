//! One durable transport owner for source terminal preparation and origin retirement.

use super::*;
use crate::win32k_subsystem::{RootPoolError, RootProviderPoolAllocation};
use nt_io_manager::source_terminal::{
    same_terminal_packet, OriginCommitObservation as Observation, OriginCommitPhase as Phase,
    TerminalPublication, TERMINAL_NOT_READY,
};

type Dispatch = unsafe fn(u64, u64) -> crate::win32k_glue::SourcePnpTerminalDispatch;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparePhase { Publish, Dispatch, ReadAck, Published, Indeterminate }

pub(super) struct RetainedTerminalPacket {
    allocation: Option<RootProviderPoolAllocation>,
    encoded: Vec<u8>,
    prepare: PreparePhase,
    commit: Phase,
    command: Option<(bool, u64, usize, Vec<u8>)>,
    ack: Option<Vec<u8>>,
}

impl RetainedTerminalPacket {
    pub(super) fn new(encoded: Vec<u8>) -> Self {
        Self { allocation: None, encoded, prepare: PreparePhase::Publish,
            commit: Phase::CaptureBefore, command: None, ack: None }
    }

    pub(super) fn indeterminate(&self) -> bool {
        self.prepare == PreparePhase::Indeterminate || self.commit == Phase::Indeterminate
    }

    pub(super) fn progress(&self) -> u64 {
        1 + (self.prepare as u64) + ((self.commit as u64) << 8)
            + ((self.allocation.is_some() as u64) << 16)
    }

    pub(super) fn needs_lane(&self, finishing: bool) -> bool {
        if finishing { self.commit == Phase::DispatchOrigin }
        else { self.prepare == PreparePhase::Dispatch }
    }

    fn failed(&mut self, error: RootPoolError) -> bool {
        if matches!(error, RootPoolError::InvalidIdentity | RootPoolError::Indeterminate) {
            self.commit = Phase::Indeterminate;
        }
        false
    }

    pub(super) unsafe fn publish(&mut self) -> bool {
        if self.indeterminate() { return false; }
        if self.prepare != PreparePhase::Publish { return true; }
        if self.allocation.is_none() {
            match crate::win32k_subsystem::try_allocate_root_provider_pool_allocation(self.encoded.len() as u64) {
                Ok(allocation) => self.allocation = Some(allocation),
                Err(error) => return self.failed(error),
            }
        }
        let lease = self.allocation.expect("owned terminal packet").packet_lease();
        if let Err(error) = crate::win32k_subsystem::try_publish_root_provider_pool_packet(lease, &self.encoded) {
            return self.failed(error);
        }
        self.prepare = PreparePhase::Dispatch;
        true
    }

    pub(super) unsafe fn prepare(&mut self, dispatch: Dispatch) -> bool {
        if !self.publish() { return false; }
        let lease = self.allocation.expect("owned terminal packet").packet_lease();
        if self.prepare == PreparePhase::Dispatch {
            if !crate::win32k_glue::source_terminal_dispatch_ready() { return false; }
            match dispatch(lease.address(), self.encoded.len() as u64) {
                crate::win32k_glue::SourcePnpTerminalDispatch::NotEntered(_) => return false,
                crate::win32k_glue::SourcePnpTerminalDispatch::Returned(status)
                    if status == TERMINAL_NOT_READY => return false,
                crate::win32k_glue::SourcePnpTerminalDispatch::Returned(0) => {
                    // Record native success BEFORE any fallible local pool readback.
                    self.prepare = PreparePhase::ReadAck;
                }
                _ => { self.prepare = PreparePhase::Indeterminate; return false; }
            }
        }
        if self.prepare == PreparePhase::ReadAck && self.ack.is_none() {
            match crate::win32k_subsystem::try_capture_root_provider_pool_packet(lease) {
                Ok(bytes) => self.ack = Some(bytes),
                Err(error) => return self.failed(error),
            }
        }
        self.ack.is_some()
    }

    pub(super) fn ack(&self) -> &[u8] { self.ack.as_deref().expect("captured terminal ACK") }

    pub(super) fn acknowledge_prepare(&mut self, valid: bool) -> bool {
        if !valid { self.prepare = PreparePhase::Indeterminate; return false; }
        assert!(self.prepare == PreparePhase::ReadAck);
        self.prepare = PreparePhase::Published;
        self.ack = None;
        true
    }

    fn observe(&mut self, observation: Observation) {
        self.commit = self.commit.observe(observation).expect("ordered origin packet effect");
    }

    pub(super) unsafe fn finish(&mut self, offset: usize, discard: bool, sequence: u64, dispatch: Dispatch) -> bool {
        if self.indeterminate() || !self.publish() { return false; }
        if let Some((saved_discard, saved_sequence, saved_offset, _)) = &self.command {
            if *saved_discard != discard || *saved_sequence != sequence || *saved_offset != offset {
                self.commit = Phase::Indeterminate;
                return false;
            }
        }
        if self.commit == Phase::Complete { return true; }
        let allocation = self.allocation.expect("retained origin command packet");
        let lease = allocation.packet_lease();
        loop {
            match self.commit {
                Phase::CaptureBefore => {
                    let mut before = match crate::win32k_subsystem::try_capture_root_provider_pool_packet(lease) {
                        Ok(bytes) => bytes,
                        Err(error) => return self.failed(error),
                    };
                    let Some(words) = before.get(offset..offset + 16) else {
                        self.commit = Phase::Indeterminate; return false;
                    };
                    let stage = u32::from_le_bytes(words[..4].try_into().unwrap());
                    let status = u32::from_le_bytes(words[4..8].try_into().unwrap());
                    let previous = if stage == 0 && status == 0 { None }
                        else { TerminalPublication::decode(stage, status) };
                    let command = if discard { TerminalPublication::DiscardRequested }
                        else { TerminalPublication::CommitRequested };
                    if !same_terminal_packet(&self.encoded, &before, offset)
                        || ((stage != 0 || status != 0) && previous.is_none())
                        || !command.can_follow(previous)
                        || (!discard && self.prepare != PreparePhase::Published)
                    { self.commit = Phase::Indeterminate; return false; }
                    let (stage, status) = command.words();
                    before[offset..offset + 4].copy_from_slice(&stage.to_le_bytes());
                    before[offset + 4..offset + 8].copy_from_slice(&status.to_le_bytes());
                    before[offset + 8..offset + 16].copy_from_slice(&sequence.to_le_bytes());
                    self.command = Some((discard, sequence, offset, before));
                    self.observe(Observation::CapturedBefore);
                }
                Phase::PublishCommand => {
                    let before = &self.command.as_ref().expect("retained command snapshot").3;
                    if let Err(error) = crate::win32k_subsystem::try_publish_root_provider_pool_packet(lease, before) {
                        return self.failed(error);
                    }
                    self.observe(Observation::CommandPublished);
                }
                Phase::DispatchOrigin => {
                    // Local progress can reach Dispatch inside this step; recheck admission here.
                    if !crate::win32k_glue::source_terminal_dispatch_ready() { return false; }
                    match dispatch(lease.address(), self.encoded.len() as u64) {
                    crate::win32k_glue::SourcePnpTerminalDispatch::NotEntered(_) => {
                        self.observe(Observation::NotEntered); return false;
                    }
                    crate::win32k_glue::SourcePnpTerminalDispatch::Returned(0) => {
                        self.observe(Observation::ReturnedSuccess);
                    }
                    _ => { self.observe(Observation::Uncertain); return false; }
                    }
                }
                Phase::ReadAck => {
                    let after = match crate::win32k_subsystem::try_capture_root_provider_pool_packet(lease) {
                        Ok(bytes) => bytes,
                        Err(error) => return self.failed(error),
                    };
                    let before = &self.command.as_ref().expect("retained command snapshot").3;
                    let expected = if discard { TerminalPublication::Discarded } else { TerminalPublication::Committed };
                    let stage = u32::from_le_bytes(after[offset..offset + 4].try_into().unwrap());
                    let status = u32::from_le_bytes(after[offset + 4..offset + 8].try_into().unwrap());
                    let valid = same_terminal_packet(before, &after, offset)
                        && TerminalPublication::decode(stage, status) == Some(expected)
                        && u64::from_le_bytes(after[offset + 8..offset + 16].try_into().unwrap()) == sequence;
                    self.observe(if valid { Observation::AckValidated } else { Observation::InvalidAck });
                    if !valid { return false; }
                }
                Phase::RetirePacket => {
                    if let Err(error) = crate::win32k_subsystem::try_retire_root_provider_pool_allocation(allocation) {
                        return self.failed(error);
                    }
                    self.allocation = None;
                    self.observe(Observation::PacketRetired);
                }
                Phase::Complete => return true,
                Phase::Indeterminate => return false,
            }
        }
    }
}
