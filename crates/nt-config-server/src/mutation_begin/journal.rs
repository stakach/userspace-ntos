//! Pre-granted requester slots retain exact BEGIN outcomes until acknowledgement.

use alloc::vec::Vec;
use nt_config_abi::mutation_begin::{disposition, Request, MAX_SLOTS};

use crate::{
    CmIdentitySource, STATUS_DEVICE_NOT_READY, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};

#[derive(Clone, Copy)]
struct Outcome {
    status: i32,
    token: u64,
}

struct Pending {
    generation: u64,
    expected_generation: u64,
    expected_mount: u64,
    semantic_journal_len: u32,
    outcome: Option<Outcome>,
}

struct Slot {
    acknowledged: u64,
    pending: Option<Pending>,
}

struct Requester {
    nonce: u64,
    slots: Vec<Slot>,
}

pub(crate) struct BeginJournal {
    nonce: u64,
    requesters: Vec<Requester>,
    granted_slots: usize,
}

impl BeginJournal {
    pub(crate) const fn new() -> Self {
        Self {
            nonce: 0,
            requesters: Vec::new(),
            granted_slots: 0,
        }
    }

    pub(crate) fn grant(
        &mut self,
        requester: u64,
        count: usize,
        source: &CmIdentitySource,
    ) -> Result<u64, i32> {
        if requester == 0 || count == 0 || count > MAX_SLOTS {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Some(existing) = self.requesters.iter().find(|bank| bank.nonce == requester) {
            return if existing.slots.len() == count {
                Ok(self.nonce)
            } else {
                Err(STATUS_INVALID_PARAMETER)
            };
        }
        let total = self
            .granted_slots
            .checked_add(count)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if total > MAX_SLOTS {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        slots.resize_with(count, || Slot {
            acknowledged: 0,
            pending: None,
        });
        self.requesters
            .try_reserve_exact(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let nonce = if self.nonce == 0 {
            source.take().ok_or(STATUS_INSUFFICIENT_RESOURCES)?
        } else {
            self.nonce
        };
        self.requesters.push(Requester {
            nonce: requester,
            slots,
        });
        self.granted_slots = total;
        self.nonce = nonce;
        Ok(nonce)
    }

    fn locate(&self, request: &Request) -> Result<(usize, usize), i32> {
        if self.nonce == 0 || request.server_nonce != self.nonce || request.request_generation == 0
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let bank = self
            .requesters
            .iter()
            .position(|bank| bank.nonce == request.requester_nonce)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let slot = usize::try_from(request.request_slot).map_err(|_| STATUS_INVALID_HANDLE)?;
        if slot >= self.requesters[bank].slots.len() {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok((bank, slot))
    }

    fn validate_pending(pending: &Pending, request: &Request) -> Result<(), i32> {
        if pending.generation != request.request_generation {
            return Err(STATUS_INVALID_HANDLE);
        }
        if pending.expected_generation != request.expected_generation
            || pending.expected_mount != request.expected_mount
            || pending.semantic_journal_len != request.semantic_journal_len
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    /// The caller records every acquired outcome before replying. Journal transitions allocate
    /// nothing after claim, including when acquiring the upload fails.
    pub(crate) fn claim(&mut self, request: &Request) -> Result<((usize, usize), bool), i32> {
        if request.expected_mount == 0
            || request.expected_generation == 0
            || request.semantic_journal_len == 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let position = self.locate(request)?;
        let slot = &mut self.requesters[position.0].slots[position.1];
        if let Some(pending) = &slot.pending {
            Self::validate_pending(pending, request)?;
            if pending.outcome.is_none() {
                return Err(STATUS_DEVICE_NOT_READY);
            }
            return Ok((position, false));
        }
        if slot.acknowledged.checked_add(1) != Some(request.request_generation) {
            return Err(STATUS_INVALID_HANDLE);
        }
        slot.pending = Some(Pending {
            generation: request.request_generation,
            expected_generation: request.expected_generation,
            expected_mount: request.expected_mount,
            semantic_journal_len: request.semantic_journal_len,
            outcome: None,
        });
        Ok((position, true))
    }

    pub(crate) fn finish(&mut self, position: (usize, usize), result: Result<u64, i32>) {
        let outcome = match result {
            Ok(token) => {
                assert_ne!(token, 0, "successful BEGIN must own a nonzero upload token");
                Outcome {
                    status: STATUS_SUCCESS,
                    token,
                }
            }
            Err(status) => {
                assert_ne!(status, STATUS_SUCCESS, "failed BEGIN must retain an error");
                Outcome { status, token: 0 }
            }
        };
        let pending = self.requesters[position.0].slots[position.1]
            .pending
            .as_mut()
            .expect("reserved BEGIN attempt missing");
        assert!(
            pending.outcome.is_none(),
            "BEGIN outcome cannot be replaced"
        );
        pending.outcome = Some(outcome);
    }

    pub(crate) fn outcome(&self, request: &Request) -> Result<(i32, u64), i32> {
        let (bank, slot) = self.locate(request)?;
        let pending = self.requesters[bank].slots[slot]
            .pending
            .as_ref()
            .ok_or(STATUS_INVALID_HANDLE)?;
        Self::validate_pending(pending, request)?;
        let outcome = pending.outcome.ok_or(STATUS_DEVICE_NOT_READY)?;
        Ok((outcome.status, outcome.token))
    }

    pub(crate) fn acknowledge(&mut self, request: &Request) -> Result<u16, i32> {
        let (bank, index) = self.locate(request)?;
        let slot = &mut self.requesters[bank].slots[index];
        if request.request_generation <= slot.acknowledged {
            return Ok(disposition::ALREADY_ACKNOWLEDGED);
        }
        let pending = slot.pending.as_ref().ok_or(STATUS_INVALID_HANDLE)?;
        if pending.generation != request.request_generation {
            return Err(STATUS_INVALID_HANDLE);
        }
        let outcome = pending.outcome.ok_or(STATUS_DEVICE_NOT_READY)?;
        if request.mutation_token != outcome.token {
            return Err(STATUS_INVALID_HANDLE);
        }
        // Retire only discovery evidence. The upload remains owned by MutationLeaseBank.
        slot.pending = None;
        slot.acknowledged = request.request_generation;
        Ok(disposition::ACKNOWLEDGED)
    }

    pub(crate) fn blocks_transfer(&self, token: u64) -> bool {
        token != 0
            && self.requesters.iter().any(|bank| {
                bank.slots.iter().any(|slot| {
                    slot.pending
                        .as_ref()
                        .and_then(|pending| pending.outcome)
                        .is_some_and(|outcome| {
                            outcome.status == STATUS_SUCCESS && outcome.token == token
                        })
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU32;

    fn fixture() -> (BeginJournal, Request) {
        let mut journal = BeginJournal::new();
        let source = CmIdentitySource::new(NonZeroU32::MIN);
        let server_nonce = journal.grant(9, 2, &source).unwrap();
        (
            journal,
            Request {
                server_nonce,
                requester_nonce: 9,
                request_slot: 0,
                request_generation: 1,
                expected_generation: 7,
                expected_mount: 3,
                semantic_journal_len: 31,
                ..Request::default()
            },
        )
    }

    #[test]
    fn exact_success_replays_and_acknowledgement_does_not_release_a_newer_gate() {
        let (mut journal, request) = fixture();
        let (position, fresh) = journal.claim(&request).unwrap();
        assert!(fresh);
        assert_eq!(journal.claim(&request), Err(STATUS_DEVICE_NOT_READY));
        assert_eq!(journal.acknowledge(&request), Err(STATUS_DEVICE_NOT_READY));
        journal.finish(position, Ok(71));
        assert_eq!(journal.claim(&request), Ok((position, false)));
        assert_eq!(journal.outcome(&request), Ok((STATUS_SUCCESS, 71)));
        assert!(journal.blocks_transfer(71));
        assert!(!journal.blocks_transfer(0));
        assert!(!journal.blocks_transfer(72));
        assert_eq!(journal.acknowledge(&request), Err(STATUS_INVALID_HANDLE));
        let ack = Request {
            mutation_token: 71,
            expected_generation: 0,
            expected_mount: 0,
            semantic_journal_len: 0,
            ..request
        };
        assert_eq!(journal.acknowledge(&ack), Ok(disposition::ACKNOWLEDGED));
        assert!(!journal.blocks_transfer(71));
        assert_eq!(journal.claim(&request), Err(STATUS_INVALID_HANDLE));
        let next = Request {
            request_generation: 2,
            ..request
        };
        let (position, fresh) = journal.claim(&next).unwrap();
        assert!(fresh);
        journal.finish(position, Ok(72));
        assert_eq!(
            journal.acknowledge(&ack),
            Ok(disposition::ALREADY_ACKNOWLEDGED)
        );
        assert!(journal.blocks_transfer(72));
        assert_eq!(journal.outcome(&next), Ok((STATUS_SUCCESS, 72)));
    }

    #[test]
    fn failure_is_cached_and_requires_zero_token_acknowledgement() {
        let (mut journal, request) = fixture();
        assert_eq!(journal.acknowledge(&request), Err(STATUS_INVALID_HANDLE));
        let (position, _) = journal.claim(&request).unwrap();
        journal.finish(position, Err(STATUS_INSUFFICIENT_RESOURCES));
        assert_eq!(journal.claim(&request), Ok((position, false)));
        assert_eq!(
            journal.outcome(&request),
            Ok((STATUS_INSUFFICIENT_RESOURCES, 0))
        );
        assert!(!journal.blocks_transfer(1));
        let wrong = Request {
            mutation_token: 71,
            ..request
        };
        assert_eq!(journal.acknowledge(&wrong), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            journal.outcome(&request),
            Ok((STATUS_INSUFFICIENT_RESOURCES, 0))
        );
        assert_eq!(journal.acknowledge(&request), Ok(disposition::ACKNOWLEDGED));
    }

    #[test]
    fn changed_request_or_authority_cannot_replace_an_outcome() {
        let (mut journal, request) = fixture();
        let (position, _) = journal.claim(&request).unwrap();
        journal.finish(position, Ok(71));
        for wrong in [
            Request {
                server_nonce: request.server_nonce + 1,
                ..request
            },
            Request {
                requester_nonce: request.requester_nonce + 1,
                ..request
            },
            Request {
                request_slot: 2,
                ..request
            },
            Request {
                request_generation: 0,
                ..request
            },
            Request {
                request_generation: 2,
                ..request
            },
            Request {
                expected_mount: 4,
                ..request
            },
            Request {
                expected_generation: 8,
                ..request
            },
            Request {
                semantic_journal_len: 32,
                ..request
            },
        ] {
            assert!(journal.claim(&wrong).is_err());
            assert!(journal.outcome(&wrong).is_err());
            assert_eq!(journal.outcome(&request), Ok((STATUS_SUCCESS, 71)));
        }
        assert!(journal.blocks_transfer(71));
    }

    #[test]
    fn grants_are_idempotent_bounded_and_isolate_requester_slots() {
        let source = CmIdentitySource::new(NonZeroU32::MIN);
        let mut journal = BeginJournal::new();
        for (requester, count) in [(0, 1), (1, 0), (1, MAX_SLOTS + 1)] {
            assert_eq!(
                journal.grant(requester, count, &source),
                Err(STATUS_INVALID_PARAMETER)
            );
        }
        let nonce = journal.grant(1, MAX_SLOTS - 1, &source).unwrap();
        assert_eq!(journal.grant(1, MAX_SLOTS - 1, &source), Ok(nonce));
        assert_eq!(
            journal.grant(1, MAX_SLOTS, &source),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            journal.grant(2, 2, &source),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(journal.grant(2, 1, &source), Ok(nonce));
        assert_eq!(
            journal.grant(3, 1, &source),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        let request = Request {
            server_nonce: nonce,
            requester_nonce: 1,
            request_slot: 0,
            request_generation: 1,
            expected_generation: 7,
            expected_mount: 3,
            semantic_journal_len: 31,
            ..Request::default()
        };
        let other = Request {
            requester_nonce: 2,
            ..request
        };
        let (first, _) = journal.claim(&request).unwrap();
        let (second, _) = journal.claim(&other).unwrap();
        journal.finish(first, Ok(71));
        journal.finish(second, Err(STATUS_INSUFFICIENT_RESOURCES));
        journal.acknowledge(&other).unwrap();
        assert!(journal.blocks_transfer(71));
        let mut reconstructed = BeginJournal::new();
        assert_ne!(reconstructed.grant(1, 1, &source).unwrap(), nonce);
        assert_eq!(reconstructed.claim(&request), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn request_generation_exhaustion_cannot_wrap_or_acknowledge_unexecuted_work() {
        let (mut journal, request) = fixture();
        journal.requesters[0].slots[0].acknowledged = u64::MAX;
        assert_eq!(journal.claim(&request), Err(STATUS_INVALID_HANDLE));
        let fresh_slot = Request {
            request_slot: 1,
            ..request
        };
        assert_eq!(journal.acknowledge(&fresh_slot), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            journal.claim(&Request {
                request_generation: 2,
                ..fresh_slot
            }),
            Err(STATUS_INVALID_HANDLE)
        );
        assert!(journal.claim(&fresh_slot).unwrap().1);
    }
}
