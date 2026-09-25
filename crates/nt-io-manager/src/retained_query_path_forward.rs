//! Retained ownership of a Mup query-path IRP forwarded to an exact hosted device.
//!
//! This contract does not execute a driver. The native adapter must prove the source IRP and
//! security graph are live, capture their bytes, and keep the source IRP until its local
//! completion routine has run. A reply or transport failure never authorizes dispatch replay.

use alloc::vec::Vec;
use core::num::NonZeroU64;
use nt_status::NtStatus;

use crate::{
    hosted_forward_target::HostedForwardTarget,
    redir_query_path::{
        capture_completion, CapturedQueryPath, QueryPathCompletion, QueryPathError,
        RetainedSecurityContextTicket,
    },
    HostedDevicePointerRegistration, HostedDomainId, HostedDomainIdentity, IoManager,
};

/// Generation-bearing identity of the originating native IRP in its hosted domain.
/// Its raw address is deliberately not part of this transport identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIrpTicket {
    pub domain: HostedDomainIdentity,
    pub id: NonZeroU64,
    pub generation: NonZeroU64,
}

impl SourceIrpTicket {
    pub fn new(domain: HostedDomainIdentity, id: u64, generation: u64) -> Option<Self> {
        if domain.domain_id == HostedDomainId::NULL || domain.cookie == 0 {
            return None;
        }
        Some(Self {
            domain,
            id: NonZeroU64::new(id)?,
            generation: NonZeroU64::new(generation)?,
        })
    }
}

/// All three identities must be checked again before native dispatch or completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryPathForwardIdentity {
    pub source: SourceIrpTicket,
    pub target: HostedDevicePointerRegistration,
    pub security: RetainedSecurityContextTicket,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPathForwardError {
    WrongIdentity,
    Target(NtStatus),
    Completion(QueryPathError),
}

#[derive(Debug)]
struct Owner {
    identity: QueryPathForwardIdentity,
    target: HostedForwardTarget,
    request: CapturedQueryPath,
}

impl Owner {
    fn validate<P>(
        &self,
        io: &IoManager<P>,
        observed: QueryPathForwardIdentity,
    ) -> Result<(), QueryPathForwardError> {
        if observed != self.identity {
            return Err(QueryPathForwardError::WrongIdentity);
        }
        self.target
            .validate(io)
            .map(|_| ())
            .map_err(QueryPathForwardError::Target)
    }
}

#[must_use = "begin through the issuing I/O Manager or retain the owner"]
#[derive(Debug)]
pub struct PreparedQueryPathForward(Owner);

#[must_use = "return the exact invocation after the native transport resolves"]
#[derive(Debug)]
pub struct QueryPathForwardInvocation(Owner);

#[must_use = "finish through the issuing I/O Manager"]
#[derive(Debug)]
pub struct QueryPathForwardReturn {
    owner: Owner,
    outcome: QueryPathForwardOutcome,
}

#[must_use = "retain until an exact terminal provider result is known"]
#[derive(Debug)]
pub struct RetainedQueryPathForward {
    owner: Owner,
    indeterminate: bool,
    transport_status: Option<NtStatus>,
}

#[must_use = "retire the retained target after source-local completion"]
#[derive(Debug)]
pub struct TerminalQueryPathForward {
    owner: Owner,
    completion: QueryPathCompletion,
}

/// After dispatch entry there is no replayable outcome. A transport error, including a claimed
/// no-entry result that lacks pre-effect proof, is `Indeterminate`.
#[derive(Debug)]
pub enum QueryPathForwardOutcome {
    Pending,
    Indeterminate(NtStatus),
    Returned {
        status: u32,
        information: u64,
        response: Vec<u8>,
    },
}

#[derive(Debug)]
pub enum QueryPathForwardResult {
    Retained(RetainedQueryPathForward),
    Terminal(TerminalQueryPathForward),
    Rejected {
        error: QueryPathForwardError,
        retained: RetainedQueryPathForward,
    },
}

impl PreparedQueryPathForward {
    /// The caller has already captured the source's METHOD_NEITHER bytes and independently
    /// retained the exact source security graph represented by `request.security`.
    pub fn new(
        source: SourceIrpTicket,
        target: HostedForwardTarget,
        request: CapturedQueryPath,
    ) -> Self {
        let identity = QueryPathForwardIdentity {
            source,
            target: target.registration(),
            security: request.security,
        };
        Self(Owner {
            identity,
            target,
            request,
        })
    }

    pub fn identity(&self) -> QueryPathForwardIdentity {
        self.0.identity
    }

    pub fn request(&self) -> &CapturedQueryPath {
        &self.0.request
    }

    /// An adapter may refuse a request before entering any native/provider transport. The
    /// prepared owner stays intact; only this pre-entry state can be attempted again.
    pub fn not_entered(self, status: NtStatus) -> (NtStatus, Self) {
        (status, self)
    }

    /// Check the exact generation-bearing identities immediately before dispatch entry.
    /// Failure returns the untouched owner and proves no provider effect was attempted here.
    pub fn begin<P>(
        self,
        io: &IoManager<P>,
        observed: QueryPathForwardIdentity,
    ) -> Result<QueryPathForwardInvocation, (QueryPathForwardError, Self)> {
        if let Err(error) = self.0.validate(io, observed) {
            return Err((error, self));
        }
        Ok(QueryPathForwardInvocation(self.0))
    }
}

impl QueryPathForwardInvocation {
    pub fn identity(&self) -> QueryPathForwardIdentity {
        self.0.identity
    }

    pub fn request(&self) -> &CapturedQueryPath {
        &self.0.request
    }

    pub fn returned(self, outcome: QueryPathForwardOutcome) -> QueryPathForwardReturn {
        QueryPathForwardReturn {
            owner: self.0,
            outcome,
        }
    }
}

impl QueryPathForwardReturn {
    pub fn finish<P>(
        self,
        io: &IoManager<P>,
        observed: QueryPathForwardIdentity,
    ) -> QueryPathForwardResult {
        let Self { owner, outcome } = self;
        if let Err(error) = owner.validate(io, observed) {
            return QueryPathForwardResult::Rejected {
                error,
                retained: RetainedQueryPathForward {
                    owner,
                    indeterminate: true,
                    transport_status: None,
                },
            };
        }
        match outcome {
            QueryPathForwardOutcome::Pending => {
                QueryPathForwardResult::Retained(RetainedQueryPathForward {
                    owner,
                    indeterminate: false,
                    transport_status: None,
                })
            }
            QueryPathForwardOutcome::Indeterminate(status) => {
                QueryPathForwardResult::Retained(RetainedQueryPathForward {
                    owner,
                    indeterminate: true,
                    transport_status: Some(status),
                })
            }
            QueryPathForwardOutcome::Returned {
                status,
                information,
                response,
            } => finish_completion(owner, status, information, &response),
        }
    }
}

fn finish_completion(
    owner: Owner,
    status: u32,
    information: u64,
    response: &[u8],
) -> QueryPathForwardResult {
    match capture_completion(&owner.request, status, information, response) {
        Ok(completion) => {
            QueryPathForwardResult::Terminal(TerminalQueryPathForward { owner, completion })
        }
        Err(error) => QueryPathForwardResult::Rejected {
            error: QueryPathForwardError::Completion(error),
            retained: RetainedQueryPathForward {
                owner,
                indeterminate: true,
                transport_status: None,
            },
        },
    }
}

impl RetainedQueryPathForward {
    pub fn identity(&self) -> QueryPathForwardIdentity {
        self.owner.identity
    }

    pub fn is_indeterminate(&self) -> bool {
        self.indeterminate
    }

    pub fn transport_status(&self) -> Option<NtStatus> {
        self.transport_status
    }

    /// A late completion (or reconciliation of uncertain delivery) is the only way out of a
    /// retained state. A mismatch preserves the owner; this method never redispatches.
    pub fn complete<P>(
        self,
        io: &IoManager<P>,
        observed: QueryPathForwardIdentity,
        status: u32,
        information: u64,
        response: &[u8],
    ) -> QueryPathForwardResult {
        if let Err(error) = self.owner.validate(io, observed) {
            return QueryPathForwardResult::Rejected {
                error,
                retained: self,
            };
        }
        finish_completion(self.owner, status, information, response)
    }
}

impl TerminalQueryPathForward {
    pub fn identity(&self) -> QueryPathForwardIdentity {
        self.owner.identity
    }

    pub fn completion(&self) -> QueryPathCompletion {
        self.completion
    }

    /// Call only after the source-domain completion routine has consumed this result. A failed
    /// checked release returns the same owner for redrive; it cannot free the native IRP.
    pub fn retire<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<QueryPathCompletion, (NtStatus, Self)> {
        if let Err(status) = self.owner.target.release(io) {
            return Err((status, self));
        }
        Ok(self.completion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        redir_query_path::{capture_query_path, QueryPathStack, SourceSecurityContext},
        DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend, MockObjectPort,
    };
    use alloc::boxed::Box;
    use nt_types::NtPath;

    fn fixture() -> (IoManager<MockObjectPort>, PreparedQueryPathForward) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\QueryPath").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                Some(&NtPath::parse_str(r"\Device\QueryPath").unwrap()),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let domain = io.register_hosted_domain();
        io.bind_hosted_device_pointer(domain, 0x5000, device)
            .unwrap();
        let target = HostedForwardTarget::capture(&mut io, domain, 0x5000).unwrap();
        let ticket = RetainedSecurityContextTicket::new(7, 3).unwrap();
        let mut input = alloc::vec![0u8; 32];
        input[0..4].copy_from_slice(&8u32.to_le_bytes());
        input[8..16].copy_from_slice(&0x6000u64.to_le_bytes());
        for (index, unit) in [b'\\' as u16, b'a' as u16, b'b' as u16, b'c' as u16]
            .into_iter()
            .enumerate()
        {
            input[16 + index * 2..18 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        let request = capture_query_path(
            QueryPathStack {
                major: 0x0e,
                minor: 0,
                requestor_kernel_mode: true,
                io_control_code: 0x0014_018f,
                input_buffer_length: 32,
                output_buffer_length: 4,
            },
            &input,
            Some(SourceSecurityContext {
                address: NonZeroU64::new(0x6000).unwrap(),
                ticket,
            }),
        )
        .unwrap();
        let source = SourceIrpTicket::new(domain, 42, 9).unwrap();
        (io, PreparedQueryPathForward::new(source, target, request))
    }

    #[test]
    fn wrong_source_generation_or_target_cannot_enter() {
        let (mut io, prepared) = fixture();
        let mut wrong = prepared.identity();
        wrong.source.generation = NonZeroU64::new(10).unwrap();
        let prepared = prepared.begin(&io, wrong).err().unwrap().1;
        let mut wrong = prepared.identity();
        let other_domain = io.register_hosted_domain();
        wrong.target = io
            .bind_hosted_device_pointer(other_domain, 0x7000, wrong.target.device_id())
            .unwrap();
        assert!(matches!(
            prepared.begin(&io, wrong),
            Err((QueryPathForwardError::WrongIdentity, _))
        ));
    }

    #[test]
    fn not_entered_is_the_only_retryable_outcome() {
        let (io, prepared) = fixture();
        let identity = prepared.identity();
        let (status, prepared) = prepared.not_entered(NtStatus::INVALID_DEVICE_REQUEST);
        assert_eq!(status, NtStatus::INVALID_DEVICE_REQUEST);
        assert!(prepared.begin(&io, identity).is_ok());
    }

    #[test]
    fn source_requires_real_domain_identity() {
        assert!(SourceIrpTicket::new(HostedDomainIdentity::default(), 42, 9).is_none());
    }

    #[test]
    fn pending_and_uncertain_effects_keep_exact_owner_without_replay() {
        let (io, prepared) = fixture();
        let identity = prepared.identity();
        let invocation = prepared.begin(&io, identity).unwrap();
        let retained = match invocation
            .returned(QueryPathForwardOutcome::Pending)
            .finish(&io, identity)
        {
            QueryPathForwardResult::Retained(retained) => retained,
            _ => panic!("pending must retain"),
        };
        assert!(!retained.is_indeterminate());
        let mut wrong = identity;
        wrong.source.generation = NonZeroU64::new(10).unwrap();
        let retained = match retained.complete(&io, wrong, 0, 0, &4u32.to_le_bytes()) {
            QueryPathForwardResult::Rejected {
                error: QueryPathForwardError::WrongIdentity,
                retained,
            } => retained,
            _ => panic!("wrong completion must retain"),
        };
        assert!(matches!(
            retained.complete(&io, identity, 0x103, 0, &[]),
            QueryPathForwardResult::Rejected {
                error: QueryPathForwardError::Completion(QueryPathError::Pending),
                ..
            }
        ));

        let (io, prepared) = fixture();
        let identity = prepared.identity();
        let invocation = prepared.begin(&io, identity).unwrap();
        let retained = match invocation
            .returned(QueryPathForwardOutcome::Indeterminate(
                NtStatus::DEVICE_BUSY,
            ))
            .finish(&io, identity)
        {
            QueryPathForwardResult::Retained(retained) => retained,
            _ => panic!("uncertain effect must retain"),
        };
        assert!(retained.is_indeterminate());
        assert_eq!(retained.transport_status(), Some(NtStatus::DEVICE_BUSY));
    }

    #[test]
    fn valid_terminal_completion_releases_target_only_after_retirement() {
        let (mut io, prepared) = fixture();
        let identity = prepared.identity();
        let device = identity.target.device_id();
        let held = io.device_reference_count(device);
        let invocation = prepared.begin(&io, identity).unwrap();
        let retained = match invocation
            .returned(QueryPathForwardOutcome::Pending)
            .finish(&io, identity)
        {
            QueryPathForwardResult::Retained(retained) => retained,
            _ => panic!("pending must retain"),
        };
        let terminal = match retained.complete(&io, identity, 0, 0, &4u32.to_le_bytes()) {
            QueryPathForwardResult::Terminal(terminal) => terminal,
            _ => panic!("valid completion must terminate"),
        };
        assert_eq!(terminal.completion().length_accepted, 4);
        assert_eq!(io.device_reference_count(device), held);
        assert_eq!(terminal.retire(&mut io).unwrap().status, 0);
        assert_eq!(io.device_reference_count(device), held - 1);
    }

    #[test]
    fn malformed_synchronous_return_can_be_reconciled_as_terminal_failure_without_replay() {
        let (mut io, prepared) = fixture();
        let identity = prepared.identity();
        let device = identity.target.device_id();
        let held = io.device_reference_count(device);
        let invocation = prepared.begin(&io, identity).unwrap();
        let retained = match invocation
            .returned(QueryPathForwardOutcome::Returned {
                status: 0,
                information: 0,
                response: 5u32.to_le_bytes().to_vec(),
            })
            .finish(&io, identity)
        {
            QueryPathForwardResult::Rejected {
                error: QueryPathForwardError::Completion(QueryPathError::InvalidPath),
                retained,
            } => retained,
            _ => panic!("malformed synchronous return must preserve the entered owner"),
        };
        assert!(retained.is_indeterminate());
        let terminal = match retained.complete(
            &io,
            identity,
            NtStatus::INVALID_DEVICE_REQUEST.raw() as u32,
            0,
            &[],
        ) {
            QueryPathForwardResult::Terminal(terminal) => terminal,
            _ => panic!("local protocol failure must terminate without another dispatch"),
        };
        assert_eq!(
            terminal.completion().status,
            NtStatus::INVALID_DEVICE_REQUEST.raw() as u32
        );
        assert_eq!(io.device_reference_count(device), held);
        terminal.retire(&mut io).unwrap();
        assert_eq!(io.device_reference_count(device), held - 1);
    }
}
