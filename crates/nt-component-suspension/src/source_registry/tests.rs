use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Source {
    catalog: u64,
    domain: u64,
    generation: u64,
    kind: u64,
    tcb: u64,
    vspace: u64,
}

impl IngressSource for Source {
    type Domain = (u64, u64, u64);
    type Kind = u64;
    fn domain(self) -> Self::Domain {
        (self.catalog, self.domain, self.generation)
    }
    fn kind(self) -> u64 {
        self.kind
    }
    fn tcb(self) -> u64 {
        self.tcb
    }
    fn vspace(self) -> u64 {
        self.vspace
    }
    fn is_valid(self) -> bool {
        self.catalog != 0
            && self.domain != 0
            && self.generation != 0
            && self.tcb != 0
            && self.vspace != 0
    }
}

fn source() -> Source {
    Source {
        catalog: 1,
        domain: 2,
        generation: 3,
        kind: 0,
        tcb: 40,
        vspace: 50,
    }
}

#[test]
fn catalog_identity_separates_equal_numeric_domains_and_generations() {
    let mut registry = IngressSourceRegistry::new();
    let a = source();
    let b = Source {
        catalog: 2,
        tcb: 41,
        ..a
    };
    let ai = registry.intern(a, |s| s == a).unwrap();
    let bi = registry.intern(b, |s| s == b).unwrap();
    assert_ne!(ai.domain(), bi.domain());
    assert_ne!(ai.generation(), bi.generation());
    assert_ne!(ai.source(), bi.source());
    assert_eq!(registry.resolve(ai, |s| s == a), Ok(a));
    assert_eq!(registry.resolve(bi, |s| s == a), Err(SourceError::NotLive));
    assert_eq!(registry.resolve(bi, |s| s == b), Ok(b));
}

#[test]
fn exact_live_source_is_idempotent_and_siblings_share_domain() {
    let mut registry = IngressSourceRegistry::new();
    let a = source();
    let ai = registry.intern(a, |_| true).unwrap();
    assert_eq!(registry.intern(a, |_| true), Ok(ai));
    let bi = registry
        .intern(
            Source {
                kind: 1,
                tcb: 41,
                ..a
            },
            |_| true,
        )
        .unwrap();
    assert_eq!(ai.domain(), bi.domain());
    assert_eq!(ai.generation(), bi.generation());
    assert_ne!(ai.source(), bi.source());
}

#[test]
fn live_tcb_kind_and_vspace_conflicts_do_not_publish() {
    let mut registry = IngressSourceRegistry::new();
    let a = source();
    registry.intern(a, |_| true).unwrap();
    for b in [
        Source { catalog: 2, ..a },
        Source { tcb: 41, ..a },
        Source {
            kind: 1,
            tcb: 41,
            vspace: 51,
            ..a
        },
    ] {
        assert_eq!(registry.intern(b, |_| true), Err(SourceError::Conflict));
        assert_eq!(registry.sources.len(), 1);
        assert_eq!(registry.domains.len(), 1);
    }
}

#[test]
fn retirement_is_exact_and_drain_refusal_preserves_tombstone_fence() {
    let mut registry = IngressSourceRegistry::new();
    let a = source();
    let ai = registry.intern(a, |_| true).unwrap();
    let b = Source {
        kind: 1,
        tcb: 41,
        ..a
    };
    let bi = registry.intern(b, |_| true).unwrap();
    assert_eq!(
        registry.finish_retirement(ai, |_| true),
        Err(SourceError::InvalidPhase)
    );
    registry.begin_retirement(ai, |s| s == a).unwrap();
    assert_eq!(
        registry.resolve(ai, |_| true),
        Err(SourceError::InvalidPhase)
    );
    assert_eq!(registry.resolve_retiring(ai, |s| s == a), Ok(a));
    assert_eq!(registry.intern(a, |_| true), Err(SourceError::Retired));
    assert_eq!(
        registry.finish_retirement(ai, |_| false),
        Err(SourceError::NotDrained)
    );
    assert_eq!(registry.resolve_retiring(ai, |_| true), Ok(a));
    registry.finish_retirement(ai, |s| s == a).unwrap();
    assert_eq!(
        registry.finish_retirement(ai, |_| true),
        Err(SourceError::InvalidPhase)
    );
    assert_eq!(
        registry.resolve_retiring(ai, |_| true),
        Err(SourceError::InvalidPhase)
    );
    assert_eq!(registry.resolve(bi, |_| true), Ok(b));
    assert_eq!(registry.intern(a, |_| true), Err(SourceError::Retired));
    let reused = Source { generation: 4, ..a };
    let next = registry.intern(reused, |_| true).unwrap();
    assert_ne!(ai, next);
    assert_ne!(ai.domain(), next.domain());
    assert_eq!(
        registry.resolve(ai, |_| true),
        Err(SourceError::InvalidPhase)
    );
}

#[test]
fn foreign_registry_and_forged_identity_are_not_authority() {
    let a = source();
    let mut first = IngressSourceRegistry::new();
    let mut second = IngressSourceRegistry::new();
    let ai = first.intern(a, |_| true).unwrap();
    let bi = second.intern(a, |_| true).unwrap();
    assert_ne!(ai, bi);
    for identity in [
        ai,
        IngressSourceIdentity {
            generation: 0,
            ..bi
        },
    ] {
        assert_eq!(
            second.resolve(identity, |_| panic!("must reject before verifier")),
            Err(SourceError::InvalidIdentity)
        );
        assert_eq!(
            second.begin_retirement(identity, |_| true),
            Err(SourceError::InvalidIdentity)
        );
    }
}

#[test]
fn retired_kind_can_be_replaced_but_domain_vspace_cannot_be_rebound() {
    let mut registry = IngressSourceRegistry::new();
    let a = source();
    let ai = registry.intern(a, |_| true).unwrap();
    registry.begin_retirement(ai, |_| true).unwrap();
    let replacement = Source { tcb: 41, ..a };
    assert_eq!(
        registry.intern(replacement, |_| true),
        Err(SourceError::Conflict)
    );
    registry.finish_retirement(ai, |_| true).unwrap();
    assert_eq!(
        registry.intern(
            Source {
                vspace: 51,
                ..replacement
            },
            |_| true
        ),
        Err(SourceError::Conflict)
    );
    let next = registry.intern(replacement, |_| true).unwrap();
    assert_eq!(next.domain(), ai.domain());
    assert_eq!(next.generation(), ai.generation());
    assert_ne!(next.source(), ai.source());
    assert_eq!(
        registry.resolve(ai, |_| true),
        Err(SourceError::InvalidPhase)
    );
    assert_eq!(
        registry.resolve(next, |s| s == replacement),
        Ok(replacement)
    );
}

#[test]
fn verifier_refusal_and_invalid_source_leave_policy_unchanged() {
    let mut registry = IngressSourceRegistry::new();
    let a = source();
    assert_eq!(
        registry.intern(Source { tcb: 0, ..a }, |_| panic!("invalid")),
        Err(SourceError::InvalidSource)
    );
    assert_eq!(registry.intern(a, |_| false), Err(SourceError::NotLive));
    assert!(registry.sources.is_empty());
    assert!(registry.domains.is_empty());
    let ai = registry.intern(a, |_| true).unwrap();
    assert_eq!(registry.intern(a, |_| false), Err(SourceError::NotLive));
    assert_eq!(
        registry.begin_retirement(ai, |_| false),
        Err(SourceError::NotLive)
    );
    assert_eq!(registry.resolve(ai, |_| true), Ok(a));
    registry.begin_retirement(ai, |_| true).unwrap();
    assert_eq!(
        registry.resolve_retiring(ai, |_| false),
        Err(SourceError::NotLive)
    );
    assert_eq!(registry.sources.len(), 1);
}
