//! Count planning over the actual loaded import graph; no loader state is mutated here.

use super::lifecycle::{ImportReferenceLedger, ReferenceReleaseLedger};

const NO_MEMORY: u32 = 0xc000_0017;

/// An ordinal enumerates the importing module's real descriptors, not a second graph store.
pub trait ReferenceGraph {
    fn dependency_at(&mut self, base: u64, ordinal: usize) -> Result<Option<u64>, u32>;
}

/// Expansion state belongs to one load operation, including its recursive fresh snaps.
pub struct ReferenceExpansion<const N: usize> {
    visited: [u64; N],
    count: usize,
}

impl<const N: usize> ReferenceExpansion<N> {
    pub const fn new() -> Self {
        Self {
            visited: [0; N],
            count: 0,
        }
    }

    pub fn mark_snapped(&mut self, base: u64) -> Result<(), u32> {
        if self.visited[..self.count].contains(&base) {
            return Ok(());
        }
        if self.count == N {
            return Err(NO_MEMORY);
        }
        self.visited[self.count] = base;
        self.count += 1;
        Ok(())
    }

    pub fn collect_imports(
        &mut self,
        graph: &mut impl ReferenceGraph,
        imports: &ImportReferenceLedger<N>,
        ledger: &mut ReferenceReleaseLedger<N>,
    ) -> Result<(), u32> {
        collect_import_reference_acquisitions(
            graph,
            imports,
            ledger,
            &mut self.visited,
            &mut self.count,
        )
    }
}

pub fn collect_import_reference_acquisitions<const N: usize>(
    graph: &mut impl ReferenceGraph,
    imports: &ImportReferenceLedger<N>,
    ledger: &mut ReferenceReleaseLedger<N>,
    visited: &mut [u64; N],
    visited_count: &mut usize,
) -> Result<(), u32> {
    for edge in imports.as_slice() {
        // A newly mapped dependency already owns its initial count and snapped imports.
        if edge.increment_existing {
            collect_reference_acquisitions(graph, edge.base, ledger, visited, visited_count)?;
        }
    }
    Ok(())
}

pub fn collect_reference_acquisitions<const N: usize>(
    graph: &mut impl ReferenceGraph,
    base: u64,
    ledger: &mut ReferenceReleaseLedger<N>,
    visited: &mut [u64; N],
    visited_count: &mut usize,
) -> Result<(), u32> {
    if !ledger.record(base) {
        return Err(NO_MEMORY);
    }
    collect_reference_weights(graph, base, ledger, visited, visited_count)
}

pub fn collect_reference_releases<const N: usize>(
    graph: &mut impl ReferenceGraph,
    base: u64,
    ledger: &mut ReferenceReleaseLedger<N>,
    visited: &mut [u64; N],
    visited_count: &mut usize,
) -> Result<(), u32> {
    collect_reference_weights(graph, base, ledger, visited, visited_count)
}

fn collect_reference_weights<const N: usize>(
    graph: &mut impl ReferenceGraph,
    base: u64,
    ledger: &mut ReferenceReleaseLedger<N>,
    visited: &mut [u64; N],
    visited_count: &mut usize,
) -> Result<(), u32> {
    if visited[..*visited_count].contains(&base) {
        return Ok(());
    }
    if *visited_count >= N {
        return Err(NO_MEMORY);
    }
    visited[*visited_count] = base;
    *visited_count += 1;
    // Preserve the importing module's existing unique-descriptor policy independently of
    // recursive expansion. An already-expanded dependency still owns this incoming edge.
    let mut dependencies = [0; N];
    let mut count = 0;
    let mut ordinal = 0;
    while let Some(dependency) = graph.dependency_at(base, ordinal)? {
        if dependency >= 0x1_0000 && !dependencies[..count].contains(&dependency) {
            if count == N {
                return Err(NO_MEMORY);
            }
            dependencies[count] = dependency;
            count += 1;
        }
        ordinal = ordinal.checked_add(1).ok_or(NO_MEMORY)?;
    }
    for &dependency in &dependencies[..count] {
        if !ledger.record(dependency) {
            return Err(NO_MEMORY);
        }
        // NT5 LdrpUpdateLoadCount3 adjusts the edge before its recursion guard.
        collect_reference_weights(graph, dependency, ledger, visited, visited_count)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::lifecycle::{
        plan_reference_add_many, plan_reference_release, ReferenceReleasePlan,
    };

    const A: u64 = 0x10000;
    const B: u64 = 0x20000;
    const C: u64 = 0x30000;
    const D: u64 = 0x40000;

    struct Diamond;
    impl ReferenceGraph for Diamond {
        fn dependency_at(&mut self, base: u64, ordinal: usize) -> Result<Option<u64>, u32> {
            Ok(match (base, ordinal) {
                (A, 0) => Some(B),
                (A, 1) => Some(C),
                (B | C, 0) => Some(D),
                _ => None,
            })
        }
    }

    struct Edges<'a>(&'a [(u64, &'a [u64])]);
    impl ReferenceGraph for Edges<'_> {
        fn dependency_at(&mut self, base: u64, ordinal: usize) -> Result<Option<u64>, u32> {
            Ok(self
                .0
                .iter()
                .find(|row| row.0 == base)
                .and_then(|row| row.1.get(ordinal))
                .copied())
        }
    }

    fn balanced(graph: &mut impl ReferenceGraph) -> ReferenceReleaseLedger<4> {
        let mut acquired = ReferenceReleaseLedger::new();
        let mut visited = [0; 4];
        let mut count = 0;
        collect_reference_acquisitions(graph, A, &mut acquired, &mut visited, &mut count).unwrap();
        let mut released = ReferenceReleaseLedger::new();
        assert!(released.record(A));
        count = 0;
        collect_reference_releases(graph, A, &mut released, &mut visited, &mut count).unwrap();
        assert_eq!(acquired, released);
        for row in acquired.as_slice() {
            let count = plan_reference_add_many(1, false, row.releases);
            assert_eq!(
                plan_reference_release(count, row.releases),
                ReferenceReleasePlan::DecrementTo(1)
            );
        }
        acquired
    }

    #[test]
    fn cycles_count_incoming_edges_before_stopping_expansion() {
        let plan = balanced(&mut Edges(&[(A, &[B]), (B, &[A])]));
        assert_eq!(plan.as_slice()[0].releases, 2);
        assert_eq!(plan.as_slice()[1].releases, 1);
    }

    #[test]
    fn duplicate_descriptors_within_one_import_remain_one_edge() {
        let plan = balanced(&mut Edges(&[(A, &[B, B]), (B, &[D, D])]));
        assert!(plan.as_slice().iter().all(|row| row.releases == 1));
    }

    #[test]
    fn pin_propagates_through_weighted_diamond_including_pinned_root() {
        let plan = balanced(&mut Diamond);
        for row in plan.as_slice() {
            let prior = if row.base == A { u16::MAX } else { 1 };
            let pinned = plan_reference_add_many(prior, true, row.releases);
            assert_eq!(pinned, u16::MAX);
            assert_eq!(
                plan_reference_release(pinned, row.releases),
                ReferenceReleasePlan::Pinned
            );
        }
    }

    #[test]
    fn capacity_and_late_graph_errors_leave_counts_unpublished() {
        fn publish<const N: usize>(
            graph: &mut impl ReferenceGraph,
            counts: &mut [u16; 4],
        ) -> Result<(), u32> {
            let mut plan = ReferenceReleaseLedger::<N>::new();
            collect_reference_acquisitions(graph, A, &mut plan, &mut [0; N], &mut 0)?;
            let mut next = *counts;
            for row in plan.as_slice() {
                let index = [A, B, C, D]
                    .iter()
                    .position(|base| *base == row.base)
                    .ok_or(0xc000_0135u32)?;
                next[index] = plan_reference_add_many(next[index], false, row.releases);
            }
            *counts = next;
            Ok(())
        }
        let original = [1u16; 4];
        let mut published = original;
        assert_eq!(publish::<2>(&mut Diamond, &mut published), Err(NO_MEMORY));
        assert_eq!(published, original);
        struct LateError;
        impl ReferenceGraph for LateError {
            fn dependency_at(&mut self, base: u64, ordinal: usize) -> Result<Option<u64>, u32> {
                if base == C {
                    Err(0xc000_0135)
                } else {
                    Diamond.dependency_at(base, ordinal)
                }
            }
        }
        assert_eq!(
            publish::<4>(&mut LateError, &mut published),
            Err(0xc000_0135)
        );
        assert_eq!(published, original);
    }

    #[test]
    fn deferred_weight_overflow_refuses_before_any_publication() {
        let mut pending = ReferenceReleaseLedger::<4>::new();
        assert!(pending.record_many(D, u32::MAX));
        let original = pending.clone();
        let mut candidate = pending.clone();
        assert!(!candidate.record_many(D, 2));
        assert_eq!(candidate, original);
        assert_eq!(pending, original);
    }

    #[test]
    fn initial_imports_consume_new_counts_and_weight_existing_edges() {
        let mut imports = ImportReferenceLedger::<4>::new();
        assert!(imports.record(B, false));
        assert!(imports.record(C, true));
        let mut acquired = ReferenceReleaseLedger::new();
        collect_import_reference_acquisitions(
            &mut Diamond,
            &imports,
            &mut acquired,
            &mut [0; 4],
            &mut 0,
        )
        .unwrap();
        assert!(!acquired.contains(B));
        // B's fresh snap already acquired D once. C's existing subtree adds another.
        let mut counts = [(A, 1u16), (B, 1), (C, 1), (D, 2)];
        for row in acquired.as_slice() {
            let count = &mut counts
                .iter_mut()
                .find(|entry| entry.0 == row.base)
                .unwrap()
                .1;
            *count = plan_reference_add_many(*count, false, row.releases);
        }
        let mut released = ReferenceReleaseLedger::new();
        assert!(released.record(A));
        collect_reference_releases(&mut Diamond, A, &mut released, &mut [0; 4], &mut 0).unwrap();
        let d = released
            .as_slice()
            .iter()
            .find(|row| row.base == D)
            .unwrap();
        assert_eq!(
            plan_reference_release(counts[3].1, d.releases),
            ReferenceReleasePlan::DecrementTo(1)
        );
        assert_eq!(
            plan_reference_release(counts[2].1, 1),
            ReferenceReleasePlan::DecrementTo(1)
        );
        assert_eq!(
            plan_reference_release(counts[1].1, 1),
            ReferenceReleasePlan::TeardownRequired
        );
    }

    #[test]
    fn nested_initial_diamond_preserves_transitive_preexisting_owner() {
        const E: u64 = 0x50000;
        let mut graph = Edges(&[(A, &[B, C]), (B, &[D]), (C, &[D]), (D, &[E])]);
        // E owns one preexisting reference. B's fresh D snap acquires E once;
        // C then snaps an existing D, exactly as native recursive publication does.
        let mut e_count = 1;
        let mut expansion = ReferenceExpansion::<5>::new();
        expansion.mark_snapped(A).unwrap();
        expansion.mark_snapped(B).unwrap();
        expansion.mark_snapped(D).unwrap();
        // Publish D->E(existing), B->D(fresh), C->D(existing), A->B/C(fresh)
        // in native recursive snap order, retaining one operation's expansion state.
        for (module, edges) in [
            (D, &[(E, true)][..]),
            (B, &[(D, false)][..]),
            (C, &[(D, true)][..]),
            (A, &[(B, false), (C, false)][..]),
        ] {
            expansion.mark_snapped(module).unwrap();
            let mut imports = ImportReferenceLedger::<5>::new();
            for &(base, existing) in edges {
                assert!(imports.record(base, existing));
            }
            let mut acquired = ReferenceReleaseLedger::new();
            expansion
                .collect_imports(&mut graph, &imports, &mut acquired)
                .unwrap();
            for row in acquired.as_slice() {
                if row.base == E {
                    e_count = plan_reference_add_many(e_count, false, row.releases);
                }
            }
        }
        let mut released = ReferenceReleaseLedger::new();
        assert!(released.record(A));
        collect_reference_releases(&mut graph, A, &mut released, &mut [0; 5], &mut 0).unwrap();
        let e = released
            .as_slice()
            .iter()
            .find(|row| row.base == E)
            .unwrap();
        assert_eq!(
            plan_reference_release(e_count, e.releases),
            ReferenceReleasePlan::DecrementTo(1)
        );
    }

    #[test]
    fn diamond_add_then_release_preserves_preexisting_dependency_reference() {
        let mut graph = Diamond;
        let mut visited = [0; 4];
        let mut count = 0;
        let mut acquisitions = ReferenceReleaseLedger::<4>::new();
        collect_reference_acquisitions(&mut graph, A, &mut acquisitions, &mut visited, &mut count)
            .unwrap();
        assert_eq!(visited[..count], [A, B, D, C]);
        let original_d = 1;
        let mut retained_d = original_d;
        for reference in acquisitions.as_slice() {
            if reference.base == D {
                retained_d = plan_reference_add_many(retained_d, false, reference.releases);
            }
        }
        let mut releases = ReferenceReleaseLedger::<4>::new();
        assert!(releases.record(A));
        count = 0;
        collect_reference_releases(&mut graph, A, &mut releases, &mut visited, &mut count).unwrap();
        let release_d = releases
            .as_slice()
            .iter()
            .find(|row| row.base == D)
            .unwrap();
        assert_eq!(
            plan_reference_release(retained_d, release_d.releases),
            ReferenceReleasePlan::DecrementTo(original_d),
            "one balanced runtime acquisition must not consume D's preexisting owner"
        );
    }
}
