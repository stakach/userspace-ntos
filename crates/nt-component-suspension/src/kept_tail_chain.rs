//! The tails a kept dispatch owes, in the order its frames unwound (#420).
//!
//! A service whose dispatch was kept unfinished did not run the post-dispatch code of any
//! frame between the service and the dispatch. Each frame's tail was kept instead, innermost
//! first. When the dispatch finishes, the tails run in that order on its true result. A tail
//! that dispatches again may be kept again: its own inner tails then come first, followed by
//! the tails not yet run, and nothing after it runs until that dispatch finishes.

extern crate alloc;
use alloc::vec::Vec;

/// What one tail did with the result it was given.
pub enum TailRun<T, R, K> {
    /// The tail finished with this result.
    Done(R),
    /// The tail dispatched again and that dispatch was kept, owing these inner tails.
    Kept(K, Vec<T>),
}

/// How the whole chain ended.
pub enum ChainEnd<T, R, K> {
    Finished(R),
    /// A tail's dispatch was kept: this is its kept target and every tail still owed.
    Kept(K, Vec<T>),
    /// The remaining tails could not be kept for lack of capacity. Each ran on `refusal`
    /// instead, which no dispatch was entered for, and this is their result.
    Refused(K, R),
}

/// Run `tails` in order on `result`. `refusal` is the result a remaining tail sees when its
/// continuation cannot be kept.
pub fn run_tails<T, R, K>(
    tails: Vec<T>,
    mut result: R,
    refusal: impl Fn() -> R,
    mut run: impl FnMut(T, R) -> TailRun<T, R, K>,
) -> ChainEnd<T, R, K> {
    let mut tails = tails.into_iter();
    while let Some(tail) = tails.next() {
        match run(tail, result) {
            TailRun::Done(next) => result = next,
            TailRun::Kept(target, mut inner) => {
                let rest: Vec<T> = tails.collect();
                if inner.try_reserve(rest.len()).is_ok() {
                    inner.extend(rest);
                    return ChainEnd::Kept(target, inner);
                }
                let mut result = refusal();
                for tail in rest {
                    result = match run(tail, result) {
                        TailRun::Done(next) => next,
                        // A refused remainder never keeps; its dispatch is not entered again.
                        TailRun::Kept(_, _) => refusal(),
                    };
                }
                return ChainEnd::Refused(target, result);
            }
        }
    }
    ChainEnd::Finished(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn tails_run_innermost_first_on_the_true_result() {
        let mut order = vec![];
        let end = run_tails(vec!["adapter", "helper"], 1u32, || 0, |tail, result| {
            order.push((tail, result));
            TailRun::<&str, u32, ()>::Done(result + 1)
        });
        assert!(matches!(end, ChainEnd::Finished(3)));
        assert_eq!(order, vec![("adapter", 1), ("helper", 2)]);
    }

    #[test]
    fn a_tail_kept_again_owes_its_inner_tails_then_the_rest() {
        let mut ran = vec![];
        let end = run_tails(vec!["projection", "outer"], 1u32, || 0, |tail, result| {
            ran.push(tail);
            if tail == "projection" { TailRun::Kept("callback", vec!["callback-tail"]) }
            else { TailRun::Done(result) }
        });
        assert_eq!(ran, vec!["projection"], "nothing after a kept tail runs yet");
        match end {
            ChainEnd::Kept(target, tails) => {
                assert_eq!(target, "callback");
                assert_eq!(tails, vec!["callback-tail", "outer"]);
            }
            _ => panic!("the second dispatch must stay kept"),
        }
    }

    #[test]
    fn no_tail_runs_twice() {
        let mut runs = 0;
        let end = run_tails(vec![1, 2, 3], 0u32, || 0, |tail, result| {
            runs += 1;
            TailRun::<u32, u32, ()>::Done(result + tail)
        });
        assert!(matches!(end, ChainEnd::Finished(6)));
        assert_eq!(runs, 3);
    }
}
