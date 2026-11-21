//! An ordinary File caller's pump kept in its File row (#420).
//!
//! A pump that stops unfinished with no lane to keep it stays with the row. The root boundary
//! resumes it. Who receives the return depends on the caller:
//! - a caller with a row of its own collects it from the row; the resumed driver must never be
//!   the one to take it, because nothing else would hand it on;
//! - a caller with no row was told `STATUS_PENDING` and reads the IRP's ordinary completion, so
//!   the return is published as that completion and never held for a collector.

/// The row's kept pump: suspended under key `K`, then returned with value `T`.
#[derive(Debug, Eq, PartialEq)]
pub enum KeptFilePump<K, T> {
    Suspended(K),
    Returned(K, T),
    /// Kept for a caller with no row: its return becomes the IRP's ordinary completion.
    DeferredCompletion,
}

/// What the row's caller found when it collected.
#[derive(Debug, Eq, PartialEq)]
pub enum FilePumpCollect<T> {
    /// Still unfinished; collect again later.
    Pending,
    /// The true return, handed over exactly once.
    Collected(T),
    /// The selector names no kept pump of this row.
    Mismatch,
}

/// Where a resumed pump's return goes.
#[derive(Debug, Eq, PartialEq)]
pub enum FilePumpReturned<P, T> {
    /// Held in the row until the row's own caller collects it.
    Kept(P),
    /// Published now as the IRP's ordinary completion; no collector exists.
    Publish(T),
}

impl<K: Copy + Eq, T> KeptFilePump<K, T> {
    /// The resumed pump returned.
    pub fn returned(self, value: T) -> FilePumpReturned<Self, T> {
        match self {
            Self::Suspended(key) => FilePumpReturned::Kept(Self::Returned(key, value)),
            returned @ Self::Returned(..) => { drop(value); FilePumpReturned::Kept(returned) }
            Self::DeferredCompletion => FilePumpReturned::Publish(value),
        }
    }

    /// The key a root redrive resumes this kept pump under, given the native pump's current
    /// key; `None` when nothing is left to resume. A row caller's selector names the kept pump
    /// for collection only: a pump that yields again carries a new native key, and is resumed
    /// under that key while the caller's selector still collects its return.
    pub fn resume_key(&self, current: K) -> Option<K> {
        match self {
            Self::Suspended(_) | Self::DeferredCompletion => Some(current),
            Self::Returned(..) => None,
        }
    }

    /// The row's caller collects with its selector. A return is taken exactly once.
    pub fn collect(slot: &mut Option<Self>, key: K) -> FilePumpCollect<T> {
        match slot.take() {
            Some(Self::Suspended(kept)) if kept == key => {
                *slot = Some(Self::Suspended(kept));
                FilePumpCollect::Pending
            }
            Some(Self::Returned(kept, value)) if kept == key => FilePumpCollect::Collected(value),
            other => { *slot = other; FilePumpCollect::Mismatch }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept<K, T>(returned: FilePumpReturned<KeptFilePump<K, T>, T>) -> Option<KeptFilePump<K, T>> {
        match returned {
            FilePumpReturned::Kept(pump) => Some(pump),
            FilePumpReturned::Publish(_) => None,
        }
    }

    #[test]
    fn a_kept_pump_is_pending_until_it_returns() {
        let mut slot = Some(KeptFilePump::<u8, &str>::Suspended(4));
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Pending);
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Pending,
            "collecting a pending pump changes nothing");
    }

    #[test]
    fn a_resumed_return_is_kept_for_its_caller_and_collected_once() {
        let mut slot = Some(KeptFilePump::<u8, &str>::Suspended(4));
        slot = slot.and_then(|pump| kept(pump.returned("true result")));
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Collected("true result"),
            "the return is never lost to the root driver that resumed it");
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Mismatch,
            "a collected return is never handed over twice");
    }

    #[test]
    fn another_selector_takes_nothing() {
        let mut slot = kept(KeptFilePump::<u8, &str>::Suspended(4).returned("mine"));
        assert_eq!(KeptFilePump::collect(&mut slot, 5), FilePumpCollect::Mismatch);
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Collected("mine"));
    }

    #[test]
    fn a_reyielded_pump_is_resumed_under_its_new_key_and_collected_by_its_selector() {
        // The caller holds selector 4; the resumed pump yielded again under native key 5.
        let mut slot = Some(KeptFilePump::<u8, &str>::Suspended(4));
        assert_eq!(slot.as_ref().and_then(|pump| pump.resume_key(5)), Some(5),
            "a re-yielded pump must still be resumed, under its current key");
        slot = slot.and_then(|pump| kept(pump.returned("true result")));
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Collected("true result"),
            "the caller's selector still collects the return exactly once");
    }

    #[test]
    fn a_returned_pump_is_not_resumed_again() {
        let pump = kept(KeptFilePump::<u8, &str>::Suspended(4).returned("done")).unwrap();
        assert_eq!(pump.resume_key(4), None);
        assert_eq!(KeptFilePump::<u8, &str>::DeferredCompletion.resume_key(7), Some(7));
    }

    #[test]
    fn a_deferred_return_is_published_not_held_for_a_collector() {
        assert_eq!(KeptFilePump::<u8, &str>::DeferredCompletion.returned("true result"),
            FilePumpReturned::Publish("true result"),
            "a caller told STATUS_PENDING has no row to collect from; holding the return loses it");
    }

    #[test]
    fn no_selector_collects_a_deferred_pump() {
        let mut slot = Some(KeptFilePump::<u8, &str>::DeferredCompletion);
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Mismatch);
        assert_eq!(slot, Some(KeptFilePump::DeferredCompletion),
            "a failed collection leaves the deferred pump in place");
    }
}
