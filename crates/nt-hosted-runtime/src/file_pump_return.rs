//! An ordinary File caller's pump kept in its File row (#420).
//!
//! A pump that stops unfinished with no lane to keep it stays with the row. The root boundary
//! resumes it, and its return is held in the row until the row's own caller collects it: the
//! resumed driver must never be the one to take it, because nothing else would hand it on.

/// The row's kept pump: suspended under key `K`, then returned with value `T`.
#[derive(Debug, Eq, PartialEq)]
pub enum KeptFilePump<K, T> {
    Suspended(K),
    Returned(K, T),
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

impl<K: Copy + Eq, T> KeptFilePump<K, T> {
    /// The resumed pump returned. The value stays in the row for its caller.
    pub fn returned(self, value: T) -> Self {
        match self {
            Self::Suspended(key) => Self::Returned(key, value),
            returned @ Self::Returned(..) => { drop(value); returned }
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
        slot = slot.map(|kept| kept.returned("true result"));
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Collected("true result"),
            "the return is never lost to the root driver that resumed it");
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Mismatch,
            "a collected return is never handed over twice");
    }

    #[test]
    fn another_selector_takes_nothing() {
        let mut slot = Some(KeptFilePump::<u8, &str>::Suspended(4).returned("mine"));
        assert_eq!(KeptFilePump::collect(&mut slot, 5), FilePumpCollect::Mismatch);
        assert_eq!(KeptFilePump::collect(&mut slot, 4), FilePumpCollect::Collected("mine"));
    }
}
