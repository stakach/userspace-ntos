//! The component device-reply lock word, and DPC admission over it (#420).
//!
//! A hosted driver's PASSIVE lanes serialize their device-service root Calls (device
//! properties, contiguous RAM, PnP notifications, ...) on one word in the component's pool page,
//! and hold it across the Call. A DPC that reaches the same word (MmGetPhysicalAddress,
//! MmUnmapIoSpace, IoReportTargetDeviceChangeAsynchronous) while a lane holds it can only spin:
//! the root cannot answer the holder's Call while it drives the DPC (boot 44963863150).
//!
//! The domain is one NT processor, so the root does not start a DPC over a holder. Admission
//! marks the word `DPC_DEFERRED`; the holder's release then reports that it must wake the root,
//! whose next DPC pass delivers the still-queued DPC.
//!
//! Word: `0` free, else `HELD | DPC_DEFERRED? | stack pointer` (the holder lane, for diagnostics
//! and exact release).

use core::sync::atomic::{AtomicU64, Ordering};

const HELD: u64 = 1 << 62;
const DPC_DEFERRED: u64 = 1 << 61;
const STACK_MASK: u64 = DPC_DEFERRED - 1;
/// Admission retries only a word that changed under its compare-exchange.
const ADMISSION_ATTEMPTS: usize = 4;

fn held_word(stack_pointer: u64) -> u64 {
    HELD | (stack_pointer & STACK_MASK)
}

/// The holder lane recorded in a held word.
pub fn device_reply_holder(word: u64) -> Option<u64> {
    (word & HELD != 0).then_some(word & STACK_MASK)
}

/// One strong attempt by the lane running on `stack_pointer`. `Err` is the observed word.
pub fn try_acquire_device_reply_lock(word: &AtomicU64, stack_pointer: u64) -> Result<(), u64> {
    word.compare_exchange(0, held_word(stack_pointer), Ordering::Acquire, Ordering::Relaxed)
        .map(|_| ())
}

/// What the releasing lane owes after its release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceReplyRelease {
    Released,
    /// The root deferred a DPC over this hold: wake it so its next DPC pass delivers it.
    WakeDeferredDpc,
}

/// Release by the exact holder. `Err` is the observed word, left unchanged.
pub fn release_device_reply_lock(
    word: &AtomicU64,
    stack_pointer: u64,
) -> Result<DeviceReplyRelease, u64> {
    let held = held_word(stack_pointer);
    let mut observed = word.load(Ordering::Acquire);
    // Only the holder clears the word and the root only adds DPC_DEFERRED, so this retries at
    // most once, after a concurrent mark.
    loop {
        if observed & !DPC_DEFERRED != held {
            return Err(observed);
        }
        match word.compare_exchange(observed, 0, Ordering::Release, Ordering::Acquire) {
            Ok(_) if observed & DPC_DEFERRED != 0 => return Ok(DeviceReplyRelease::WakeDeferredDpc),
            Ok(_) => return Ok(DeviceReplyRelease::Released),
            Err(actual) => observed = actual,
        }
    }
}

/// Root's DPC admission for the domain that owns `word`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceReplyDpcAdmission {
    Start,
    /// A lane holds the word; the DPC stays queued and the holder's release wakes the root.
    Deferred { holder_stack_pointer: u64 },
}

/// Never waits. A held word is marked so its release wakes the root.
pub fn admit_dpc_over_device_reply_lock(word: &AtomicU64) -> DeviceReplyDpcAdmission {
    let mut observed = word.load(Ordering::Acquire);
    for _ in 0..ADMISSION_ATTEMPTS {
        if observed == 0 {
            return DeviceReplyDpcAdmission::Start;
        }
        match word.compare_exchange(observed, observed | DPC_DEFERRED, Ordering::AcqRel,
            Ordering::Acquire)
        {
            Ok(_) => return DeviceReplyDpcAdmission::Deferred {
                holder_stack_pointer: observed & STACK_MASK,
            },
            Err(actual) => observed = actual,
        }
    }
    // Still changing: defer without the mark. The changing word belongs to a running lane,
    // whose next root event opens another DPC pass.
    DeviceReplyDpcAdmission::Deferred { holder_stack_pointer: observed & STACK_MASK }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY: u64 = 0x1000_f01f_800;
    const WORKER: u64 = 0x1001_121f_000;

    #[test]
    fn a_dpc_never_starts_over_a_holder_and_its_release_wakes_the_root() {
        let word = AtomicU64::new(0);
        assert_eq!(admit_dpc_over_device_reply_lock(&word), DeviceReplyDpcAdmission::Start);

        try_acquire_device_reply_lock(&word, PRIMARY).unwrap();
        assert_eq!(admit_dpc_over_device_reply_lock(&word),
            DeviceReplyDpcAdmission::Deferred { holder_stack_pointer: PRIMARY },
            "a DPC started over the holder could only spin on it");
        assert_eq!(device_reply_holder(word.load(Ordering::Relaxed)), Some(PRIMARY));
        assert_eq!(try_acquire_device_reply_lock(&word, WORKER).map_err(|_| ()), Err(()),
            "the deferral mark does not free the word");

        assert_eq!(release_device_reply_lock(&word, PRIMARY), Ok(DeviceReplyRelease::WakeDeferredDpc),
            "the deferred DPC is delivered by an explicit wake, not by an unrelated event");
        assert_eq!(admit_dpc_over_device_reply_lock(&word), DeviceReplyDpcAdmission::Start);
    }

    #[test]
    fn a_release_with_no_deferred_dpc_owes_no_wake() {
        let word = AtomicU64::new(0);
        try_acquire_device_reply_lock(&word, PRIMARY).unwrap();
        assert_eq!(release_device_reply_lock(&word, PRIMARY), Ok(DeviceReplyRelease::Released));
        assert_eq!(word.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn only_the_exact_holder_releases() {
        let word = AtomicU64::new(0);
        try_acquire_device_reply_lock(&word, PRIMARY).unwrap();
        let _ = admit_dpc_over_device_reply_lock(&word);
        assert!(release_device_reply_lock(&word, WORKER).is_err());
        assert_eq!(device_reply_holder(word.load(Ordering::Relaxed)), Some(PRIMARY));
        assert_eq!(release_device_reply_lock(&word, PRIMARY), Ok(DeviceReplyRelease::WakeDeferredDpc));
        assert!(release_device_reply_lock(&word, PRIMARY).is_err(), "a free word has no holder");
    }
}
