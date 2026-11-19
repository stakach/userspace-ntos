//! Reissue a syscall whose input capture needed provider bytes for a routed image or mapped
//! data-section page.
//!
//! NT resolves a page fault taken while probing or capturing a user buffer and carries on. The
//! executive cannot wait for a provider READ inside a handler, so the capture names the page
//! and fails; once the handler has returned without effect the caller is parked on the owned
//! page-in and the transport reissues the call.

/// Which owned page-in worker supplies the page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputPageSource {
    /// A routed SEC_IMAGE view page.
    Image,
    /// A routed file-backed data Section view page.
    Mapped,
}

/// The page a failed capture needed, recorded by the residency path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeferredInputPage {
    /// Thread whose dispatch performed the copy. Work retained for another caller can run
    /// inside this dispatch; its pages are not this call's input.
    pub caller_thread: u64,
    pub process_index: usize,
    pub page: u64,
    pub write: bool,
    pub source: InputPageSource,
}

/// What the reply tail does with a completed dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputPageInSettlement {
    /// Return the handler's status.
    Reply,
    /// Park the caller on this page and reissue the call once it is mapped.
    PageInAndRetry(DeferredInputPage),
}

/// Decide whether a dispatch that named a deferred input page may be reissued.
///
/// Only an NT error is replayable: a handler that fails a capture returns before any effect,
/// exactly as it must for an invalid pointer. A success, informational or warning status means
/// the handler went on without those bytes and may have acted. `plain_status_reply` is false
/// when the dispatch transferred its Reply, redirected the caller's context or owes any other
/// record of this exact reply; such a call is never reissued.
pub const fn settle_input_pagein(
    deferred: Option<DeferredInputPage>,
    caller_thread: u64,
    status: u32,
    plain_status_reply: bool,
) -> InputPageInSettlement {
    match deferred {
        Some(page) if plain_status_reply && status >> 30 == 3
            && page.caller_thread == caller_thread => {
            InputPageInSettlement::PageInAndRetry(page)
        }
        _ => InputPageInSettlement::Reply,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: DeferredInputPage =
        DeferredInputPage { caller_thread: 256, process_index: 9, page: 0x7ff9_3002_0000, write: false,
            source: InputPageSource::Image };
    const MAPPED: DeferredInputPage = DeferredInputPage { source: InputPageSource::Mapped, ..PAGE };

    #[test]
    fn a_failed_capture_of_a_cold_image_page_reissues_the_call() {
        // KVM run 43595199385: NtAlpcConnectPort for `\\LsaAuthenticationPort` and NtWriteFile
        // from an image page both returned an error because the page-in READ pended.
        assert_eq!(settle_input_pagein(Some(PAGE), 256, 0xc000_0005, true),
            InputPageInSettlement::PageInAndRetry(PAGE));
        assert_eq!(settle_input_pagein(Some(PAGE), 256, 0xc000_0185, true),
            InputPageInSettlement::PageInAndRetry(PAGE));
    }

    #[test]
    fn a_failed_capture_of_a_cold_mapped_section_page_reissues_the_call() {
        // A buffer in a routed data-section view: the copy names the page instead of issuing
        // a synchronous READ that could pend, and the caller waits on the section page-in.
        assert_eq!(settle_input_pagein(Some(MAPPED), 256, 0xc000_0006, true),
            InputPageInSettlement::PageInAndRetry(MAPPED));
        assert_eq!(settle_input_pagein(Some(MAPPED), 256, 0, true), InputPageInSettlement::Reply);
    }

    #[test]
    fn a_dispatch_that_may_have_acted_is_never_reissued() {
        for status in [0, 0x103, 0x4000_0000, 0x8000_0005] {
            assert_eq!(settle_input_pagein(Some(PAGE), 256, status, true),
                InputPageInSettlement::Reply, "status {status:#x} is not a clean failure");
        }
        assert_eq!(settle_input_pagein(Some(PAGE), 256, 0xc000_0005, false),
            InputPageInSettlement::Reply, "the Reply or context is no longer the tail's");
        assert_eq!(settle_input_pagein(None, 256, 0xc000_0005, true), InputPageInSettlement::Reply);
        assert_eq!(settle_input_pagein(Some(PAGE), 460, 0xc000_0005, true),
            InputPageInSettlement::Reply, "the page belongs to another caller's retained work");
    }
}
