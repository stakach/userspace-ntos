//! One-shot ownership for a syscall whose user output needs a retained page-in.

/// Admission for the physical page map, one syscall dispatch and its terminal Reply. Entering
/// an effect is durable; a refused or uncertain effect cannot authorize replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyOutputContinuation {
    PageReady,
    MapEntered,
    Mapped,
    DispatchEntered,
    ReplyReady(u32),
    ReplyEntered(u32),
}

impl CopyOutputContinuation {
    pub fn enter_map(&mut self) -> bool {
        if *self != Self::PageReady { return false; }
        *self = Self::MapEntered;
        true
    }
    pub fn map_completed(&mut self) -> bool {
        if *self != Self::MapEntered { return false; }
        *self = Self::Mapped;
        true
    }
    pub fn enter_dispatch(&mut self) -> bool {
        if *self != Self::Mapped { return false; }
        *self = Self::DispatchEntered;
        true
    }
    pub fn dispatch_completed(&mut self, status: u32) -> bool {
        if *self != Self::DispatchEntered { return false; }
        *self = Self::ReplyReady(status);
        true
    }
    pub fn fail_before_dispatch(&mut self, status: u32) -> bool {
        if !matches!(*self, Self::PageReady | Self::Mapped) { return false; }
        *self = Self::ReplyReady(status);
        true
    }
    pub const fn reply_status(self) -> Option<u32> {
        match self { Self::ReplyReady(status) | Self::ReplyEntered(status) => Some(status), _ => None }
    }
    pub fn enter_reply(&mut self) -> bool {
        let Self::ReplyReady(status) = *self else { return false; };
        *self = Self::ReplyEntered(status);
        true
    }
}

/// `NtQueryDefaultLocale` writes one DWORD through its second argument. Invalid pointers are
/// left to the ordinary handler so its null and alignment status precedence remains authoritative.
pub const fn query_default_locale_output_page(output: u64, user_limit: u64) -> Option<u64> {
    if output == 0 || output & 3 != 0 { return None; }
    match output.checked_add(4) {
        Some(end) if end <= user_limit => Some(output & !0xfff),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_output_preflight_preserves_pointer_validation() {
        assert_eq!(query_default_locale_output_page(0, 0x20_000), None);
        assert_eq!(query_default_locale_output_page(0x1001, 0x20_000), None);
        assert_eq!(query_default_locale_output_page(u64::MAX - 3, u64::MAX), None);
        assert_eq!(query_default_locale_output_page(0x1ffc, 0x20_000), Some(0x1000));
        assert_eq!(query_default_locale_output_page(0x20_000, 0x20_000), None);
    }

    #[test]
    fn retained_output_effects_are_one_shot_across_reply_retries() {
        let mut owner = CopyOutputContinuation::PageReady;
        assert!(owner.enter_map());
        assert!(!owner.enter_map(), "uncertain map cannot be replayed");
        assert!(owner.map_completed());
        assert!(!owner.enter_map(), "post-map resource retry cannot remap");
        assert!(owner.enter_dispatch());
        assert!(!owner.enter_dispatch(), "entered syscall cannot be replayed");
        assert!(owner.dispatch_completed(0x1234));
        assert_eq!(owner.reply_status(), Some(0x1234));
        assert!(!owner.enter_dispatch());
        assert_eq!(owner.reply_status(), Some(0x1234));
        assert!(owner.enter_reply());
        assert!(!owner.enter_reply(), "uncertain Reply send cannot be repeated");
    }
}
