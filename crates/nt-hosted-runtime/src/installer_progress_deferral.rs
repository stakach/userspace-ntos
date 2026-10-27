//! A bounded grace interval for an installer that is advancing through distinct INF probes.
//!
//! The executive supplies a generation-fenced live worker and its verified parent. A probe is
//! observed only after the worker's `NtOpenKey` for an `IniFileMapping\\*.inf` key has completed.
//! A missing key is a completed probe, not a successful registry mutation. This policy never
//! counts timer wakes, generic I/O, or a repeated probe as installer progress.

const INF_MAPPING_PREFIX: &[u8] =
    b"\\registry\\machine\\software\\microsoft\\windows nt\\currentversion\\inifilemapping\\";
const MAX_INF_NAME: usize = 128;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallerOwner<Process> {
    pub worker: Process,
    pub parent: Process,
    /// A live registered noninteractive service ancestor reached by the current PM parent chain.
    pub service: Process,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InfName {
    bytes: [u8; MAX_INF_NAME],
    len: u8,
}

impl InfName {
    fn from_mapping_path(path: &str) -> Option<Self> {
        let path = path.as_bytes();
        let name = path.get(INF_MAPPING_PREFIX.len()..)?;
        if !path[..INF_MAPPING_PREFIX.len()].eq_ignore_ascii_case(INF_MAPPING_PREFIX)
            || name.len() < 5
            || name.len() > MAX_INF_NAME
            || !name[name.len() - 4..].eq_ignore_ascii_case(b".inf")
            || !name.iter().all(|byte| byte.is_ascii_alphanumeric()
                || matches!(*byte, b'_' | b'-' | b'.'))
        {
            return None;
        }
        let mut bytes = [0; MAX_INF_NAME];
        for (dest, byte) in bytes.iter_mut().zip(name) {
            *dest = byte.to_ascii_lowercase();
        }
        Some(Self { bytes, len: name.len() as u8 })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompletedInfProbe<Process> {
    owner: InstallerOwner<Process>,
    name: InfName,
    at_100ns: u64,
}

/// At most two 180-second graces per genuine boot-progress epoch. The outer boot harness remains
/// authoritative and must retain its one-hour limit.
pub struct InstallerProgressDeferral<Process> {
    owner: InstallerOwner<Process>,
    epoch: u64,
    epoch_started_100ns: u64,
    latest: Option<CompletedInfProbe<Process>>,
    granted: Option<CompletedInfProbe<Process>>,
    grants: u8,
}

impl<Process: Copy + Eq> InstallerProgressDeferral<Process> {
    pub const MAX_GRANTS_PER_EPOCH: u8 = 2;

    pub const fn new(owner: InstallerOwner<Process>, epoch: u64, now_100ns: u64) -> Self {
        Self {
            owner,
            epoch,
            epoch_started_100ns: now_100ns,
            latest: None,
            granted: None,
            grants: 0,
        }
    }

    pub fn observe_epoch(&mut self, epoch: u64, now_100ns: u64) {
        if epoch != self.epoch {
            self.epoch = epoch;
            self.epoch_started_100ns = now_100ns;
            self.latest = None;
            self.granted = None;
            self.grants = 0;
        }
    }

    /// `owner` must be resolved from the admitted caller's exact process identity and current
    /// parent relation. Call this only at the completed `NtOpenKey` result boundary.
    pub fn observe_completed_probe(
        &mut self,
        owner: InstallerOwner<Process>,
        path: &str,
        status: u32,
        now_100ns: u64,
    ) -> bool {
        if owner.service != self.owner.service
            || now_100ns < self.epoch_started_100ns
            || self.latest.is_some_and(|last| now_100ns <= last.at_100ns)
            || status != STATUS_OBJECT_NAME_NOT_FOUND
        {
            return false;
        }
        let Some(name) = InfName::from_mapping_path(path) else {
            return false;
        };
        if owner != self.owner {
            // A sibling helper can take over only within the same service generation. Retain
            // the prior INF names and grant budget, while fencing its ungranted probe.
            self.owner = owner;
        }
        if self.latest.is_some_and(|last| last.name == name)
            || self.granted.is_some_and(|last| last.name == name)
        {
            return false;
        }
        self.latest = Some(CompletedInfProbe { owner, name, at_100ns: now_100ns });
        true
    }

    /// A grace requires a still-live exact owner, a different completed INF probe since the
    /// previous grace, and a probe within the current 180-second window.
    pub fn grant(
        &mut self,
        live_owner: Option<InstallerOwner<Process>>,
        now_100ns: u64,
        window_100ns: u64,
    ) -> bool {
        let Some(probe) = self.latest else { return false };
        if live_owner != Some(self.owner)
            || probe.owner != self.owner
            || self.grants >= Self::MAX_GRANTS_PER_EPOCH
            || now_100ns < probe.at_100ns
            || now_100ns - probe.at_100ns > window_100ns
            || self.granted.is_some_and(|last| {
                probe.at_100ns <= last.at_100ns || probe.name == last.name
            })
        {
            return false;
        }
        self.granted = Some(probe);
        self.grants += 1;
        true
    }

    pub const fn grants(&self) -> u8 { self.grants }

    pub const fn owner(&self) -> InstallerOwner<Process> { self.owner }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::ToString;

    const WINDOW: u64 = 180 * 10_000_000;
    const PREFIX: &str =
        "\\registry\\machine\\software\\microsoft\\windows nt\\currentversion\\inifilemapping\\";
    const OWNER: InstallerOwner<(u32, u64)> = InstallerOwner {
        worker: (424, 3),
        parent: (160, 2),
        service: (120, 1),
    };

    fn probe(policy: &mut InstallerProgressDeferral<(u32, u64)>, name: &str, at: u64) -> bool {
        let mut path = PREFIX.to_string();
        path.push_str(name);
        policy.observe_completed_probe(OWNER, &path, STATUS_OBJECT_NAME_NOT_FOUND, at)
    }

    #[test]
    fn distinct_completed_inf_probes_earn_only_two_bounded_graces() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        assert!(probe(&mut policy, "sffdisk.inf", 200));
        assert!(policy.grant(Some(OWNER), 200 + WINDOW, WINDOW));
        assert!(probe(&mut policy, "usbstor.inf", 300 + WINDOW));
        assert!(policy.grant(Some(OWNER), 300 + WINDOW, WINDOW));
        assert!(probe(&mut policy, "input.inf", 400 + WINDOW));
        assert!(!policy.grant(Some(OWNER), 400 + WINDOW, WINDOW));
        assert_eq!(policy.grants(), 2);
    }

    #[test]
    fn stale_repeated_or_unowned_probe_cannot_extend_window() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        assert!(!policy.grant(Some(OWNER), 200, WINDOW));
        assert!(probe(&mut policy, "input.inf", 200));
        assert!(!policy.grant(None, 201, WINDOW));
        assert!(!policy.grant(Some(InstallerOwner { worker: (424, 4), ..OWNER }), 201, WINDOW));
        assert!(!policy.grant(Some(OWNER), 201 + WINDOW, WINDOW));
        assert!(policy.grant(Some(OWNER), 200 + WINDOW, WINDOW));
        assert!(!probe(&mut policy, "INPUT.INF", 300 + WINDOW));
        assert!(!policy.grant(Some(OWNER), 300 + WINDOW, WINDOW));
    }

    #[test]
    fn only_exact_completed_inf_mapping_probe_is_evidence() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        assert!(!policy.observe_completed_probe(
            OWNER, &std::format!("{PREFIX}disk.inf"), 0, 200,
        ));
        assert!(!policy.observe_completed_probe(
            OWNER, "\\registry\\machine\\software\\disk.inf", STATUS_OBJECT_NAME_NOT_FOUND, 200,
        ));
        assert!(!policy.observe_completed_probe(
            OWNER, &std::format!("{PREFIX}sub\\disk.inf"), STATUS_OBJECT_NAME_NOT_FOUND, 200,
        ));
        assert!(!policy.grant(Some(OWNER), 200, WINDOW));
    }

    #[test]
    fn new_boot_epoch_requires_new_completed_probe() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        assert!(probe(&mut policy, "disk.inf", 200));
        policy.observe_epoch(8, 300);
        assert!(!policy.grant(Some(OWNER), 300, WINDOW));
        assert!(!probe(&mut policy, "usbstor.inf", 299));
        assert!(probe(&mut policy, "usbstor.inf", 301));
        assert!(policy.grant(Some(OWNER), 301, WINDOW));
    }

    #[test]
    fn returning_to_a_granted_inf_does_not_hide_a_newer_distinct_probe() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        assert!(probe(&mut policy, "disk.inf", 200));
        assert!(policy.grant(Some(OWNER), 201, WINDOW));
        assert!(probe(&mut policy, "input.inf", 202));
        assert!(!probe(&mut policy, "disk.inf", 203));
        assert!(policy.grant(Some(OWNER), 204, WINDOW));
    }

    #[test]
    fn service_child_handoff_keeps_the_epoch_grant_limit() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        assert!(probe(&mut policy, "unattend.inf", 200));
        assert!(policy.grant(Some(OWNER), 201, WINDOW));
        let next = InstallerOwner { worker: (500, 1), ..OWNER };
        assert!(policy.observe_completed_probe(
            next, &std::format!("{PREFIX}disk.inf"), STATUS_OBJECT_NAME_NOT_FOUND, 300,
        ));
        assert_eq!(policy.owner(), next);
        assert!(!policy.grant(Some(OWNER), 301, WINDOW));
        assert!(policy.grant(Some(next), 301, WINDOW));
        assert!(!policy.grant(Some(next), 302, WINDOW));
        assert_eq!(policy.grants(), 2);
    }

    #[test]
    fn unrelated_service_cannot_replace_the_progress_owner() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        assert!(probe(&mut policy, "unattend.inf", 200));
        let unrelated = InstallerOwner {
            worker: (600, 1),
            parent: (580, 1),
            service: (560, 1),
        };
        assert!(!policy.observe_completed_probe(
            unrelated, &std::format!("{PREFIX}disk.inf"), STATUS_OBJECT_NAME_NOT_FOUND, 300,
        ));
        assert_eq!(policy.owner(), OWNER);
        assert!(policy.grant(Some(OWNER), 301, WINDOW));
    }

    #[test]
    fn recycled_service_generation_cannot_replace_the_progress_owner() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        let recycled = InstallerOwner {
            worker: (600, 1),
            parent: (580, 1),
            service: (OWNER.service.0, OWNER.service.1 + 1),
        };
        assert!(!policy.observe_completed_probe(
            recycled, &std::format!("{PREFIX}disk.inf"), STATUS_OBJECT_NAME_NOT_FOUND, 200,
        ));
        assert_eq!(policy.owner(), OWNER);
        assert_eq!(policy.grants(), 0);
    }

    #[test]
    fn helper_handoff_does_not_count_the_same_inf_again() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        assert!(probe(&mut policy, "display.inf", 200));
        assert!(policy.grant(Some(OWNER), 201, WINDOW));
        let next = InstallerOwner { worker: (500, 1), ..OWNER };
        assert!(!policy.observe_completed_probe(
            next, &std::format!("{PREFIX}DISPLAY.inf"), STATUS_OBJECT_NAME_NOT_FOUND, 300,
        ));
        assert_eq!(policy.owner(), next);
        assert!(!policy.grant(Some(next), 301, WINDOW));
        assert!(policy.observe_completed_probe(
            next, &std::format!("{PREFIX}monitor.inf"), STATUS_OBJECT_NAME_NOT_FOUND, 302,
        ));
        assert!(policy.grant(Some(next), 303, WINDOW));
    }

    #[test]
    fn ungranted_prior_helper_probe_cannot_be_granted_by_new_helper() {
        let mut policy = InstallerProgressDeferral::new(OWNER, 7, 100);
        assert!(probe(&mut policy, "display.inf", 200));
        let next = InstallerOwner { worker: (500, 1), ..OWNER };
        assert!(!policy.observe_completed_probe(
            next, &std::format!("{PREFIX}DISPLAY.inf"), STATUS_OBJECT_NAME_NOT_FOUND, 300,
        ));
        assert!(!policy.grant(Some(next), 301, WINDOW));
        assert_eq!(policy.grants(), 0);
    }
}
