//! Which failed native services belong in the process-creation failure trace, and which of them
//! have already been reported.
//!
//! Creating a process is a dozen services issued by kernel32, advapi32 and ntdll. Each caller
//! collapses the NTSTATUS it gets into a DOS error, and several statuses share one, so a boot log
//! that carries only the caller's own message cannot name the step that failed. The executive
//! reports each distinct failure once: the service, its status and the calling process.

/// `STATUS_INVALID_SYSTEM_SERVICE`: the service number is not in the native table.
pub const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;
/// `NtCurrentProcess()`.
const CURRENT_PROCESS: u64 = u64::MAX;
/// `SEC_IMAGE`.
const SEC_IMAGE: u64 = 0x0100_0000;

/// Services that only ever act on process and thread creation.
const CREATION_SERVICES: &[&str] = &[
    "NtCreateUserProcess",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "NtCreateThread",
    "NtCreateThreadEx",
    "NtResumeThread",
    "NtSetInformationProcess",
    "NtAssignProcessToJobObject",
    "NtDuplicateToken",
    "NtFilterToken",
    "NtQuerySection",
];

/// Services whose first argument is a process handle. They belong to process creation when that
/// process is not the caller itself: the creator building the new address space.
const FOREIGN_PROCESS_SERVICES: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtProtectVirtualMemory",
    "NtFreeVirtualMemory",
    "NtQueryInformationProcess",
    "NtTerminateProcess",
];

/// The name to report for a failed service, or `None` when the failure is not process creation.
///
/// `args` are the service's register arguments as issued. A service number that is not served at
/// all is always reported: the caller cannot proceed past it whatever it was creating.
pub fn reportable_service(ssn: u32, status: u32, args: &[u64]) -> Option<&'static str> {
    if (status as i32) >= 0 {
        return None;
    }
    let name = crate::name_of(ssn)?;
    if status == STATUS_INVALID_SYSTEM_SERVICE || CREATION_SERVICES.contains(&name) {
        return Some(name);
    }
    if FOREIGN_PROCESS_SERVICES.contains(&name) {
        return (args.first().copied()? != CURRENT_PROCESS).then_some(name);
    }
    if name == "NtCreateSection" {
        return (args.get(5).copied()? & SEC_IMAGE != 0).then_some(name);
    }
    None
}

/// The distinct failures one boot may report. A few dozen processes each probing a service or two
/// that fails must not exhaust the trace before the failure that matters.
pub const FAILURE_TRACE_CAPACITY: usize = 256;

/// The failures already reported, keyed by service, status and calling process.
#[derive(Clone, Debug)]
pub struct FailureTrace {
    seen: [(u32, u32, u32); FAILURE_TRACE_CAPACITY],
    len: usize,
}

impl Default for FailureTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl FailureTrace {
    pub const fn new() -> Self {
        Self { seen: [(0, 0, 0); FAILURE_TRACE_CAPACITY], len: 0 }
    }

    /// Record a finished service. Returns the service name when this is the first report of that
    /// failure and the trace still has room; the caller prints exactly one line for it.
    pub fn observe(&mut self, ssn: u32, status: u32, pi: u32, args: &[u64]) -> Option<&'static str> {
        let name = reportable_service(ssn, status, args)?;
        let key = (ssn, status, pi);
        if self.seen[..self.len].contains(&key) || self.len == FAILURE_TRACE_CAPACITY {
            return None;
        }
        self.seen[self.len] = key;
        self.len += 1;
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssn_of;

    fn ssn(name: &str) -> u32 {
        ssn_of(name).unwrap()
    }

    #[test]
    fn an_unserved_service_is_named_whatever_it_is() {
        // The failure this trace exists for: kernel32 issuing NtCreateUserProcess for a process
        // created under a user token, answered STATUS_INVALID_SYSTEM_SERVICE.
        assert_eq!(
            reportable_service(ssn("NtCreateUserProcess"), STATUS_INVALID_SYSTEM_SERVICE, &[]),
            Some("NtCreateUserProcess")
        );
        assert_eq!(
            reportable_service(ssn("NtNotifyChangeKey"), STATUS_INVALID_SYSTEM_SERVICE, &[]),
            Some("NtNotifyChangeKey")
        );
        // A number outside the native table has no name to report.
        assert_eq!(reportable_service(0x1286, STATUS_INVALID_SYSTEM_SERVICE, &[]), None);
    }

    #[test]
    fn creation_services_report_failures_and_only_failures() {
        for name in CREATION_SERVICES {
            assert_eq!(reportable_service(ssn(name), 0xC000_0061, &[]), Some(*name));
            assert_eq!(reportable_service(ssn(name), 0x8000_0005, &[]), Some(*name));
            for success in [0, 0x103, 0x4000_0003] {
                assert_eq!(reportable_service(ssn(name), success, &[]), None);
            }
        }
    }

    #[test]
    fn address_space_services_report_only_against_another_process() {
        for name in FOREIGN_PROCESS_SERVICES {
            assert_eq!(reportable_service(ssn(name), 0xC000_0018, &[0x1a4]), Some(*name));
            assert_eq!(reportable_service(ssn(name), 0xC000_0018, &[u64::MAX]), None);
            assert_eq!(reportable_service(ssn(name), 0xC000_0018, &[]), None);
        }
    }

    #[test]
    fn only_image_sections_report() {
        let section = ssn("NtCreateSection");
        let image = [0, 0xf001f, 0, 0, 0x10, 0x0100_0000, 0x44];
        let data = [0, 0xf001f, 0, 0, 0x04, 0x0800_0000, 0x44];
        assert_eq!(reportable_service(section, 0xC000_007B, &image), Some("NtCreateSection"));
        assert_eq!(reportable_service(section, 0xC000_007B, &data), None);
    }

    #[test]
    fn ordinary_failures_stay_out_of_the_trace() {
        for name in ["NtOpenFile", "NtOpenKey", "NtQueryValueKey", "NtClose", "NtWaitForSingleObject"] {
            assert_eq!(reportable_service(ssn(name), 0xC000_0034, &[0x1a4]), None, "{name}");
        }
    }

    #[test]
    fn each_failure_is_reported_once_per_process() {
        let mut trace = FailureTrace::new();
        let create = ssn("NtCreateProcessEx");
        assert_eq!(trace.observe(create, 0xC000_009A, 8, &[]), Some("NtCreateProcessEx"));
        assert_eq!(trace.observe(create, 0xC000_009A, 8, &[]), None);
        // Another status, and the same status from another process, are different facts.
        assert_eq!(trace.observe(create, 0xC000_00BB, 8, &[]), Some("NtCreateProcessEx"));
        assert_eq!(trace.observe(create, 0xC000_009A, 9, &[]), Some("NtCreateProcessEx"));
        assert_eq!(trace.observe(create, 0, 8, &[]), None);
    }

    #[test]
    fn the_trace_is_bounded() {
        let mut trace = FailureTrace::new();
        let create = ssn("NtCreateThread");
        for pi in 0..FAILURE_TRACE_CAPACITY as u32 {
            assert!(trace.observe(create, 0xC000_009A, pi, &[]).is_some());
        }
        assert_eq!(trace.observe(create, 0xC000_009A, 1000, &[]), None);
        assert_eq!(trace.observe(create, 0xC000_0017, 0, &[]), None);
    }
}
