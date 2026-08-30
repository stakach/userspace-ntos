//! win32k-owned policy for NT job-object UI restrictions.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

pub const JOB_OBJECT_UILIMIT_HANDLES: u32 = 0x0000_0001;
pub const JOB_OBJECT_UILIMIT_READCLIPBOARD: u32 = 0x0000_0002;
pub const JOB_OBJECT_UILIMIT_WRITECLIPBOARD: u32 = 0x0000_0004;
pub const JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: u32 = 0x0000_0008;
pub const JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: u32 = 0x0000_0010;
pub const JOB_OBJECT_UILIMIT_GLOBALATOMS: u32 = 0x0000_0020;
pub const JOB_OBJECT_UILIMIT_DESKTOP: u32 = 0x0000_0040;
pub const JOB_OBJECT_UILIMIT_EXITWINDOWS: u32 = 0x0000_0080;
pub const JOB_OBJECT_UI_VALID_FLAGS: u32 = 0x0000_00FF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiOperation {
    ReadClipboard,
    WriteClipboard,
    ChangeSystemParameters,
    ChangeDisplaySettings,
    AccessGlobalAtoms,
    CreateOrSwitchDesktop,
    ExitWindows,
}

impl UiOperation {
    pub const fn restriction(self) -> u32 {
        match self {
            Self::ReadClipboard => JOB_OBJECT_UILIMIT_READCLIPBOARD,
            Self::WriteClipboard => JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
            Self::ChangeSystemParameters => JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
            Self::ChangeDisplaySettings => JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
            Self::AccessGlobalAtoms => JOB_OBJECT_UILIMIT_GLOBALATOMS,
            Self::CreateOrSwitchDesktop => JOB_OBJECT_UILIMIT_DESKTOP,
            Self::ExitWindows => JOB_OBJECT_UILIMIT_EXITWINDOWS,
        }
    }
}

/// `PROCESSINFO.pW32Job` participates only in USER-handle isolation. Other UI restrictions use
/// the component's membership store without changing the handle-validation identity.
pub const fn process_job_token(restrictions: u32, token: u64) -> u64 {
    if restrictions & JOB_OBJECT_UILIMIT_HANDLES != 0 {
        token
    } else {
        0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovedJob {
    pub job: u64,
    pub token: u64,
    pub restrictions: u32,
    pub members: Vec<u64>,
}

#[derive(Debug)]
struct JobPolicy {
    job: u64,
    token: u64,
    restrictions: u32,
    members: Vec<u64>,
}

/// Session-local policy installed by win32k's registered job callout.
#[derive(Debug, Default)]
pub struct JobUiPolicyStore {
    jobs: Vec<JobPolicy>,
}

impl JobUiPolicyStore {
    pub const fn new() -> Self {
        Self { jobs: Vec::new() }
    }

    fn job_index(&self, job: u64) -> Option<usize> {
        self.jobs.iter().position(|record| record.job == job)
    }

    fn member_job_index(&self, process: u64) -> Option<usize> {
        self.jobs
            .iter()
            .position(|record| record.members.contains(&process))
    }

    pub fn contains_job(&self, job: u64) -> bool {
        self.job_index(job).is_some()
    }

    pub fn job_token(&self, job: u64) -> Option<u64> {
        self.job_index(job).map(|index| self.jobs[index].token)
    }

    pub fn restrictions(&self, job: u64) -> Result<u32, u32> {
        let index = self.job_index(job).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(self.jobs[index].restrictions)
    }

    pub fn members(&self, job: u64) -> Result<&[u64], u32> {
        let index = self.job_index(job).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(&self.jobs[index].members)
    }

    pub fn process_in_job(&self, job: u64, process: u64) -> bool {
        self.job_index(job)
            .is_some_and(|index| self.jobs[index].members.contains(&process))
    }

    pub fn register_job(&mut self, job: u64, token: u64, restrictions: u32) -> Result<(), u32> {
        if job == 0 || token == 0 || restrictions & !JOB_OBJECT_UI_VALID_FLAGS != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.contains_job(job) || self.jobs.iter().any(|record| record.token == token) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.jobs
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.jobs.push(JobPolicy {
            job,
            token,
            restrictions,
            members: Vec::new(),
        });
        Ok(())
    }

    pub fn set_restrictions(&mut self, job: u64, restrictions: u32) -> Result<(), u32> {
        if restrictions & !JOB_OBJECT_UI_VALID_FLAGS != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let index = self.job_index(job).ok_or(STATUS_INVALID_HANDLE)?;
        self.jobs[index].restrictions = restrictions;
        Ok(())
    }

    /// Attach a real `W32PROCESS` to the job. Returns the stable token written to
    /// `PROCESSINFO.pW32Job`.
    pub fn add_process(&mut self, job: u64, process: u64) -> Result<u64, u32> {
        if process == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let index = self.job_index(job).ok_or(STATUS_INVALID_HANDLE)?;
        if let Some(owner) = self.member_job_index(process) {
            return if owner == index {
                Ok(self.jobs[index].token)
            } else {
                Err(STATUS_ACCESS_DENIED)
            };
        }
        self.jobs[index]
            .members
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.jobs[index].members.push(process);
        Ok(self.jobs[index].token)
    }

    pub fn remove_process(&mut self, job: u64, process: u64) -> Result<u64, u32> {
        let index = self.job_index(job).ok_or(STATUS_INVALID_HANDLE)?;
        let member = self.jobs[index]
            .members
            .iter()
            .position(|candidate| *candidate == process)
            .ok_or(STATUS_INVALID_HANDLE)?;
        self.jobs[index].members.remove(member);
        Ok(self.jobs[index].token)
    }

    pub fn take_job(&mut self, job: u64) -> Result<RemovedJob, u32> {
        let index = self.job_index(job).ok_or(STATUS_INVALID_HANDLE)?;
        let record = self.jobs.remove(index);
        Ok(RemovedJob {
            job: record.job,
            token: record.token,
            restrictions: record.restrictions,
            members: record.members,
        })
    }

    pub fn restrictions_for_process(&self, process: u64) -> u32 {
        self.member_job_index(process)
            .map(|index| self.jobs[index].restrictions)
            .unwrap_or(0)
    }

    pub fn operation_allowed(&self, process: u64, operation: UiOperation) -> bool {
        self.restrictions_for_process(process) & operation.restriction() == 0
    }
}

/// NT5 `JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS` blocks mutations but not SPI queries.
pub const fn is_system_parameter_write(action: u32) -> bool {
    matches!(
        action,
        0x0002
            | 0x0004
            | 0x0006
            | 0x000B
            | 0x000F
            | 0x0011
            | 0x0013
            | 0x0014
            | 0x0015
            | 0x0017
            | 0x001A
            | 0x001C
            | 0x001D
            | 0x001E
            | 0x0020
            | 0x0021
            | 0x0022
            | 0x0024
            | 0x0025
            | 0x002A
            | 0x002C
            | 0x002E
            | 0x002F
            | 0x0031
            | 0x0033
            | 0x0035
            | 0x0037
            | 0x0039
            | 0x003B
            | 0x003D
            | 0x003F
            | 0x0041
            | 0x0043
            | 0x0045
            | 0x0047
            | 0x0049
            | 0x004B
            | 0x004C
            | 0x004D
            | 0x004E
            | 0x0051
            | 0x0052
            | 0x0055
            | 0x0056
            | 0x0057
            | 0x0058
            | 0x005A
            | 0x005B
            | 0x005D
            | 0x0060
            | 0x0063
            | 0x0065
            | 0x0067
            | 0x0069
            | 0x006B
            | 0x006D
            | 0x006F
            | 0x0071
            | 0x0075
            | 0x0077
            | 0x0083
            | 0x008D
            | 0x0091
            | 0x1001
            | 0x1003
            | 0x1005
            | 0x1007
            | 0x1009
            | 0x100B
            | 0x100D
            | 0x100F
            | 0x1013
            | 0x1015
            | 0x1017
            | 0x1019
            | 0x101B
            | 0x101D
            | 0x101F
            | 0x1021
            | 0x1023
            | 0x1025
            | 0x1027
            | 0x103F
            | 0x1041
            | 0x1043
            | 0x1049
            | 0x104B
            | 0x2001
            | 0x2003
            | 0x2005
            | 0x2007
            | 0x2009
            | 0x200B
            | 0x200D
            | 0x200F
            | 0x2011
            | 0x2013
            | 0x2025
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_tokens_and_membership_are_stable_and_exact() {
        let mut store = JobUiPolicyStore::new();
        store
            .register_job(1, 0x1000, JOB_OBJECT_UILIMIT_HANDLES)
            .unwrap();
        store.register_job(2, 0x2000, 0).unwrap();
        assert_eq!(store.add_process(1, 0xAA), Ok(0x1000));
        assert_eq!(store.add_process(1, 0xAA), Ok(0x1000));
        assert_eq!(store.add_process(2, 0xAA), Err(STATUS_ACCESS_DENIED));
        assert_eq!(store.add_process(1, 0xBB), Ok(0x1000));
        assert_eq!(store.remove_process(1, 0xAA), Ok(0x1000));
        assert_eq!(store.restrictions_for_process(0xAA), 0);
    }

    #[test]
    fn restriction_updates_preserve_members_and_cover_every_class() {
        let mut store = JobUiPolicyStore::new();
        store.register_job(7, 0x7000, 0).unwrap();
        store.add_process(7, 0x77).unwrap();
        store
            .set_restrictions(7, JOB_OBJECT_UI_VALID_FLAGS)
            .unwrap();
        for operation in [
            UiOperation::ReadClipboard,
            UiOperation::WriteClipboard,
            UiOperation::ChangeSystemParameters,
            UiOperation::ChangeDisplaySettings,
            UiOperation::AccessGlobalAtoms,
            UiOperation::CreateOrSwitchDesktop,
            UiOperation::ExitWindows,
        ] {
            assert!(!store.operation_allowed(0x77, operation));
        }
        store.set_restrictions(7, 0).unwrap();
        assert!(store.operation_allowed(0x77, UiOperation::ReadClipboard));
    }

    #[test]
    fn process_job_identity_is_published_only_for_handle_isolation() {
        assert_eq!(
            process_job_token(JOB_OBJECT_UILIMIT_READCLIPBOARD, 0x7000),
            0
        );
        assert_eq!(
            process_job_token(
                JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_HANDLES,
                0x7000,
            ),
            0x7000
        );
    }

    #[test]
    fn terminate_returns_owned_members_for_component_rundown() {
        let mut store = JobUiPolicyStore::new();
        store
            .register_job(9, 0x9000, JOB_OBJECT_UILIMIT_DESKTOP)
            .unwrap();
        store.add_process(9, 0x91).unwrap();
        store.add_process(9, 0x92).unwrap();
        let removed = store.take_job(9).unwrap();
        assert_eq!(removed.job, 9);
        assert_eq!(removed.token, 0x9000);
        assert_eq!(removed.members, [0x91, 0x92]);
        assert!(!store.contains_job(9));
    }

    #[test]
    fn invalid_identity_and_masks_fail_closed() {
        let mut store = JobUiPolicyStore::new();
        assert_eq!(store.register_job(0, 1, 0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(store.register_job(1, 0, 0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            store.register_job(1, 1, 0x100),
            Err(STATUS_INVALID_PARAMETER)
        );
        store.register_job(1, 1, 0).unwrap();
        assert_eq!(
            store.set_restrictions(1, 0x100),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(store.add_process(99, 1), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn system_parameter_queries_remain_allowed() {
        assert!(is_system_parameter_write(0x0014));
        assert!(is_system_parameter_write(0x200F));
        assert!(is_system_parameter_write(0x2025));
        assert!(!is_system_parameter_write(0x0001));
        assert!(!is_system_parameter_write(0x0030));
        assert!(!is_system_parameter_write(0x2010));
    }
}
