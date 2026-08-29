//! NT job-object policy owned by the Process Manager.
//!
//! This module contains only architecture-neutral Ps state. Object namespace parsing, native
//! buffer marshalling, I/O completion delivery, and hosted-process mechanism teardown stay at the
//! executive boundary.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::{ProcessId, ProcessTimes, STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES};

pub type JobId = u32;

pub const STATUS_PROCESS_NOT_IN_JOB: u32 = 0x0000_0123;
pub const STATUS_PROCESS_IN_JOB: u32 = 0x0000_0124;
pub const STATUS_QUOTA_EXCEEDED: u32 = 0xC000_0044;

pub const JOB_OBJECT_ASSIGN_PROCESS: u32 = 0x0001;
pub const JOB_OBJECT_SET_ATTRIBUTES: u32 = 0x0002;
pub const JOB_OBJECT_QUERY: u32 = 0x0004;
pub const JOB_OBJECT_TERMINATE: u32 = 0x0008;
pub const JOB_OBJECT_SET_SECURITY_ATTRIBUTES: u32 = 0x0010;
pub const JOB_OBJECT_ALL_ACCESS: u32 = 0x001F_001F;

pub const JOB_OBJECT_LIMIT_WORKINGSET: u32 = 0x0000_0001;
pub const JOB_OBJECT_LIMIT_PROCESS_TIME: u32 = 0x0000_0002;
pub const JOB_OBJECT_LIMIT_JOB_TIME: u32 = 0x0000_0004;
pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
pub const JOB_OBJECT_LIMIT_AFFINITY: u32 = 0x0000_0010;
pub const JOB_OBJECT_LIMIT_PRIORITY_CLASS: u32 = 0x0000_0020;
pub const JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME: u32 = 0x0000_0040;
pub const JOB_OBJECT_LIMIT_SCHEDULING_CLASS: u32 = 0x0000_0080;
pub const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x0000_0100;
pub const JOB_OBJECT_LIMIT_JOB_MEMORY: u32 = 0x0000_0200;
pub const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x0000_0400;
pub const JOB_OBJECT_LIMIT_BREAKAWAY_OK: u32 = 0x0000_0800;
pub const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK: u32 = 0x0000_1000;
pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
pub const JOB_OBJECT_BASIC_LIMIT_VALID_FLAGS: u32 = 0x0000_00FF;
pub const JOB_OBJECT_EXTENDED_LIMIT_VALID_FLAGS: u32 = 0x0000_3FFF;

pub const JOB_OBJECT_UI_VALID_FLAGS: u32 = 0x0000_00FF;
pub const JOB_OBJECT_SECURITY_NO_ADMIN: u32 = 0x0000_0001;
pub const JOB_OBJECT_SECURITY_RESTRICTED_TOKEN: u32 = 0x0000_0002;
pub const JOB_OBJECT_SECURITY_ONLY_TOKEN: u32 = 0x0000_0004;
pub const JOB_OBJECT_SECURITY_FILTER_TOKENS: u32 = 0x0000_0008;
pub const JOB_OBJECT_SECURITY_VALID_FLAGS: u32 = 0x0000_000F;

pub const JOB_OBJECT_TERMINATE_AT_END_OF_JOB: u32 = 0;
pub const JOB_OBJECT_POST_AT_END_OF_JOB: u32 = 1;

pub const JOB_OBJECT_MSG_END_OF_JOB_TIME: u32 = 1;
pub const JOB_OBJECT_MSG_END_OF_PROCESS_TIME: u32 = 2;
pub const JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT: u32 = 3;
pub const JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
pub const JOB_OBJECT_MSG_NEW_PROCESS: u32 = 6;
pub const JOB_OBJECT_MSG_EXIT_PROCESS: u32 = 7;
pub const JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS: u32 = 8;

const MAXIMUM_SCHEDULING_CLASS: u32 = 9;

/// Expand generic job access bits using the NT job-object generic mapping.
pub fn map_job_access(desired: u32) -> u32 {
    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const STANDARD_RIGHTS_READ: u32 = READ_CONTROL;
    const STANDARD_RIGHTS_WRITE: u32 = READ_CONTROL;
    const STANDARD_RIGHTS_EXECUTE: u32 = READ_CONTROL;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

    let mut mapped =
        desired & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | MAXIMUM_ALLOWED);
    if desired & GENERIC_READ != 0 {
        mapped |= STANDARD_RIGHTS_READ | JOB_OBJECT_QUERY;
    }
    if desired & GENERIC_WRITE != 0 {
        mapped |= STANDARD_RIGHTS_WRITE
            | JOB_OBJECT_ASSIGN_PROCESS
            | JOB_OBJECT_SET_ATTRIBUTES
            | JOB_OBJECT_TERMINATE;
    }
    if desired & GENERIC_EXECUTE != 0 {
        mapped |= STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE;
    }
    if desired & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        mapped |= JOB_OBJECT_ALL_ACCESS;
    }
    mapped
        & (DELETE
            | READ_CONTROL
            | WRITE_DAC
            | WRITE_OWNER
            | SYNCHRONIZE
            | JOB_OBJECT_ASSIGN_PROCESS
            | JOB_OBJECT_SET_ATTRIBUTES
            | JOB_OBJECT_QUERY
            | JOB_OBJECT_TERMINATE
            | JOB_OBJECT_SET_SECURITY_ATTRIBUTES)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JobBasicLimits {
    pub per_process_user_time_limit: i64,
    pub per_job_user_time_limit: i64,
    pub limit_flags: u32,
    pub minimum_working_set_size: u64,
    pub maximum_working_set_size: u64,
    pub active_process_limit: u32,
    pub affinity: u64,
    pub priority_class: u32,
    pub scheduling_class: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoCounters {
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_count: u64,
    pub write_transfer_count: u64,
    pub other_transfer_count: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JobExtendedLimits {
    pub basic: JobBasicLimits,
    pub io: IoCounters,
    pub process_memory_limit: u64,
    pub job_memory_limit: u64,
    pub peak_process_memory_used: u64,
    pub peak_job_memory_used: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JobAccounting {
    pub total_user_time: i64,
    pub total_kernel_time: i64,
    pub this_period_total_user_time: i64,
    pub this_period_total_kernel_time: i64,
    pub total_page_fault_count: u32,
    pub total_processes: u32,
    pub active_processes: u32,
    pub total_terminated_processes: u32,
    pub io: IoCounters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionPortAssociation {
    pub port_id: u32,
    pub completion_key: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobNotification {
    pub job_id: JobId,
    pub association: CompletionPortAssociation,
    pub message: u32,
    pub process_id: ProcessId,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JobNotifications {
    entries: [Option<JobNotification>; 2],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JobTimeLimitActions {
    pub terminate_process: Option<ProcessId>,
    pub terminate_job: Option<JobId>,
}

impl JobNotifications {
    fn push(&mut self, notification: Option<JobNotification>) {
        let Some(notification) = notification else {
            return;
        };
        if let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(notification);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = JobNotification> + '_ {
        self.entries.iter().flatten().copied()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JobCloseAction {
    pub kill_active_processes: bool,
    pub destroyed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobDestruction {
    pub id: JobId,
    pub released_completion_port: Option<CompletionPortAssociation>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JobAssignment {
    pub status: u32,
    pub notification: Option<JobNotification>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct JobMember {
    process_id: ProcessId,
    active: bool,
    accounting_folded: bool,
    forced_termination: bool,
    process_time_limit_reached: bool,
}

#[derive(Debug)]
struct Job {
    id: JobId,
    session_id: u32,
    handle_count: u32,
    wait_references: u32,
    close_done: bool,
    signaled: bool,
    basic_limits: JobBasicLimits,
    extended_limits: JobExtendedLimits,
    accounting: JobAccounting,
    ui_restrictions: u32,
    security_limits: u32,
    end_of_job_time_action: u32,
    period_start_total_user_time: i64,
    period_start_total_kernel_time: i64,
    job_time_limit_reached: bool,
    completion_port: Option<CompletionPortAssociation>,
    member_level: u32,
    set_head: Option<JobId>,
    set_next: Option<JobId>,
    set_pin_references: u32,
    members: Vec<JobMember>,
}

impl Job {
    fn notification(&self, message: u32, process_id: ProcessId) -> Option<JobNotification> {
        self.completion_port.map(|association| JobNotification {
            job_id: self.id,
            association,
            message,
            process_id,
        })
    }

    fn has_process_reference(&self) -> bool {
        !self.members.is_empty()
    }

    fn can_destroy(&self) -> bool {
        self.handle_count == 0
            && self.wait_references == 0
            && self.set_pin_references == 0
            && !self.has_process_reference()
    }
}

#[derive(Default)]
pub struct JobStore {
    jobs: Vec<Option<Job>>,
    pending_notifications: VecDeque<JobNotification>,
    destructions: Vec<Option<JobDestruction>>,
}

impl JobStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(id: JobId) -> Option<usize> {
        id.checked_sub(1).map(|id| id as usize)
    }

    fn get(&self, id: JobId) -> Option<&Job> {
        self.jobs.get(Self::slot(id)?)?.as_ref()
    }

    fn get_mut(&mut self, id: JobId) -> Option<&mut Job> {
        self.jobs.get_mut(Self::slot(id)?)?.as_mut()
    }

    pub fn contains(&self, id: JobId) -> bool {
        self.get(id).is_some()
    }

    pub fn queue_notifications(&mut self, notifications: JobNotifications) {
        self.pending_notifications.extend(notifications.iter());
    }

    pub fn queue_notification(&mut self, notification: Option<JobNotification>) {
        self.pending_notifications.extend(notification);
    }

    pub fn take_notification(&mut self) -> Option<JobNotification> {
        self.pending_notifications.pop_front()
    }

    pub fn take_destruction(&mut self) -> Option<JobDestruction> {
        let slot = self.destructions.iter().position(Option::is_some)?;
        self.destructions[slot].take()
    }

    fn destroy_cascade(&mut self, mut id: JobId) {
        loop {
            let Some(slot) = Self::slot(id) else {
                return;
            };
            let can_destroy = self
                .jobs
                .get(slot)
                .and_then(Option::as_ref)
                .is_some_and(Job::can_destroy);
            if !can_destroy {
                return;
            }
            let Some(job) = self.jobs[slot].take() else {
                return;
            };
            let next = job.set_next;
            self.destructions[slot] = Some(JobDestruction {
                id: job.id,
                released_completion_port: job.completion_port,
            });

            let Some(next_id) = next else {
                return;
            };
            let Some(next_job) = self.get_mut(next_id) else {
                return;
            };
            next_job.set_pin_references = next_job.set_pin_references.saturating_sub(1);

            // The next object inherits the set pin. Refresh the head identity used by level
            // selection before deciding whether this unreferenced object also deletes.
            let mut cursor = Some(next_id);
            while let Some(member_id) = cursor {
                let Some(member) = self.get_mut(member_id) else {
                    break;
                };
                member.set_head = Some(next_id);
                cursor = member.set_next;
            }
            id = next_id;
        }
    }

    pub fn create(&mut self, session_id: u32) -> Result<JobId, u32> {
        self.jobs
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.destructions
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.jobs.push(None);
        self.destructions.push(None);
        let slot = self.jobs.len() - 1;
        let id = u32::try_from(slot + 1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.jobs[slot] = Some(Job {
            id,
            session_id,
            handle_count: 0,
            wait_references: 0,
            close_done: false,
            signaled: false,
            basic_limits: JobBasicLimits {
                scheduling_class: 5,
                ..JobBasicLimits::default()
            },
            extended_limits: JobExtendedLimits::default(),
            accounting: JobAccounting::default(),
            ui_restrictions: 0,
            security_limits: 0,
            end_of_job_time_action: JOB_OBJECT_TERMINATE_AT_END_OF_JOB,
            period_start_total_user_time: 0,
            period_start_total_kernel_time: 0,
            job_time_limit_reached: false,
            completion_port: None,
            member_level: 0,
            set_head: None,
            set_next: None,
            set_pin_references: 0,
            members: Vec::new(),
        });
        Ok(id)
    }

    pub fn discard_unreferenced(&mut self, id: JobId) -> bool {
        let Some(slot) = Self::slot(id) else {
            return false;
        };
        let destroy = self
            .jobs
            .get(slot)
            .and_then(Option::as_ref)
            .is_some_and(Job::can_destroy);
        if destroy {
            self.destroy_cascade(id);
        }
        destroy
    }

    pub fn retain_handle(&mut self, id: JobId) -> Result<(), u32> {
        let job = self.get_mut(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        job.handle_count = job
            .handle_count
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    pub fn release_handle(&mut self, id: JobId) -> Result<JobCloseAction, u32> {
        let slot = Self::slot(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        let job = self
            .jobs
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(crate::STATUS_INVALID_HANDLE)?;
        job.handle_count = job
            .handle_count
            .checked_sub(1)
            .ok_or(crate::STATUS_INVALID_PARAMETER)?;
        if job.handle_count != 0 {
            return Ok(JobCloseAction::default());
        }
        job.close_done = true;
        let kill_active_processes =
            job.basic_limits.limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0;
        let destroyed = job.can_destroy();
        let action = JobCloseAction {
            kill_active_processes,
            destroyed,
        };
        if destroyed {
            self.destroy_cascade(id);
        }
        Ok(action)
    }

    pub fn retain_wait(&mut self, id: JobId) -> Result<(), u32> {
        let job = self.get_mut(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        job.wait_references = job
            .wait_references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    pub fn release_wait(&mut self, id: JobId) -> Result<bool, u32> {
        let slot = Self::slot(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        let job = self
            .jobs
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(crate::STATUS_INVALID_HANDLE)?;
        job.wait_references = job
            .wait_references
            .checked_sub(1)
            .ok_or(crate::STATUS_INVALID_PARAMETER)?;
        let destroyed = job.can_destroy();
        if destroyed {
            self.destroy_cascade(id);
        }
        Ok(destroyed)
    }

    pub fn is_signaled(&self, id: JobId) -> bool {
        self.get(id).is_some_and(|job| job.signaled)
    }

    pub fn job_for_process(&self, process_id: ProcessId) -> Option<JobId> {
        self.jobs.iter().flatten().find_map(|job| {
            job.members
                .iter()
                .any(|member| member.process_id == process_id)
                .then_some(job.id)
        })
    }

    pub fn assign(
        &mut self,
        id: JobId,
        process_id: ProcessId,
        process_session_id: u32,
    ) -> Result<JobAssignment, u32> {
        if self.job_for_process(process_id).is_some() {
            return Err(STATUS_ACCESS_DENIED);
        }
        let job = self.get_mut(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        if job.session_id != process_session_id {
            return Err(STATUS_ACCESS_DENIED);
        }
        if job.close_done && job.basic_limits.limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0
        {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        job.members
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        job.members.push(JobMember {
            process_id,
            active: true,
            accounting_folded: false,
            forced_termination: false,
            process_time_limit_reached: false,
        });
        job.accounting.total_processes = job.accounting.total_processes.saturating_add(1);
        job.accounting.active_processes = job.accounting.active_processes.saturating_add(1);
        let over_limit = job.basic_limits.limit_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0
            && job.accounting.active_processes > job.basic_limits.active_process_limit;
        if over_limit {
            let member = job.members.last_mut().expect("just inserted job member");
            member.active = false;
            member.forced_termination = true;
            job.accounting.active_processes -= 1;
            return Ok(JobAssignment {
                status: STATUS_QUOTA_EXCEEDED,
                notification: job.notification(JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT, 0),
            });
        }
        Ok(JobAssignment {
            status: 0,
            notification: job.notification(JOB_OBJECT_MSG_NEW_PROCESS, process_id),
        })
    }

    pub fn exit_process(
        &mut self,
        process_id: ProcessId,
        times: ProcessTimes,
        exit_status: u32,
    ) -> JobNotifications {
        let Some(id) = self.job_for_process(process_id) else {
            return JobNotifications::default();
        };
        let Some(job) = self.get_mut(id) else {
            return JobNotifications::default();
        };
        let Some(member) = job
            .members
            .iter_mut()
            .find(|member| member.process_id == process_id)
        else {
            return JobNotifications::default();
        };
        if member.accounting_folded {
            return JobNotifications::default();
        }
        let was_active = member.active;
        member.active = false;
        member.accounting_folded = true;
        let forced_termination = member.forced_termination;
        if was_active {
            job.accounting.active_processes = job.accounting.active_processes.saturating_sub(1);
        }
        if forced_termination {
            job.accounting.total_terminated_processes =
                job.accounting.total_terminated_processes.saturating_add(1);
        }
        job.accounting.total_user_time = job
            .accounting
            .total_user_time
            .saturating_add(times.user_time);
        job.accounting.total_kernel_time = job
            .accounting
            .total_kernel_time
            .saturating_add(times.kernel_time);
        job.accounting.this_period_total_user_time = job
            .accounting
            .this_period_total_user_time
            .saturating_add(times.user_time);
        job.accounting.this_period_total_kernel_time = job
            .accounting
            .this_period_total_kernel_time
            .saturating_add(times.kernel_time);

        if !was_active {
            return JobNotifications::default();
        }

        let mut notifications = JobNotifications::default();
        notifications.push(job.notification(
            if exit_status == 0 {
                JOB_OBJECT_MSG_EXIT_PROCESS
            } else {
                JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS
            },
            process_id,
        ));
        if job.accounting.active_processes == 0 {
            job.signaled = true;
            notifications.push(job.notification(JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, 0));
        }
        notifications
    }

    pub fn mark_process_forced_termination(&mut self, process_id: ProcessId) -> Result<(), u32> {
        let id = self
            .job_for_process(process_id)
            .ok_or(crate::STATUS_INVALID_HANDLE)?;
        let job = self.get_mut(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        let member = job
            .members
            .iter_mut()
            .find(|member| member.process_id == process_id)
            .ok_or(crate::STATUS_INVALID_HANDLE)?;
        member.forced_termination = true;
        Ok(())
    }

    pub fn remove_process_reference(&mut self, process_id: ProcessId) -> Option<JobId> {
        let id = self.job_for_process(process_id)?;
        let slot = Self::slot(id)?;
        let job = self.jobs.get_mut(slot)?.as_mut()?;
        let member = job
            .members
            .iter()
            .position(|member| member.process_id == process_id)?;
        if job.members[member].active {
            job.accounting.active_processes = job.accounting.active_processes.saturating_sub(1);
        }
        job.members.remove(member);
        if job.can_destroy() {
            self.destroy_cascade(id);
        }
        Some(id)
    }

    pub fn active_process_ids_owned(&self, id: JobId) -> Result<Vec<ProcessId>, u32> {
        let job = self.get(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        let count = job.members.iter().filter(|member| member.active).count();
        let mut process_ids = Vec::new();
        process_ids
            .try_reserve_exact(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        process_ids.extend(
            job.members
                .iter()
                .filter(|member| member.active)
                .map(|member| member.process_id),
        );
        Ok(process_ids)
    }

    pub fn process_ids_owned(&self, id: JobId) -> Result<(u32, Vec<ProcessId>), u32> {
        let job = self.get(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        let assigned = job.accounting.active_processes;
        let process_ids = self.active_process_ids_owned(id)?;
        Ok((assigned, process_ids))
    }

    pub fn accounting(&self, id: JobId) -> Result<JobAccounting, u32> {
        self.get(id)
            .map(|job| job.accounting)
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    pub fn time_period_start(&self, id: JobId) -> Result<(i64, i64), u32> {
        self.get(id)
            .map(|job| {
                (
                    job.period_start_total_user_time,
                    job.period_start_total_kernel_time,
                )
            })
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    pub fn has_time_limits(&self) -> bool {
        self.jobs.iter().flatten().any(|job| {
            job.basic_limits.limit_flags
                & (JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_JOB_TIME)
                != 0
                && job.accounting.active_processes != 0
        })
    }

    pub fn basic_limits(&self, id: JobId) -> Result<JobBasicLimits, u32> {
        self.get(id)
            .map(|job| job.basic_limits)
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    pub fn extended_limits(&self, id: JobId) -> Result<JobExtendedLimits, u32> {
        self.get(id)
            .map(|job| {
                let mut limits = job.extended_limits;
                limits.basic = job.basic_limits;
                limits
            })
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    pub fn set_basic_limits(&mut self, id: JobId, limits: JobBasicLimits) -> Result<(), u32> {
        let accounting = self.accounting(id)?;
        self.set_basic_limits_at(
            id,
            limits,
            accounting.total_user_time,
            accounting.total_kernel_time,
        )
    }

    pub fn set_basic_limits_at(
        &mut self,
        id: JobId,
        mut limits: JobBasicLimits,
        total_user_time: i64,
        total_kernel_time: i64,
    ) -> Result<(), u32> {
        if limits.limit_flags & !JOB_OBJECT_BASIC_LIMIT_VALID_FLAGS != 0 {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        Self::validate_limits(&limits)?;
        if limits.limit_flags & JOB_OBJECT_LIMIT_SCHEDULING_CLASS == 0 {
            limits.scheduling_class = 5;
        }
        let job = self.get_mut(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        let previous_job_time_enabled =
            job.basic_limits.limit_flags & JOB_OBJECT_LIMIT_JOB_TIME != 0;
        let previous_job_time = job.basic_limits.per_job_user_time_limit;
        let previous_period_user = job.accounting.this_period_total_user_time;
        let previous_period_kernel = job.accounting.this_period_total_kernel_time;
        let set_job_time = limits.limit_flags & JOB_OBJECT_LIMIT_JOB_TIME != 0;
        let preserve_job_time = limits.limit_flags & JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME != 0;
        limits.limit_flags &= !JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME;
        job.basic_limits = limits;
        if set_job_time {
            job.accounting.this_period_total_user_time = 0;
            job.accounting.this_period_total_kernel_time = 0;
            job.period_start_total_user_time = total_user_time;
            job.period_start_total_kernel_time = total_kernel_time;
            job.job_time_limit_reached = false;
            job.signaled = false;
        } else if preserve_job_time && previous_job_time_enabled {
            job.basic_limits.limit_flags |= JOB_OBJECT_LIMIT_JOB_TIME;
            job.basic_limits.per_job_user_time_limit = previous_job_time;
            job.accounting.this_period_total_user_time = previous_period_user;
            job.accounting.this_period_total_kernel_time = previous_period_kernel;
        }
        for member in job.members.iter_mut().filter(|member| member.active) {
            member.process_time_limit_reached = false;
        }
        job.extended_limits.basic = job.basic_limits;
        Ok(())
    }

    pub fn set_extended_limits(&mut self, id: JobId, limits: JobExtendedLimits) -> Result<(), u32> {
        let accounting = self.accounting(id)?;
        self.set_extended_limits_at(
            id,
            limits,
            accounting.total_user_time,
            accounting.total_kernel_time,
        )
    }

    pub fn set_extended_limits_at(
        &mut self,
        id: JobId,
        mut limits: JobExtendedLimits,
        total_user_time: i64,
        total_kernel_time: i64,
    ) -> Result<(), u32> {
        if limits.basic.limit_flags & !JOB_OBJECT_EXTENDED_LIMIT_VALID_FLAGS != 0 {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        Self::validate_limits(&limits.basic)?;
        if limits.basic.limit_flags & JOB_OBJECT_LIMIT_SCHEDULING_CLASS == 0 {
            limits.basic.scheduling_class = 5;
        }
        let job = self.get_mut(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        let previous_job_time_enabled =
            job.basic_limits.limit_flags & JOB_OBJECT_LIMIT_JOB_TIME != 0;
        let previous_job_time = job.basic_limits.per_job_user_time_limit;
        let previous_period_user = job.accounting.this_period_total_user_time;
        let previous_period_kernel = job.accounting.this_period_total_kernel_time;
        let set_job_time = limits.basic.limit_flags & JOB_OBJECT_LIMIT_JOB_TIME != 0;
        let preserve_job_time = limits.basic.limit_flags & JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME != 0;
        limits.basic.limit_flags &= !JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME;
        job.basic_limits = limits.basic;
        job.extended_limits = limits;
        if set_job_time {
            job.accounting.this_period_total_user_time = 0;
            job.accounting.this_period_total_kernel_time = 0;
            job.period_start_total_user_time = total_user_time;
            job.period_start_total_kernel_time = total_kernel_time;
            job.job_time_limit_reached = false;
            job.signaled = false;
        } else if preserve_job_time && previous_job_time_enabled {
            job.basic_limits.limit_flags |= JOB_OBJECT_LIMIT_JOB_TIME;
            job.basic_limits.per_job_user_time_limit = previous_job_time;
            job.extended_limits.basic = job.basic_limits;
            job.accounting.this_period_total_user_time = previous_period_user;
            job.accounting.this_period_total_kernel_time = previous_period_kernel;
        }
        for member in job.members.iter_mut().filter(|member| member.active) {
            member.process_time_limit_reached = false;
        }
        Ok(())
    }

    fn validate_limits(limits: &JobBasicLimits) -> Result<(), u32> {
        if limits.limit_flags & JOB_OBJECT_LIMIT_PROCESS_TIME != 0
            && limits.per_process_user_time_limit <= 0
        {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        if limits.limit_flags & JOB_OBJECT_LIMIT_JOB_TIME != 0
            && limits.per_job_user_time_limit <= 0
        {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        if limits.limit_flags & JOB_OBJECT_LIMIT_WORKINGSET != 0
            && (limits.minimum_working_set_size == 0
                || limits.maximum_working_set_size == 0
                || limits.minimum_working_set_size > limits.maximum_working_set_size)
        {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        if limits.limit_flags & JOB_OBJECT_LIMIT_AFFINITY != 0 && limits.affinity == 0 {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        if limits.limit_flags & JOB_OBJECT_LIMIT_PRIORITY_CLASS != 0
            && !(1..=6).contains(&limits.priority_class)
        {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        if limits.limit_flags & JOB_OBJECT_LIMIT_SCHEDULING_CLASS != 0
            && limits.scheduling_class >= MAXIMUM_SCHEDULING_CLASS
        {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        if limits.limit_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS != 0
            && limits.active_process_limit == 0
        {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    pub fn evaluate_time_limits(
        &mut self,
        id: JobId,
        process_id: ProcessId,
        process_user_time: i64,
        this_period_job_user_time: i64,
    ) -> Result<JobTimeLimitActions, u32> {
        let mut process_notification = None;
        let mut job_notification = None;
        let actions = {
            let job = self.get_mut(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
            let member_index = job
                .members
                .iter()
                .position(|member| member.process_id == process_id && member.active)
                .ok_or(crate::STATUS_INVALID_HANDLE)?;
            let job_limit_reached = job.basic_limits.limit_flags & JOB_OBJECT_LIMIT_JOB_TIME != 0
                && !job.job_time_limit_reached
                && this_period_job_user_time > job.basic_limits.per_job_user_time_limit;
            let mut actions = JobTimeLimitActions::default();
            if job_limit_reached {
                job.job_time_limit_reached = true;
                job_notification = job.notification(JOB_OBJECT_MSG_END_OF_JOB_TIME, 0);
                if job.end_of_job_time_action == JOB_OBJECT_TERMINATE_AT_END_OF_JOB
                    || job.completion_port.is_none()
                {
                    for member in job.members.iter_mut().filter(|member| member.active) {
                        member.forced_termination = true;
                    }
                    actions.terminate_job = Some(id);
                }
            }
            let process_limit_reached =
                job.basic_limits.limit_flags & JOB_OBJECT_LIMIT_PROCESS_TIME != 0
                    && !job.members[member_index].process_time_limit_reached
                    && process_user_time > job.basic_limits.per_process_user_time_limit;
            if process_limit_reached {
                let member = &mut job.members[member_index];
                member.process_time_limit_reached = true;
                member.forced_termination = true;
                process_notification =
                    job.notification(JOB_OBJECT_MSG_END_OF_PROCESS_TIME, process_id);
                if actions.terminate_job.is_none() {
                    actions.terminate_process = Some(process_id);
                }
            }
            actions
        };
        self.queue_notification(process_notification);
        self.queue_notification(job_notification);
        Ok(actions)
    }

    pub fn complete_job_time_notification(
        &mut self,
        id: JobId,
        delivered: bool,
    ) -> Result<bool, u32> {
        let job = self.get_mut(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        if job.end_of_job_time_action != JOB_OBJECT_POST_AT_END_OF_JOB
            || job.basic_limits.limit_flags & JOB_OBJECT_LIMIT_JOB_TIME == 0
            || !job.job_time_limit_reached
        {
            return Ok(false);
        }
        if delivered {
            job.basic_limits.limit_flags &= !JOB_OBJECT_LIMIT_JOB_TIME;
            job.basic_limits.per_job_user_time_limit = 0;
            job.extended_limits.basic = job.basic_limits;
        } else {
            job.job_time_limit_reached = false;
        }
        Ok(delivered)
    }

    pub fn ui_restrictions(&self, id: JobId) -> Result<u32, u32> {
        self.get(id)
            .map(|job| job.ui_restrictions)
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    pub fn set_ui_restrictions(&mut self, id: JobId, restrictions: u32) -> Result<(), u32> {
        if restrictions & !JOB_OBJECT_UI_VALID_FLAGS != 0 {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        self.get_mut(id)
            .ok_or(crate::STATUS_INVALID_HANDLE)?
            .ui_restrictions = restrictions;
        Ok(())
    }

    pub fn security_limits(&self, id: JobId) -> Result<u32, u32> {
        self.get(id)
            .map(|job| job.security_limits)
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    pub fn set_security_limits(&mut self, id: JobId, limits: u32) -> Result<(), u32> {
        if limits & !JOB_OBJECT_SECURITY_VALID_FLAGS != 0 {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        self.get_mut(id)
            .ok_or(crate::STATUS_INVALID_HANDLE)?
            .security_limits = limits;
        Ok(())
    }

    pub fn end_of_job_time_action(&self, id: JobId) -> Result<u32, u32> {
        self.get(id)
            .map(|job| job.end_of_job_time_action)
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    pub fn set_end_of_job_time_action(&mut self, id: JobId, action: u32) -> Result<(), u32> {
        if action > JOB_OBJECT_POST_AT_END_OF_JOB {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        self.get_mut(id)
            .ok_or(crate::STATUS_INVALID_HANDLE)?
            .end_of_job_time_action = action;
        Ok(())
    }

    pub fn completion_port(&self, id: JobId) -> Result<Option<CompletionPortAssociation>, u32> {
        self.get(id)
            .map(|job| job.completion_port)
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    pub fn associate_completion_port(
        &mut self,
        id: JobId,
        association: CompletionPortAssociation,
    ) -> Result<(), u32> {
        let job = self.get_mut(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
        if association.port_id == 0 || job.completion_port.is_some() || job.close_done {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        job.completion_port = Some(association);
        Ok(())
    }

    pub fn member_level(&self, id: JobId) -> Result<u32, u32> {
        self.get(id)
            .map(|job| job.member_level)
            .ok_or(crate::STATUS_INVALID_HANDLE)
    }

    pub fn create_set(&mut self, members: &[(JobId, u32)]) -> Result<(), u32> {
        if members.len() <= 1 {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        let mut previous_level = 0;
        for (index, &(id, level)) in members.iter().enumerate() {
            let job = self.get(id).ok_or(crate::STATUS_INVALID_HANDLE)?;
            if level <= previous_level || job.member_level != 0 {
                return Err(crate::STATUS_INVALID_PARAMETER);
            }
            if members[..index].iter().any(|(other, _)| *other == id) {
                return Err(crate::STATUS_INVALID_PARAMETER);
            }
            previous_level = level;
        }
        let head = members[0].0;
        for (index, &(id, level)) in members.iter().enumerate() {
            let job = self.get_mut(id).expect("validated job set member");
            job.member_level = level;
            job.set_head = Some(head);
            job.set_next = members.get(index + 1).map(|entry| entry.0);
            if index != 0 {
                job.set_pin_references += 1;
            }
        }
        Ok(())
    }

    pub fn select_from_set(&self, parent: JobId, requested_level: u32) -> Result<JobId, u32> {
        if requested_level == 0 {
            return self
                .contains(parent)
                .then_some(parent)
                .ok_or(crate::STATUS_INVALID_HANDLE);
        }
        let parent_job = self.get(parent).ok_or(crate::STATUS_INVALID_HANDLE)?;
        if parent_job.member_level == 0 || parent_job.member_level > requested_level {
            return Err(STATUS_ACCESS_DENIED);
        }
        let head = parent_job.set_head.ok_or(STATUS_ACCESS_DENIED)?;
        self.jobs
            .iter()
            .flatten()
            .find(|job| {
                job.id != parent
                    && job.set_head == Some(head)
                    && job.member_level == requested_level
            })
            .map(|job| job.id)
            .ok_or(STATUS_ACCESS_DENIED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_times(user_time: i64, kernel_time: i64) -> ProcessTimes {
        ProcessTimes {
            create_time: 0,
            exit_time: 0,
            kernel_time,
            user_time,
        }
    }

    #[test]
    fn one_job_membership_session_and_accounting_are_exact() {
        let mut jobs = JobStore::new();
        let first = jobs.create(3).unwrap();
        let other = jobs.create(3).unwrap();
        assert_eq!(jobs.assign(first, 40, 4), Err(STATUS_ACCESS_DENIED));
        assert_eq!(jobs.assign(first, 40, 3).unwrap().status, 0);
        assert_eq!(jobs.assign(other, 40, 3), Err(STATUS_ACCESS_DENIED));
        assert_eq!(jobs.job_for_process(40), Some(first));
        let notices = jobs.exit_process(40, zero_times(12, 7), 5);
        assert_eq!(notices.iter().count(), 0);
        let accounting = jobs.accounting(first).unwrap();
        assert_eq!(accounting.total_processes, 1);
        assert_eq!(accounting.active_processes, 0);
        assert_eq!(
            (accounting.total_user_time, accounting.total_kernel_time),
            (12, 7)
        );
        assert!(jobs
            .exit_process(40, zero_times(99, 99), 0)
            .iter()
            .next()
            .is_none());
    }

    #[test]
    fn active_limit_keeps_membership_and_requests_termination() {
        let mut jobs = JobStore::new();
        let job = jobs.create(0).unwrap();
        jobs.set_basic_limits(
            job,
            JobBasicLimits {
                limit_flags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                active_process_limit: 1,
                scheduling_class: 5,
                ..JobBasicLimits::default()
            },
        )
        .unwrap();
        assert_eq!(jobs.assign(job, 4, 0).unwrap().status, 0);
        assert_eq!(
            jobs.assign(job, 8, 0).unwrap().status,
            STATUS_QUOTA_EXCEEDED
        );
        assert_eq!(jobs.job_for_process(8), Some(job));
        assert_eq!(jobs.accounting(job).unwrap().active_processes, 1);
        assert!(jobs
            .exit_process(8, zero_times(3, 2), STATUS_QUOTA_EXCEEDED)
            .iter()
            .next()
            .is_none());
        let accounting = jobs.accounting(job).unwrap();
        assert_eq!(accounting.total_terminated_processes, 1);
        assert_eq!(
            (accounting.total_user_time, accounting.total_kernel_time),
            (3, 2)
        );
    }

    #[test]
    fn completion_messages_and_last_handle_close_follow_job_lifetime() {
        let mut jobs = JobStore::new();
        let job = jobs.create(0).unwrap();
        jobs.retain_handle(job).unwrap();
        let association = CompletionPortAssociation {
            port_id: 7,
            completion_key: 0xCAFE,
        };
        jobs.associate_completion_port(job, association).unwrap();
        let assignment = jobs.assign(job, 44, 0).unwrap();
        assert_eq!(
            assignment.notification.unwrap().message,
            JOB_OBJECT_MSG_NEW_PROCESS
        );
        let notices = jobs.exit_process(44, zero_times(0, 0), 0);
        let messages: Vec<_> = notices.iter().map(|notice| notice.message).collect();
        assert_eq!(
            messages,
            [
                JOB_OBJECT_MSG_EXIT_PROCESS,
                JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO
            ]
        );
        let close = jobs.release_handle(job).unwrap();
        assert!(!close.destroyed);
        assert!(jobs.contains(job));
        assert_eq!(jobs.remove_process_reference(44), Some(job));
        assert!(!jobs.contains(job));
        assert_eq!(
            jobs.take_destruction(),
            Some(JobDestruction {
                id: job,
                released_completion_port: Some(association),
            })
        );
    }

    #[test]
    fn kill_on_close_and_wait_references_delay_destruction() {
        let mut jobs = JobStore::new();
        let job = jobs.create(0).unwrap();
        jobs.set_extended_limits(
            job,
            JobExtendedLimits {
                basic: JobBasicLimits {
                    limit_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    scheduling_class: 5,
                    ..JobBasicLimits::default()
                },
                ..JobExtendedLimits::default()
            },
        )
        .unwrap();
        jobs.retain_handle(job).unwrap();
        jobs.retain_wait(job).unwrap();
        assert!(!jobs.release_handle(job).unwrap().destroyed);
        assert!(jobs.release_wait(job).unwrap());
        assert!(!jobs.contains(job));

        let job = jobs.create(0).unwrap();
        jobs.set_extended_limits(
            job,
            JobExtendedLimits {
                basic: JobBasicLimits {
                    limit_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    scheduling_class: 5,
                    ..JobBasicLimits::default()
                },
                ..JobExtendedLimits::default()
            },
        )
        .unwrap();
        jobs.retain_handle(job).unwrap();
        jobs.assign(job, 12, 0).unwrap();
        assert!(jobs.release_handle(job).unwrap().kill_active_processes);
    }

    #[test]
    fn limits_validate_and_job_sets_select_exact_levels() {
        let mut jobs = JobStore::new();
        let first = jobs.create(0).unwrap();
        let second = jobs.create(0).unwrap();
        assert_eq!(
            jobs.set_basic_limits(
                first,
                JobBasicLimits {
                    limit_flags: JOB_OBJECT_LIMIT_AFFINITY,
                    scheduling_class: 5,
                    ..JobBasicLimits::default()
                }
            ),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
        jobs.create_set(&[(first, 1), (second, 3)]).unwrap();
        assert_eq!(jobs.select_from_set(first, 0), Ok(first));
        assert_eq!(jobs.select_from_set(first, 3), Ok(second));
        assert_eq!(jobs.select_from_set(second, 1), Err(STATUS_ACCESS_DENIED));
        assert_eq!(
            jobs.create_set(&[(first, 4), (second, 5)]),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn job_set_pins_pass_forward_during_ordered_deletion() {
        let mut jobs = JobStore::new();
        let first = jobs.create(0).unwrap();
        let second = jobs.create(0).unwrap();
        jobs.retain_handle(first).unwrap();
        jobs.retain_handle(second).unwrap();
        jobs.create_set(&[(first, 1), (second, 3)]).unwrap();

        assert!(!jobs.release_handle(second).unwrap().destroyed);
        assert!(jobs.contains(second));
        assert!(jobs.release_handle(first).unwrap().destroyed);
        assert!(!jobs.contains(first));
        assert!(!jobs.contains(second));
        assert_eq!(jobs.take_destruction().unwrap().id, first);
        assert_eq!(jobs.take_destruction().unwrap().id, second);
        assert_eq!(jobs.take_destruction(), None);
    }
}
