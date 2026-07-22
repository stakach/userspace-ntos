//! Host-tested planning and dispatch for per-thread loader detach callouts.

use super::host::{DllReason, LoaderHost};

pub const LDRP_IMAGE_DLL: u32 = 0x0000_0004;
pub const LDRP_DONT_CALL_FOR_THREADS: u32 = 0x0004_0000;
pub const LDRP_PROCESS_ATTACH_CALLED: u32 = 0x0008_0000;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ThreadModuleState {
    pub base: u64,
    pub entry_point_rva: u32,
    pub flags: u32,
    pub has_tls: bool,
    pub is_ntdll: bool,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ThreadDetachAction {
    pub base: u64,
    pub entry_point_rva: u32,
    pub call_tls: bool,
}

pub type ThreadAttachAction = ThreadDetachAction;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ThreadPlanError {
    CapacityExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadDetachPlan<const N: usize> {
    actions: [ThreadDetachAction; N],
    len: usize,
    executable_tls_base: u64,
}

impl<const N: usize> ThreadDetachPlan<N> {
    pub const fn empty() -> Self {
        Self {
            actions: [ThreadDetachAction {
                base: 0,
                entry_point_rva: 0,
                call_tls: false,
            }; N],
            len: 0,
            executable_tls_base: 0,
        }
    }

    pub fn actions(&self) -> &[ThreadDetachAction] {
        &self.actions[..self.len]
    }

    pub const fn executable_tls_base(&self) -> u64 {
        self.executable_tls_base
    }
}

pub type ThreadAttachPlan<const N: usize> = ThreadDetachPlan<N>;

pub fn plan_thread_attach<const N: usize>(
    process_shutdown: bool,
    modules_in_initialization_order: &[ThreadModuleState],
    executable_tls_base: u64,
) -> Result<ThreadAttachPlan<N>, ThreadPlanError> {
    let mut plan = ThreadAttachPlan::empty();
    if process_shutdown {
        return Ok(plan);
    }
    plan.executable_tls_base = executable_tls_base;

    for module in modules_in_initialization_order {
        let required = LDRP_IMAGE_DLL | LDRP_PROCESS_ATTACH_CALLED;
        if module.base == 0
            || module.entry_point_rva == 0
            || module.is_ntdll
            || module.flags & required != required
            || module.flags & LDRP_DONT_CALL_FOR_THREADS != 0
        {
            continue;
        }
        if plan.len == N {
            return Err(ThreadPlanError::CapacityExceeded);
        }
        plan.actions[plan.len] = ThreadAttachAction {
            base: module.base,
            entry_point_rva: module.entry_point_rva,
            call_tls: module.has_tls,
        };
        plan.len += 1;
    }
    Ok(plan)
}

pub fn plan_thread_detach<const N: usize>(
    thread_init_committed: bool,
    process_shutdown: bool,
    modules_in_successful_attach_order: &[ThreadModuleState],
    executable_tls_base: u64,
) -> Result<ThreadDetachPlan<N>, ThreadPlanError> {
    let mut plan = ThreadDetachPlan::empty();
    if !thread_init_committed {
        return Ok(plan);
    }
    plan.executable_tls_base = executable_tls_base;
    if process_shutdown {
        return Ok(plan);
    }

    for module in modules_in_successful_attach_order.iter().rev() {
        let required = LDRP_IMAGE_DLL | LDRP_PROCESS_ATTACH_CALLED;
        if module.base == 0
            || module.entry_point_rva == 0
            || module.is_ntdll
            || module.flags & required != required
            || module.flags & LDRP_DONT_CALL_FOR_THREADS != 0
        {
            continue;
        }
        if plan.len == N {
            return Err(ThreadPlanError::CapacityExceeded);
        }
        plan.actions[plan.len] = ThreadDetachAction {
            base: module.base,
            entry_point_rva: module.entry_point_rva,
            call_tls: module.has_tls,
        };
        plan.len += 1;
    }
    Ok(plan)
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ThreadDetachReport {
    pub tls_calls: usize,
    pub dll_main_calls: usize,
}

pub fn drive_thread_detach<H: LoaderHost, const N: usize>(
    plan: &ThreadDetachPlan<N>,
    host: &mut H,
) -> ThreadDetachReport {
    let mut report = ThreadDetachReport::default();
    for action in plan.actions() {
        if action.call_tls {
            let _ = host.run_tls_callbacks(action.base, DllReason::ThreadDetach);
            report.tls_calls += 1;
        }
        let _ = host.call_dll_main(
            action.base,
            action.entry_point_rva,
            DllReason::ThreadDetach,
        );
        report.dll_main_calls += 1;
    }
    if plan.executable_tls_base() != 0 {
        let _ = host.run_tls_callbacks(plan.executable_tls_base(), DllReason::ThreadDetach);
        report.tls_calls += 1;
    }
    report
}

pub fn drive_thread_attach<H: LoaderHost, const N: usize>(
    plan: &ThreadAttachPlan<N>,
    host: &mut H,
) -> ThreadDetachReport {
    let mut report = ThreadDetachReport::default();
    for action in plan.actions() {
        if action.call_tls {
            let _ = host.run_tls_callbacks(action.base, DllReason::ThreadAttach);
            report.tls_calls += 1;
        }
        let _ = host.call_dll_main(
            action.base,
            action.entry_point_rva,
            DllReason::ThreadAttach,
        );
        report.dll_main_calls += 1;
    }
    if plan.executable_tls_base() != 0 {
        let _ = host.run_tls_callbacks(plan.executable_tls_base(), DllReason::ThreadAttach);
        report.tls_calls += 1;
    }
    report
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::loader::host::{LoaderHost, MapRequest};
    use crate::{NtStatus, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};
    use alloc::vec::Vec;

    fn module(base: u64) -> ThreadModuleState {
        ThreadModuleState {
            base,
            entry_point_rva: 0x100,
            flags: LDRP_IMAGE_DLL | LDRP_PROCESS_ATTACH_CALLED,
            has_tls: false,
            is_ntdll: false,
        }
    }

    #[test]
    fn uncommitted_thread_never_receives_detach_callouts() {
        let plan = plan_thread_detach::<1>(false, false, &[module(1)], 2).unwrap();
        assert!(plan.actions().is_empty());
        assert_eq!(plan.executable_tls_base(), 0);
    }

    #[test]
    fn detach_plan_reverses_attach_order_and_filters_ineligible_modules() {
        let mut no_entry = module(4);
        no_entry.entry_point_rva = 0;
        let mut disabled = module(5);
        disabled.flags |= LDRP_DONT_CALL_FOR_THREADS;
        let mut not_attached = module(6);
        not_attached.flags &= !LDRP_PROCESS_ATTACH_CALLED;
        let mut not_dll = module(7);
        not_dll.flags &= !LDRP_IMAGE_DLL;
        let mut ntdll = module(8);
        ntdll.is_ntdll = true;
        let mut tls = module(3);
        tls.has_tls = true;
        let modules = [module(1), module(2), tls, no_entry, disabled, not_attached, not_dll, ntdll];

        let plan = plan_thread_detach::<3>(true, false, &modules, 9).unwrap();
        assert_eq!(
            plan.actions(),
            &[
                ThreadDetachAction { base: 3, entry_point_rva: 0x100, call_tls: true },
                ThreadDetachAction { base: 2, entry_point_rva: 0x100, call_tls: false },
                ThreadDetachAction { base: 1, entry_point_rva: 0x100, call_tls: false },
            ]
        );
        assert_eq!(plan.executable_tls_base(), 9);
    }

    #[test]
    fn attach_plan_preserves_initialization_order_and_filters_ineligible_modules() {
        let mut no_entry = module(4);
        no_entry.entry_point_rva = 0;
        let mut disabled = module(5);
        disabled.flags |= LDRP_DONT_CALL_FOR_THREADS;
        let mut not_attached = module(6);
        not_attached.flags &= !LDRP_PROCESS_ATTACH_CALLED;
        let mut not_dll = module(7);
        not_dll.flags &= !LDRP_IMAGE_DLL;
        let mut ntdll = module(8);
        ntdll.is_ntdll = true;
        let mut tls = module(3);
        tls.has_tls = true;
        let modules = [module(1), module(2), tls, no_entry, disabled, not_attached, not_dll, ntdll];

        let plan = plan_thread_attach::<3>(false, &modules, 9).unwrap();
        assert_eq!(
            plan.actions(),
            &[
                ThreadAttachAction { base: 1, entry_point_rva: 0x100, call_tls: false },
                ThreadAttachAction { base: 2, entry_point_rva: 0x100, call_tls: false },
                ThreadAttachAction { base: 3, entry_point_rva: 0x100, call_tls: true },
            ]
        );
        assert_eq!(plan.executable_tls_base(), 9);
    }

    #[test]
    fn process_shutdown_suppresses_all_thread_attach_callouts() {
        let plan = plan_thread_attach::<1>(true, &[module(1)], 9).unwrap();
        assert!(plan.actions().is_empty());
        assert_eq!(plan.executable_tls_base(), 0);
    }

    #[test]
    fn attach_planning_reports_capacity_before_any_dispatch() {
        assert_eq!(
            plan_thread_attach::<1>(false, &[module(1), module(2)], 0),
            Err(ThreadPlanError::CapacityExceeded)
        );
    }

    #[test]
    fn process_shutdown_suppresses_dlls_but_keeps_executable_tls() {
        let plan = plan_thread_detach::<1>(true, true, &[module(1)], 9).unwrap();
        assert!(plan.actions().is_empty());
        assert_eq!(plan.executable_tls_base(), 9);
    }

    #[test]
    fn planning_reports_capacity_before_any_dispatch() {
        assert_eq!(
            plan_thread_detach::<1>(true, false, &[module(1), module(2)], 0),
            Err(ThreadPlanError::CapacityExceeded)
        );
    }

    #[derive(Default)]
    struct OrderHost {
        calls: Vec<(u8, u64)>,
    }

    impl LoaderHost for OrderHost {
        fn map_image(&mut self, _req: &MapRequest) -> NtStatus { STATUS_NOT_IMPLEMENTED }
        fn write_iat_slot(&mut self, _base: u64, _rva: u32, _value: u64) -> NtStatus {
            STATUS_NOT_IMPLEMENTED
        }
        fn call_dll_main(&mut self, base: u64, _rva: u32, _reason: DllReason) -> NtStatus {
            self.calls.push((2, base));
            STATUS_NOT_IMPLEMENTED
        }
        fn run_tls_callbacks(&mut self, base: u64, _reason: DllReason) -> NtStatus {
            self.calls.push((1, base));
            STATUS_NOT_IMPLEMENTED
        }
        fn commit_peb_teb(&mut self, _peb: u64, _teb: u64) -> NtStatus { STATUS_SUCCESS }
        fn transfer_to_entry(&mut self, _entry: u64, _peb: u64) -> NtStatus { STATUS_SUCCESS }
    }

    #[test]
    fn driver_runs_tls_before_dll_main_and_continues_after_errors() {
        let mut first = module(1);
        first.has_tls = true;
        let plan = plan_thread_detach::<2>(true, false, &[module(2), first], 9).unwrap();
        let mut host = OrderHost::default();
        assert_eq!(
            drive_thread_detach(&plan, &mut host),
            ThreadDetachReport { tls_calls: 2, dll_main_calls: 2 }
        );
        assert_eq!(host.calls, [(1, 1), (2, 1), (2, 2), (1, 9)]);
    }

    #[test]
    fn attach_driver_runs_forward_tls_before_dll_main_then_executable_tls() {
        let mut first = module(1);
        first.has_tls = true;
        let plan = plan_thread_attach::<2>(false, &[first, module(2)], 9).unwrap();
        let mut host = OrderHost::default();
        assert_eq!(
            drive_thread_attach(&plan, &mut host),
            ThreadDetachReport { tls_calls: 2, dll_main_calls: 2 }
        );
        assert_eq!(host.calls, [(1, 1), (2, 1), (2, 2), (1, 9)]);
    }
}
