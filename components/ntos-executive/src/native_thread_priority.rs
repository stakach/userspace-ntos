//! Exact native TCB priority effects for win32k Ps/Ke requests.

use super::*;
use nt_user_host::thread_priority_transition::{
    PriorityEffect, PriorityTransitionOutcome, PriorityTransitionOwner,
};

const STATUS_DEVICE_NOT_READY: u32 = 0xc000_00a3;

pub(crate) enum PendingPlan {
    ByClass(nt_process::ProcessPriorityByClassPlan),
    Thread(nt_process::KernelThreadPriorityPlan),
}

pub(crate) type NativePriorityOwner = PriorityTransitionOwner<PendingPlan, HostedThreadRole>;

/// A new hosted user TCB starts at the same priority as its canonical ETHREAD projection.
pub(super) fn initial_priority(pm: &nt_process::ProcessManager, tid: u64) -> Result<u8, u32> {
    let tid = u32::try_from(tid).map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
    let nt_priority = pm.thread_scheduling_state(tid)?.priority;
    let physical = nt_user_host::hosted_priority::hosted_tcb_priority(nt_priority)?;
    Ok(physical)
}

fn value<'a>(snapshot: &'a nt_config_client::HiveKeySnapshot, name: &str, value_type: u32) -> Option<&'a [u8]> {
    snapshot.values.iter().find(|value| value.name.eq_ignore_ascii_case(name))
        .filter(|value| value.value_type == value_type)
        .map(|value| value.data.as_slice())
}

fn product_type_is(raw: &[u8], expected: &str) -> bool {
    if raw.len() % 2 != 0 { return false; }
    let mut units = raw.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    for expected_byte in expected.bytes() {
        let Some(actual) = units.next() else { return false; };
        if actual > 0x7f || !u8::try_from(actual).is_ok_and(|ch| ch.eq_ignore_ascii_case(&expected_byte)) {
            return false;
        }
    }
    units.all(|unit| unit == 0)
}

/// Read the mounted SYSTEM authority before borrowing PM or any runtime owner. A missing or
/// malformed value is visible; neither the policy nor the product type is guessed.
unsafe fn live_quantum_policy() -> Result<nt_process::ProcessPriorityQuantumPolicy, u32> {
    let control = config_manager_query_system_hive_key(
        r"\Registry\Machine\System\CurrentControlSet\Control\PriorityControl",
    ).map_err(|status| status as u32)?;
    let product = config_manager_query_system_hive_key(
        r"\Registry\Machine\System\CurrentControlSet\Control\ProductOptions",
    ).map_err(|status| status as u32)?;
    if control.mount_generation != product.mount_generation {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    let raw = value(&control, "Win32PrioritySeparation", 4)
        .filter(|bytes| bytes.len() == 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    let product_type = value(&product, "ProductType", 1).ok_or(STATUS_DEVICE_NOT_READY)?;
    let nt_as_system = if product_type_is(product_type, "WinNT") {
        false
    } else if product_type_is(product_type, "LanmanNT")
        || product_type_is(product_type, "ServerNT")
    {
        true
    } else {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    };
    Ok(nt_process::ProcessPriorityQuantumPolicy::from_priority_separation(raw, nt_as_system))
}

fn exact_runtime(
    handler: &ExecNtHandler, lifetime: nt_process::ThreadLifetime,
) -> Result<HostedThreadRuntime, u32> {
    if !handler.pm.validate_thread_lifetime(lifetime) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let runtime = handler.thread_runtime.executable_by_tid(u64::from(lifetime.thread_id()))
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    if runtime.tcb <= 1 || runtime.process.pid != lifetime.process_id()
        || handler.capture_process_identity(runtime.pi) != Some(runtime.process)
    {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    Ok(runtime)
}

fn build_by_class_effects(
    handler: &ExecNtHandler, plan: &nt_process::ProcessPriorityByClassPlan,
) -> Result<alloc::vec::Vec<PriorityEffect<HostedThreadRole>>, u32> {
    let mut effects = alloc::vec::Vec::new();
    effects.try_reserve_exact(plan.thread_effects().len())
        .map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
    for effect in plan.thread_effects() {
        if effect.expected().priority == effect.next().priority { continue; }
        if matches!(effect.state(), nt_process::ThreadState::Initialized | nt_process::ThreadState::Terminated) {
            continue;
        }
        let runtime = exact_runtime(handler, effect.lifetime())?;
        let previous = nt_user_host::hosted_priority::hosted_tcb_priority(effect.expected().priority)?;
        let next = nt_user_host::hosted_priority::hosted_tcb_priority(effect.next().priority)?;
        effects.push(PriorityEffect::new(runtime.binding(), effect.lifetime(), previous, next));
    }
    Ok(effects)
}

fn run(
    handler: &mut ExecNtHandler, plan: PendingPlan,
    effects: alloc::vec::Vec<PriorityEffect<HostedThreadRole>>,
) -> Result<u64, u32> {
    if handler.priority_transition_owner.is_some() {
        return Err(nt_process::STATUS_DEVICE_BUSY);
    }
    let owner = NativePriorityOwner::new(plan, effects)
        .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
    handler.thread_runtime.reserve_priority_effects(owner.effects())?;
    handler.priority_transition_owner = Some(owner);

    loop {
        let Some(effect) = handler.priority_transition_owner.as_ref().unwrap().next_effect() else {
            break;
        };
        let binding = effect.binding();
        if !handler.pm.validate_thread_lifetime(effect.lifetime())
            || handler.thread_runtime.get_by_tid(binding.tid)
                .is_none_or(|runtime| runtime.binding() != binding)
            || handler.capture_process_identity(binding.pi) != Some(binding.process)
        {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let invocation = handler.priority_transition_owner.as_mut().unwrap()
            .begin(binding, effect.lifetime())
            .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
        let status = unsafe { tcb_set_priority_r(invocation.tcb(), u64::from(invocation.next())) };
        let outcome = if status == 0 {
            PriorityTransitionOutcome::Acknowledged
        } else {
            PriorityTransitionOutcome::Rejected(status as u32)
        };
        if handler.priority_transition_owner.as_mut().unwrap()
            .complete(invocation, outcome).is_err()
        {
            return Err(nt_process::STATUS_UNSUCCESSFUL);
        }
    }

    let plan = handler.priority_transition_owner.as_ref().unwrap()
        .acknowledged_payload().map_err(|_| nt_process::STATUS_UNSUCCESSFUL)?;
    let previous = match plan {
        PendingPlan::ByClass(plan) => {
            handler.pm.commit_process_priority_by_class_retained(plan)?;
            0
        }
        PendingPlan::Thread(plan) => {
            handler.pm.commit_kernel_thread_priority_retained(plan)? as u32 as u64
        }
    };
    handler.thread_runtime.release_priority_effects(
        handler.priority_transition_owner.as_ref().unwrap().effects(),
    )?;
    handler.priority_transition_owner.as_mut().unwrap().finish()
        .map_err(|_| nt_process::STATUS_UNSUCCESSFUL)?;
    handler.priority_transition_owner = None;
    Ok(previous)
}

pub(super) fn dispatch(
    handler: &mut ExecNtHandler, op: u64, object: u64, value: u64,
) -> (i32, u64, u64, u64) {
    let result = match op {
        win32k_subsystem::W32_PS_OP_SET_PROCESS_PRIORITY_BY_CLASS => {
            u32::try_from(value).map_err(|_| nt_process::STATUS_INVALID_PARAMETER)
                .and_then(|mode| {
                    let policy = unsafe { live_quantum_policy() }?;
                    let plan = handler.pm.prepare_process_priority_by_class_for_kernel_object(object, mode, policy)?;
                    let effects = build_by_class_effects(handler, &plan)?;
                    run(handler, PendingPlan::ByClass(plan), effects)
                })
        }
        win32k_subsystem::W32_PS_OP_SET_THREAD_PRIORITY => {
            let plan = handler.pm.prepare_kernel_thread_priority(object, value as u32 as i32);
            plan.and_then(|plan| {
                let runtime = exact_runtime(handler, plan.lifetime())?;
                let previous = nt_user_host::hosted_priority::hosted_tcb_priority(plan.previous())?;
                let next = nt_user_host::hosted_priority::hosted_tcb_priority(plan.next())?;
                let mut effects = alloc::vec::Vec::new();
                if previous != next {
                    effects.try_reserve_exact(1).map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
                    effects.push(PriorityEffect::new(runtime.binding(), plan.lifetime(), previous, next));
                }
                run(handler, PendingPlan::Thread(plan), effects)
            })
        }
        _ => Err(nt_process::STATUS_INVALID_PARAMETER),
    };
    match result {
        Ok(previous) => (0, previous, 0, 0),
        Err(status) => (status as i32, 0, 0, 0),
    }
}

pub(super) const fn is_priority_effect_op(op: u64) -> bool {
    op == win32k_subsystem::W32_PS_OP_SET_PROCESS_PRIORITY_BY_CLASS
        || op == win32k_subsystem::W32_PS_OP_SET_THREAD_PRIORITY
}
