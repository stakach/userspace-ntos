//! A level IRQ deferred behind an ordinary thread's actual lock keeps its physical bit latched.
//! The next timer notification must yield the retained IRP to retry that exact bit; the device
//! cannot send a second level notification until the original delivery is acknowledged.

use std::process::Command;

const PUMP: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const RECEIVER: &str = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn deferred_actual_lock_irq_retries_on_timer_without_new_irq_badge() {
    let start = PUMP.find("unsafe fn pump_scheduler_work_pending(").expect("scheduler predicate");
    let end = PUMP[start..].find("\n\nstruct PumpMessage").expect("predicate boundary");
    let predicate = &PUMP[start..start + end];
    syn::parse_str::<syn::ItemFn>(predicate).expect("parse native scheduler predicate");

    let receive = RECEIVER.split("pub(super) unsafe fn receive(").nth(1).expect("shared receiver");
    assert!(receive.contains("pump_scheduler_work_pending(ch, irq)"));
    let drain = DRIVER.split("unsafe fn drain_pending_hosted_irqs_snapshot()").nth(1)
        .expect("physical IRQ drain");
    assert!(drain.contains("HOSTED_IRQ_PENDING_EVENTS.fetch_or(deferred"),
        "busy delivery must retain its physical bit for the next checkpoint");

    let source = format!("{MOCKS}\n{predicate}\n{CASES}");
    let directory = std::env::temp_dir().join(format!("nt-deferred-irq-retry-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, source).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "native predicate fixture failed to compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    assert!(result.status.success(), "deferred actual-lock IRQ must be retried:\n{}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

const MOCKS: &str = r#"
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, PartialEq, Eq)] enum ReqKind { Irp, Syscall }
struct Caps { kind: ReqKind, kernel_irq_yield: bool }
struct PumpChannel { caps: Caps }

mod driver_launch {
    use super::*;
    pub static PENDING_IRQ: AtomicBool = AtomicBool::new(false);
    pub fn hosted_irq_work_pending() -> bool { PENDING_IRQ.load(Ordering::Relaxed) }
    pub fn hosted_driver_dpc_activation_pending() -> bool { false }
    pub fn mounted_native_block_nested_ready() -> bool { false }
}
mod dispatcher_bootstrap {
    pub fn timer_work_pending() -> bool { false }
}
"#;

const CASES: &str = r#"
#[test]
fn deferred_level_irq_uses_timer_arrival_to_retry_while_irp_reply_is_retained() {
    let irp = PumpChannel { caps: Caps { kind: ReqKind::Irp, kernel_irq_yield: false } };
    driver_launch::PENDING_IRQ.store(true, Ordering::Relaxed);
    assert!(unsafe { pump_scheduler_work_pending(&irp, false) },
        "a latched deferred IRQ must schedule a checkpoint without another IRQ badge");
    driver_launch::PENDING_IRQ.store(false, Ordering::Relaxed);
    assert!(!unsafe { pump_scheduler_work_pending(&irp, false) },
        "a timer with no pending IRQ or other work must not spuriously yield");
}

#[test]
fn exact_channel_still_controls_scheduler_authority() {
    let nonyielding = PumpChannel { caps: Caps { kind: ReqKind::Syscall, kernel_irq_yield: false } };
    let yielding = PumpChannel { caps: Caps { kind: ReqKind::Syscall, kernel_irq_yield: true } };
    driver_launch::PENDING_IRQ.store(true, Ordering::Relaxed);
    assert!(!unsafe { pump_scheduler_work_pending(&nonyielding, false) });
    assert!(unsafe { pump_scheduler_work_pending(&yielding, false) });
}
"#;
