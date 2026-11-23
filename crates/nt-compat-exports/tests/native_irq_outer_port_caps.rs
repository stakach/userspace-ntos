//! Compile the native IRQ wrapper to prove a private IRQ CNode leaves the primary cap intact.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const IRQ_BROKER: &str = include_str!("../../../components/ntos-executive/src/hosted_irq_broker.rs");

#[test]
fn dpc_projection_uses_the_retained_private_irq_cnode() {
    let view = IRQ_BROKER
        .split_once("struct HostedIrqLaneView {")
        .expect("retained IRQ lane view")
        .1
        .split_once("\nimpl HostedIrqLaneView")
        .expect("lane view end")
        .0;
    assert!(view.contains("cnode: u64"));
    let selector = IRQ_BROKER
        .split_once("unsafe fn lane_view_for_domain(")
        .expect("retained lane selector")
        .1
        .split_once("\nunsafe fn ")
        .expect("lane selector end")
        .0;
    assert!(selector.contains("cnode: lane.cnode"));
    assert!(IRQ_BROKER.contains("lane.shared_va, lane.cnode,"));
}

#[test]
fn nested_private_irq_never_rewrites_primary_port_caps_on_return() {
    let start = SOURCE
        .find("unsafe fn dispatch_hosted_irq_connection(\n")
        .expect("production IRQ dispatch wrapper");
    let tail = &SOURCE[start..];
    let end = tail
        .find("\nunsafe fn dispatch_hosted_irq_connection_on_lane(")
        .expect("production IRQ wrapper end");
    let fixture = format!("{SUPPORT}\n{}\n{CASES}", &tail[..end]);
    let directory =
        std::env::temp_dir().join(format!("nt-private-irq-cnode-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "IRQ fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "IRQ regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
#[derive(Clone, Copy)] struct HostedDeviceBinding { instance: usize, device_id: u64 }
#[derive(Clone, Copy)] struct HostedIrqConnection { binding: HostedDeviceBinding }
enum HostedIrqConnectionDispatchOutcome { Replied }
mod nt_status { #[derive(Debug)] pub enum NtStatus { INVALID_DEVICE_REQUEST } }
static mut PRIMARY_CAP: u64 = 0;
static mut IRQ_CAP: u64 = 0;
fn current_hosted_device_dispatch_binding(_: usize) -> Option<HostedDeviceBinding> {
    Some(HostedDeviceBinding { instance:0, device_id:1 })
}
unsafe fn dispatch_hosted_irq_connection_on_lane(_: HostedIrqConnection)
    -> Result<HostedIrqConnectionDispatchOutcome, nt_status::NtStatus> {
    IRQ_CAP = 0xB;
    Ok(HostedIrqConnectionDispatchOutcome::Replied)
}
unsafe fn restore_outer_port_caps_after_irq(_: usize, _: Option<HostedDeviceBinding>, _: u64) {
    PRIMARY_CAP = 0;
}
"#;

const CASES: &str = r#"
#[test]
fn irq_return_does_not_touch_primary_cnode() {
    unsafe {
        PRIMARY_CAP = 0xA;
        IRQ_CAP = 0;
        let irq = HostedIrqConnection { binding: HostedDeviceBinding { instance:0, device_id:2 } };
        assert!(dispatch_hosted_irq_connection(irq).is_ok());
        assert_eq!(IRQ_CAP,0xB);
        assert_eq!(PRIMARY_CAP,0xA, "private IRQ cap projection must not rewrite primary CNode");
    }
}
"#;
