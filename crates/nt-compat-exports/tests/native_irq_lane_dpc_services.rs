//! DPC-legal exports reach the root through typed IRQ-lane services.
//!
//! A DPC or ISR runs on its domain's IRQ lane, whose root exchange admits only typed arena
//! services and walls on any primary-channel label. An export NT documents as callable at
//! DISPATCH_LEVEL must therefore check for lane context before any raw root Call.

use syn::{visit::Visit, Item};

const SOURCES: &[(&str, &str)] = &[
    ("driver_launch.rs", include_str!("../../../components/ntos-executive/src/driver_launch.rs")),
    ("hosted_start_io.rs", include_str!("../../../components/ntos-executive/src/hosted_start_io.rs")),
    ("hosted_driver_wmi.rs", include_str!("../../../components/ntos-executive/src/hosted_driver_wmi.rs")),
    ("hosted_driver_hal_beep.rs",
        include_str!("../../../components/ntos-executive/src/hosted_driver_hal_beep.rs")),
];

/// (export, the function that implements it).
const DPC_LEGAL: &[(&str, &str)] = &[
    ("HalMakeBeep", "make_beep"),
    ("IoStartNextPacket", "s_io_start_next_packet"),
    ("KePulseEvent", "s_ke_pulse_event"),
    ("KeReleaseSemaphore", "s_ke_release_semaphore"),
    ("MmBuildMdlForNonPagedPool", "s_mm_build_mdl_for_nonpaged_pool"),
    ("HalGetBusDataByOffset/HalSetBusDataByOffset", "hosted_pci_config_call"),
    ("IoWMIWriteEvent", "write_event"),
    ("IoAllocateIrp", "s_io_allocate_irp"),
    ("ObfDereferenceObject", "s_obf_dereference_object"),
    // A DPC runs in the processor's idle thread, in the Idle process.
    ("PsGetCurrentThreadId/PsGetCurrentProcessId/IoGetCurrentProcess", "current_ps_value"),
];

/// The driver-side entry points that publish a typed service on the current IRQ lane.
const LANE_REQUESTS: &[&str] = &[
    "hosted_irq_lane_request",
    "hosted_irq_lane_dispatcher_signal",
    // The MDL service publishes HostedIrqServiceKind::Mdl on the lane (hosted_mdl_service).
    "require_hosted_mdl_service",
];

fn function(name: &str) -> syn::ItemFn {
    SOURCES.iter().find_map(|(_, source)| {
        syn::parse_file(source).unwrap().items.into_iter().find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
    }).unwrap_or_else(|| panic!("{name} not found"))
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(last) = path.path.segments.last() {
                self.0.push(last.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn dpc_legal_exports_request_typed_lane_services() {
    for (export, implementation) in DPC_LEGAL {
        let mut calls = Calls::default();
        calls.visit_item_fn(&function(implementation));
        let lane = calls.0.iter().position(|name| LANE_REQUESTS.contains(&name.as_str()));
        let raw = calls.0.iter().position(|name| name.starts_with("call_on4"));
        assert!(lane.is_some(), "{export} must request its root service on the IRQ lane");
        assert!(raw.is_none_or(|raw| lane.is_some_and(|lane| lane < raw)),
            "{export} checks for the IRQ lane before any primary-channel Call");
    }
}
