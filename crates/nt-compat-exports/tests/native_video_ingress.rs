use syn::{visit::Visit, Item};

struct Paths(Vec<String>);
impl<'ast> Visit<'ast> for Paths {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.0.extend(path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_path(self, path);
    }
}
fn paths(source: &str) -> Vec<String> {
    let mut paths = Paths(Vec::new());
    paths.visit_file(&syn::parse_file(source).unwrap());
    paths.0
}

#[test]
fn real_eng_device_io_control_uses_native_irp_imports_without_a_private_transport() {
    let source = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let parsed = syn::parse_file(source).unwrap();
    for item in parsed.items {
        let name = match item {
            Item::Fn(item) => item.sig.ident.to_string(),
            Item::Const(item) => item.ident.to_string(),
            _ => continue,
        };
        assert!(!matches!(name.as_str(), "patch_eng_device_io_control" | "s_eng_device_io_control"
            | "request_video_device_io_control" | "service_video_device_io_control" | "W32_VIDEO_IOCTL_LABEL"),
            "obsolete EngDeviceIoControl bypass remains: {name}");
    }
}

#[test]
fn legacy_video_dispatch_cannot_bypass_the_retained_source_work() {
    let paths = paths(include_str!("../../../components/ntos-executive/src/spawn_hosts.rs"));
    assert!(!paths.iter().any(|name| name == "W32_VIDEO_IOCTL_LABEL"));
    assert!(!paths.iter().any(|name| name == "pump_service_video_device_io_control"));
}

#[test]
fn reserved_video_aperture_is_not_admitted_as_an_anonymous_private_fault() {
    let paths = paths(include_str!("../../../components/ntos-executive/src/spawn_hosts.rs"));
    assert!(paths.iter().any(|name| name == "is_reserved_win32k_video_aperture"),
        "reserved video aperture faults must be refused before generic private-page allocation");
}

#[test]
fn framebuffer_mode_observation_consumes_only_real_source_completion() {
    let source = paths(include_str!("../../../components/ntos-executive/src/hosted_kernel_win32k_source_ioctl.rs"));
    assert!(source.iter().any(|name| name == "observe_terminal"),
        "mode evidence must come from the actual completed IOCTL, not another injected query");
    let aperture = paths(include_str!("../../../components/ntos-executive/src/hosted_video_caller_aperture.rs"));
    for required in ["IOCTL_VIDEO_QUERY_CURRENT_MODE", "parse_video_mode_information",
        "publish_active_framebuffer_mode", "FB_BAR_PADDR"] {
        assert!(aperture.iter().any(|name| name == required),
            "actual mode observation must validate {required}");
    }
}
