use std::fs;
use std::path::PathBuf;

fn source(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join("../../components/ntos-executive/src").join(name))
        .expect("native source")
}

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).expect("function");
    let body = &source[start..];
    let open = body.find('{').expect("body");
    let mut depth = 0;
    for (offset, byte) in body.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &body[..open + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function")
}

#[test]
fn monitor_enumeration_pointer_is_projected_before_terminal_publication() {
    let bridge = source("hosted_kernel_win32k_source_ioctl.rs");
    let capture = function(&bridge, "capture_output");
    let projection = function(&bridge, "project_monitor_array");
    assert!(projection.contains("IOCTL_VIDEO_ENUM_MONITOR_PDO"));
    assert!(projection.contains("capture_hosted_video_monitor_array"));
    assert!(projection.contains("try_publish_root_provider_pool_packet"));
    assert!(capture.contains("self.project_monitor_array(length)"));
    assert!(capture.find("project_monitor_array").unwrap()
        < capture.find("self.output_captured = true").unwrap());
}

#[test]
fn monitor_projection_free_is_exact_and_not_a_generic_foreign_pool_free() {
    let subsystem = source("win32k_subsystem.rs");
    let free = function(&subsystem, "s_ex_free_pool_with_tag");
    assert!(free.contains("release_monitor_array_projection"));
    assert!(free.find("release_monitor_array_projection").unwrap()
        < free.find("provider_pool_free(p)").unwrap());
}

#[test]
fn sealed_stop_settles_an_unpublished_monitor_projection() {
    let bridge = source("hosted_kernel_win32k_source_ioctl.rs");
    let stopped = function(&bridge, "finish_stopped");
    assert!(stopped.contains("settle_monitor_array_on_stop"));
}

#[test]
fn sealed_stop_retires_a_captured_source_before_projection_exists() {
    let bridge = source("hosted_kernel_win32k_source_ioctl.rs");
    let settle = function(&bridge, "settle_monitor_array_on_stop");
    assert!(settle.contains("retire_unpublished_after_sealed_stop"));
}

#[test]
fn native_free_requires_a_registered_exact_monitor_projection() {
    let subsystem = source("win32k_subsystem.rs");
    let free = function(&subsystem, "release_monitor_array_projection");
    assert!(free.contains("source_irp_call::claim_monitor_array_projection_free"));
    let terminal = source("win32k_source_irp_call.rs");
    let complete = function(&terminal, "complete_terminal");
    assert!(complete.contains("register_monitor_array_projection"));
}

#[test]
fn claimed_projection_still_blocks_generic_free_until_physical_retirement() {
    let component = source("win32k_source_irp_call.rs");
    let claim = function(&component, "claim_monitor_array_projection_free");
    assert!(claim.contains("admissions[index].claimed = true"));
    assert!(!claim.contains("admissions.swap_remove(index)"));
}
