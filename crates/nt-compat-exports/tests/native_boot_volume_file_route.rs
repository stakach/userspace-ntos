//! A Boot-backed volume File must retain its exact mounted device owner for FSCTLs.

extern crate alloc;

#[path = "../../../components/ntos-executive/src/exec_volume_open_route.rs"]
mod volume_open_route;

use alloc::vec::Vec;

fn resolved(device_id: u64, remaining_name: &str) -> Result<(u64, Vec<u16>), u32> {
    Ok((device_id, remaining_name.encode_utf16().collect()))
}

#[test]
fn boot_volume_file_route_requires_exact_resolved_filesystem_device() {
    use volume_open_route::route_exact_volume_file_target;

    const MOUNTED_FILESYSTEM_DEVICE: u64 = 41;
    let registered_kernel_filesystem = |device_id| device_id == MOUNTED_FILESYSTEM_DEVICE;

    // The Object Manager's empty remaining FileName denotes a volume File, even on Boot.
    assert!(route_exact_volume_file_target(
        Some(&resolved(MOUNTED_FILESYSTEM_DEVICE, "")),
        registered_kernel_filesystem,
    ));

    // A root directory and ordinary children are distinct File objects on that device.
    for remaining_name in [r"\", r"\Windows\System32\autochk.exe"] {
        assert!(!route_exact_volume_file_target(
            Some(&resolved(MOUNTED_FILESYSTEM_DEVICE, remaining_name)),
            registered_kernel_filesystem,
        ));
    }

    // Numeric device identity alone cannot establish a registered filesystem owner.
    assert!(!route_exact_volume_file_target(
        Some(&resolved(MOUNTED_FILESYSTEM_DEVICE + 1, "")),
        registered_kernel_filesystem,
    ));
    assert!(!route_exact_volume_file_target(
        Some(&Err(0xC000_0034)),
        registered_kernel_filesystem,
    ));
    assert!(!route_exact_volume_file_target(None, registered_kernel_filesystem));
}

#[test]
fn native_open_and_create_use_the_same_exact_volume_policy_before_local_fallback() {
    let open = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let create = include_str!("../../../components/ntos-executive/src/exec_file_create.rs");

    let policy = open
        .split("fn route_absolute_open_to_kernel_file(")
        .nth(1)
        .expect("shared absolute File route policy");
    let policy = policy.split("\n    }").next().expect("route policy body");
    assert!(policy.contains("route_exact_volume_file_target"),
        "Boot volume File admission must use exact Object Manager resolution and registered device authority");

    for (source, name, options) in [
        (open, "nt_open_file_captured", "open_options"),
        (create, "nt_create_file_captured", "create_options"),
    ] {
        let body = source
            .split(&format!("fn {name}("))
            .nth(1)
            .unwrap_or_else(|| panic!("missing {name}"));
        let call = format!("route_absolute_open_to_kernel_file(name16, {options}, mount_route, resolved)");
        let normalized: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let call: String = call.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(normalized.contains(&call),
            "{name} must pass the retained exact target into the shared route policy");
    }
}
