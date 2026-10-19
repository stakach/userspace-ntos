//! Native file opens must reach a live named driver device before filesystem fallback.

extern crate alloc;

use std::path::PathBuf;

#[path = "../../../components/ntos-executive/src/exec_named_device_route.rs"]
mod named_device_route;

const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

fn native_source(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    std::fs::read_to_string(path).expect("native source exists")
}

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("missing {name}"));
    let body = &source[start..];
    let next = body.find("\n    }").expect("function closes") + 6;
    &body[..next]
}

#[test]
fn native_open_and_create_route_named_driver_peers_before_filesystem_fallback() {
    let open = native_source("exec_handler.rs");
    let create = native_source("exec_file_create.rs");
    for (source, method, fallback) in [
        (&open, "nt_open_file_service", "writable_fs::writable_path_into"),
        (&create, "nt_create_file_service", "writable_fs::volume_path_into"),
    ] {
        let body = function_body(source, method);
        let route = body
            .find("create_registered_driver_peer_file(")
            .unwrap_or_else(|| panic!("{method} lacks named driver-device routing"));
        let fallback = body.find(fallback).expect("filesystem fallback remains");
        assert!(route < fallback, "{method} must route devices before filesystem fallback");
        assert!(body[..route].contains("!Self::is_named_pipe_root_path(name16)"));
        assert!(body[..route].contains("!nt_fs::is_named_pipe_path(name16)"));
        assert!(body.contains("create_registered_driver_peer_relative_file("));
    }
}

#[test]
fn named_driver_peer_route_uses_object_namespace_and_canonical_dispatch() {
    let source = native_source("exec_handler.rs");
    let route = function_body(&source, "create_registered_driver_peer_file");
    assert!(route.contains("resolve_named_driver_peer"));
    assert!(route.contains("resolve_hosted_device_file_name"));
    assert!(route.contains("registered_file_target"));
    assert!(route.contains("RegisteredFileTarget::DriverPeer"));
    assert!(route.contains("create_registered_file_from_target"));
    let dispatch = function_body(&source, "create_registered_file_from_target");
    assert!(dispatch.contains("registered_create_file"));
    assert!(!route.contains("KeyboardClass"), "routing must not hardcode the guest class name");
    assert!(route.contains("STATUS_OBJECT_NAME_NOT_FOUND"));
    assert!(route.contains("STATUS_OBJECT_PATH_NOT_FOUND"));
    let relative = function_body(&source, "create_registered_driver_peer_relative_file");
    assert!(relative.contains("device_id_by_name(\"\\\\Device\\\\NamedPipe\")"));
    assert!(relative.contains("Some(parent_file_id)"));
    let driver = native_source("driver_launch.rs");
    let resolver = &driver[driver.find("fn resolve_hosted_device_file_name(").unwrap()..];
    let resolver = &resolver[..resolver.find("\n}").unwrap()];
    assert!(resolver.contains("hosted_io_create_file_ingress::resolve_absolute_name"));
}

#[test]
fn named_driver_peer_resolution_preserves_exact_name_and_rejects_unknown_objects() {
    use named_device_route::resolve_named_driver_peer;

    let keyboard = "\\Device\\KeyboardClass0".encode_utf16().collect::<Vec<_>>();
    let route = resolve_named_driver_peer(
        &keyboard,
        true,
        |name, case_insensitive| {
            assert_eq!(name, keyboard);
            assert!(case_insensitive);
            Ok((71_u64, Vec::new()))
        },
        |device| Ok(*device == 71),
    )
    .unwrap();
    assert_eq!(route, Some((71, Vec::new())));

    let filesystem = "\\Device\\HarddiskVolume1\\boot.ini".encode_utf16().collect::<Vec<_>>();
    let result = resolve_named_driver_peer(
        &filesystem,
        true,
        |_, _| Ok((8_u64, "\\boot.ini".encode_utf16().collect())),
        |device| Ok(*device == 71),
    );
    assert_eq!(result, Ok(None), "filesystem devices retain their normal path");

    let unknown = "\\Device\\MissingClass0".encode_utf16().collect::<Vec<_>>();
    let result = resolve_named_driver_peer(
        &unknown,
        true,
        |_, _| Err::<(u64, Vec<u16>), _>(OBJECT_NAME_NOT_FOUND),
        |_| panic!("an unknown object cannot authorize device dispatch"),
    );
    assert_eq!(result, Err(OBJECT_NAME_NOT_FOUND));
}

#[test]
fn named_pipe_aliases_keep_the_existing_endpoint_route() {
    for path in [
        "\\??\\pipe\\ntsvcs",
        "\\DosDevices\\pipe\\ntsvcs",
        "\\Device\\NamedPipe\\ntsvcs",
    ] {
        assert!(nt_fs::is_named_pipe_path(&path.encode_utf16().collect::<Vec<_>>()));
    }
}

#[test]
fn ordinary_peer_create_can_publish_without_fs_context_but_endpoint_cannot() {
    let source = native_source("exec_handler.rs");
    let body = function_body(&source, "publish_registered_create");
    let route = body.find("hosted_file_route(file_id)").expect("exact canonical File route");
    let mismatch = body.find("live_context != fs_context").expect("driver context mismatch fails closed");
    let ordinary = body
        .find("major == major::IRP_MJ_CREATE && provider_context == 0")
        .expect("ordinary CREATE branch");
    let bind = body[ordinary..]
        .find("bind_reserved_file_handle(file_id, reservation, desired_access)")
        .expect("ordinary CREATE binds its reserved handle")
        + ordinary;
    let required = body.find("if fs_context == 0").expect("endpoint requires file context");
    let pipe = body.find("pipe_fid_name_remember").expect("named-pipe endpoint branch");
    assert!(route < mismatch && mismatch < ordinary);
    assert!(ordinary < bind && bind < required && required < pipe,
        "zero FsContext must not reject an ordinary named driver CREATE, while endpoints still require it");
}
