//! A pending QUERY_CAPABILITIES completion retains its fixed in/out payload even when
//! the driver reports zero IoStatus.Information.

use std::process::Command;

#[test]
fn pending_capabilities_completion_uses_pnp_payload_length() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let completion = &driver[driver.find("unsafe fn complete_hosted_irp_with_owner(").unwrap()..];
    let completion = &completion[..completion.find("/// `PVOID IoAllocateErrorLogEntry").unwrap()];
    assert!(completion.contains(
        "pending_irp_completion_output_len(\n            target.major as u64,\n            target.minor as u64,\n            target.control_code,\n            target.control_method,\n            target.output_capacity,\n            status,\n            information,\n        )"
    ));

    let start = driver.find("fn pending_irp_completion_output_len(").unwrap();
    let end = driver[start..].find("\nunsafe fn pool_alloc_zeroed(").unwrap() + start;
    let helper = &driver[start..end];
    syn::parse_str::<syn::ItemFn>(helper).expect("extract actual native completion-length helper");

    let fixture = format!(
        "const IRP_MJ_PNP: u64 = 0x1b;\n\
         const IRP_MJ_DEVICE_CONTROL: u64 = 0x0e;\n\
         const STATUS_BUFFER_OVERFLOW: u32 = 0x80000005;\n\
         const STATUS_BUFFER_TOO_SMALL: u32 = 0xc0000023;\n\
         const HOSTED_ACPI_NAMESPACE_HEADER_LEN: usize = 8;\n\
         mod nt_acpi {{ pub const IOCTL_ACPI_ENUM_CHILDREN: u32 = 0x0032c020; }}\n\
         mod ioctl {{ pub const METHOD_BUFFERED: u32 = 0; }}\n\
         mod nt_pnp_abi {{ pub const IRP_MN_QUERY_CAPABILITIES: u8 = 0x09; \
         pub const DEVICE_CAPABILITIES_X64_SIZE: usize = 64; }}\n\
         mod nt_io_manager {{ pub fn retained_control_output_transfer_len(\
         _: u8, _: u8, _: u64, _: u64) -> u64 {{ 7 }} }}\n\
         {helper}\n\
         #[test] fn zero_information_still_retains_capabilities() {{\n\
         assert_eq!(pending_irp_completion_output_len(IRP_MJ_PNP, 9, 0, 0, 64, 0, 0), 64);\n\
         assert_eq!(pending_irp_completion_output_len(IRP_MJ_PNP, 8, 0, 0, 64, 0, 0), 7);\n\
         }}"
    );
    let directory = std::env::temp_dir().join(format!(
        "nt-pending-capabilities-completion-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&source, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native helper fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native helper fixture failed:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
