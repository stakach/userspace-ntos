//! ACPI namespace overflow retains its 8-byte METHOD_BUFFERED header even when
//! IoStatus.Information is zero, without changing the driver's completion metadata.

use std::process::Command;

#[test]
fn pending_acpi_namespace_overflow_retains_exact_header() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = driver.find("fn pending_irp_completion_output_len(").unwrap();
    let end = driver[start..].find("\nunsafe fn pool_alloc_zeroed(").unwrap() + start;
    let helper = &driver[start..end];
    syn::parse_str::<syn::ItemFn>(helper).expect("extract actual native completion-length helper");

    assert!(driver.contains("control_code: read_volatile("));
    assert!(driver.contains("control_code: fsctl as u32"));
    assert!(driver.contains(
        "target.control_code,\n            target.control_method,\n            target.output_capacity,\n            status,\n            information,"
    ));
    assert!(driver.contains(
        "completed.control_code,\n                completed.control_method,\n                outlen,\n                st as u32,\n                info,"
    ));

    let fixture = format!(
        "const IRP_MJ_PNP: u64 = 0x1b;\n\
         const IRP_MJ_DEVICE_CONTROL: u64 = 0x0e;\n\
         const STATUS_BUFFER_OVERFLOW: u32 = 0x80000005;\n\
         const HOSTED_ACPI_NAMESPACE_HEADER_LEN: usize = 8;\n\
         mod ioctl {{ pub const METHOD_BUFFERED: u32 = 0; }}\n\
         mod nt_pnp_abi {{ pub const IRP_MN_QUERY_CAPABILITIES: u8 = 0x09; \
         pub const DEVICE_CAPABILITIES_X64_SIZE: usize = 64; }}\n\
         mod nt_acpi {{ pub const IOCTL_ACPI_ENUM_CHILDREN: u32 = 0x0032c020; }}\n\
         mod nt_io_manager {{ pub fn retained_control_output_transfer_len(\
         _: u8, _: u8, information: u64, capacity: u64) -> u64 {{ information.min(capacity) }} }}\n\
         {helper}\n\
         #[test] fn exact_acpi_probe_only() {{\n\
         assert_eq!(pending_irp_completion_output_len(IRP_MJ_DEVICE_CONTROL, 0, \
         nt_acpi::IOCTL_ACPI_ENUM_CHILDREN, 0, 8, STATUS_BUFFER_OVERFLOW, 0), 8);\n\
         assert_eq!(pending_irp_completion_output_len(IRP_MJ_DEVICE_CONTROL, 0, \
         nt_acpi::IOCTL_ACPI_ENUM_CHILDREN, 0, 16, STATUS_BUFFER_OVERFLOW, 0), 0);\n\
         assert_eq!(pending_irp_completion_output_len(IRP_MJ_DEVICE_CONTROL, 0, \
         0x0032c024, 0, 8, STATUS_BUFFER_OVERFLOW, 0), 0);\n\
         assert_eq!(pending_irp_completion_output_len(IRP_MJ_DEVICE_CONTROL, 0, \
         nt_acpi::IOCTL_ACPI_ENUM_CHILDREN, 0, 8, 0, 0), 0);\n\
         assert_eq!(pending_irp_completion_output_len(IRP_MJ_PNP, 9, 0, 0, 64, 0, 0), 64);\n\
         }}"
    );
    let directory = std::env::temp_dir().join(format!(
        "nt-acpi-namespace-overflow-{}",
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
