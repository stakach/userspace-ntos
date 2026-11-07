//! Temporary measurement contract for one authenticated umpnpmgr install pipe.
//! The pipe name, canonical FileId, and process generations are diagnostic keys only.

use nt_hosted_runtime::{InstallChildIdentity, InstallPipeDiagnostic, InstallPipeIdentity};

const PIPE: InstallPipeIdentity = InstallPipeIdentity {
    owner_pid: 168,
    owner_generation: 6,
    file_id: (3u64 << 40) | 0x8c,
};
const CHILD: InstallChildIdentity = InstallChildIdentity { pid: 572, generation: 16 };
const CLIENT_FILE: u64 = (5u64 << 40) | 0x8d;

fn utf16(value: &str) -> Vec<u16> { value.encode_utf16().chain([0]).collect() }
fn bytes(value: &[u16]) -> Vec<u8> { value.iter().flat_map(|unit| unit.to_le_bytes()).collect() }
fn pipe_name(id: &str) -> Vec<u16> {
    utf16(&format!(r"PNP_Device_Install_Pipe_0.{{{id}}}"))
}

#[test]
fn fifth_write_reports_exact_device_and_child_terminal_for_one_pipe_generation() {
    let mut trace = InstallPipeDiagnostic::<2>::new();
    let name = pipe_name("af990c70-ff1e-416f-b1aa-57a14d8ab3fa");
    let event = utf16("Global\\PNP_Device_Install_Event_0.{af990c70-ff1e-416f-b1aa-57a14d8ab3fa}");
    let device = utf16(r"ACPI\PNP0303\0");
    assert!(trace.register_server(PIPE, &name));
    assert!(trace.attach_child(PIPE, &name, CHILD, CLIENT_FILE));
    for payload in [
        ((event.len() * 2) as u32).to_le_bytes().to_vec(), bytes(&event),
        0u32.to_le_bytes().to_vec(), ((device.len() * 2) as u32).to_le_bytes().to_vec(),
    ] {
        assert!(trace.record_server_write(PIPE, &payload).is_none());
    }
    assert!(trace.record_server_write(InstallPipeIdentity {
        file_id: (4u64 << 40) | 0x8c, ..PIPE
    }, &bytes(&device)).is_none(), "a recycled FileId cannot complete the observation");
    let observation = trace.record_server_write(PIPE, &bytes(&device))
        .expect("fifth complete write publishes one bounded observation");
    assert_eq!(observation.pipe, PIPE);
    assert_eq!(observation.child, CHILD);
    assert_eq!(observation.client_file_id, CLIENT_FILE);
    assert_eq!(&observation.device[..observation.device_len], device.as_slice());
    assert!(trace.record_child_terminal(InstallChildIdentity {
        generation: CHILD.generation + 1, ..CHILD
    }, 0).is_none(), "reused child PID cannot retire this observation");
    let terminal = trace.record_child_terminal(CHILD, 0).expect("exact child terminal");
    assert_eq!(terminal.pipe, PIPE);
    assert_eq!(terminal.child, CHILD);
    assert_eq!(terminal.exit_status, 0);
    assert_eq!(trace.counts().published, 1);
    assert_eq!(trace.counts().terminal, 1);
    assert_eq!(trace.counts().rejected, 2);
}

#[test]
fn pipe_name_and_capacity_are_explicitly_bounded() {
    let mut trace = InstallPipeDiagnostic::<1>::new();
    let name = pipe_name("af990c70-ff1e-416f-b1aa-57a14d8ab3fa");
    let other = pipe_name("88f0b539-5385-4981-a6cb-c8e06903a103");
    assert!(trace.register_server(PIPE, &name));
    assert!(!trace.attach_child(PIPE, &other, CHILD, CLIENT_FILE), "a peer name is not authority");
    assert!(!trace.register_server(InstallPipeIdentity { file_id: PIPE.file_id + 1, ..PIPE }, &other));
    assert_eq!(trace.counts().rejected, 1);
    assert_eq!(trace.counts().overflow, 1);
}

#[test]
fn staged_write_advances_only_after_exact_successful_irp_terminal() {
    let mut trace = InstallPipeDiagnostic::<1>::new();
    let name = pipe_name("af990c70-ff1e-416f-b1aa-57a14d8ab3fa");
    assert!(trace.register_server(PIPE, &name));
    let first = 4u32.to_le_bytes();
    let irp = (7u64 << 40) | 0x21;
    assert!(trace.stage_server_write(PIPE, irp, &first));
    assert!(trace.complete_server_write(PIPE, (8u64 << 40) | 0x21, 0, 4).is_none());
    assert!(trace.complete_server_write(PIPE, irp, 0xc0000001, 0).is_none());
    assert_eq!(trace.counts().rejected, 1);
    assert!(trace.stage_server_write(PIPE, irp + 1, &first));
    assert!(trace.complete_server_write(PIPE, irp + 1, 0, 4).is_none());
    assert_eq!(trace.counts().published, 0, "only the fifth write may publish a device");
}
