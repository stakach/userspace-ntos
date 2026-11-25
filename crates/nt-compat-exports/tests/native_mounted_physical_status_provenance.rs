//! Execute the production native terminal-data body against controlled SCSI completions.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");

fn terminal_data_body() -> &'static str {
    let start = BLOCK
        .find("fn terminal_data<'a>(")
        .expect("production terminal_data");
    let tail = &BLOCK[start..];
    &tail[..tail.find("\nfn settle(").expect("end of terminal_data")]
}

fn work_claim_physical_body() -> &'static str {
    let start = BLOCK
        .find("    fn complete_physical(self, result:")
        .expect("production WorkClaim physical handoff");
    let tail = &BLOCK[start..];
    &tail[..tail
        .find("    fn complete_cached(")
        .expect("end of physical handoff")]
}

struct FixtureDir(PathBuf);

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn malformed_successful_sector_packet_keeps_distinct_failure_origin() {
    let dir = FixtureDir(std::env::temp_dir().join(format!(
        "nt-mounted-terminal-provenance-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    )));
    fs::create_dir(&dir.0).expect("create fixture directory");
    let source = dir.0.join("terminal_data.rs");
    let binary = dir.0.join("terminal_data_test");
    let mut fixture = String::from(PREFIX);
    fixture.push_str(terminal_data_body());
    fixture.push_str("\nimpl WorkClaim {\n");
    fixture.push_str(work_claim_physical_body());
    fixture.push_str("\n}\n");
    fixture.push_str(SUFFIX);
    fs::write(&source, fixture).expect("write extracted production fixture");

    let build = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .arg("--edition=2021")
        .arg("--test")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("compile extracted production body");
    assert!(
        build.status.success(),
        "production terminal-data fixture did not compile:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let run = Command::new(&binary)
        .arg("--nocapture")
        .output()
        .expect("run extracted production fixture");
    assert!(
        run.status.success(),
        "production terminal-data behavior failed:\n{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// The terminal-data fixture below establishes that an authenticated failing SCSI terminal
/// yields Provider(0xc000009a). Exercise that exact typed result through the real installed
/// READ owner. Its completion tuple is consumed by the mounted File IRP backend.
#[test]
fn authenticated_physical_failure_reaches_mounted_read_completion() {
    use nt_fs::{
        FatPathGeometry, FatRangeProgress, MountedSectorError, ReadCompletions, ReadError,
        ReadSectorClaim,
    };
    use nt_status::NtStatus;

    let mut reads = ReadCompletions::new();
    let geometry = FatPathGeometry {
        fat_start_sector: 1,
        data_start_sector: 2,
        total_sectors: 18,
        sectors_per_cluster: 1,
    };
    let irp = 0x52;
    reads
        .capture_range(irp, 7, 9, geometry, 2, 0, 512, None)
        .expect("capture one installed File READ");
    let claim = reads
        .claim_next_bounded(1)
        .expect("exact physical sector claim");
    assert_eq!((claim.irp, claim.mount, claim.file), (irp, 7, 9));
    assert_eq!(reads.next_completion(), None);
    assert_eq!(reads.ack(irp), Err(ReadError::NotPublished));

    let failure = MountedSectorError::Provider(NtStatus::INSUFFICIENT_RESOURCES);
    assert_eq!(
        reads.complete_sectors(
            ReadSectorClaim {
                generation: claim.generation + 1,
                ..claim
            },
            Err(failure)
        ),
        Err(ReadError::WrongClaim)
    );
    assert_eq!(reads.next_completion(), None);
    assert_eq!(
        reads.complete_sectors(claim, Err(failure)),
        Ok(FatRangeProgress::Complete)
    );
    assert_eq!(
        reads.complete_sectors(claim, Err(failure)),
        Err(ReadError::WrongClaim)
    );

    assert_eq!(
        reads.next_completion(),
        Some((irp, NtStatus::INSUFFICIENT_RESOURCES.raw(), 0))
    );
    assert_eq!(
        reads.next_completion(),
        None,
        "File IRP completion publishes once"
    );
    assert!(
        reads.has_outstanding(),
        "File IRP owner remains retained until ACK"
    );
    assert_eq!(reads.ack(irp + 1), Err(ReadError::WrongIdentity));
    assert!(reads.has_outstanding());
    reads.ack(irp).expect("exact File IRP ACK");
    assert!(!reads.has_outstanding());
}

const PREFIX: &str = r#"
#![allow(dead_code)]
use std::cell::RefCell;
use std::rc::Rc;
mod nt_status {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NtStatus(pub i32);
    impl NtStatus {
        pub const SUCCESS: Self = Self(0);
        pub const INSUFFICIENT_RESOURCES: Self = Self(0xc000009au32 as i32);
        pub const INVALID_DEVICE_REQUEST: Self = Self(0xc0000010u32 as i32);
        pub fn is_success(self) -> bool { self.0 >= 0 }
    }
}
mod nt_fs {
    use super::nt_status::NtStatus;
    pub const STATUS_DATA_ERROR: u32 = 0xc000003e;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FatPathError { Corrupt }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MountedSectorError { Provider(NtStatus), Fat(FatPathError), Transport }
    impl MountedSectorError {
        pub fn status(self) -> NtStatus {
            match self {
                Self::Provider(status) => status,
                Self::Fat(_) | Self::Transport => NtStatus(STATUS_DATA_ERROR as i32),
            }
        }
    }
}
mod nt_io_manager {
    pub mod scsi_srb_transport { #[derive(Clone, Copy)] pub struct ScsiSrbRoute; }
    pub mod scsi_block_command {
        #[derive(Clone, Copy)]
        pub enum BlockCommandKind { Read, Write, Flush, Capacity }
    }
}
use nt_io_manager::scsi_block_command::BlockCommandKind;
use nt_io_manager::scsi_srb_transport::ScsiSrbRoute;
#[derive(Clone, Copy)] struct IrpId(u64);
struct Terminal { status: nt_status::NtStatus, packet: Vec<u8> }
struct ScsiBlockCommand;
impl ScsiBlockCommand {
    fn kind(&self) -> BlockCommandKind { BlockCommandKind::Read }
    fn verify_completion(&self, srb: u8, len: usize) -> Result<(), ()> {
        if srb == 1 && len == 512 { Ok(()) } else { Err(()) }
    }
}
struct Decoded<'a> { srb: u8, data: &'a [u8] }
fn decode_scsi_completion<'a>(packet: &'a [u8], _: ScsiSrbRoute, _: IrpId)
    -> Result<Decoded<'a>, ()>
{
    if packet.len() != 513 { return Err(()); }
    Ok(Decoded { srb: packet[0], data: &packet[1..] })
}
struct SectorClaim(Rc<RefCell<Option<nt_fs::MountedSectorError>>>);
impl SectorClaim {
    fn complete_physical(self, result: Result<&[u8], nt_fs::MountedSectorError>) {
        *self.0.borrow_mut() = result.err();
    }
}
struct SnapshotClaim(Rc<RefCell<Option<nt_status::NtStatus>>>);
enum WorkClaim { Sector(SectorClaim), Snapshot(SnapshotClaim) }
impl WorkClaim {
    fn complete(self, result: Result<&[u8], nt_status::NtStatus>) {
        match self {
            Self::Snapshot(claim) => *claim.0.borrow_mut() = result.err(),
            Self::Sector(_) => panic!("physical sector error reached numeric snapshot path"),
        }
    }
}
"#;

const SUFFIX: &str = r#"
#[test]
fn authenticated_provider_failure_retains_its_exact_ntstatus() {
    let terminal = Terminal {
        status: nt_status::NtStatus::INSUFFICIENT_RESOURCES,
        packet: Vec::new(),
    };
    let failure: nt_fs::MountedSectorError =
        terminal_data(&ScsiBlockCommand, ScsiSrbRoute, IrpId(41), &terminal).unwrap_err();
    assert_eq!(failure, nt_fs::MountedSectorError::Provider(
        nt_status::NtStatus::INSUFFICIENT_RESOURCES));
    assert_eq!(failure.status(), nt_status::NtStatus::INSUFFICIENT_RESOURCES);
}

#[test]
fn malformed_successful_packet_is_data_error_without_provider_provenance() {
    let terminal = Terminal { status: nt_status::NtStatus::SUCCESS, packet: vec![0] };
    let failure: nt_fs::MountedSectorError =
        terminal_data(&ScsiBlockCommand, ScsiSrbRoute, IrpId(42), &terminal).unwrap_err();
    assert_eq!(failure, nt_fs::MountedSectorError::Transport);
    assert_eq!(failure.status(), nt_status::NtStatus(nt_fs::STATUS_DATA_ERROR as i32));
}

#[test]
fn invalid_successful_srb_is_data_error_without_provider_provenance() {
    let mut packet = vec![0; 513];
    packet[0] = 2;
    let terminal = Terminal { status: nt_status::NtStatus::SUCCESS, packet };
    let failure: nt_fs::MountedSectorError =
        terminal_data(&ScsiBlockCommand, ScsiSrbRoute, IrpId(43), &terminal).unwrap_err();
    assert_eq!(failure, nt_fs::MountedSectorError::Transport);
    assert_eq!(failure.status(), nt_status::NtStatus(nt_fs::STATUS_DATA_ERROR as i32));
}

#[test]
fn valid_successful_packet_reaches_sector_bytes() {
    let mut packet = vec![0; 513];
    packet[0] = 1;
    packet[1] = 0x5a;
    let terminal = Terminal { status: nt_status::NtStatus::SUCCESS, packet };
    let bytes = terminal_data(&ScsiBlockCommand, ScsiSrbRoute, IrpId(44), &terminal).unwrap();
    assert_eq!(bytes.len(), 512);
    assert_eq!(bytes[0], 0x5a);
}

#[test]
fn physical_sector_handoff_retains_provider_and_transport_origins() {
    let provider = Rc::new(RefCell::new(None));
    WorkClaim::Sector(SectorClaim(provider.clone())).complete_physical(
        Err(nt_fs::MountedSectorError::Provider(
            nt_status::NtStatus::INSUFFICIENT_RESOURCES)));
    assert_eq!(*provider.borrow(), Some(nt_fs::MountedSectorError::Provider(
        nt_status::NtStatus::INSUFFICIENT_RESOURCES)));

    let transport = Rc::new(RefCell::new(None));
    WorkClaim::Sector(SectorClaim(transport.clone())).complete_physical(
        Err(nt_fs::MountedSectorError::Transport));
    assert_eq!(*transport.borrow(), Some(nt_fs::MountedSectorError::Transport));
}

#[test]
fn physical_snapshot_handoff_converts_only_at_its_numeric_owner_boundary() {
    let provider = Rc::new(RefCell::new(None));
    WorkClaim::Snapshot(SnapshotClaim(provider.clone())).complete_physical(
        Err(nt_fs::MountedSectorError::Provider(
            nt_status::NtStatus::INSUFFICIENT_RESOURCES)));
    assert_eq!(*provider.borrow(), Some(nt_status::NtStatus::INSUFFICIENT_RESOURCES));

    let transport = Rc::new(RefCell::new(None));
    WorkClaim::Snapshot(SnapshotClaim(transport.clone())).complete_physical(
        Err(nt_fs::MountedSectorError::Transport));
    assert_eq!(*transport.borrow(), Some(nt_status::NtStatus(nt_fs::STATUS_DATA_ERROR as i32)));
}
"#;
