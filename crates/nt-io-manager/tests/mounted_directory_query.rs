//! NtQueryDirectoryFile on a canonical mounted directory File, through the contract the native
//! path uses: canonical CREATE of a directory File, a typed IRP_MJ_DIRECTORY_CONTROL built by
//! `build_and_dispatch_external_to_device_with_stack_flags`, provider admission through
//! `DirectoryQueryRequest`, the layered FAT+overlay union, and the per-File cursor. The
//! completed status/information pair is exactly what the native ingress writes to the IOSB.

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use nt_io_abi::major;
use nt_io_manager::{
    completion_output_transfer_len, CreateOptions, CreateParameters, DeviceCharacteristics,
    DeviceFlags, DeviceId, DeviceType, DirectoryQueryParameters, DirectoryQueryRequest,
    DispatchContext, DispatchOutcome, DriverDispatchBackend, ExternalDispatchResult, FileId,
    IoManager, IoParameters, IrpId, IrpProjection, MockObjectPort, ShareAccess, StackFlags,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, NtPath, UnicodeString};

const FILE_LIST_DIRECTORY: u32 = 0x0001;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

fn entry(name: &str, short: &str, file_id: u64, size: u64, attributes: u32) -> nt_fs::DirectoryEntry {
    let mut entry = nt_fs::DirectoryEntry {
        file_id,
        end_of_file: size,
        allocation_size: size.next_multiple_of(4096),
        attributes,
        last_write_time: 0x01d0_0000_0000_0000 + file_id,
        ..nt_fs::DirectoryEntry::default()
    };
    assert!(entry.set_name(&name.encode_utf16().collect::<Vec<_>>()));
    assert!(entry.set_short_name(&short.encode_utf16().collect::<Vec<_>>()));
    entry
}

/// The `Fonts` directory as the mounted provider sees it: the installed FAT stream (with one
/// file shadowed by the writable overlay) unioned with an overlay-only child.
fn fonts_listing() -> Vec<nt_fs::DirectoryEntry> {
    let installed = [
        entry(".", "", 1, 0, FILE_ATTRIBUTE_DIRECTORY),
        entry("..", "", 2, 0, FILE_ATTRIBUTE_DIRECTORY),
        entry("arial.ttf", "ARIAL.TTF", 3, 367_112, FILE_ATTRIBUTE_ARCHIVE),
        entry("tahoma.ttf", "TAHOMA.TTF", 4, 1000, FILE_ATTRIBUTE_ARCHIVE),
    ];
    let overlay = [
        entry("TAHOMA.TTF", "", 40, 2000, FILE_ATTRIBUTE_ARCHIVE),
        entry("user font.ttf", "USERFO~1.TTF", 50, 77, FILE_ATTRIBUTE_ARCHIVE),
    ];
    nt_fs::merge_layered_directory_entries(&installed, &overlay).unwrap()
}

#[derive(Default)]
struct Opened {
    directory: bool,
    granted: u32,
    cursor: nt_fs::DirectoryQueryState,
}

#[derive(Default)]
struct Volume {
    opens: HashMap<FileId, Opened>,
}

struct MountedBackend(Rc<RefCell<Volume>>);

impl DriverDispatchBackend for MountedBackend {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        let file = irp.file_id.ok_or(NtStatus::INVALID_PARAMETER)?;
        let mut volume = self.0.borrow_mut();
        match (irp.major, &irp.parameters) {
            (major::IRP_MJ_CREATE, IoParameters::Create(create)) => {
                volume.opens.insert(file, Opened {
                    directory: create.create_options.contains(CreateOptions::DIRECTORY_FILE),
                    granted: create.desired_access.bits(),
                    cursor: nt_fs::DirectoryQueryState::new(),
                });
                Ok(DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS, information: 1, file_context: Some(file.raw()),
                })
            }
            (major::IRP_MJ_DIRECTORY_CONTROL, _) => {
                let open = volume.opens.get_mut(&file).ok_or(NtStatus::INVALID_HANDLE)?;
                let request = DirectoryQueryRequest::admit(
                    irp, open.directory, open.granted, ctx.system_buffer.len(),
                )?;
                let length = request.length();
                let result = request.query(&mut open.cursor, &fonts_listing(),
                    &mut ctx.system_buffer[..length]);
                Ok(DispatchOutcome::Completed {
                    status: NtStatus(result.status as i32),
                    information: result.information as u64,
                    file_context: None,
                })
            }
            _ => Err(NtStatus::INVALID_DEVICE_REQUEST),
        }
    }

    fn cancel_irp(&mut self, _: IrpId) -> Result<(), NtStatus> {
        panic!("the inline provider never retains a query")
    }
}

struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
    device: DeviceId,
}

impl Fixture {
    fn new() -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        // Like the mounted volume, register exactly the majors the provider implements.
        let driver = io.create_kernel_driver_with_majors(
            &NtPath::parse_str(r"\Driver\MountedVolumeQueryProof").unwrap(),
            Box::new(MountedBackend(Rc::default())),
            &[major::IRP_MJ_CREATE, major::IRP_MJ_DIRECTORY_CONTROL],
        ).unwrap();
        let device = io.create_device(driver, None, DeviceType::DISK_FILE_SYSTEM,
            DeviceCharacteristics::empty(), DeviceFlags::BUFFERED_IO, 0).unwrap();
        Self { io, client, device }
    }

    fn open(&mut self, name: &str, access: u32, options: CreateOptions) -> FileId {
        let access = AccessMask::from_bits_retain(access);
        let file = self.io.allocate_external_file(self.client, self.device, access,
            ShareAccess::READ | ShareAccess::WRITE, options, UnicodeString::from_str(name)).unwrap();
        let created = self.io.build_and_dispatch_external_to_device(
            self.client, self.device, Some(file), 0, 0, major::IRP_MJ_CREATE,
            IoParameters::Create(CreateParameters {
                desired_access: access,
                share_access: ShareAccess::READ | ShareAccess::WRITE,
                create_options: options,
                create_disposition: nt_fs::FILE_OPEN,
                ..CreateParameters::default()
            }), 0, 0, &mut [],
        ).unwrap();
        assert!(matches!(created, ExternalDispatchResult::Completed { status: NtStatus::SUCCESS, .. }));
        file
    }

    /// The IoStatus pair and the copied user output, as the native ingress delivers them.
    fn query(&mut self, file: FileId, class: u32, length: u32, flags: StackFlags,
        pattern: Option<&str>) -> Result<(NtStatus, u64, Vec<u8>), NtStatus>
    {
        let mut buffer = vec![0xccu8; length as usize];
        let result = self.io.build_and_dispatch_external_to_device_with_stack_flags(
            self.client, self.device, Some(file), 0, 7, major::IRP_MJ_DIRECTORY_CONTROL,
            IoParameters::QueryDirectory(DirectoryQueryParameters {
                length, information_class: class, file_index: 0,
                pattern: pattern.map(UnicodeString::from_str),
            }), flags, 0, length, &mut buffer,
        )?;
        let ExternalDispatchResult::Completed { status, information, .. } = result else {
            panic!("the inline provider completes the query");
        };
        let copied = completion_output_transfer_len(information, u64::from(length)) as usize;
        buffer.truncate(copied);
        Ok((status, information, buffer))
    }
}

struct Record { next: u32, name: String, end_of_file: u64, attributes: u32, short: Option<String> }

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn utf16(bytes: &[u8]) -> String {
    String::from_utf16(&bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect::<Vec<_>>()).unwrap()
}

/// Walk NextEntryOffset exactly as a Win32 caller does, checking 8-byte record alignment.
fn records(class: u32, output: &[u8]) -> Vec<Record> {
    let (length_at, name_at) = match class {
        nt_fs::FILE_DIRECTORY_INFORMATION => (60, 64),
        nt_fs::FILE_BOTH_DIRECTORY_INFORMATION => (60, 94),
        nt_fs::FILE_NAMES_INFORMATION => (8, 12),
        _ => unreachable!(),
    };
    let mut records = Vec::new();
    let mut offset = 0usize;
    loop {
        assert_eq!(offset % 8, 0, "records are 8-byte aligned");
        let record = &output[offset..];
        let next = u32_at(record, 0);
        let name_length = u32_at(record, length_at) as usize;
        let name = utf16(&record[name_at..name_at + name_length]);
        let fixed = class != nt_fs::FILE_NAMES_INFORMATION;
        let short = (class == nt_fs::FILE_BOTH_DIRECTORY_INFORMATION).then(|| {
            let short_length = record[68] as usize;
            utf16(&record[70..70 + short_length])
        });
        if next != 0 {
            assert_eq!(next as usize, (name_at + name_length).next_multiple_of(8),
                "NextEntryOffset is the aligned record stride");
        } else {
            assert_eq!(output.len(), offset + name_at + name_length,
                "IoStatus.Information ends at the last record's name");
        }
        records.push(Record {
            next,
            name,
            end_of_file: if fixed { u64::from_le_bytes(record[40..48].try_into().unwrap()) } else { 0 },
            attributes: if fixed { u32_at(record, 56) } else { 0 },
            short,
        });
        if next == 0 { return records; }
        offset += next as usize;
    }
}

const ACCESS: u32 = FILE_LIST_DIRECTORY | SYNCHRONIZE;

#[test]
fn full_scan_packs_directory_information_and_then_reports_no_more_files() {
    let mut fixture = Fixture::new();
    let fonts = fixture.open(r"\ReactOS\Fonts", ACCESS, CreateOptions::DIRECTORY_FILE);
    let (status, information, output) = fixture.query(fonts, nt_fs::FILE_DIRECTORY_INFORMATION,
        4096, StackFlags::RESTART_SCAN, None).unwrap();
    assert_eq!(status, NtStatus::SUCCESS);
    assert_eq!(information as usize, output.len());
    let listed = records(nt_fs::FILE_DIRECTORY_INFORMATION, &output);
    assert_eq!(listed.iter().map(|record| record.name.as_str()).collect::<Vec<_>>(),
        [".", "..", "arial.ttf", "TAHOMA.TTF", "user font.ttf"],
        "installed order, overlay shadowing in place, overlay-only children appended");
    assert_eq!(listed[2].end_of_file, 367_112);
    assert_eq!(listed[3].end_of_file, 2000, "the overlay copy shadows the installed file");
    assert_eq!(listed[0].attributes, FILE_ATTRIBUTE_DIRECTORY);
    assert_eq!(listed[4].attributes, FILE_ATTRIBUTE_ARCHIVE);
    assert_eq!(listed.last().unwrap().next, 0);

    let (status, information, output) = fixture.query(fonts, nt_fs::FILE_DIRECTORY_INFORMATION,
        4096, StackFlags::empty(), None).unwrap();
    assert_eq!((status.raw() as u32, information), (nt_fs::STATUS_NO_MORE_FILES, 0));
    assert!(output.is_empty(), "no bytes are delivered with an exhausted cursor");

    let (status, _, output) = fixture.query(fonts, nt_fs::FILE_DIRECTORY_INFORMATION,
        4096, StackFlags::RESTART_SCAN, None).unwrap();
    assert_eq!(status, NtStatus::SUCCESS, "RESTART_SCAN rewinds the per-File cursor");
    assert_eq!(records(nt_fs::FILE_DIRECTORY_INFORMATION, &output).len(), 5);
}

#[test]
fn single_entry_and_pattern_queries_advance_one_cursor_per_file() {
    let mut fixture = Fixture::new();
    let fonts = fixture.open(r"\ReactOS\Fonts", ACCESS, CreateOptions::DIRECTORY_FILE);
    let other = fixture.open(r"\ReactOS\Fonts", ACCESS, CreateOptions::DIRECTORY_FILE);
    let single = StackFlags::RETURN_SINGLE_ENTRY;
    let mut names = Vec::new();
    for flags in [single | StackFlags::RESTART_SCAN, single, single] {
        let (status, information, output) = fixture.query(fonts, nt_fs::FILE_NAMES_INFORMATION,
            256, flags, Some("*.ttf")).unwrap();
        assert_eq!(status, NtStatus::SUCCESS);
        let listed = records(nt_fs::FILE_NAMES_INFORMATION, &output);
        assert_eq!((listed.len(), information as usize), (1, output.len()));
        names.push(listed[0].name.clone());
    }
    assert_eq!(names, ["arial.ttf", "TAHOMA.TTF", "user font.ttf"]);
    let (status, information, _) = fixture.query(fonts, nt_fs::FILE_NAMES_INFORMATION, 256,
        single, None).unwrap();
    assert_eq!((status.raw() as u32, information), (nt_fs::STATUS_NO_MORE_FILES, 0),
        "the first query's pattern stays bound to the cursor");

    let (status, _, output) = fixture.query(other, nt_fs::FILE_BOTH_DIRECTORY_INFORMATION,
        4096, StackFlags::RESTART_SCAN, Some("USERFO~1.TTF")).unwrap();
    assert_eq!(status, NtStatus::SUCCESS, "another File's cursor is independent");
    let listed = records(nt_fs::FILE_BOTH_DIRECTORY_INFORMATION, &output);
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].name.as_str(), listed[0].short.as_deref()),
        ("user font.ttf", Some("USERFO~1.TTF")), "short names match and are packed");

    let fresh = fixture.open(r"\ReactOS\Fonts", ACCESS, CreateOptions::DIRECTORY_FILE);
    let (status, information, _) = fixture.query(fresh, nt_fs::FILE_NAMES_INFORMATION, 256,
        StackFlags::RESTART_SCAN, Some("*.fon")).unwrap();
    assert_eq!((status.raw() as u32, information), (nt_fs::STATUS_NO_SUCH_FILE, 0),
        "an initial scan with no match is NO_SUCH_FILE, not NO_MORE_FILES");
}

#[test]
fn a_record_larger_than_the_buffer_overflows_without_advancing() {
    let mut fixture = Fixture::new();
    let fonts = fixture.open(r"\ReactOS\Fonts", ACCESS, CreateOptions::DIRECTORY_FILE);
    let length = nt_fs::directory_query_minimum_length(nt_fs::FILE_DIRECTORY_INFORMATION).unwrap();
    let (status, _, _) = fixture.query(fonts, nt_fs::FILE_DIRECTORY_INFORMATION, length as u32,
        StackFlags::RESTART_SCAN, Some("user font.ttf")).unwrap();
    assert_eq!(status.raw() as u32, nt_fs::STATUS_BUFFER_OVERFLOW);
    let (status, _, output) = fixture.query(fonts, nt_fs::FILE_DIRECTORY_INFORMATION, 4096,
        StackFlags::empty(), None).unwrap();
    assert_eq!(status, NtStatus::SUCCESS, "the truncated record is returned again");
    assert_eq!(records(nt_fs::FILE_DIRECTORY_INFORMATION, &output)[0].name, "user font.ttf");
}

#[test]
fn provider_admission_refuses_requests_it_cannot_honour_exactly() {
    let mut fixture = Fixture::new();
    let fonts = fixture.open(r"\ReactOS\Fonts", ACCESS, CreateOptions::DIRECTORY_FILE);
    let file = fixture.open(r"\ReactOS\Fonts\arial.ttf", ACCESS, CreateOptions::NON_DIRECTORY_FILE);
    let unlisted = fixture.open(r"\ReactOS\Fonts", SYNCHRONIZE, CreateOptions::DIRECTORY_FILE);
    // A provider refusal is the IRP's terminal IoStatus with no information or output.
    let mut refused = |file, flags| {
        let (status, information, output) = fixture.query(file, nt_fs::FILE_DIRECTORY_INFORMATION,
            4096, flags, None).unwrap();
        assert_eq!((information, output.len()), (0, 0));
        status
    };
    assert_eq!(refused(fonts, StackFlags::INDEX_SPECIFIED), NtStatus::NOT_SUPPORTED,
        "positional queries stay explicit until seek semantics exist");
    assert_eq!(refused(file, StackFlags::RESTART_SCAN), NtStatus::INVALID_DEVICE_REQUEST);
    assert_eq!(refused(unlisted, StackFlags::RESTART_SCAN), NtStatus::ACCESS_DENIED);
}
