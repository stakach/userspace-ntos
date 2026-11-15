use super::*;
use alloc::vec;

fn create_info(init_flags: u32, additional_access: u32) -> [u8; PS_CREATE_INFO_SIZE] {
    let mut bytes = [0u8; PS_CREATE_INFO_SIZE];
    bytes[..8].copy_from_slice(&(PS_CREATE_INFO_SIZE as u64).to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&init_flags.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&additional_access.to_le_bytes());
    bytes
}

fn attribute_list(entries: &[(u64, u64, u64)]) -> Vec<u8> {
    let total = PS_ATTRIBUTE_LIST_HEADER + entries.len() * PS_ATTRIBUTE_SIZE;
    let mut bytes = (total as u64).to_le_bytes().to_vec();
    for (attribute, size, value) in entries {
        bytes.extend_from_slice(&attribute.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
    }
    bytes
}

// kernel32's combined constants: number | PS_ATTRIBUTE_INPUT (0x20000) | THREAD (0x10000) |
// ADDITIVE (0x40000).
const IMAGE_NAME: u64 = PS_ATTRIBUTE_IMAGE_NAME | 0x2_0000;
const CLIENT_ID: u64 = PS_ATTRIBUTE_CLIENT_ID | 0x1_0000;
const IMAGE_INFO: u64 = PS_ATTRIBUTE_IMAGE_INFO;
const TOKEN: u64 = PS_ATTRIBUTE_TOKEN | 0x6_0000;

#[test]
fn create_info_must_be_the_exact_initial_structure() {
    assert_eq!(decode_create_info(&create_info(0, 0)), Ok(CreateInfoInput::default()));
    assert_eq!(
        decode_create_info(&create_info(0x2000_0001, 0x80)),
        Ok(CreateInfoInput {
            write_output_on_exit: true,
            prohibited_image_characteristics: 0x2000,
            additional_file_access: 0x80,
        })
    );
    let mut wrong_size = create_info(0, 0);
    wrong_size[0] = 0x48;
    assert_eq!(decode_create_info(&wrong_size), Err(STATUS_INVALID_PARAMETER));
    let mut not_initial = create_info(0, 0);
    not_initial[8] = PS_CREATE_SUCCESS as u8;
    assert_eq!(decode_create_info(&not_initial), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(decode_create_info(&[0u8; 0x40]), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn the_attribute_list_kernel32_builds_for_a_user_token_decodes() {
    let list = attribute_list(&[
        (IMAGE_NAME, 70, 0x1000),
        (CLIENT_ID, 16, 0x2000),
        (IMAGE_INFO, 0x40, 0x3000),
        (TOKEN, 8, 0x1a4),
    ]);
    assert_eq!(
        decode_attribute_list(&list),
        Ok(Attributes {
            image_name: (0x1000, 70),
            parent_process: None,
            debug_port: 0,
            token: Some(0x1a4),
            client_id_out: 0x2000,
            image_info_out: 0x3000,
        })
    );
}

#[test]
fn an_attribute_list_needs_a_whole_image_name() {
    assert_eq!(decode_attribute_list(&[0u8; 8]), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        decode_attribute_list(&attribute_list(&[(CLIENT_ID, 16, 0x2000)])),
        Err(STATUS_INVALID_PARAMETER)
    );
    for (size, value) in [(0, 0x1000), (7, 0x1000), (8, 0), (0x1_0000, 0x1000)] {
        assert_eq!(
            decode_attribute_list(&attribute_list(&[(IMAGE_NAME, size, value)])),
            Err(STATUS_INVALID_PARAMETER),
            "size={size} value={value:#x}"
        );
    }
}

#[test]
fn attributes_that_would_change_the_process_are_refused_not_dropped() {
    for number in [
        PS_ATTRIBUTE_HANDLE_LIST,
        PS_ATTRIBUTE_MITIGATION_OPTIONS,
        PS_ATTRIBUTE_CHILD_PROCESS_POLICY,
        PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        PS_ATTRIBUTE_BNO_ISOLATION,
        PS_ATTRIBUTE_COMPONENT_FILTER,
    ] {
        let list = attribute_list(&[(IMAGE_NAME, 8, 0x1000), (number | 0x2_0000, 8, 0x4000)]);
        assert_eq!(decode_attribute_list(&list), Err(STATUS_NOT_SUPPORTED), "attribute {number}");
    }
    // The pinned kernel ignores attribute numbers it does not know (here PsAttributeTebAddress
    // and PsAttributeJobList, which kernel32 applies itself after the call).
    let list = attribute_list(&[(IMAGE_NAME, 8, 0x1000), (4 | 0x1_0000, 8, 0x4000), (19, 8, 0)]);
    assert!(decode_attribute_list(&list).is_ok());
}

#[derive(Default)]
struct Recorder {
    calls: Vec<alloc::string::String>,
    fail: Option<(&'static str, u32)>,
    open_denied_with: Option<u32>,
    image_characteristics: u16,
}

impl Recorder {
    fn step(&mut self, name: &'static str, detail: alloc::string::String) -> Result<(), u32> {
        self.calls.push(alloc::format!("{name}{detail}"));
        match self.fail {
            Some((failing, status)) if failing == name => Err(status),
            _ => Ok(()),
        }
    }
}

impl UserProcessOps for Recorder {
    fn open_image(&mut self, name: &[u16], access: u32) -> Result<u64, u32> {
        let name = alloc::string::String::from_utf16_lossy(name);
        self.step("open", alloc::format!("({name},{access:#x})"))?;
        if self.open_denied_with == Some(access) {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(0x10)
    }
    fn create_image_section(&mut self, file: u64) -> Result<u64, u32> {
        self.step("section", alloc::format!("({file:#x})"))?;
        Ok(0x20)
    }
    fn create_process(
        &mut self,
        access: u32,
        object_attributes: u64,
        parent: Option<u64>,
        flags: u32,
        section: u64,
        debug_port: u64,
    ) -> Result<u64, u32> {
        self.step(
            "process",
            alloc::format!(
                "({access:#x},{object_attributes:#x},{parent:?},{flags:#x},{section:#x},{debug_port:#x})"
            ),
        )?;
        Ok(0x30)
    }
    fn query_image(&mut self, section: u64) -> Result<ImageInformation, u32> {
        self.step("image", alloc::format!("({section:#x})"))?;
        let mut bytes = [0u8; SECTION_IMAGE_INFORMATION_SIZE];
        bytes[..8].copy_from_slice(&0x1_4000_1000u64.to_le_bytes());
        bytes[0x20..0x24].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x2c..0x2e].copy_from_slice(&self.image_characteristics.to_le_bytes());
        bytes[0x2e..0x30].copy_from_slice(&0x8160u16.to_le_bytes());
        Ok(ImageInformation { bytes })
    }
    fn query_peb(&mut self, process: u64) -> Result<u64, u32> {
        self.step("peb", alloc::format!("({process:#x})"))?;
        Ok(0x7ff_d000)
    }
    fn assign_primary_token(&mut self, process: u64, token: u64) -> Result<(), u32> {
        self.step("token", alloc::format!("({process:#x},{token:#x})"))
    }
    fn write_parameters(
        &mut self,
        process: u64,
        peb: u64,
        _image: &ImageInformation,
        parameters: u64,
    ) -> Result<u64, u32> {
        self.step("parameters", alloc::format!("({process:#x},{peb:#x},{parameters:#x})"))?;
        Ok(0x2_0000)
    }
    fn create_initial_thread(
        &mut self,
        process: u64,
        access: u32,
        object_attributes: u64,
        image: &ImageInformation,
        peb: u64,
        suspended: bool,
    ) -> Result<(u64, [u64; 2]), u32> {
        self.step(
            "thread",
            alloc::format!(
                "({process:#x},{access:#x},{object_attributes:#x},{:#x},{peb:#x},{suspended})",
                image.transfer_address()
            ),
        )?;
        Ok((0x40, [0x148, 0x14c]))
    }
    fn terminate_process(&mut self, process: u64, status: u32) {
        self.calls.push(alloc::format!("terminate({process:#x},{status:#x})"));
    }
    fn close(&mut self, handle: u64) {
        self.calls.push(alloc::format!("close({handle:#x})"));
    }
}

const NAME: &[u16] = &[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16, b'u' as u16];

fn request(token: Option<u64>) -> Request<'static> {
    Request {
        image_name: NAME,
        process_access: 0x1f_ffff,
        thread_access: 0x1f_03ff,
        process_object_attributes: 0x500,
        thread_object_attributes: 0x600,
        process_flags: 0,
        thread_flags: THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        process_parameters: 0x7000,
        create_info: CreateInfoInput::default(),
        attributes: Attributes { token, ..Attributes::default() },
    }
}

#[test]
fn a_process_under_a_user_token_is_built_in_kernel_order_with_the_token_before_any_thread() {
    let mut ops = Recorder::default();
    let created = create_user_process(&mut ops, &request(Some(0x1a4))).unwrap();
    assert_eq!(
        ops.calls,
        vec![
            "open(\\??\\u,0x100020)",
            "section(0x10)",
            "process(0x1fffff,0x500,None,0x0,0x20,0x0)",
            "image(0x20)",
            "peb(0x30)",
            "token(0x30,0x1a4)",
            "parameters(0x30,0x7ffd000,0x7000)",
            "thread(0x30,0x1f03ff,0x600,0x140001000,0x7ffd000,true)",
            "close(0x20)",
            "close(0x10)",
        ]
    );
    assert_eq!(created.process, 0x30);
    assert_eq!(created.thread, 0x40);
    assert_eq!(created.client_id, [0x148, 0x14c]);
    assert_eq!((created.file, created.section), (0, 0));
    assert_eq!((created.parameters, created.peb), (0x2_0000, 0x7ff_d000));

    let mut info = create_info(0, 0);
    encode_success(&mut info, &created);
    assert_eq!(read_u64(&info, 0), PS_CREATE_INFO_SIZE as u64);
    assert_eq!(read_u32(&info, 8), PS_CREATE_SUCCESS);
    assert_eq!(read_u64(&info, 0x28), 0x2_0000);
    assert_eq!(read_u64(&info, 0x38), 0x7ff_d000);
}

#[test]
fn no_token_and_no_parameters_skip_those_services() {
    let mut ops = Recorder::default();
    let mut request = request(None);
    request.process_parameters = 0;
    request.thread_flags = 0;
    request.attributes.parent_process = Some(0x88);
    request.attributes.debug_port = 0x99;
    request.process_flags = 0x4;
    let created = create_user_process(&mut ops, &request).unwrap();
    assert_eq!(created.parameters, 0);
    assert_eq!(
        ops.calls[2..6],
        [
            "process(0x1fffff,0x500,Some(136),0x4,0x20,0x99)",
            "image(0x20)",
            "peb(0x30)",
            "thread(0x30,0x1f03ff,0x600,0x140001000,0x7ffd000,false)",
        ]
    );
}

#[test]
fn a_failure_after_the_process_exists_terminates_it_and_closes_every_handle() {
    for (step, expected) in [
        ("image", Step::QueryImage),
        ("peb", Step::QueryProcess),
        ("token", Step::AssignToken),
        ("parameters", Step::WriteParameters),
        ("thread", Step::CreateThread),
    ] {
        let mut ops = Recorder { fail: Some((step, 0xC000_0061)), ..Recorder::default() };
        let failure = create_user_process(&mut ops, &request(Some(0x1a4))).unwrap_err();
        assert_eq!(
            failure,
            Failure {
                status: 0xC000_0061,
                step: expected,
                state: None,
                file: 0,
                dll_characteristics: 0
            }
        );
        let tail = &ops.calls[ops.calls.len() - 4..];
        assert_eq!(
            tail,
            ["terminate(0x30,0xc0000061)", "close(0x30)", "close(0x20)", "close(0x10)"],
            "{step}"
        );
        // A failed step is the last service of the sequence proper.
        assert!(ops.calls[ops.calls.len() - 5].starts_with(step), "{step}");

        let mut info = create_info(0, 0);
        encode_failure(&mut info, &failure);
        assert_eq!(info, create_info(0, 0), "a later failure reports no creation state");
    }
}

#[test]
fn a_refused_process_closes_the_image_handles_and_terminates_nothing() {
    let mut ops = Recorder { fail: Some(("process", 0xC000_009A)), ..Recorder::default() };
    let failure = create_user_process(&mut ops, &request(None)).unwrap_err();
    assert_eq!((failure.status, failure.step), (0xC000_009A, Step::CreateProcess));
    assert_eq!(ops.calls[3..], ["close(0x20)", "close(0x10)"]);
}

#[test]
fn open_and_section_failures_report_their_creation_state() {
    let mut ops = Recorder { fail: Some(("open", 0xC000_0034)), ..Recorder::default() };
    let failure = create_user_process(&mut ops, &request(None)).unwrap_err();
    assert_eq!(failure.state, Some(PS_CREATE_FAIL_ON_FILE_OPEN));
    assert_eq!(ops.calls.len(), 1);
    let mut info = create_info(0, 0);
    encode_failure(&mut info, &failure);
    assert_eq!(read_u32(&info, 8), PS_CREATE_FAIL_ON_FILE_OPEN);
    assert_eq!(read_u64(&info, 0x10), 0);

    let mut ops = Recorder { fail: Some(("section", 0xC000_007B)), ..Recorder::default() };
    let failure = create_user_process(&mut ops, &request(None)).unwrap_err();
    assert_eq!(
        (failure.status, failure.state, failure.file),
        (0xC000_007B, Some(PS_CREATE_FAIL_ON_SECTION_CREATE), 0)
    );
    assert_eq!(ops.calls[2..], ["close(0x10)"]);

    // With WriteOutputOnExit the caller receives the image File of a failed section.
    let mut ops = Recorder { fail: Some(("section", 0xC000_007B)), ..Recorder::default() };
    let mut with_output = request(None);
    with_output.create_info.write_output_on_exit = true;
    let failure = create_user_process(&mut ops, &with_output).unwrap_err();
    assert_eq!(failure.file, 0x10);
    assert_eq!(ops.calls.len(), 2);
    let mut info = create_info(1, 0);
    encode_failure(&mut info, &failure);
    assert_eq!(read_u32(&info, 8), PS_CREATE_FAIL_ON_SECTION_CREATE);
    assert_eq!(read_u64(&info, 0x10), 0x10);
}

#[test]
fn write_output_on_exit_returns_the_image_handles_and_retries_a_denied_wider_open() {
    let mut ops = Recorder { open_denied_with: Some(0x10_00a0), ..Recorder::default() };
    let mut request = request(None);
    request.create_info =
        CreateInfoInput { write_output_on_exit: true, additional_file_access: 0x80, ..Default::default() };
    let created = create_user_process(&mut ops, &request).unwrap();
    assert_eq!(ops.calls[..2], ["open(\\??\\u,0x1000a0)", "open(\\??\\u,0x100020)"]);
    assert_eq!((created.file, created.section), (0x10, 0x20));
    assert!(!ops.calls.iter().any(|call| call.starts_with("close")));
    let mut info = create_info(1, 0x80);
    encode_success(&mut info, &created);
    assert_eq!((read_u64(&info, 0x18), read_u64(&info, 0x20)), (0x10, 0x20));
}

#[test]
fn a_prohibited_image_fails_as_an_exe_format_error() {
    let mut ops = Recorder { image_characteristics: 0x2022, ..Recorder::default() };
    let mut request = request(None);
    request.create_info.prohibited_image_characteristics = 0x2000; // IMAGE_FILE_DLL
    let failure = create_user_process(&mut ops, &request).unwrap_err();
    assert_eq!(
        (failure.status, failure.step, failure.state, failure.dll_characteristics),
        (
            STATUS_INVALID_IMAGE_FORMAT,
            Step::ImageCharacteristics,
            Some(PS_CREATE_FAIL_EXE_FORMAT),
            0x8160
        )
    );
    assert_eq!(ops.calls[ops.calls.len() - 4], "terminate(0x30,0xc000007b)");
    let mut info = create_info(0x2000_0000, 0);
    encode_failure(&mut info, &failure);
    assert_eq!(read_u32(&info, 8), PS_CREATE_FAIL_EXE_FORMAT);
    assert_eq!(read_u16(&info, 0x10), 0x8160);
}

#[test]
fn illegal_process_flags_and_an_empty_name_touch_nothing() {
    for (flags, name) in [(0x20, NAME), (0, &[][..])] {
        let mut ops = Recorder::default();
        let mut request = request(None);
        request.process_flags = flags;
        request.image_name = name;
        let failure = create_user_process(&mut ops, &request).unwrap_err();
        assert_eq!((failure.status, failure.step), (STATUS_INVALID_PARAMETER, Step::Arguments));
        assert!(ops.calls.is_empty());
    }
}

#[test]
fn the_failure_record_names_the_step_and_status() {
    let failure = Failure {
        status: 0xC000_0061,
        step: Step::AssignToken,
        state: None,
        file: 0,
        dll_characteristics: 0,
    };
    let record = failure_record(&failure);
    assert_eq!(
        record.bytes(),
        b"[nt-create-user-process-failed] step=assign-token status=0xc0000061\n"
    );
    assert!(!record.overflowed());
}

#[test]
fn the_child_block_is_denormalized_and_points_at_the_child_environment() {
    use crate::rtl::process_params::{self, ParamString, ParamsInput};
    let image: Vec<u16> = "C:\\Windows\\system32\\userinit.exe".encode_utf16().collect();
    let desktop: Vec<u16> = "WinSta0\\Default".encode_utf16().collect();
    let built = process_params::create_process_parameters(&ParamsInput {
        image_path_name: ParamString::new(&image),
        command_line: ParamString::new(&image),
        desktop_info: ParamString::new(&desktop),
        ..ParamsInput::default()
    });
    let denormalized = built.block.clone();
    // The caller (kernel32) normalizes its block at the address it lives at.
    let caller_address = 0x1_0000_3000u64;
    let mut caller = built.block;
    process_params::set_environment_pointer(&mut caller, 0x1_0000_9000);
    process_params::normalize(&mut caller, caller_address);
    assert_ne!(caller, denormalized);

    let child = child_parameter_block(&caller, caller_address, 0x2_0000);
    assert_eq!(process_params::environment_pointer(&child), 0x2_0000);
    let mut expected = denormalized;
    process_params::set_environment_pointer(&mut expected, 0x2_0000);
    assert_eq!(child, expected, "the strings are block-relative again and the flag is clear");
}
