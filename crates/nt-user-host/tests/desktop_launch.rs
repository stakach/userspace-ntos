use nt_user_host::desktop_launch::{
    capture_desktop_launch_contract, DesktopLaunchContract, SetupValue,
};

fn value<'a>(name: &'a str, value_type: u32, data: &'a [u8]) -> SetupValue<'a> {
    SetupValue {
        name,
        value_type,
        data,
    }
}

#[test]
fn installed_and_media_contracts_come_from_one_immutable_snapshot() {
    let mut zero = 0u32.to_le_bytes();
    let one = 1u32.to_le_bytes();
    let other_setup = 9u32.to_le_bytes();
    let command: Vec<u8> = "setup.exe\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let captured = capture_desktop_launch_contract([
        value("SystemSetupInProgress", 4, &zero),
        value("SetupType", 4, &zero),
    ]);
    assert_eq!(captured, DesktopLaunchContract::InstalledLogon);
    zero.copy_from_slice(&one);
    // ReactOS winlogon/setup.c GetSetupType treats every nonzero DWORD as setup; RunSetup
    // accepts REG_SZ or REG_EXPAND_SZ CmdLine. This classifier changes no registry or NT policy.
    for (ty, bytes) in [
        (1, command.as_slice()),
        (2, command.as_slice()),
        (1, &command[..command.len() - 2]),
        (2, &command[..command.len() - 2]),
    ] {
        assert_eq!(
            capture_desktop_launch_contract([
                value("SystemSetupInProgress", 4, &one),
                value("SetupType", 4, &other_setup),
                value("CmdLine", ty, bytes),
            ]),
            DesktopLaunchContract::MediaSetup
        );
    }
    let later = capture_desktop_launch_contract([
        value("SystemSetupInProgress", 4, &zero),
        value("SetupType", 4, &zero),
        value("CmdLine", 1, &command),
    ]);
    assert_eq!(later, DesktopLaunchContract::MediaSetup);
    assert_eq!(captured, DesktopLaunchContract::InstalledLogon);
}

#[test]
fn missing_malformed_duplicate_or_inconsistent_setup_is_unavailable() {
    let zero = 0u32.to_le_bytes();
    let one = 1u32.to_le_bytes();
    let command: Vec<u8> = "setup.exe\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let overlong = vec![b'x'; 522];
    let full_unterminated: Vec<u8> = "x"
        .repeat(260)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let invalid_commands: &[&[u8]] = &[
        &[],
        &[0, 0],
        &[b' ', 0, 0, 0],
        &[b'x', 0, 0, 0, b'y', 0, 0, 0],
        &[b'x'],
        &[0, 0xd8, 0, 0],
        &overlong,
        &full_unterminated,
    ];
    for command in invalid_commands {
        assert_eq!(
            capture_desktop_launch_contract([
                value("SystemSetupInProgress", 4, &one),
                value("SetupType", 4, &one),
                value("CmdLine", 1, command),
            ]),
            DesktopLaunchContract::Unavailable
        );
    }
    for values in [
        vec![],
        vec![value("SetupType", 4, &zero)],
        vec![
            value("SystemSetupInProgress", 4, &one),
            value("SetupType", 4, &zero),
        ],
        vec![
            value("SystemSetupInProgress", 4, &zero),
            value("SetupType", 4, &one),
        ],
        vec![
            value("SystemSetupInProgress", 4, &one),
            value("SetupType", 4, &one),
        ],
        vec![
            value("SystemSetupInProgress", 1, &one),
            value("SetupType", 4, &one),
            value("CmdLine", 1, &command),
        ],
        vec![
            value("SystemSetupInProgress", 4, &one[..3]),
            value("SetupType", 4, &one),
            value("CmdLine", 1, &command),
        ],
        vec![
            value("SystemSetupInProgress", 4, &one),
            value("SetupType", 4, &one),
            value("setuptype", 4, &one),
            value("CmdLine", 1, &command),
        ],
        vec![
            value("SystemSetupInProgress", 4, &one),
            value("SetupType", 4, &one),
            value("CmdLine", 3, &command),
        ],
    ] {
        assert_eq!(
            capture_desktop_launch_contract(values),
            DesktopLaunchContract::Unavailable
        );
    }
}
