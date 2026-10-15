//! Classification of a single coherent Setup snapshot for acceptance evidence only.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopLaunchContract {
    InstalledLogon,
    MediaSetup,
    Unavailable,
}

#[derive(Clone, Copy)]
pub struct SetupValue<'a> {
    pub name: &'a str,
    pub value_type: u32,
    pub data: &'a [u8],
}

pub fn capture_desktop_launch_contract<'a>(
    values: impl IntoIterator<Item = SetupValue<'a>>,
) -> DesktopLaunchContract {
    let mut setup_type = None;
    let mut in_progress = None;
    let mut command = None;
    for value in values {
        let slot = if value.name.eq_ignore_ascii_case("SetupType") {
            &mut setup_type
        } else if value.name.eq_ignore_ascii_case("SystemSetupInProgress") {
            &mut in_progress
        } else if value.name.eq_ignore_ascii_case("CmdLine") {
            &mut command
        } else {
            continue;
        };
        if slot.replace(value).is_some() {
            return DesktopLaunchContract::Unavailable;
        }
    }
    let (Some(setup_type), Some(in_progress)) =
        (setup_type.and_then(dword), in_progress.and_then(dword))
    else {
        return DesktopLaunchContract::Unavailable;
    };
    match (setup_type != 0, in_progress != 0) {
        (false, false) => DesktopLaunchContract::InstalledLogon,
        (true, true) if command.is_some_and(usable_command) => DesktopLaunchContract::MediaSetup,
        _ => DesktopLaunchContract::Unavailable,
    }
}

fn dword(value: SetupValue<'_>) -> Option<u32> {
    if value.value_type != 4 {
        return None;
    }
    Some(u32::from_le_bytes(value.data.try_into().ok()?))
}

fn usable_command(value: SetupValue<'_>) -> bool {
    // ROS RunSetupThreadProc queries WCHAR Shell[MAX_PATH], then appends its own NUL.
    // A short unterminated registry string is therefore valid; embedded garbage is not evidence.
    if !matches!(value.value_type, 1 | 2)
        || value.data.is_empty()
        || value.data.len() % 2 != 0
        || value.data.len() > 260 * 2
    {
        return false;
    }
    let units = || {
        value
            .data
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let first_nul = units().position(|unit| unit == 0);
    if first_nul.is_none() && value.data.len() == 260 * 2 {
        return false;
    }
    if let Some(index) = first_nul {
        if units().skip(index).any(|unit| unit != 0) {
            return false;
        }
    }
    let count = first_nul.unwrap_or(value.data.len() / 2);
    let mut non_whitespace = false;
    for character in core::char::decode_utf16(units().take(count)) {
        let Ok(character) = character else {
            return false;
        };
        non_whitespace |= !character.is_whitespace();
    }
    non_whitespace
}
