//! Locale and MUI helpers for the ntdll export layer.
//!
//! The live registry/NLS policy plane is not complete yet, so these helpers expose the process-wide
//! default UI language that the current kernel image can honestly support: en-US / 0409. The ABI
//! wrappers are responsible for copying the resulting multi-string into user buffers.

extern crate alloc;

use alloc::vec::Vec;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

pub const MUI_FULL_LANGUAGE: u32 = 0x0001;
pub const MUI_LANGUAGE_ID: u32 = 0x0004;
pub const MUI_LANGUAGE_NAME: u32 = 0x0008;
pub const MUI_MERGE_SYSTEM_FALLBACK: u32 = 0x0010;
pub const MUI_MERGE_USER_FALLBACK: u32 = 0x0020;
pub const MUI_UI_FALLBACK: u32 = MUI_MERGE_SYSTEM_FALLBACK | MUI_MERGE_USER_FALLBACK;
pub const MUI_THREAD_LANGUAGES: u32 = 0x0040;
pub const MUI_MACHINE_LANGUAGE_SETTINGS: u32 = 0x0400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreferredUiLanguageKind {
    System,
    Thread,
    User,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreferredUiLanguageFormat {
    LanguageId,
    LanguageName,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreferredUiLanguages {
    pub count: u32,
    pub required: u32,
    pub units: Vec<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreferredUiLanguageQuery {
    pub status: u32,
    pub count: u32,
    pub required: u32,
    pub units: Vec<u16>,
}

fn preferred_format(
    kind: PreferredUiLanguageKind,
    flags: u32,
) -> Result<PreferredUiLanguageFormat, u32> {
    let language_bits = flags & (MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME);
    if language_bits == (MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if flags & MUI_FULL_LANGUAGE != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let allowed = match kind {
        PreferredUiLanguageKind::System => {
            MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME | MUI_UI_FALLBACK | MUI_MACHINE_LANGUAGE_SETTINGS
        }
        PreferredUiLanguageKind::Thread => {
            MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME | MUI_UI_FALLBACK | MUI_THREAD_LANGUAGES
        }
        PreferredUiLanguageKind::User => MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME | MUI_UI_FALLBACK,
    };
    if flags & !allowed != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }

    if flags & MUI_LANGUAGE_ID != 0 {
        Ok(PreferredUiLanguageFormat::LanguageId)
    } else if flags & MUI_LANGUAGE_NAME != 0 {
        Ok(PreferredUiLanguageFormat::LanguageName)
    } else {
        match kind {
            PreferredUiLanguageKind::Thread => Ok(PreferredUiLanguageFormat::LanguageId),
            PreferredUiLanguageKind::System | PreferredUiLanguageKind::User => {
                Ok(PreferredUiLanguageFormat::LanguageName)
            }
        }
    }
}

fn push_ascii(out: &mut Vec<u16>, s: &[u8]) {
    for &byte in s {
        out.push(byte as u16);
    }
}

pub fn preferred_ui_languages(
    kind: PreferredUiLanguageKind,
    flags: u32,
) -> Result<PreferredUiLanguages, u32> {
    let format = preferred_format(kind, flags)?;
    let mut units = Vec::new();
    match format {
        PreferredUiLanguageFormat::LanguageId => push_ascii(&mut units, b"0409"),
        PreferredUiLanguageFormat::LanguageName => push_ascii(&mut units, b"en-US"),
    }
    units.push(0);
    units.push(0);
    Ok(PreferredUiLanguages {
        count: 1,
        required: units.len() as u32,
        units,
    })
}

pub fn query_preferred_ui_languages(
    kind: PreferredUiLanguageKind,
    flags: u32,
    buffer_present: bool,
    buffer_capacity: u32,
) -> PreferredUiLanguageQuery {
    let languages = match preferred_ui_languages(kind, flags) {
        Ok(languages) => languages,
        Err(status) => {
            return PreferredUiLanguageQuery {
                status,
                count: 0,
                required: 0,
                units: Vec::new(),
            }
        }
    };

    if !buffer_present && buffer_capacity != 0 {
        return PreferredUiLanguageQuery {
            status: STATUS_INVALID_PARAMETER,
            count: 0,
            required: languages.required,
            units: Vec::new(),
        };
    }

    if buffer_present && buffer_capacity < languages.required {
        return PreferredUiLanguageQuery {
            status: STATUS_BUFFER_TOO_SMALL,
            count: languages.count,
            required: languages.required,
            units: Vec::new(),
        };
    }

    PreferredUiLanguageQuery {
        status: STATUS_SUCCESS,
        count: languages.count,
        required: languages.required,
        units: if buffer_present {
            languages.units
        } else {
            Vec::new()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_id_is_hex_multi_sz() {
        let languages =
            preferred_ui_languages(PreferredUiLanguageKind::System, MUI_LANGUAGE_ID).unwrap();
        assert_eq!(languages.count, 1);
        assert_eq!(languages.required, 6);
        assert_eq!(
            languages.units,
            alloc::vec![b'0' as u16, b'4' as u16, b'0' as u16, b'9' as u16, 0, 0]
        );
    }

    #[test]
    fn language_name_is_locale_name_multi_sz() {
        let languages =
            preferred_ui_languages(PreferredUiLanguageKind::User, MUI_LANGUAGE_NAME).unwrap();
        assert_eq!(languages.count, 1);
        assert_eq!(languages.required, 7);
        assert_eq!(
            languages.units,
            alloc::vec![
                b'e' as u16,
                b'n' as u16,
                b'-' as u16,
                b'U' as u16,
                b'S' as u16,
                0,
                0
            ]
        );
    }

    #[test]
    fn defaults_match_kernelbase_expectations() {
        assert_eq!(
            preferred_ui_languages(PreferredUiLanguageKind::System, 0)
                .unwrap()
                .required,
            7
        );
        assert_eq!(
            preferred_ui_languages(PreferredUiLanguageKind::User, 0)
                .unwrap()
                .required,
            7
        );
        assert_eq!(
            preferred_ui_languages(PreferredUiLanguageKind::Thread, 0)
                .unwrap()
                .required,
            6
        );
    }

    #[test]
    fn invalid_flag_combinations_are_rejected() {
        assert_eq!(
            preferred_ui_languages(PreferredUiLanguageKind::User, MUI_FULL_LANGUAGE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            preferred_ui_languages(
                PreferredUiLanguageKind::User,
                MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            preferred_ui_languages(
                PreferredUiLanguageKind::User,
                MUI_LANGUAGE_ID | MUI_MACHINE_LANGUAGE_SETTINGS
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn query_without_buffer_reports_required_size() {
        let query =
            query_preferred_ui_languages(PreferredUiLanguageKind::System, MUI_LANGUAGE_ID, false, 0);
        assert_eq!(query.status, STATUS_SUCCESS);
        assert_eq!(query.count, 1);
        assert_eq!(query.required, 6);
        assert!(query.units.is_empty());
    }

    #[test]
    fn query_rejects_null_buffer_with_nonzero_capacity() {
        let query =
            query_preferred_ui_languages(PreferredUiLanguageKind::User, MUI_LANGUAGE_ID, false, 1);
        assert_eq!(query.status, STATUS_INVALID_PARAMETER);
        assert_eq!(query.count, 0);
        assert_eq!(query.required, 6);
    }

    #[test]
    fn query_reports_too_small_without_copy_payload() {
        let query =
            query_preferred_ui_languages(PreferredUiLanguageKind::Thread, MUI_LANGUAGE_ID, true, 5);
        assert_eq!(query.status, STATUS_BUFFER_TOO_SMALL);
        assert_eq!(query.count, 1);
        assert_eq!(query.required, 6);
        assert!(query.units.is_empty());
    }
}
