//! Pure lookup and buffer-planning logic for activation-context application settings.

use crate::NtStatus;

use super::activation_manifest::ManifestApplicationSetting;

pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D;
pub const STATUS_SXS_KEY_NOT_FOUND: NtStatus = 0xC015_0008;

pub const WINDOWS_SETTINGS_2005: &str = "http://schemas.microsoft.com/SMI/2005/WindowsSettings";

const WINDOWS_SETTINGS_NAMESPACES: [&str; 6] = [
    WINDOWS_SETTINGS_2005,
    "http://schemas.microsoft.com/SMI/2011/WindowsSettings",
    "http://schemas.microsoft.com/SMI/2016/WindowsSettings",
    "http://schemas.microsoft.com/SMI/2017/WindowsSettings",
    "http://schemas.microsoft.com/SMI/2019/WindowsSettings",
    "http://schemas.microsoft.com/SMI/2020/WindowsSettings",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationSettingQuery<'a> {
    pub value: &'a [u16],
    pub required_chars: usize,
    pub status: NtStatus,
}

pub fn query_application_setting<'a>(
    settings: &'a [ManifestApplicationSetting],
    namespace: Option<&[u16]>,
    name: &[u16],
    buffer_chars: usize,
) -> Result<ApplicationSettingQuery<'a>, NtStatus> {
    match namespace {
        Some(namespace) if is_valid_namespace(namespace) => {}
        Some(_) => return Err(STATUS_INVALID_PARAMETER),
        None => {}
    }
    let setting = settings
        .iter()
        .find(|setting| {
            let namespace_matches = namespace.map_or_else(
                || ascii_eq(&setting.namespace, WINDOWS_SETTINGS_2005),
                |namespace| setting.namespace == namespace,
            );
            namespace_matches && setting.name == name
        })
        .ok_or(STATUS_SXS_KEY_NOT_FOUND)?;
    let required_chars = setting
        .value
        .len()
        .checked_add(1)
        .ok_or(STATUS_BUFFER_TOO_SMALL)?;
    Ok(ApplicationSettingQuery {
        value: &setting.value,
        required_chars,
        // ReactOS compares against wcslen(value), although wcscpy writes the terminator too.
        status: if buffer_chars < setting.value.len() {
            STATUS_BUFFER_TOO_SMALL
        } else {
            0
        },
    })
}

pub fn is_valid_namespace(namespace: &[u16]) -> bool {
    WINDOWS_SETTINGS_NAMESPACES
        .iter()
        .any(|candidate| ascii_eq(namespace, candidate))
}

fn ascii_eq(input: &[u16], expected: &str) -> bool {
    input.len() == expected.len()
        && input
            .iter()
            .zip(expected.bytes())
            .all(|(left, right)| *left == u16::from(right))
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn setting(namespace: &str, name: &str, value: &str) -> ManifestApplicationSetting {
        ManifestApplicationSetting {
            namespace: wide(namespace),
            name: wide(name),
            value: wide(value),
        }
    }

    #[test]
    fn defaults_to_2005_and_preserves_insertion_order() {
        let settings = vec![
            setting(WINDOWS_SETTINGS_2005, "dpiAware", "first"),
            setting(WINDOWS_SETTINGS_2005, "dpiAware", "second"),
        ];
        let query =
            query_application_setting(&settings, None, &wide("dpiAware"), usize::MAX).unwrap();
        assert_eq!(query.value, wide("first"));
        assert_eq!(query.required_chars, 6);
        assert_eq!(query.status, 0);
    }

    #[test]
    fn validates_namespaces_and_matches_name_case() {
        let settings = vec![setting(
            "http://schemas.microsoft.com/SMI/2016/WindowsSettings",
            "dpiAwareness",
            "true",
        )];
        assert_eq!(
            query_application_setting(
                &settings,
                Some(&wide("urn:invalid")),
                &wide("dpiAwareness"),
                8,
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            query_application_setting(
                &settings,
                Some(&wide(
                    "http://schemas.microsoft.com/SMI/2016/WindowsSettings"
                )),
                &wide("DpiAwareness"),
                8,
            ),
            Err(STATUS_SXS_KEY_NOT_FOUND)
        );
    }

    #[test]
    fn reports_native_buffer_boundary_and_required_terminator() {
        let settings = vec![setting(WINDOWS_SETTINGS_2005, "dpiAware", "true")];
        let exact_native =
            query_application_setting(&settings, None, &wide("dpiAware"), 4).unwrap();
        assert_eq!(exact_native.required_chars, 5);
        assert_eq!(exact_native.status, 0);
        let short = query_application_setting(&settings, None, &wide("dpiAware"), 3).unwrap();
        assert_eq!(short.required_chars, 5);
        assert_eq!(short.status, STATUS_BUFFER_TOO_SMALL);
    }

    #[test]
    fn supports_explicit_empty_values() {
        let settings = vec![setting(WINDOWS_SETTINGS_2005, "dpiAware", "")];
        let query = query_application_setting(&settings, None, &wide("dpiAware"), 0).unwrap();
        assert_eq!(query.value, []);
        assert_eq!(query.required_chars, 1);
        assert_eq!(query.status, 0);
    }
}
