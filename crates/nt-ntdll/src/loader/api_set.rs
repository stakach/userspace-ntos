//! Api-set contract names (`api-ms-*`, `ext-ms-*`) and the DLLs that host them.
//!
//! ReactOS `ApiSetResolveToHost` (`sdk/lib/apisets/apisets.c`): a name starting with `api-` or
//! `ext-` is looked up, without its `.dll` extension and ignoring case, in a sorted table of
//! contracts. An entry applies when its version mask includes the process's api-set version.
//! The table belongs to the hosted release; the DLL build reads it from the release's ntdll.

use core::cmp::Ordering;

const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

/// `(contract name without extension, host DLL file name, APISET_* version mask)`. Names are
/// lowercase and a table is sorted by name.
pub type ApiSetEntry = (&'static str, &'static str, u8);

/// `APISET_*` version bits (`sdk/lib/apisets/apisets.h`).
pub const APISET_WIN7: u8 = 1 << 0;
pub const APISET_WIN8: u8 = 1 << 1;
pub const APISET_WIN81: u8 = 1 << 2;
pub const APISET_WIN10: u8 = 1 << 3;

/// The api-set version of a process, from the OS version the kernel published in its PEB
/// (`OSMajorVersion`, `OSMinorVersion`). This is the pinned release's `LdrpApisetVersion`
/// (its ntdll at RVA 0x2440): NT 10.0 and later use the Windows 10 contracts, 6.3 the 8.1 ones,
/// 6.2 the 8 ones, 6.1 the 7 ones, and anything older resolves no contracts. ReactOS selects
/// the same bits from its application-compatibility version instead.
pub fn api_set_version(os_major: u32, os_minor: u32) -> u8 {
    match (os_major << 8) | os_minor {
        version if version > 0x9ff => APISET_WIN10,
        version if version > 0x602 => APISET_WIN81,
        0x602 => APISET_WIN8,
        0x601 => APISET_WIN7,
        _ => 0,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiSetHost {
    /// Not a contract name, an unknown contract, or one that is not active for the version.
    NotAContract,
    /// An active contract the release records without a host DLL.
    Unhosted,
    /// File name of the host DLL in System32.
    Host(&'static str),
}

/// `name` is the whole requested name in lowercase ASCII; a path never names a contract.
pub fn resolve_api_set(table: &[ApiSetEntry], name: &[u8], versions: u8) -> ApiSetHost {
    if !(name.starts_with(b"api-") || name.starts_with(b"ext-")) {
        return ApiSetHost::NotAContract;
    }
    let contract = name.strip_suffix(b".dll").unwrap_or(name);
    resolve_exact_contract(table, versions, |entry| entry.as_bytes().cmp(contract))
}

fn resolve_exact_contract(
    table: &[ApiSetEntry],
    versions: u8,
    mut compare: impl FnMut(&str) -> Ordering,
) -> ApiSetHost {
    let Ok(index) = table.binary_search_by(|(entry, _, _)| compare(entry)) else {
        return ApiSetHost::NotAContract;
    };
    let (_, host, mask) = table[index];
    active_api_set_host(host, mask, versions)
}

fn active_api_set_host(host: &'static str, mask: u8, versions: u8) -> ApiSetHost {
    if mask & versions == 0 {
        ApiSetHost::NotAContract
    } else if host.is_empty() {
        ApiSetHost::Unhosted
    } else {
        ApiSetHost::Host(host)
    }
}

fn folded_contract(name: &[u16]) -> impl Iterator<Item = u16> + '_ {
    name.iter().copied().map(|unit| match unit {
        0x41..=0x5a => unit + 0x20,
        _ => unit,
    })
}

fn compare_contract(entry: &[u8], name: &[u16]) -> Ordering {
    entry.iter().copied().map(u16::from).cmp(folded_contract(name))
}

fn query_contract_family(table: &[ApiSetEntry], name: &[u16], versions: u8) -> (bool, bool) {
    // The basic presence query asks about a family, excluding the last dash-delimited
    // component and anything from the first dot. The loader still requires an exact name.
    let stem = name.split(|&unit| unit == u16::from(b'.')).next().unwrap_or_default();
    let Some(last_dash) = stem.iter().rposition(|&unit| unit == u16::from(b'-')) else {
        return (false, false);
    };
    let family_prefix = &stem[..=last_dash];
    let first = table.partition_point(|(entry, _, _)| {
        compare_contract(entry.as_bytes(), family_prefix) == Ordering::Less
    });

    let mut in_schema = false;
    for &(entry, host, mask) in &table[first..] {
        let entry = entry.as_bytes();
        let Some(prefix) = entry.get(..family_prefix.len()) else {
            break;
        };
        if compare_contract(prefix, family_prefix) != Ordering::Equal {
            break;
        }
        if entry[family_prefix.len()..].contains(&b'-') {
            continue;
        }
        match active_api_set_host(host, mask, versions) {
            ApiSetHost::NotAContract => {}
            ApiSetHost::Unhosted => in_schema = true,
            ApiSetHost::Host(_) => return (true, true),
        }
    }
    (in_schema, false)
}

/// Query a counted name without opening a DLL. The result is `(in_active_schema, has_host)`.
///
/// With `match_family`, this is the basic API-set presence query. It accepts an extension
/// and matches the family ignoring the final version component. Otherwise this is the
/// extended presence query, which requires an exact, extension-free contract name.
pub fn query_api_set_presence(
    table: &[ApiSetEntry],
    name: &[u16],
    versions: u8,
    match_family: bool,
) -> Result<(bool, bool), u32> {
    let has_prefix = name.len() > 4 && {
        let prefix = &name[..4];
        compare_contract(b"api-", prefix) == Ordering::Equal
            || compare_contract(b"ext-", prefix) == Ordering::Equal
    };
    if match_family {
        return Ok(if has_prefix {
            query_contract_family(table, name, versions)
        } else {
            (false, false)
        });
    }
    if !has_prefix || name.contains(&u16::from(b'.')) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(match resolve_exact_contract(table, versions, |entry| {
        compare_contract(entry.as_bytes(), name)
    }) {
        ApiSetHost::NotAContract => (false, false),
        ApiSetHost::Unhosted => (true, false),
        ApiSetHost::Host(_) => (true, true),
    })
}

/// Rows of the pinned release's table that its own images and callers use.
#[cfg(test)]
pub(crate) const RELEASE_ROWS: &[ApiSetEntry] = &[
    ("api-ms-win-composition-windowmanager-l1-1-0", "udwm.dll", 0x8),
    ("api-ms-win-core-localization-l1-2-1", "kernel32.dll", 0xc),
    ("api-ms-win-core-synch-l1-2-0", "kernelbase.dll", 0xe),
    ("ext-ms-win-ntos-ksr-l1-1-5", "", 0x8),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_contracts_by_name_extension_and_version() {
        let resolve = |name: &[u8], versions| resolve_api_set(RELEASE_ROWS, name, versions);
        assert_eq!(
            resolve(b"api-ms-win-composition-windowmanager-l1-1-0.dll", APISET_WIN10),
            ApiSetHost::Host("udwm.dll")
        );
        assert_eq!(
            resolve(b"api-ms-win-core-synch-l1-2-0", APISET_WIN10),
            ApiSetHost::Host("kernelbase.dll")
        );
        // Recorded for Windows 10 only: not active for a Windows 7 process.
        assert_eq!(
            resolve(b"api-ms-win-composition-windowmanager-l1-1-0", 1),
            ApiSetHost::NotAContract
        );
        assert_eq!(resolve(b"ext-ms-win-ntos-ksr-l1-1-5", APISET_WIN10), ApiSetHost::Unhosted);
        assert_eq!(
            resolve(b"api-ms-win-core-synch-l1-2-0.drv", APISET_WIN10),
            ApiSetHost::NotAContract
        );
        assert_eq!(resolve(b"api-ms-win-core-synch-l1-2", APISET_WIN10), ApiSetHost::NotAContract);
        assert_eq!(resolve(b"apisetschema.dll", APISET_WIN10), ApiSetHost::NotAContract);
        assert_eq!(resolve(b"api-", APISET_WIN10), ApiSetHost::NotAContract);
        assert_eq!(
            resolve_api_set(&[], b"api-ms-win-core-synch-l1-2-0", APISET_WIN10),
            ApiSetHost::NotAContract
        );
        // No api-set version: nothing is a contract.
        assert_eq!(resolve(b"api-ms-win-core-synch-l1-2-0", 0), ApiSetHost::NotAContract);
    }

    #[test]
    fn api_set_presence_distinguishes_schema_membership_from_a_host() {
        let query = |name: &str, versions, match_family| {
            let counted: alloc::vec::Vec<u16> = name.encode_utf16().collect();
            query_api_set_presence(RELEASE_ROWS, &counted, versions, match_family)
        };
        for name in [
            "API-MS-WIN-CORE-SYNCH-L1-2-0.DLL",
            "API-MS-WIN-CORE-SYNCH-L1-2-9",
            "API-MS-WIN-CORE-SYNCH-L1-2-9.fake",
        ] {
            assert_eq!(query(name, APISET_WIN10, true), Ok((true, true)), "{name}");
        }
        assert_eq!(
            query("Api-Ms-Win-Core-Synch-L1-2-0", APISET_WIN10, false),
            Ok((true, true))
        );
        assert_eq!(
            query("api-ms-win-core-synch-l1-2-9", APISET_WIN10, false),
            Ok((false, false))
        );
        assert_eq!(
            query("ext-ms-win-ntos-ksr-l1-1-5", APISET_WIN10, false),
            Ok((true, false))
        );
        assert_eq!(
            query("ext-ms-win-ntos-ksr-l1-1-5", APISET_WIN7, false),
            Ok((false, false))
        );
        assert_eq!(
            query("API-MS-WIN-CORE-SYNCH-L1-2-9", APISET_WIN7, true),
            Ok((false, false))
        );
        for name in ["", "foo", "foo.dll", "api-", "ext-"] {
            assert_eq!(query(name, APISET_WIN10, true), Ok((false, false)), "{name}");
            assert_eq!(query(name, APISET_WIN10, false), Err(0xc000_000d), "{name}");
        }
        for name in ["api-ms-win-core-synch-l1-2", "ext-ms-win-no-such-family-l1-1-0"] {
            assert_eq!(query(name, APISET_WIN10, true), Ok((false, false)), "{name}");
            assert_eq!(query(name, APISET_WIN10, false), Ok((false, false)), "{name}");
        }
        assert_eq!(
            query("api-ms-win-core-synch-l1-2-0é", APISET_WIN10, false),
            Ok((false, false))
        );
        for name in [
            "api-ms-win-core-synch-l1-2-0.dll",
            "api-ms-win-core-synch-l1-2-9.fake",
            "api-ms-win-core.synch-l1-2-0",
        ] {
            assert_eq!(query(name, APISET_WIN10, false), Err(0xc000_000d), "{name}");
        }
        assert_eq!(
            resolve_api_set(RELEASE_ROWS, b"api-ms-win-core-synch-l1-2-9", APISET_WIN10),
            ApiSetHost::NotAContract,
            "family presence does not authorize loader redirection"
        );
    }

    #[test]
    fn basic_presence_checks_the_active_family_without_matching_nested_names() {
        let table = [
            ("api-demo-l1-1-0", "", APISET_WIN10),
            ("api-demo-l1-1-0-child-l1-1-0", "other.dll", APISET_WIN10),
            ("api-demo-l1-1-7", "demo.dll", APISET_WIN7),
        ];
        let name: alloc::vec::Vec<u16> = "api-demo-l1-1-9".encode_utf16().collect();
        assert_eq!(query_api_set_presence(&table, &name, APISET_WIN10, true), Ok((true, false)));
        assert_eq!(query_api_set_presence(&table, &name, APISET_WIN7, true), Ok((true, true)));
    }

    #[test]
    fn api_set_version_follows_the_published_os_version() {
        for (major, minor, expected) in [
            (10, 0, APISET_WIN10),
            (11, 0, APISET_WIN10),
            (6, 3, APISET_WIN81),
            (6, 4, APISET_WIN81),
            (6, 2, APISET_WIN8),
            (6, 1, APISET_WIN7),
            (6, 0, 0),
            (5, 2, 0),
        ] {
            assert_eq!(api_set_version(major, minor), expected, "{major}.{minor}");
        }
        // dwm.exe's contract is recorded for Windows 10 only: the release resolves it because
        // its kernel publishes NT 10.0, and a process told it runs on 6.1 cannot.
        let dwm = b"api-ms-win-composition-windowmanager-l1-1-0.dll";
        assert_eq!(
            resolve_api_set(RELEASE_ROWS, dwm, api_set_version(10, 0)),
            ApiSetHost::Host("udwm.dll")
        );
        assert_eq!(
            resolve_api_set(RELEASE_ROWS, dwm, api_set_version(6, 1)),
            ApiSetHost::NotAContract
        );
    }
}
