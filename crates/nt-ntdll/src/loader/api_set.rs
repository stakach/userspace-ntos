//! Api-set contract names (`api-ms-*`, `ext-ms-*`) and the DLLs that host them.
//!
//! ReactOS `ApiSetResolveToHost` (`sdk/lib/apisets/apisets.c`): a name starting with `api-` or
//! `ext-` is looked up, without its `.dll` extension and ignoring case, in a sorted table of
//! contracts. An entry applies when its version mask includes the process's api-set version.
//! The table belongs to the hosted release; the DLL build reads it from the release's ntdll.

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
    let Ok(index) = table.binary_search_by(|(entry, _, _)| entry.as_bytes().cmp(contract)) else {
        return ApiSetHost::NotAContract;
    };
    let (_, host, mask) = table[index];
    if mask & versions == 0 {
        ApiSetHost::NotAContract
    } else if host.is_empty() {
        ApiSetHost::Unhosted
    } else {
        ApiSetHost::Host(host)
    }
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
