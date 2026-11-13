//! Paths supplied by the installed LiberNT userspace image.

pub(crate) const ROOT: &[u8] = b"windows";
pub(crate) const ROOT_PREFIX: &[u8] = b"windows\\";
pub(crate) const SYSTEM32_PREFIX: &[u8] = b"windows\\system32\\";
pub(crate) const SYSTEM32_SLASH_PREFIX: &[u8] = b"windows/system32/";
pub(crate) const DRIVERS_PREFIX: &[u8] = b"windows\\system32\\drivers\\";
pub(crate) const CONFIG: &[u8] = b"windows\\system32\\config";
pub(crate) const USERS: &[u8] = b"users";
pub(crate) const USERS_SOURCE: &[u8] = b"Users";
pub(crate) const USERS_PREFIX: &[u8] = b"users\\";
pub(crate) const PROFILE_DIRECTORY_VALUE: &[u8] = b"%SystemDrive%\\Users";
pub(crate) const ADMIN_PROFILE_VALUE: &[u8] = b"%SystemDrive%\\Users\\Administrator";

pub(crate) const SMSS: &[u8] = b"windows\\system32\\smss.exe";
pub(crate) const CSRSS: &[u8] = b"windows\\system32\\csrss.exe";
pub(crate) const WINLOGON: &[u8] = b"windows\\system32\\winlogon.exe";
pub(crate) const SERVICES: &[u8] = b"windows\\system32\\services.exe";
pub(crate) const LSASS: &[u8] = b"windows\\system32\\lsass.exe";
pub(crate) const USERINIT: &[u8] = b"windows\\system32\\userinit.exe";
pub(crate) const EXPLORER: &[u8] = b"windows\\explorer.exe";
pub(crate) const NTDLL: &[u8] = b"windows\\system32\\ntdll.dll";
pub(crate) const WIN32K: &[u8] = b"windows\\system32\\win32k.sys";
pub(crate) const VERSION_DLL: &[u8] = b"windows\\system32\\version.dll";
pub(crate) const ARIAL: &[u8] = b"windows\\Fonts\\arial.ttf";
pub(crate) const ARIAL_STR: &str = "windows\\Fonts\\arial.ttf";
pub(crate) const FONTS_STR: &str = "windows\\Fonts";
pub(crate) const VERSION_DLL_STR: &str = "windows\\system32\\version.dll";
pub(crate) const CSRSRV: &[u8] = b"windows\\system32\\csrsrv.dll";
pub(crate) const KERNEL32_VISTA: &[u8] = b"windows\\system32\\kernel32_vista.dll";
pub(crate) const ADVAPI32_VISTA: &[u8] = b"windows\\system32\\advapi32_vista.dll";
pub(crate) const NTDLL_VISTA: &[u8] = b"windows\\system32\\ntdll_vista.dll";
pub(crate) const CONFIG_SYSTEM: &[u8] = b"windows\\system32\\config\\system";
pub(crate) const CONFIG_SECURITY: &[u8] = b"windows\\system32\\config\\security";
pub(crate) const CONFIG_SAM: &[u8] = b"windows\\system32\\config\\sam";
pub(crate) const CONFIG_SOFTWARE: &[u8] = b"windows\\system32\\config\\software";
pub(crate) const CONFIG_DEFAULT: &[u8] = b"windows\\system32\\config\\default";
pub(crate) const SEH_LINKAGE: &[u8] = b"windows\\system32\\nt-seh-linkage.dll";
pub(crate) const UNATTEND: &[u8] = b"windows\\unattend.inf";
pub(crate) const BOOTSTAT: &[u8] = b"windows\\bootstat.dat";
pub(crate) const PROFILE_DEFAULT_SOURCE: &[u8] = b"Users\\Default";
pub(crate) const PROFILE_DEFAULT_APPDATA_SOURCE: &[u8] = b"Users\\Default\\AppData";

pub(crate) const NT_CONFIG_SYSTEM: &str = r"\??\C:\Windows\System32\Config\SYSTEM";
pub(crate) const NT_CONFIG_SOFTWARE: &str = r"\??\C:\Windows\System32\Config\SOFTWARE";
pub(crate) const NT_CONFIG_SECURITY: &str = r"\??\C:\Windows\System32\Config\SECURITY";
pub(crate) const NT_CONFIG_SAM: &str = r"\??\C:\Windows\System32\Config\SAM";
pub(crate) const NT_CONFIG_DEFAULT: &str = r"\??\C:\Windows\System32\Config\DEFAULT";
pub(crate) const NT_BOOTSTAT: &str = r"\??\C:\Windows\bootstat.dat";
pub(crate) const NT_USERS: &str = r"\??\C:\Users";
pub(crate) const NT_DEFAULT_PROFILE: &str = r"\??\C:\Users\Default";
pub(crate) const NT_DEFAULT_PROFILE_APPDATA: &str = r"\??\C:\Users\Default\AppData";
pub(crate) const NT_PUBLIC_PROFILE: &str = r"\??\C:\Users\Public";
pub(crate) const NT_ADMIN_PROFILE: &str = r"\??\C:\Users\Administrator";
pub(crate) const NT_ADMIN_PROFILE_APPDATA: &str = r"\??\C:\Users\Administrator\AppData";
pub(crate) const NT_DEFAULT_NTUSER: &str = r"\??\C:\Users\Default\ntuser.dat";
pub(crate) const NT_ADMIN_NTUSER: &str = r"\??\C:\Users\Administrator\ntuser.dat";

pub(crate) const DOS_ROOT_PREFIX: &[u8] = b"C:\\Windows\\";
pub(crate) const DOS_SYSTEM32_PREFIX: &[u8] = b"C:\\Windows\\System32\\";
pub(crate) const DOS_DEFAULT_PROFILE: &str = r"C:\Users\Default";
pub(crate) const DEVICE_ROOT_PREFIX: &[u8] =
    b"\\Device\\Harddisk0\\Partition1\\windows\\";
pub(crate) const DEVICE_SYSTEM32_PREFIX: &[u8] =
    b"\\Device\\Harddisk0\\Partition1\\windows\\system32\\";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_images_and_registry_live_below_one_installed_root() {
        for path in [SMSS, CSRSS, WINLOGON, SERVICES, LSASS, USERINIT, NTDLL, WIN32K] {
            assert!(path.starts_with(SYSTEM32_PREFIX));
        }
        assert!(EXPLORER.starts_with(ROOT_PREFIX));
        assert!(CONFIG.starts_with(SYSTEM32_PREFIX));
        assert!(CONFIG_SOFTWARE.starts_with(CONFIG));
        assert_eq!(ROOT, b"windows");
        assert_eq!(USERS, b"users");
        assert_eq!(PROFILE_DIRECTORY_VALUE, b"%SystemDrive%\\Users");
    }
}
