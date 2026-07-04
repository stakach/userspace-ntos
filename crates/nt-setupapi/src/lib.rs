//! # `nt-setupapi` — user-mode device discovery (CfgMgr32 + SetupAPI)
//!
//! The Win32 device-discovery surface a user program uses to find device interfaces + resolve
//! their device paths (spec: NT User-Mode Device Discovery, SetupAPI / CFGMGR32 v0.1), backed by
//! the Configuration Manager's interface records ([`nt_config_manager::ConfigManager`]):
//!
//! - **CfgMgr32** — [`CM_Get_Device_Interface_List_Size`] / [`CM_Get_Device_Interface_List`]:
//!   the `MULTI_SZ` list of interface paths for a class GUID, with a present/enabled filter,
//!   optional device-ID filter, and buffer sizing (`CR_BUFFER_SMALL`).
//! - **SetupAPI** — an [`HDEVINFO`] handle table ([`DevInfoSets`]) + [`get_class_devs`],
//!   [`enum_device_interfaces`], [`get_device_interface_detail`] (the two-call sizing pattern),
//!   [`destroy_device_info_list`].
//!
//! Device paths are the Configuration Manager symbolic link mapped to the Win32 `\\?\` form. The
//! logic operates on values only (no raw user pointers); the Driver Host projects into the
//! Win32 structs at the boundary. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use nt_config_manager::ConfigManager;

// --- error model (spec §7.1) -------------------------------------------------

/// `CONFIGRET` (CfgMgr32).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ConfigRet {
    Success = 0x00,
    InvalidPointer = 0x03,
    InvalidFlag = 0x04,
    NoSuchDevInst = 0x0D,
    Failure = 0x13,
    BufferSmall = 0x1A,
    NoSuchValue = 0x25,
}

// Win32 error codes (SetupAPI, `GetLastError`).
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_NOT_FOUND: u32 = 1168;

/// `CONFIGRET` → Win32 error (spec §7.1).
pub fn configret_to_win32_error(cr: ConfigRet) -> u32 {
    match cr {
        ConfigRet::Success => ERROR_SUCCESS,
        ConfigRet::InvalidPointer | ConfigRet::InvalidFlag => ERROR_INVALID_PARAMETER,
        ConfigRet::BufferSmall => ERROR_INSUFFICIENT_BUFFER,
        ConfigRet::NoSuchValue => ERROR_NO_MORE_ITEMS,
        ConfigRet::NoSuchDevInst => ERROR_NOT_FOUND,
        ConfigRet::Failure => ERROR_INVALID_PARAMETER,
    }
}

// --- flags -------------------------------------------------------------------

pub const CM_GET_DEVICE_INTERFACE_LIST_PRESENT: u32 = 0x0;
pub const CM_GET_DEVICE_INTERFACE_LIST_ALL_DEVICES: u32 = 0x1;
const CM_VALID_FLAGS: u32 = CM_GET_DEVICE_INTERFACE_LIST_ALL_DEVICES;

pub const DIGCF_PRESENT: u32 = 0x02;
pub const DIGCF_ALLCLASSES: u32 = 0x04;
pub const DIGCF_DEVICEINTERFACE: u32 = 0x10;

/// Map a Configuration Manager kernel symbolic link (`\??\…`) to the Win32 device path
/// (`\\?\…`) a user program opens (spec §13).
pub fn device_path(symbolic_link: &str) -> String {
    if let Some(rest) = symbolic_link.strip_prefix(r"\??\") {
        let mut s = String::from(r"\\?\");
        s.push_str(rest);
        s
    } else {
        String::from(symbolic_link)
    }
}

/// The matching interface device paths for a class GUID (enabled-only unless `ALL_DEVICES`),
/// optionally filtered to a devnode instance ID (case-insensitive, spec §9.3).
fn matching_paths(
    cm: &ConfigManager,
    guid: &str,
    device_id: Option<&str>,
    flags: u32,
) -> Vec<String> {
    let enabled_only = flags & CM_GET_DEVICE_INTERFACE_LIST_ALL_DEVICES == 0;
    cm.interfaces_by_guid(guid, enabled_only)
        .iter()
        .filter(|i| match device_id {
            None => true,
            Some(id) => cm
                .devnodes()
                .iter()
                .find(|d| d.id == i.devnode)
                .is_some_and(|d| d.instance_id.eq_ignore_ascii_case(id)),
        })
        .map(|i| device_path(&i.symbolic_link))
        .collect()
}

/// Build the `MULTI_SZ` (each path + NUL, then a final NUL) as UTF-16LE code units (spec §9.2).
/// An empty list is a single NUL.
fn build_multi_sz(paths: &[String]) -> Vec<u16> {
    let mut out = Vec::new();
    for p in paths {
        out.extend(p.encode_utf16());
        out.push(0);
    }
    out.push(0); // final terminating NUL
    out
}

// --- CfgMgr32 (spec §9) ------------------------------------------------------

/// `CM_Get_Device_Interface_List_SizeW` — the required WCHAR count for the interface list,
/// including the final double-NUL (spec §9.1). `guid` `None` models a null `InterfaceClassGuid`.
pub fn cm_get_device_interface_list_size(
    cm: &ConfigManager,
    guid: Option<&str>,
    device_id: Option<&str>,
    flags: u32,
) -> Result<u32, ConfigRet> {
    let guid = guid.ok_or(ConfigRet::InvalidPointer)?;
    if flags & !CM_VALID_FLAGS != 0 {
        return Err(ConfigRet::InvalidFlag);
    }
    let paths = matching_paths(cm, guid, device_id, flags);
    Ok(build_multi_sz(&paths).len() as u32)
}

/// `CM_Get_Device_Interface_ListW` — fill (up to `buffer_len` WCHARs) the `MULTI_SZ` list of
/// interface paths (spec §9.2). Returns the list on success, or `CR_BUFFER_SMALL` if too small.
pub fn cm_get_device_interface_list(
    cm: &ConfigManager,
    guid: Option<&str>,
    device_id: Option<&str>,
    buffer_len: u32,
    flags: u32,
) -> Result<Vec<u16>, ConfigRet> {
    let guid = guid.ok_or(ConfigRet::InvalidPointer)?;
    if flags & !CM_VALID_FLAGS != 0 {
        return Err(ConfigRet::InvalidFlag);
    }
    let paths = matching_paths(cm, guid, device_id, flags);
    let list = build_multi_sz(&paths);
    if (list.len() as u32) > buffer_len {
        return Err(ConfigRet::BufferSmall);
    }
    Ok(list)
}

// --- SetupAPI (spec §10-§11) -------------------------------------------------

/// One enumerated interface element referenced by an `SP_DEVICE_INTERFACE_DATA.Reserved` token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceElement {
    pub guid: String,
    pub device_path: String,
    pub devnode: u64,
}

struct DevInfoSet {
    id: u64,
    generation: u32,
    class_guid: Option<String>,
    interfaces: Vec<InterfaceElement>,
    destroyed: bool,
}

/// An opaque `HDEVINFO` (index + generation).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HDevInfo(pub u64);

impl HDevInfo {
    /// `INVALID_HANDLE_VALUE`.
    pub const INVALID: HDevInfo = HDevInfo(u64::MAX);
    pub fn is_valid(self) -> bool {
        self != Self::INVALID
    }
    fn slot(self) -> u32 {
        self.0 as u32
    }
    fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

/// The user-mode `HDEVINFO` handle table (spec §10.1).
#[derive(Default)]
pub struct DevInfoSets {
    sets: Vec<DevInfoSet>,
    next_gen: u32,
}

impl DevInfoSets {
    pub fn new() -> Self {
        Self {
            sets: Vec::new(),
            next_gen: 1,
        }
    }

    fn resolve(&self, h: HDevInfo) -> Option<&DevInfoSet> {
        let s = self.sets.get(h.slot() as usize)?;
        (!s.destroyed && s.generation == h.generation() && s.id == h.0).then_some(s)
    }
    fn resolve_mut(&mut self, h: HDevInfo) -> Option<&mut DevInfoSet> {
        let s = self.sets.get_mut(h.slot() as usize)?;
        (!s.destroyed && s.generation == h.generation() && s.id == h.0).then_some(s)
    }

    /// `SetupDiGetClassDevsW(ClassGuid, Enumerator, hwnd, Flags)` — snapshot the matching device
    /// interfaces for a class GUID into a new `HDEVINFO` (spec §11.1). Requires
    /// `DIGCF_DEVICEINTERFACE`; returns `INVALID` (+ `ERROR_INVALID_PARAMETER`) otherwise.
    pub fn get_class_devs(
        &mut self,
        cm: &ConfigManager,
        guid: Option<&str>,
        flags: u32,
    ) -> HDevInfo {
        if flags & DIGCF_DEVICEINTERFACE == 0 || guid.is_none() {
            return HDevInfo::INVALID;
        }
        let guid = guid.unwrap();
        let enabled_only = flags & DIGCF_PRESENT != 0;
        let interfaces: Vec<InterfaceElement> = cm
            .interfaces_by_guid(guid, enabled_only)
            .iter()
            .map(|i| InterfaceElement {
                guid: i.guid.clone(),
                device_path: device_path(&i.symbolic_link),
                devnode: i.devnode,
            })
            .collect();
        let slot = self.sets.len() as u64;
        let generation = self.next_gen;
        self.next_gen += 1;
        let id = (generation as u64) << 32 | slot;
        self.sets.push(DevInfoSet {
            id,
            generation,
            class_guid: Some(guid.into()),
            interfaces,
            destroyed: false,
        });
        HDevInfo(id)
    }

    pub fn class_guid(&self, h: HDevInfo) -> Option<&str> {
        self.resolve(h)?.class_guid.as_deref()
    }

    /// `SetupDiEnumDeviceInterfaces(set, …, InterfaceClassGuid, MemberIndex, …)` — the
    /// `member_index`-th interface, or `None` (→ `ERROR_NO_MORE_ITEMS`) past the end (spec §11.2).
    pub fn enum_device_interfaces(
        &self,
        h: HDevInfo,
        member_index: u32,
    ) -> Option<InterfaceElement> {
        self.resolve(h)?
            .interfaces
            .get(member_index as usize)
            .cloned()
    }

    /// `SetupDiGetDeviceInterfaceDetailW` — resolve an interface element to its device path
    /// (spec §11.3), returning it if `buffer_wchars` is large enough, else the required WCHAR
    /// count + `ERROR_INSUFFICIENT_BUFFER` (the two-call sizing pattern). The path is
    /// NUL-terminated.
    pub fn get_device_interface_detail(
        &self,
        h: HDevInfo,
        member_index: u32,
        buffer_wchars: u32,
    ) -> Result<Vec<u16>, (u32, u32)> {
        let element = self
            .enum_device_interfaces(h, member_index)
            .ok_or((ERROR_INVALID_HANDLE, 0))?;
        let mut path: Vec<u16> = element.device_path.encode_utf16().collect();
        path.push(0);
        let required = path.len() as u32;
        if buffer_wchars < required {
            return Err((ERROR_INSUFFICIENT_BUFFER, required));
        }
        Ok(path)
    }

    /// `SetupDiDestroyDeviceInfoList` — invalidate the handle (spec §11.4). Returns `false`
    /// (`ERROR_INVALID_HANDLE`) for a stale handle.
    pub fn destroy_device_info_list(&mut self, h: HDevInfo) -> bool {
        match self.resolve_mut(h) {
            Some(s) => {
                s.destroyed = true;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests;
