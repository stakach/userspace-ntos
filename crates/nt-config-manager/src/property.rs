//! PnP property store — legacy `DEVICE_REGISTRY_PROPERTY` values + `DEVPROPKEY` properties
//! attached to devnodes (spec §11). Property values are typed opaque byte blobs; the Driver
//! Host projects them into `DEVPROPTYPE`/`UNICODE_STRING` at the driver boundary.

use alloc::vec::Vec;

/// Legacy `DEVICE_REGISTRY_PROPERTY` ordinals (spec §11.3, WDM `IoGetDeviceProperty`).
pub mod device_property {
    pub const DEVICE_DESCRIPTION: u32 = 0;
    pub const HARDWARE_ID: u32 = 1;
    pub const COMPATIBLE_IDS: u32 = 2;
    pub const CLASS_NAME: u32 = 7;
    pub const CLASS_GUID: u32 = 8;
    pub const DRIVER_KEY_NAME: u32 = 9;
    pub const MANUFACTURER: u32 = 10;
    pub const FRIENDLY_NAME: u32 = 12;
    pub const LOCATION_INFORMATION: u32 = 13;
    pub const PHYSICAL_DEVICE_OBJECT_NAME: u32 = 14;
    pub const ENUMERATOR_NAME: u32 = 24;
}

/// `DEVPROPTYPE` values (spec §11.4).
pub mod devprop_type {
    pub const EMPTY: u32 = 0;
    pub const STRING: u32 = 0x12;
    pub const STRING_LIST: u32 = 0x2012;
    pub const BINARY: u32 = 0x1003;
    pub const UINT32: u32 = 0x07;
    pub const UINT64: u32 = 0x08;
    pub const BOOLEAN: u32 = 0x11;
    pub const GUID: u32 = 0x0d;
}

/// A `DEVPROPKEY` — a format GUID + property id (spec §11.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DevPropKey {
    pub fmtid: [u8; 16],
    pub pid: u32,
}

/// A typed property value (`DEVPROPTYPE` tag + raw data).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyValue {
    pub prop_type: u32,
    pub data: Vec<u8>,
}

impl PropertyValue {
    pub fn string(s: &str) -> Self {
        Self {
            prop_type: devprop_type::STRING,
            data: crate::encode_sz(s),
        }
    }
    pub fn uint32(v: u32) -> Self {
        Self {
            prop_type: devprop_type::UINT32,
            data: v.to_le_bytes().to_vec(),
        }
    }
    pub fn as_uint32(&self) -> Option<u32> {
        (self.prop_type == devprop_type::UINT32 && self.data.len() == 4)
            .then(|| u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]))
    }
    /// Decode a `DEVPROP_TYPE_STRING` (UTF-16LE) value.
    pub fn as_string(&self) -> Option<alloc::string::String> {
        (self.prop_type == devprop_type::STRING)
            .then(|| crate::registry::decode_utf16le(&self.data))
    }
}

/// A device's property bag (spec §11.5): legacy ordinal properties + modern `DEVPROPKEY`s.
#[derive(Clone, Debug, Default)]
pub struct PropertyBag {
    legacy: Vec<(u32, PropertyValue)>,
    devprops: Vec<(DevPropKey, PropertyValue)>,
}

impl PropertyBag {
    pub fn set_legacy(&mut self, property: u32, value: PropertyValue) {
        if let Some(slot) = self.legacy.iter_mut().find(|(p, _)| *p == property) {
            slot.1 = value;
        } else {
            self.legacy.push((property, value));
        }
    }
    pub fn get_legacy(&self, property: u32) -> Option<&PropertyValue> {
        self.legacy
            .iter()
            .find(|(p, _)| *p == property)
            .map(|(_, v)| v)
    }
    pub fn set_devprop(&mut self, key: DevPropKey, value: PropertyValue) {
        if let Some(slot) = self.devprops.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.devprops.push((key, value));
        }
    }
    pub fn get_devprop(&self, key: &DevPropKey) -> Option<&PropertyValue> {
        self.devprops.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}
