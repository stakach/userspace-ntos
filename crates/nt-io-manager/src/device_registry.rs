//! IoOpenDeviceRegistryKey selection policy, not PDO, registry or handle authority.
//! NT5: base/ntos/inc/pnp.h and base/ntos/io/pnpmgr/{pnpioapi,pnpsubs}.c.

use alloc::vec::Vec;

const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;
const STATUS_NAME_TOO_LONG: u32 = 0xc000_0106;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
const KEY_READ: u32 = 0x0002_0019;
const KEY_WRITE: u32 = 0x0002_0006;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const MAX_NAME_UNITS: usize = u16::MAX as usize / 2;

pub const PLUGPLAY_REGKEY_DEVICE: u32 = 1;
pub const PLUGPLAY_REGKEY_DRIVER: u32 = 2;
pub const PLUGPLAY_REGKEY_CURRENT_HWPROFILE: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceRegistryKeyType {
    Device,
    Driver,
    ProfileDevice,
    ProfileDriver,
}

impl DeviceRegistryKeyType {
    /// Reject combinations instead of treating any non-DRIVER request as DEVICE.
    pub fn from_flags(flags: u32) -> Result<Self, u32> {
        match flags {
            PLUGPLAY_REGKEY_DEVICE => Ok(Self::Device),
            PLUGPLAY_REGKEY_DRIVER => Ok(Self::Driver),
            value if value == PLUGPLAY_REGKEY_DEVICE | PLUGPLAY_REGKEY_CURRENT_HWPROFILE => {
                Ok(Self::ProfileDevice)
            }
            value if value == PLUGPLAY_REGKEY_DRIVER | PLUGPLAY_REGKEY_CURRENT_HWPROFILE => {
                Ok(Self::ProfileDriver)
            }
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    /// Names are captured from the authenticated, retained PDO's devnode/global Driver property.
    /// They are counted UTF-16 relative registry names, not provider pointers or ASCII aliases.
    /// This plan grants no authority and performs no registry mutation or handle allocation.
    pub fn plan(
        self,
        instance_path: &[u16],
        driver_key: Option<&[u16]>,
        desired_access: u32,
    ) -> Result<DeviceRegistryKeyPlan, u32> {
        let (parent, name, base, access) = match self {
            Self::Device => {
                validate_relative_name(instance_path)?;
                (
                    Some(join("Enum\\", instance_path, "")?),
                    utf16("Device Parameters")?,
                    CURRENT_CONTROL_SET,
                    desired_access | READ_CONTROL | WRITE_DAC,
                )
            }
            Self::ProfileDevice => {
                validate_relative_name(instance_path)?;
                (
                    None,
                    join("Enum\\", instance_path, "")?,
                    CURRENT_PROFILE,
                    desired_access,
                )
            }
            Self::Driver | Self::ProfileDriver => {
                let name = driver_key.ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
                validate_relative_name(name)?;
                (
                    None,
                    join("Control\\Class\\", name, "")?,
                    if self == Self::Driver {
                        CURRENT_CONTROL_SET
                    } else {
                        CURRENT_PROFILE
                    },
                    desired_access,
                )
            }
        };
        let plan = DeviceRegistryKeyPlan {
            kind: self,
            base,
            parent,
            name,
            access,
        };
        // Check the whole name before returning a plan, not after opening its parents.
        let total = base.encode_utf16().count()
            + 1
            + plan.name.len()
            + plan.parent.as_ref().map_or(0, |parent| parent.len() + 1);
        if total > MAX_NAME_UNITS {
            return Err(STATUS_NAME_TOO_LONG);
        }
        Ok(plan)
    }
}

const CURRENT_CONTROL_SET: &str = r"\Registry\Machine\System\CurrentControlSet";
const CURRENT_PROFILE: &str = r"\Registry\Machine\System\CurrentControlSet\Hardware Profiles\Current\System\CurrentControlSet";

/// All selected keys are created/opened nonvolatile, case-insensitively, with a kernel handle in
/// the designated System handle table. The caller must first open `base` with `base_access()`;
/// when present, `parent` must already exist and be opened with `parent_access()`. The relative
/// `name` is create/open, including missing intermediate components beneath the opened base.
/// Creation requests `requested_access()`, including the two extra Device Parameters rights;
/// canonical Key authorization determines the final grant. This plan is not proof of authorization.
#[derive(Debug, PartialEq, Eq)]
pub struct DeviceRegistryKeyPlan {
    kind: DeviceRegistryKeyType,
    base: &'static str,
    parent: Option<Vec<u16>>,
    name: Vec<u16>,
    access: u32,
}

impl DeviceRegistryKeyPlan {
    pub fn base(&self) -> &'static str {
        self.base
    }
    pub const fn base_access(&self) -> u32 {
        KEY_READ
    }
    pub fn parent(&self) -> Option<&[u16]> {
        self.parent.as_deref()
    }
    pub fn parent_access(&self) -> Option<u32> {
        self.parent.as_ref().map(|_| KEY_WRITE)
    }
    pub fn name(&self) -> &[u16] {
        &self.name
    }
    pub const fn requested_access(&self) -> u32 {
        self.access
    }
    pub fn adjust_new_device_parameters_dacl(&self) -> bool {
        self.kind == DeviceRegistryKeyType::Device
    }

    /// Logical CM path. The mounted CM resolver, not this policy, selects the physical profile.
    pub fn absolute_path(&self) -> Result<Vec<u16>, u32> {
        let length = self.base.encode_utf16().count()
            + 1
            + self.name.len()
            + self.parent.as_ref().map_or(0, |parent| parent.len() + 1);
        let mut path = Vec::new();
        path.try_reserve_exact(length)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        path.extend(self.base.encode_utf16());
        path.push(b'\\' as u16);
        if let Some(parent) = &self.parent {
            path.extend_from_slice(parent);
            path.push(b'\\' as u16);
        }
        path.extend_from_slice(&self.name);
        Ok(path)
    }
}

fn validate_relative_name(name: &[u16]) -> Result<(), u32> {
    if name.is_empty() {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    if name.len() > MAX_NAME_UNITS {
        return Err(STATUS_NAME_TOO_LONG);
    }
    if name.contains(&0)
        || name
            .split(|unit| *unit == b'\\' as u16)
            .any(|part| part.is_empty())
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

fn utf16(value: &str) -> Result<Vec<u16>, u32> {
    join(value, &[], "")
}

fn join(prefix: &str, name: &[u16], suffix: &str) -> Result<Vec<u16>, u32> {
    let length = prefix.encode_utf16().count() + name.len() + suffix.encode_utf16().count();
    if length > MAX_NAME_UNITS {
        return Err(STATUS_NAME_TOO_LONG);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    result.extend(prefix.encode_utf16());
    result.extend_from_slice(name);
    result.extend(suffix.encode_utf16());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::String, vec};

    #[test]
    fn exact_flag_combinations_and_no_unknown_bit_coercion() {
        for flags in 0..=0x200 {
            assert_eq!(
                DeviceRegistryKeyType::from_flags(flags).is_ok(),
                matches!(flags, 1 | 2 | 5 | 6)
            );
        }
        assert!(DeviceRegistryKeyType::from_flags(u32::MAX).is_err());
    }

    #[test]
    fn four_variants_preserve_parent_profile_and_access_semantics() {
        let instance = utf16(r"PCI\VEN_1234\0").unwrap();
        let driver = utf16(r"{1234}\0002").unwrap();
        for flags in [1, 2, 5, 6] {
            let plan = DeviceRegistryKeyType::from_flags(flags)
                .unwrap()
                .plan(&instance, Some(&driver), 0x8200_0001)
                .unwrap();
            let profile = if flags & 4 != 0 {
                r"\Hardware Profiles\Current\System\CurrentControlSet"
            } else {
                ""
            };
            let tail = match flags {
                1 => r"Enum\PCI\VEN_1234\0\Device Parameters",
                5 => r"Enum\PCI\VEN_1234\0",
                _ => r"Control\Class\{1234}\0002",
            };
            assert_eq!(
                String::from_utf16(&plan.absolute_path().unwrap()).unwrap(),
                format!(r"{CURRENT_CONTROL_SET}{profile}\{tail}")
            );
            assert_eq!(plan.base_access(), KEY_READ);
            assert_eq!(
                plan.requested_access(),
                0x8200_0001
                    | if flags == 1 {
                        READ_CONTROL | WRITE_DAC
                    } else {
                        0
                    }
            );
            assert_eq!(
                plan.parent_access(),
                if flags == 1 { Some(KEY_WRITE) } else { None }
            );
            assert_eq!(plan.adjust_new_device_parameters_dacl(), flags == 1);
        }
    }

    #[test]
    fn names_are_counted_utf16_without_ascii_conversion_or_driver_aliases() {
        let instance = vec![0x03bb, 0x5c, 0xd801, 0x5c, 0x4e2d];
        let plan = DeviceRegistryKeyType::Device
            .plan(&instance, None, 0)
            .unwrap();
        assert_eq!(&plan.parent().unwrap()[5..], &instance);
        assert_eq!(plan.requested_access(), READ_CONTROL | WRITE_DAC);
        assert_eq!(
            DeviceRegistryKeyType::Driver.plan(&[], None, 0),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        for invalid in [
            vec![],
            vec![0],
            utf16(r"\Registry\Machine").unwrap(),
            utf16("Class\\").unwrap(),
            utf16("Class\\\\Name").unwrap(),
        ] {
            assert!(DeviceRegistryKeyType::Driver
                .plan(&[], Some(&invalid), 0)
                .is_err());
        }
    }

    #[test]
    fn full_native_name_limit_is_checked_before_any_parent_can_be_opened() {
        let overhead = CURRENT_CONTROL_SET.encode_utf16().count() + 1 + "Control\\Class\\".len();
        let name = vec![b'a' as u16; MAX_NAME_UNITS - overhead];
        let plan = DeviceRegistryKeyType::Driver
            .plan(&[], Some(&name), 1)
            .unwrap();
        assert_eq!(plan.absolute_path().unwrap().len(), MAX_NAME_UNITS);
        let too_long = vec![b'a' as u16; name.len() + 1];
        assert_eq!(
            DeviceRegistryKeyType::Driver.plan(&[], Some(&too_long), 1),
            Err(STATUS_NAME_TOO_LONG)
        );
    }
}
