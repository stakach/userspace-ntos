//! Mounted-SYSTEM filter policy read through CM-owned key snapshots.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    Backend, ConfigClient, HiveKeySnapshot, HiveValueSnapshot, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_NOT_FOUND,
};

const ENUM_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Enum";
const CLASS_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Control\Class";
#[cfg(test)]
const REG_SZ: u32 = 1;
const REG_MULTI_SZ: u32 = 7;

/// Filter services in the NT PnP AddDevice order around the function driver.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceFilterPolicySnapshot {
    pub mount_generation: u64,
    pub class_guid: Option<String>,
    pub device_lower: Vec<String>,
    pub class_lower: Vec<String>,
    pub device_upper: Vec<String>,
    pub class_upper: Vec<String>,
}

fn value<'a>(key: &'a HiveKeySnapshot, name: &str) -> Option<&'a HiveValueSnapshot> {
    key.values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
}

fn reg_sz(value: &HiveValueSnapshot) -> Result<String, i32> {
    if value.data.len() < 4 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    crate::decode_terminated_reg_sz(value.value_type, &value.data)
        .ok_or(STATUS_INVALID_PARAMETER)
}

fn filter_list(key: &HiveKeySnapshot, name: &str) -> Result<Vec<String>, i32> {
    let Some(value) = value(key, name) else {
        return Ok(Vec::new());
    };
    if value.value_type != REG_MULTI_SZ || value.data.len() < 4 || value.data.len() % 2 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let units: Vec<_> = value
        .data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    if !units.ends_with(&[0, 0]) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut names = Vec::new();
    let mut begin = 0;
    for (index, unit) in units[..units.len() - 1].iter().enumerate() {
        if *unit != 0 {
            continue;
        }
        if index == begin {
            if units.len() == 2 {
                return Ok(names);
            }
            return Err(STATUS_INVALID_PARAMETER);
        }
        let name =
            String::from_utf16(&units[begin..index]).map_err(|_| STATUS_INVALID_PARAMETER)?;
        if name.contains('\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        names.push(name);
        begin = index + 1;
    }
    if begin != units.len() - 1 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(names)
}

impl<B: Backend> ConfigClient<B> {
    /// Read ordered per-device and setup-class filter lists for a mounted Enum instance.
    /// A missing class key supplies no class filters; malformed values fail closed.
    pub fn query_device_filter_policy(
        &mut self,
        instance_id: &str,
    ) -> Result<Option<DeviceFilterPolicySnapshot>, i32> {
        if instance_id.is_empty() || instance_id.contains('\0') || instance_id.starts_with('\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let device_path = alloc::format!(r"{}\{}", ENUM_PATH, instance_id);
        let device = match self.query_system_hive_key(&device_path) {
            Ok(key) => key,
            Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ok(None),
            Err(status) => return Err(status),
        };
        let class_guid = value(&device, "ClassGUID").map(reg_sz).transpose()?;
        if class_guid
            .as_ref()
            .is_some_and(|guid| guid.is_empty() || guid.contains('\\'))
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let class = if let Some(guid) = &class_guid {
            match self.query_system_hive_key(&alloc::format!(r"{}\{}", CLASS_PATH, guid)) {
                Ok(key) => {
                    if key.mount_generation != device.mount_generation {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    Some(key)
                }
                Err(STATUS_OBJECT_NAME_NOT_FOUND) => None,
                Err(status) => return Err(status),
            }
        } else {
            None
        };
        Ok(Some(DeviceFilterPolicySnapshot {
            mount_generation: device.mount_generation,
            class_guid,
            device_lower: filter_list(&device, "LowerFilters")?,
            class_lower: class
                .as_ref()
                .map(|key| filter_list(key, "LowerFilters"))
                .transpose()?
                .unwrap_or_default(),
            device_upper: filter_list(&device, "UpperFilters")?,
            class_upper: class
                .as_ref()
                .map(|key| filter_list(key, "UpperFilters"))
                .transpose()?
                .unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::num::NonZeroU32;
    use nt_config_manager::{encode_multi_sz, encode_sz};
    use nt_config_server::CmServer;
    use nt_hive_core::{encode_image, Hive, HiveKind, RegistryValueType};

    struct Direct(CmServer);

    impl Backend for Direct {
        fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> nt_config_abi::CmReply {
            self.0.dispatch(opcode, input, output)
        }
    }

    #[test]
    fn mounted_policy_preserves_device_and_class_order() {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        let dev = hive.create_key(r"ControlSet001\Enum\ROOT\SAMPLE\0000");
        let class = hive.create_key(r"ControlSet001\Control\Class\{sample-guid}");
        hive.set_value(
            dev,
            "ClassGUID",
            RegistryValueType::Sz,
            encode_sz("{sample-guid}"),
        );
        for (key, name, names) in [
            (dev, "LowerFilters", &["device-low-a", "device-low-b"][..]),
            (class, "LowerFilters", &["class-low"][..]),
            (dev, "UpperFilters", &["device-high"][..]),
            (class, "UpperFilters", &["class-high-a", "class-high-b"][..]),
        ] {
            hive.set_value(
                key,
                name,
                RegistryValueType::MultiSz,
                encode_multi_sz(names),
            );
        }
        hive.finish_clean_import();
        let mut client = ConfigClient::new(Direct(CmServer::new_for_incarnation(NonZeroU32::MIN)));
        assert_eq!(client.import_system_hive(&encode_image(&hive)), Ok(1));
        let policy = client
            .query_device_filter_policy(r"ROOT\SAMPLE\0000")
            .unwrap()
            .unwrap();
        assert_eq!(policy.mount_generation, 1);
        assert_eq!(policy.device_lower, ["device-low-a", "device-low-b"]);
        assert_eq!(policy.class_lower, ["class-low"]);
        assert_eq!(policy.device_upper, ["device-high"]);
        assert_eq!(policy.class_upper, ["class-high-a", "class-high-b"]);
        assert_eq!(
            client.query_device_filter_policy(r"ROOT\MISSING\0000"),
            Ok(None)
        );
    }

    #[test]
    fn malformed_lists_do_not_silently_disappear() {
        let key = HiveKeySnapshot {
            mount_generation: 1,
            path: String::new(),
            class_name: None,
            security_descriptor: None,
            subkeys: Vec::new(),
            values: vec![HiveValueSnapshot {
                name: "LowerFilters".into(),
                value_type: REG_SZ,
                data: encode_sz("filter"),
            }],
        };
        assert_eq!(
            filter_list(&key, "LowerFilters"),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}
