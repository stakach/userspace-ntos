//! Registry-selected device and setup-class filter services.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    encode_multi_sz, encode_sz, ConfigManager, Registry, RegistryKeyId, RegistryValueType,
    CONTROL_CLASS_PATH, ENUM_PATH,
};

/// Filter lists in NT PnP AddDevice order, with the function service between lower and upper.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceFilterPolicy {
    pub class_guid: Option<String>,
    pub device_lower: Vec<String>,
    pub class_lower: Vec<String>,
    pub device_upper: Vec<String>,
    pub class_upper: Vec<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceFilterPolicyError {
    MalformedClassGuid,
    MalformedFilterList,
}

fn filter_list(
    registry: &Registry,
    key: RegistryKeyId,
    name: &str,
) -> Result<Vec<String>, DeviceFilterPolicyError> {
    let Some(value) = registry.query_value(key, name) else {
        return Ok(Vec::new());
    };
    if value.value_type != RegistryValueType::MultiSz
        || value.data.len() < 4
        || value.data.len() % 2 != 0
        || !value.data.ends_with(&[0, 0, 0, 0])
    {
        return Err(DeviceFilterPolicyError::MalformedFilterList);
    }
    let names = value
        .as_multi_string()
        .ok_or(DeviceFilterPolicyError::MalformedFilterList)?;
    let borrowed: Vec<_> = names.iter().map(String::as_str).collect();
    if names
        .iter()
        .any(|name| name.is_empty() || name.contains('\\'))
        || value.data != encode_multi_sz(&borrowed)
    {
        return Err(DeviceFilterPolicyError::MalformedFilterList);
    }
    Ok(names)
}

impl ConfigManager {
    /// Read filter policy from the live Enum instance and its `Control\Class\{GUID}` key.
    /// Missing class policy is empty; malformed present policy is an error.
    pub fn device_filter_policy(
        &self,
        instance_id: &str,
    ) -> Result<Option<DeviceFilterPolicy>, DeviceFilterPolicyError> {
        if instance_id.is_empty() || instance_id.contains('\0') {
            return Ok(None);
        }
        let registry = self.registry();
        let Some(device_key) = registry.open_key(&alloc::format!(r"{}\{}", ENUM_PATH, instance_id))
        else {
            return Ok(None);
        };
        let class_guid = match registry.query_value(device_key, "ClassGUID") {
            None => None,
            Some(value) => {
                let guid = value
                    .as_string()
                    .ok_or(DeviceFilterPolicyError::MalformedClassGuid)?;
                if value.value_type != RegistryValueType::Sz
                    || guid.is_empty()
                    || guid.contains('\\')
                    || value.data != encode_sz(&guid)
                {
                    return Err(DeviceFilterPolicyError::MalformedClassGuid);
                }
                Some(guid)
            }
        };
        let class_key = class_guid.as_ref().and_then(|guid| {
            registry.open_key(&alloc::format!(r"{}\{}", CONTROL_CLASS_PATH, guid))
        });
        Ok(Some(DeviceFilterPolicy {
            class_guid,
            device_lower: filter_list(registry, device_key, "LowerFilters")?,
            class_lower: class_key
                .map(|key| filter_list(registry, key, "LowerFilters"))
                .transpose()?
                .unwrap_or_default(),
            device_upper: filter_list(registry, device_key, "UpperFilters")?,
            class_upper: class_key
                .map(|key| filter_list(registry, key, "UpperFilters"))
                .transpose()?
                .unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_multi_sz;

    #[test]
    fn preserves_device_then_class_filter_order() {
        let mut cm = ConfigManager::new();
        let dev = cm
            .registry_mut()
            .create_key(&alloc::format!(r"{}\ROOT\SAMPLE\0000", ENUM_PATH));
        cm.registry_mut()
            .set_string(dev, "ClassGUID", "{sample-guid}");
        let class = cm
            .registry_mut()
            .create_key(&alloc::format!(r"{}\{{sample-guid}}", CONTROL_CLASS_PATH));
        for (key, name, values) in [
            (dev, "LowerFilters", &["device-low-a", "device-low-b"][..]),
            (class, "LowerFilters", &["class-low"][..]),
            (dev, "UpperFilters", &["device-high"][..]),
            (class, "UpperFilters", &["class-high-a", "class-high-b"][..]),
        ] {
            cm.registry_mut().set_value(
                key,
                name,
                RegistryValueType::MultiSz,
                encode_multi_sz(values),
            );
        }
        let policy = cm
            .device_filter_policy(r"ROOT\SAMPLE\0000")
            .unwrap()
            .unwrap();
        assert_eq!(policy.device_lower, ["device-low-a", "device-low-b"]);
        assert_eq!(policy.class_lower, ["class-low"]);
        assert_eq!(policy.device_upper, ["device-high"]);
        assert_eq!(policy.class_upper, ["class-high-a", "class-high-b"]);
        assert_eq!(cm.device_filter_policy(r"ROOT\MISSING\0000"), Ok(None));
    }

    #[test]
    fn rejects_wrong_type_instead_of_dropping_filter() {
        let mut cm = ConfigManager::new();
        let dev = cm
            .registry_mut()
            .create_key(&alloc::format!(r"{}\ROOT\SAMPLE\0000", ENUM_PATH));
        cm.registry_mut()
            .set_string(dev, "LowerFilters", "unexpected-sz");
        assert_eq!(
            cm.device_filter_policy(r"ROOT\SAMPLE\0000"),
            Err(DeviceFilterPolicyError::MalformedFilterList)
        );
    }
}
