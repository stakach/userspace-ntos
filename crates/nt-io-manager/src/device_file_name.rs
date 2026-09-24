//! Resolve a provider File name against dynamically registered Device names.

use crate::{DeviceId, IoManager};

fn fold_ascii(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) {
        unit + 32
    } else {
        unit
    }
}

fn device_prefix_len(name: &[u16], device: &nt_types::NtPath, ignore_case: bool) -> Option<usize> {
    if name.first() != Some(&(b'\\' as u16)) || device.components().is_empty() {
        return None;
    }
    let mut offset = 1;
    for (index, component) in device.components().iter().enumerate() {
        if index != 0 {
            if name.get(offset) != Some(&(b'\\' as u16)) {
                return None;
            }
            offset += 1;
        }
        let length = name[offset..]
            .iter()
            .position(|unit| *unit == b'\\' as u16)
            .unwrap_or(name.len() - offset);
        let candidate = &name[offset..offset + length];
        if candidate.len() != component.len()
            || !candidate
                .iter()
                .zip(component.as_units())
                .all(|(&left, &right)| {
                    if ignore_case {
                        fold_ascii(left) == fold_ascii(right)
                    } else {
                        left == right
                    }
                })
        {
            return None;
        }
        offset += length;
    }
    (offset == name.len() || name[offset] == b'\\' as u16).then_some(offset)
}

impl<P> IoManager<P> {
    /// Match the longest live Device path at a component boundary. The suffix starts with its
    /// separator, or is empty for an exact Device open; no device identity is hardcoded here.
    pub fn device_prefix_for_file_name(
        &self,
        name: &[u16],
        ignore_case: bool,
    ) -> Option<(DeviceId, usize)> {
        self.devices
            .iter()
            .filter_map(|(id, record)| {
                (!record.delete_pending)
                    .then(|| record.name.as_ref())
                    .flatten()
                    .and_then(|path| device_prefix_len(name, path, ignore_case))
                    .map(|length| (id, length))
            })
            .max_by_key(|(_, length)| *length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType, DriverBackendId,
        DriverRecord, MajorFunctionTable, MockObjectPort,
    };
    use nt_types::{NtPath, ObjectId};

    fn path(value: &str) -> NtPath {
        NtPath::parse_str(value).unwrap()
    }

    fn name(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().collect()
    }

    #[test]
    fn longest_live_registered_prefix_wins_without_partial_component_matches() {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            path("\\Driver\\Redirector"),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ));
        let mut register = |path_value: &str| {
            io.add_device(DeviceRecord::new(
                ObjectId::NULL,
                driver,
                Some(path(path_value)),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            ))
        };
        let parent = register("\\Device\\Redirector");
        let child = register("\\Device\\Redirector\\Private");
        let full = name("\\device\\redirector\\private\\file");
        let (device, suffix) = io.device_prefix_for_file_name(&full, true).unwrap();
        assert_eq!(device, child);
        assert_eq!(&full[suffix..], name("\\file"));
        assert_eq!(io.device_prefix_for_file_name(&full, false), None);
        assert_eq!(
            io.device_prefix_for_file_name(&name("\\Device\\RedirectorX\\file"), true),
            None
        );
        let exact = name("\\Device\\Redirector");
        assert_eq!(
            io.device_prefix_for_file_name(&exact, true),
            Some((parent, exact.len()))
        );
        io.remove_device(child).unwrap();
        let (device, suffix) = io.device_prefix_for_file_name(&full, true).unwrap();
        assert_eq!(device, parent);
        assert_eq!(&full[suffix..], name("\\private\\file"));
    }
}
