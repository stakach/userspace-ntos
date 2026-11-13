//! Bounded, typed DEVPROPKEY publication into the Configuration Manager authority.

use super::*;

pub const MAX_DEVPROP_WRITE_BYTES: usize = 1024;

impl CmServer {
    pub(super) fn op_set_device_devprop(&mut self, buf: &[u8]) -> CmReply {
        let Some(req) = CmDevpropSetRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header = core::mem::size_of::<CmDevpropSetRequest>();
        let instance_end = match header.checked_add(req.instance_len_bytes as usize) {
            Some(end) => end,
            None => return reply(STATUS_INVALID_PARAMETER, 0),
        };
        if req.abi_size as usize != header || req.abi_version != CM_ABI_VERSION
            || req.instance_offset as usize != header
            || req.instance_len_bytes == 0 || req.instance_len_bytes % 2 != 0
            || req.instance_len_bytes as usize > CM_MAX_INSTANCE_UNITS * 2
            || req.data_offset as usize != instance_end
            || req.data_len as usize > MAX_DEVPROP_WRITE_BYTES
            || instance_end.checked_add(req.data_len as usize) != Some(buf.len())
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let mut units = [0u16; CM_MAX_INSTANCE_UNITS];
        let Some(count) = read_utf16(buf, req.instance_offset, req.instance_len_bytes, &mut units)
        else { return reply(STATUS_INVALID_PARAMETER, 0); };
        if units[..count].contains(&0) { return reply(STATUS_INVALID_PARAMETER, 0); }
        let Ok(instance) = String::from_utf16(&units[..count]) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let data = &buf[instance_end..];
        match req.property_type {
            devprop_type::UINT32 if data.len() == 4 => {}
            devprop_type::STRING if data.len() >= 2 && data.len() % 2 == 0
                && data[data.len() - 2..] == [0, 0]
                && data[..data.len() - 2].chunks_exact(2).all(|unit| unit != [0, 0]) => {}
            _ => return reply(STATUS_INVALID_PARAMETER, 0),
        }
        let Some(id) = self.cm.devnode(&instance).map(|devnode| devnode.id)
            .or_else(|| self.cm.index_registry_devnode(&instance))
        else { return reply(STATUS_OBJECT_NAME_NOT_FOUND, 0); };
        let value = PropertyValue { prop_type: req.property_type, data: data.to_vec() };
        if self.cm.assign_devprop(id, DevPropKey { fmtid: req.fmtid, pid: req.pid }, value) {
            reply(STATUS_SUCCESS, 0)
        } else {
            reply(STATUS_OBJECT_NAME_NOT_FOUND, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTANCE: &str = r"ACPI\TEST\0001";

    fn request(instance: &str, value: &[u8]) -> Vec<u8> {
        let mut units = Vec::new();
        for unit in instance.encode_utf16() { units.extend_from_slice(&unit.to_le_bytes()); }
        let header_size = core::mem::size_of::<CmDevpropSetRequest>();
        let header = CmDevpropSetRequest {
            abi_size: header_size as u16,
            abi_version: CM_ABI_VERSION,
            property_type: devprop_type::UINT32,
            fmtid: [0xa5; 16],
            pid: 23,
            instance_offset: header_size as u32,
            instance_len_bytes: units.len() as u32,
            data_offset: (header_size + units.len()) as u32,
            data_len: value.len() as u32,
        };
        let mut out = Vec::new();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(&units);
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn typed_write_requires_existing_devnode_and_is_queryable() {
        let mut server = CmServer::new_for_incarnation(core::num::NonZeroU32::MIN);
        let value = 7u32.to_le_bytes();
        assert_eq!(server.dispatch(opcode::CM_OP_SET_DEVICE_DEVPROP,
            &request(INSTANCE, &value), &mut []).status, STATUS_OBJECT_NAME_NOT_FOUND);
        let id = server.cm.register_devnode(INSTANCE, None, Some(r"\Device\AcpiTest"), &[], &[]);
        assert_eq!(server.dispatch(opcode::CM_OP_SET_DEVICE_DEVPROP,
            &request(INSTANCE, &value), &mut []).status, STATUS_SUCCESS);
        assert_eq!(server.cm.query_devprop(id, &DevPropKey { fmtid: [0xa5; 16], pid: 23 })
            .and_then(PropertyValue::as_uint32), Some(7));
        assert_eq!(server.dispatch(opcode::CM_OP_SET_DEVICE_DEVPROP,
            &request(INSTANCE, &[1, 2, 3]), &mut []).status, STATUS_INVALID_PARAMETER);
    }
}
