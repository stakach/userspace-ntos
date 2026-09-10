//! Read-only mounted SYSTEM identity, distinct from generation and operation replay journals.

use super::*;
use nt_config_abi::CmSystemHiveMountRequest;

impl CmServer {
    pub(super) fn op_query_system_hive_mount(&self, buf: &[u8]) -> CmReply {
        let size = core::mem::size_of::<CmSystemHiveMountRequest>();
        let Some(req) = CmSystemHiveMountRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if buf.len() != size
            || req.abi_size as usize != size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
            || req._reserved != 0
            || req.expected_generation == 0
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let Some(mounted) = self.system_hive.as_ref() else {
            return reply(STATUS_DEVICE_NOT_READY, 0);
        };
        if req.expected_generation != mounted.generation
            || (req.expected_identity != 0 && req.expected_identity != mounted.identity)
        {
            return reply(STATUS_REVISION_MISMATCH, 0);
        }
        reply_with_info(STATUS_SUCCESS, 0, mounted.generation, mounted.identity)
    }
}

#[cfg(test)]
mod tests;
