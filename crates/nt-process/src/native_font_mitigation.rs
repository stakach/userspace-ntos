//! Exact process mitigation state queried by native win32k Ps imports.

use crate::{ProcessManager, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS};

/// PROCESS_MITIGATION_POLICY::ProcessFontDisablePolicy in the Windows Kit.
pub const PROCESS_FONT_DISABLE_POLICY: u32 = 9;

impl ProcessManager {
    /// `PsGetProcessMitigationPolicyFlags(EPROCESS, selector)` currently supports only the font
    /// policy consumed by the pinned win32k image. The caller must supply an exact published body.
    pub fn process_mitigation_policy_flags_by_kernel_object(
        &self,
        eprocess: u64,
        selector: u32,
    ) -> Result<u32, u32> {
        if selector != PROCESS_FONT_DISABLE_POLICY {
            return Err(STATUS_INVALID_INFO_CLASS);
        }
        let pid = self
            .pid_for_kernel_process_object(eprocess)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(process.font_disable_policy_flags)
    }
}
