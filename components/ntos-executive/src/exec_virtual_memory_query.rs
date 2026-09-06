//! Native memory queries project private backing without changing fault-handler view policy.

use super::*;
use super::virtual_memory_copy::ProcessWriteProbe;
use nt_address_space::native_output::VmBasicQueryOutput;

pub(super) unsafe fn native_page_protection(
    pi: usize,
    info: nt_address_space::VmBasicInformation,
) -> u32 {
    let page = info.base_address;
    let private = csrss_frame_get_exact_record(pi as u64, page)
        .is_some_and(|record| record.owns_frame)
        || (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).contains(pi as u64, page);
    nt_address_space::query::page_protection(info.type_, info.protect, private)
}

impl ExecNtHandler {
    unsafe fn query_native_memory_basic_information(
        &self,
        target_pi: usize,
        address: u64,
    ) -> Result<nt_address_space::VmBasicInformation, u32> {
        let information = self.query_memory_basic_information(target_pi, address)?;
        if !matches!(
            information.type_,
            nt_address_space::MEM_IMAGE | nt_address_space::MEM_MAPPED
        ) {
            return Ok(information);
        }
        let table = process_committed_mapping_table(target_pi)
            .ok_or(nt_address_space::STATUS_NOT_COMMITTED)?;
        table
            .query_basic_with_private_pages(
                address,
                process_private_backing_pages(target_pi as u64),
            )?
            .ok_or(nt_address_space::STATUS_NOT_COMMITTED)
    }

    pub(crate) unsafe fn nt_query_virtual_memory_with_user_memory(
        &mut self,
        args: &[u64],
        memory: SyscallUserMemory,
    ) -> u32 {
        const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        const HIGHEST_USER_ADDRESS: u64 = 0x0000_07ff_fffe_ffff;
        let process_handle = args.first().copied().unwrap_or(0);
        let base = args.get(1).copied().unwrap_or(0);
        let info_class = nt_ulong_arg(args.get(2).copied().unwrap_or(u64::MAX));
        let buffer = args.get(3).copied().unwrap_or(0);
        let length = args.get(4).copied().unwrap_or(0);
        let return_length = args.get(5).copied().unwrap_or(0);

        if info_class != 0 {
            return STATUS_INVALID_INFO_CLASS;
        }
        let output = VmBasicQueryOutput {
            information: buffer,
            length,
            return_length,
        };
        let SyscallUserMemory::CurrentProcess = memory;
        if let Err(status) = output.probe(&mut ProcessWriteProbe::current(self), USER_ADDRESS_LIMIT) {
            return status;
        }
        if base > HIGHEST_USER_ADDRESS {
            return STATUS_INVALID_PARAMETER;
        }

        let (target_pid, target_pi) = match self
            .resolve_process_for_access(process_handle, nt_process::PROCESS_QUERY_INFORMATION)
        {
            Ok(target) => target,
            Err(status) => return status,
        };
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            return nt_process::STATUS_PROCESS_IS_TERMINATING;
        }

        let info = match self.query_native_memory_basic_information(target_pi, base) {
            Ok(info) => info,
            Err(status) => return status,
        };
        output.publish(&mut ProcessWriteProbe::current(self), &info.encode_x64())
            .map_or_else(|status| status, |_| 0)
    }
}
