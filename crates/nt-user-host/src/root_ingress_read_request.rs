//! Memory-only decoding of an ordinary selected native File READ Call.

use nt_component_suspension::ReceivedMessage;
use nt_syscall::{NativeService, NativeServiceTable};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedRootReadRequest {
    handle: u64,
}

impl SelectedRootReadRequest {
    pub fn parse(message: &ReceivedMessage, table: &NativeServiceTable) -> Option<Self> {
        let info = message.info();
        if info >> 12 != nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL
            || message.message_len()?
                != nt_syscall_abi::native_syscall_request_len(9) as usize
        {
            return None;
        }
        let ssn = u32::try_from(message.word(0)?).ok()?;
        let entry = table.lookup(ssn)?;
        if entry.service != NativeService::NtReadFile || entry.max_args != 9 {
            return None;
        }
        Some(Self { handle: message.word(2)? })
    }

    pub const fn handle(self) -> u64 { self.handle }
}

#[cfg(test)]
mod tests {
    use nt_component_suspension::{IpcBufferSnapshot, ReceivedMessage};
    use nt_syscall::{NativeService, NativeServiceTable, UserlandAbiProfile};

    fn table() -> NativeServiceTable {
        NativeServiceTable::from_numbers(
            UserlandAbiProfile::Windows7, &[(NativeService::NtReadFile, 191)],
        )
    }

    fn message(info: u64, ssn: u64, handle: u64) -> ReceivedMessage {
        ReceivedMessage::new(828, info, [ssn, 0, handle, 0],
            IpcBufferSnapshot::capture(|_| 0))
    }

    #[test]
    fn selected_read_requires_registered_service_and_complete_native_call() {
        let read = message(nt_syscall_abi::native_syscall_message_info(9), 191, 0x6a11);
        assert_eq!(super::SelectedRootReadRequest::parse(&read, &table()).unwrap().handle(), 0x6a11);
        assert!(super::SelectedRootReadRequest::parse(
            &message(nt_syscall_abi::native_syscall_message_info(9), 190, 0x6a11), &table()).is_none());
        assert!(super::SelectedRootReadRequest::parse(
            &message(nt_syscall_abi::native_syscall_message_info(8), 191, 0x6a11), &table()).is_none());
        assert!(super::SelectedRootReadRequest::parse(
            &message(11, 191, 0x6a11), &table()).is_none());
    }
}
