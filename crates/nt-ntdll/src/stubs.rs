//! The data-driven `Nt*` stub table.
//!
//! Every `Nt*` export our ntdll ships resolves — by NAME — to an SSN (from the shared
//! [`nt_syscall_abi`](nt_syscall_abi) table, the single source of truth) and a transport backend
//! (from [`transport::Backend::for_ssn`]). A stub is then just: look up the SSN, marshal the args,
//! call [`transport::syscall`]. This module builds that table over the whole required
//! surface and provides the generic invoke path; [`crate::rtl`] + a few wired stubs prove the
//! pattern end-to-end.

use crate::transport::{self, Backend};
use crate::{NtStatus, STATUS_INVALID_SYSTEM_SERVICE};
use nt_syscall_abi::{NtSyscall, NT_SYSCALLS};

/// One resolved `Nt*` stub: its export name, SSN, and chosen transport backend.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Stub {
    /// The `Nt*` export name.
    pub name: &'static str,
    /// The SSN (from the shared ABI table).
    pub ssn: u32,
    /// The transport backend selected for this SSN.
    pub backend: Backend,
}

impl Stub {
    /// Invoke this stub's syscall with the given register-width args.
    pub fn invoke(&self, args: &[u64]) -> NtStatus {
        transport::syscall(self.backend, self.ssn, args)
    }
}

/// The full `Nt*` stub table, one [`Stub`] per required export, in the shared table's SSN order.
///
/// Built at first use (const-fn `Backend::for_ssn` means this is cheap and allocation-free — it's a
/// direct projection of [`NT_SYSCALLS`]).
pub struct StubTable {
    stubs: [Stub; NT_SYSCALLS.len()],
}

impl Default for StubTable {
    fn default() -> Self {
        Self::new()
    }
}

impl StubTable {
    /// Build the stub table from the shared ABI table.
    pub fn new() -> Self {
        // Project each shared ABI entry into a stub with its selected backend.
        let mut stubs = [Stub {
            name: "",
            ssn: 0,
            backend: Backend::X86Trap,
        }; NT_SYSCALLS.len()];
        let mut i = 0;
        while i < NT_SYSCALLS.len() {
            let NtSyscall { name, ssn } = NT_SYSCALLS[i];
            stubs[i] = Stub {
                name,
                ssn,
                backend: Backend::for_ssn(ssn),
            };
            i += 1;
        }
        StubTable { stubs }
    }

    /// All stubs.
    pub fn all(&self) -> &[Stub] {
        &self.stubs
    }

    /// The number of stubs (= the required `Nt*` surface size).
    pub fn len(&self) -> usize {
        self.stubs.len()
    }

    /// Whether the table is empty (never, for the real table).
    pub fn is_empty(&self) -> bool {
        self.stubs.is_empty()
    }

    /// Resolve a stub by `Nt*` export name.
    pub fn get(&self, name: &str) -> Option<&Stub> {
        self.stubs.iter().find(|s| s.name == name)
    }

    /// Resolve a stub by SSN.
    pub fn get_by_ssn(&self, ssn: u32) -> Option<&Stub> {
        self.stubs.iter().find(|s| s.ssn == ssn)
    }

    /// Invoke a stub by name. Returns [`STATUS_INVALID_SYSTEM_SERVICE`] for an unknown name — never
    /// a silent success (matches the executive dispatcher's contract).
    pub fn invoke(&self, name: &str, args: &[u64]) -> NtStatus {
        match self.get(name) {
            Some(s) => s.invoke(args),
            None => STATUS_INVALID_SYSTEM_SERVICE,
        }
    }
}

// --- Proof-of-pattern slice: fully-wired representative Nt* stubs -------------------------------
//
// These prove the name -> SSN -> transport path end-to-end for services spanning the range. Each is
// a thin, typed wrapper that resolves its SSN through the shared ABI table and issues the transport
// call — exactly the shape the full 188-stub body port (Step 2b) will fill out. On the host the
// transport returns STATUS_NOT_IMPLEMENTED (no trap available); on the x86_64 target it issues the
// real trap. The wiring — SSN resolution + backend selection + arg marshalling — is what's proven.

/// `NtClose(Handle)` — SSN 27. Closes an object handle.
pub fn nt_close(table: &StubTable, handle: u64) -> NtStatus {
    table.invoke("NtClose", &[handle])
}

/// `NtDelayExecution(Alertable, DelayInterval*)` — SSN 61.
pub fn nt_delay_execution(table: &StubTable, alertable: bool, interval: u64) -> NtStatus {
    table.invoke("NtDelayExecution", &[alertable as u64, interval])
}

/// `NtCreateFile(FileHandle*, DesiredAccess, ObjectAttributes*, IoStatusBlock*, ...)` — SSN 39.
/// (>4 args in the real ABI; the extra args go via a stack thunk in the full port. Here we wire the
/// leading register args to prove SSN resolution.)
pub fn nt_create_file(
    table: &StubTable,
    file_handle_out: u64,
    desired_access: u64,
    object_attributes: u64,
    io_status_block: u64,
) -> NtStatus {
    table.invoke(
        "NtCreateFile",
        &[file_handle_out, desired_access, object_attributes, io_status_block],
    )
}

/// `NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *NumberOfBytes, NewProtect, *OldProtect)`
/// — SSN 143.
pub fn nt_protect_virtual_memory(
    table: &StubTable,
    process: u64,
    base_address: u64,
    region_size: u64,
    new_protect: u64,
) -> NtStatus {
    table.invoke(
        "NtProtectVirtualMemory",
        &[process, base_address, region_size, new_protect],
    )
}

/// `NtWaitForSingleObject(Handle, Alertable, Timeout*)` — SSN 281.
pub fn nt_wait_for_single_object(
    table: &StubTable,
    handle: u64,
    alertable: bool,
    timeout: u64,
) -> NtStatus {
    table.invoke("NtWaitForSingleObject", &[handle, alertable as u64, timeout])
}
