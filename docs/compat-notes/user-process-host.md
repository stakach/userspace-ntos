# NT User Process Host + official ntdll bootstrap — compatibility notes

The seL4-hosted user-mode side (spec: NT User Process Host + Official ntdll Bootstrap). Wires the
native syscall dispatcher to the real subsystems + builds the PEB/TEB/KUSER_SHARED_DATA.

## nt-user-host (implemented, Milestones 29.1-29.3)

- WindowsProfile (§3): the pinned version profile (Windows 11 23H2 — OSMajor 10, build 22631,
  platform NT, NumberOfProcessors).
- PEB/TEB/KUSER builders (§10-§12): byte layouts with the required fields at their real x64
  offsets — PEB (ImageBaseAddress@0x10, Ldr@0x18, ProcessParameters@0x20, NumberOfProcessors@0xB8,
  OSMajor/Minor/Build/Platform @0x118..), TEB (NT_TIB StackBase/Limit/Self, ClientId, PEB pointer,
  LastError), KUSER_SHARED_DATA (a read-only page at 0x7FFE0000: TickCount, SystemTime, NtProductType,
  NtMajor/MinorVersion, ProcessorFeatures).
- UserProcessHost (§8): launch a process (nt-process) + its main thread and build its PEB/TEB/KUSER
  at fixed user VAs (spec §14).
- KernelServices (§7, §16): the NativeSyscallHandler wiring the dispatcher to real subsystems —
  NtOpenKey/NtQueryValueKey → Configuration Manager registry, NtCreateFile/NtReadFile/NtWriteFile →
  MemFs filesystem, NtAllocateVirtualMemory → Address Space, NtTerminateProcess → Process Manager,
  NtQuerySystemTime + NtQuerySystemInformation(SystemBasicInformation/TimeOfDay) → KUSER/profile.
  Unimplemented services return STATUS_NOT_IMPLEMENTED (never silently succeed, §9.2).
- nt-syscall gains NtQuerySystemInformation + NtQuerySystemTime services.
- 5 unit tests: PEB/TEB layout offsets, KUSER version, host launch (process+thread+structs),
  dispatch across registry/memory/sysinfo/time, dispatch file create/write/read.

## User Process Host in QEMU (implemented, Milestone 29 — `configuration-manager`)

The `configuration-manager` component now also proves the User Process Host bare-metal on seL4
(38/38 checks): it builds a KernelServices layer (fresh ConfigManager + MemFs), launches a
UserProcessHost — verifying the PEB (OSBuildNumber=22631), TEB (ClientId + PEB pointer at their
real offsets), and KUSER_SHARED_DATA (NtMajorVersion=10) — then dispatches real syscalls through
the wired handler: NtOpenKey→NtQueryValueKey returns Answer=42 (registry), NtQuerySystemTime
returns the KUSER time, and NtAllocateVirtualMemory reserves a region (address space).

## Windows 7 pin + driving the real ntdll (implemented)

The v0.1 profile is pinned to **Windows 7 SP1** (NT 6.1, build 7601) to avoid the NT 6.3+ ABI
complexity, and the host now loads + drives the *real* unmodified `references/ntdll.dll`:

- `nt-pe-loader` gained export-table parsing (`PeFile::exports` → name/RVA/ordinal).
- `nt-syscall`: `UserlandAbiProfile::Windows7` + `NativeServiceTable::from_numbers` (a table keyed
  by real syscall numbers, not sequential test numbers).
- `nt-user-host::NtdllImage`: loads the official ntdll as a PE image (layout + relocations),
  decodes the syscall number from each `Nt*`/`Zw*` stub's own bytes (`mov r10,rcx; mov eax,<ssn>;
  syscall`), and builds the Windows-7 service table keyed by those real numbers.
  `NtdllImage::invoke` executes a real export stub the way the CPU would — reads the loaded stub,
  takes the `eax` immediate, dispatches it.
- Integration tests (skipped when `references/ntdll.dll` is absent): the real ntdll has 400 syscall
  stubs; the numbers match the known Win7 SP1 x64 SSDT (NtClose=0x0C, NtOpenKey=0x0F,
  NtQueryValueKey=0x14, NtQuerySystemInformation=0x33, NtWaitForSingleObject=0x01); and executing
  the real `NtOpenKey`/`NtQueryValueKey`/`NtQuerySystemInformation` stubs dispatches end-to-end
  through the wired subsystems (registry Answer=42, NumberOfProcessors).
