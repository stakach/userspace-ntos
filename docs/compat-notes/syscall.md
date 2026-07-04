# NT Native Syscall + Userland ABI — compatibility notes

The kernel entry the official ntdll.dll reaches through (spec: NT Native Syscall + Official
Userland ABI). A per-profile service table + a dispatcher routing syscall numbers to subsystems.

## nt-syscall (implemented, Milestones 28.1-28.3, 28.6 partial)

- Profiles (§6): `UserlandAbiProfile` (Test = deterministic sequential numbers; Windows11 shape TBD).
- Service table (§9.1): `NativeService` enum (the required §16 Nt* services — object/file/registry/
  memory/process/security families), `NativeServiceTable::test_profile` (number<->service<->name,
  per-service min/max arg counts), `SyscallRegisterAbi::x64` (eax=number, r10/rdx/r8/r9 args, rax=status).
- Dispatcher (§9.3): `NativeSyscallDispatcher::dispatch`/`dispatch_service` — validate the service
  number + argument count, build a `NativeCallContext`, set PreviousMode (`SyscallOrigin` carries
  Nt=UserMode / Zw=KernelMode, §8.4), route to a `NativeSyscallHandler`, return `SyscallResult`.
  Unknown number → STATUS_INVALID_SYSTEM_SERVICE without invoking the handler; unimplemented
  services return an error (never silently succeed, §9.2).
- copyin/copyout (§10): `UserProbe` (probe_for_read/write over committed user ranges).
- The `NativeSyscallHandler` trait is the seam the kernel-services layer implements to wire the
  Object/File/Registry/Memory/Process/Security subsystems; the tests wire a ConfigManager +
  ProcessManager so NtOpenKey→NtQueryValueKey (Answer=42) and NtTerminateProcess dispatch end-to-end.
- 8 unit tests: service-table numbering, unknown-service rejection, arg-count validation, Nt-vs-Zw
  previous mode, end-to-end registry query, end-to-end process terminate, unimplemented-not-silent,
  user-probe ranges.

## Syscall dispatch in QEMU (implemented, Milestone 28 — `configuration-manager`)

The `configuration-manager` component now also proves the native syscall dispatcher bare-metal on
seL4 (36/36 checks): a `NativeSyscallDispatcher` (Test profile) with a handler wiring the
component's ConfigManager — `NtQueryValueKey` dispatches to the registry and returns Answer=42 with
PreviousMode=UserMode (the Nt* path), an unknown service number is rejected with
STATUS_INVALID_SYSTEM_SERVICE, and a Zw* call runs as PreviousMode=KernelMode.
