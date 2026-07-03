//! The `DriverEntry` call gate (spec §8.1). Abstracted behind a trait so host
//! tests substitute a Rust closure (this host is aarch64 and cannot execute x64
//! driver code) while the kernel uses the real Microsoft-x64 gate.

use nt_kernel_abi::GuestAddr;

use crate::DriverServices;

/// The arguments to a `DriverEntry` / dispatch call.
#[derive(Copy, Clone, Debug)]
pub struct EntryContext {
    /// Absolute address of the routine to call (`load_base + rva`).
    pub entry_point: u64,
    /// Guest address of the `DRIVER_OBJECT` projection.
    pub driver_object: GuestAddr,
    /// Guest address of the `RegistryPath` `UNICODE_STRING` projection.
    pub registry_path: GuestAddr,
}

/// A gate that invokes a driver routine under the Microsoft x64 ABI (spec §8.1).
pub trait DriverEntryGate {
    /// Call `DriverEntry(DriverObject, RegistryPath)`; returns the `NTSTATUS`. The
    /// routine reaches kernel services + guest memory via `services` — the real
    /// gate lets the driver call export trampolines that reach the same services;
    /// a mock gate calls them explicitly.
    fn call_driver_entry(&self, ctx: EntryContext, services: &mut DriverServices) -> i32;
}

/// A host/test gate backed by a Rust closure — no real x64 execution.
pub struct MockGate<F>(pub F);

impl<F> DriverEntryGate for MockGate<F>
where
    F: Fn(&EntryContext, &mut DriverServices) -> i32,
{
    fn call_driver_entry(&self, ctx: EntryContext, services: &mut DriverServices) -> i32 {
        (self.0)(&ctx, services)
    }
}

/// The real gate: calls the mapped driver's entry point under the Microsoft x64
/// calling convention. Only available on x86_64 (the loaded code is x64). The
/// driver reaches kernel services through its import trampolines, not `services`.
#[cfg(target_arch = "x86_64")]
pub struct Win64Gate;

#[cfg(target_arch = "x86_64")]
impl DriverEntryGate for Win64Gate {
    fn call_driver_entry(&self, ctx: EntryContext, _services: &mut DriverServices) -> i32 {
        // SAFETY: the Driver Host guarantees `entry_point` is a mapped, executable,
        // relocated `DriverEntry` whose ABI is the Microsoft x64 calling convention
        // (spec §8.1) before the driver is started; the driver accesses the
        // projections at the guest addresses passed here directly.
        unsafe {
            let f: extern "win64" fn(u64, u64) -> i32 =
                core::mem::transmute(ctx.entry_point as *const ());
            f(ctx.driver_object.0, ctx.registry_path.0)
        }
    }
}
