//! # `nt-driver-host` — load + run a WDM driver
//!
//! Orchestrates the Driver Host v0.1 path (spec §6, §9): validate + map + relocate
//! a `.sys` image, patch its imports to export trampolines, build the
//! `DRIVER_OBJECT` + `RegistryPath` projections, call `DriverEntry`, and capture
//! the `MajorFunction` dispatch table + `DriverUnload` it installs. The
//! `DriverEntry` call is abstracted behind [`DriverEntryGate`] so host tests use a
//! Rust mock (this build host cannot execute x64) while the kernel uses the real
//! Microsoft-x64 gate. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

mod call;
mod load;
mod services;

#[cfg(target_arch = "x86_64")]
pub use call::Win64Gate;
pub use call::{DriverEntryGate, EntryContext, MockGate};
pub use services::{
    BridgeCreateDevice, BridgeDeviceIds, DriverServices, IoManagerBridge, NullBridge,
};

// Re-exported so gate closures + callers need only depend on this crate.
pub use nt_driver_runtime::{Arena, DriverRuntime};

use alloc::string::String;
use alloc::vec::Vec;

use nt_compat_exports::{ExportRegistry, ImportReport};
use nt_kernel_abi::{GuestAddr, MAJOR_FUNCTION_COUNT};
use nt_pe_loader::{MappedImage, PeError};
use nt_status::NtStatus;

/// The driver's lifecycle state (spec §9).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DriverState {
    Unloaded,
    Loaded,
    Started,
    Failed,
}

/// Why a load / start failed.
#[derive(Clone, Debug)]
pub enum LoadError {
    /// The PE image is malformed.
    Parse(PeError),
    /// Mapping / relocating / patching failed.
    Map(PeError),
    /// One or more imports cannot run under the v0.1 export set (spec §9).
    BlockedImports(ImportReport),
    /// The runtime arena is exhausted.
    OutOfArena,
    /// `start` called before a successful `load`.
    NotLoaded,
    /// `DriverEntry` returned a failure `NTSTATUS`.
    DriverEntryFailed(i32),
}

/// A loaded Driver Host instance for one driver.
pub struct DriverHost {
    registry: ExportRegistry,
    runtime: DriverRuntime,
    image: Option<MappedImage>,
    driver_object: Option<GuestAddr>,
    registry_path: Option<GuestAddr>,
    state: DriverState,
    dispatch: [GuestAddr; MAJOR_FUNCTION_COUNT],
    unload_routine: GuestAddr,
    entry_status: i32,
    trampoline_next: u64,
    bound_trampolines: Vec<(String, String, u64)>,
}

impl DriverHost {
    /// A Driver Host whose object arena is `arena_capacity` bytes based at guest
    /// address `arena_base`, with import trampolines assigned from
    /// `trampoline_base`.
    pub fn new(arena_base: u64, arena_capacity: usize, trampoline_base: u64) -> Self {
        Self {
            registry: ExportRegistry::new(),
            runtime: DriverRuntime::new(arena_base, arena_capacity),
            image: None,
            driver_object: None,
            registry_path: None,
            state: DriverState::Unloaded,
            dispatch: [GuestAddr::NULL; MAJOR_FUNCTION_COUNT],
            unload_routine: GuestAddr::NULL,
            entry_status: 0,
            trampoline_next: trampoline_base,
            bound_trampolines: Vec::new(),
        }
    }

    /// Call `DriverEntry` through `gate` and capture what it installs (spec §9
    /// steps 10–11). The driver reaches the I/O Manager through `bridge` (for
    /// `IoCreateDevice` etc.). On success the driver is `Started`; on failure the
    /// partial projections are cleaned up (spec §9 failure path) and the driver is
    /// `Failed`.
    pub fn start(
        &mut self,
        gate: &dyn DriverEntryGate,
        bridge: &mut dyn IoManagerBridge,
    ) -> Result<(), LoadError> {
        let (Some(drv), Some(regpath), Some(image)) =
            (self.driver_object, self.registry_path, self.image.as_ref())
        else {
            return Err(LoadError::NotLoaded);
        };
        let ctx = EntryContext {
            entry_point: image.entry_point(),
            driver_object: drv,
            registry_path: regpath,
        };
        let status = {
            let mut services = DriverServices::new(&mut self.runtime, bridge);
            gate.call_driver_entry(ctx, &mut services)
        };
        self.entry_status = status;

        if NtStatus(status).is_success() {
            // Capture the dispatch table + DriverUnload the driver installed.
            if let Some(drvobj) = self.runtime.driver_object() {
                self.dispatch = drvobj.major_function;
                self.unload_routine = drvobj.driver_unload;
            }
            self.state = DriverState::Started;
            Ok(())
        } else {
            self.cleanup_failed();
            self.state = DriverState::Failed;
            Err(LoadError::DriverEntryFailed(status))
        }
    }

    fn cleanup_failed(&mut self) {
        if let Some(d) = self.driver_object {
            self.runtime.objects_mut().retire(d);
        }
        if let Some(r) = self.registry_path {
            self.runtime.objects_mut().retire(r);
        }
    }

    // --- inspection --------------------------------------------------------

    pub fn state(&self) -> DriverState {
        self.state
    }
    pub fn entry_status(&self) -> i32 {
        self.entry_status
    }

    /// The dispatch routine the driver installed for `major`, if any.
    pub fn dispatch(&self, major: u8) -> Option<GuestAddr> {
        let a = self.dispatch.get(major as usize).copied()?;
        (!a.is_null()).then_some(a)
    }

    /// The `DriverUnload` routine, if the driver installed one.
    pub fn unload_routine(&self) -> Option<GuestAddr> {
        (!self.unload_routine.is_null()).then_some(self.unload_routine)
    }

    /// The `(dll, name, trampoline)` bindings made for the driver's imports.
    pub fn bound_trampolines(&self) -> &[(String, String, u64)] {
        &self.bound_trampolines
    }

    pub fn driver_object_addr(&self) -> Option<GuestAddr> {
        self.driver_object
    }
    pub fn image(&self) -> Option<&MappedImage> {
        self.image.as_ref()
    }
    pub fn runtime(&self) -> &DriverRuntime {
        &self.runtime
    }
    pub fn runtime_mut(&mut self) -> &mut DriverRuntime {
        &mut self.runtime
    }
    pub fn registry(&self) -> &ExportRegistry {
        &self.registry
    }
    pub fn registry_mut(&mut self) -> &mut ExportRegistry {
        &mut self.registry
    }
}
