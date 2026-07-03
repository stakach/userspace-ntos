//! The driver load sequence (spec §9 steps 3–10): parse, import check, map,
//! relocate, IAT patch, and projection setup.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use nt_pe_loader::{ImportRef, PeFile};

use crate::{DriverHost, DriverState, LoadError};

impl DriverHost {
    /// Load `bytes` (a `.sys` image) at `image_base`, checking imports, mapping +
    /// relocating the image, patching the IAT to export trampolines, and creating
    /// the `DRIVER_OBJECT` + `RegistryPath` projections. Leaves the driver
    /// `Loaded` (call [`DriverHost::start`] to run `DriverEntry`).
    pub fn load(
        &mut self,
        bytes: &[u8],
        image_base: u64,
        registry_path: &str,
    ) -> Result<(), LoadError> {
        let pe = PeFile::parse(bytes).map_err(LoadError::Parse)?;
        let imports = pe.imports().map_err(LoadError::Parse)?;

        // Resolve every import against the export set *before* execution (spec §9
        // step 5) — a blocked/missing import fails the load with a clear report.
        let mut pairs: Vec<(String, String)> = Vec::new();
        for dll in &imports {
            for f in &dll.functions {
                let name = match f {
                    ImportRef::ByName { name, .. } => name.clone(),
                    ImportRef::ByOrdinal { ordinal, .. } => {
                        let mut s = String::from("#");
                        s.push_str(&ordinal.to_string());
                        s
                    }
                };
                pairs.push((dll.name.clone(), name));
            }
        }
        let report = self
            .registry
            .check(pairs.iter().map(|(d, n)| (d.as_str(), n.as_str())));
        if !report.runnable() {
            return Err(LoadError::BlockedImports(report));
        }

        // Map + relocate (spec §9 step 6).
        let mut image = pe.map(image_base).map_err(LoadError::Map)?;

        // Patch each IAT slot to its export trampoline (spec §9 steps 7–8).
        for dll in &imports {
            for f in &dll.functions {
                if let ImportRef::ByName {
                    name, iat_slot_rva, ..
                } = f
                {
                    let tramp = self.bind_trampoline(&dll.name, name);
                    image
                        .patch_iat(*iat_slot_rva, tramp)
                        .map_err(LoadError::Map)?;
                }
            }
        }
        self.image = Some(image);

        // Projections (spec §9 steps 9–10).
        let drv = self
            .runtime
            .create_driver_object()
            .ok_or(LoadError::OutOfArena)?;
        let regpath = self
            .runtime
            .alloc_unicode_string(registry_path)
            .ok_or(LoadError::OutOfArena)?;
        self.driver_object = Some(drv);
        self.registry_path = Some(regpath);
        self.state = DriverState::Loaded;
        Ok(())
    }

    /// Assign (once) a trampoline address for `dll!name` + record the binding.
    fn bind_trampoline(&mut self, dll: &str, name: &str) -> u64 {
        if let Some(addr) = self.registry.trampoline(dll, name) {
            return addr;
        }
        let addr = self.trampoline_next;
        self.trampoline_next += 16;
        self.registry.set_trampoline(dll, name, addr);
        self.bound_trampolines
            .push((dll.to_string(), name.to_string(), addr));
        addr
    }
}
