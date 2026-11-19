//! The shim engine interface the loader calls (ReactOS `dll/ntdll/ldr/ldrutils.c`
//! `LdrpGetShimEngineInterface`): five `SE_*` exports of the shim engine module. The engine is
//! enabled only when all five resolve; otherwise it is not used at all.

/// The exports, in the order the interface stores them.
pub const SHIM_ENGINE_EXPORTS: [&str; 5] = [
    "SE_DllLoaded",
    "SE_DllUnloaded",
    "SE_InstallBeforeInit",
    "SE_InstallAfterInit",
    "SE_ProcessDying",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShimEngineInterface {
    pub dll_loaded: u64,
    pub dll_unloaded: u64,
    pub install_before_init: u64,
    pub install_after_init: u64,
    pub process_dying: u64,
}

impl ShimEngineInterface {
    /// Resolve the interface with `lookup` (an export address, or 0 when absent).
    pub fn resolve(mut lookup: impl FnMut(&str) -> u64) -> Option<Self> {
        let mut addresses = [0u64; 5];
        for (address, name) in addresses.iter_mut().zip(SHIM_ENGINE_EXPORTS) {
            *address = lookup(name);
            if *address == 0 {
                return None;
            }
        }
        Some(Self {
            dll_loaded: addresses[0],
            dll_unloaded: addresses[1],
            install_before_init: addresses[2],
            install_after_init: addresses[3],
            process_dying: addresses[4],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_engine_is_used_only_with_its_complete_interface() {
        let all = ShimEngineInterface::resolve(|name| match name {
            "SE_DllLoaded" => 0x10,
            "SE_DllUnloaded" => 0x20,
            "SE_InstallBeforeInit" => 0x30,
            "SE_InstallAfterInit" => 0x40,
            "SE_ProcessDying" => 0x50,
            _ => 0,
        })
        .unwrap();
        assert_eq!((all.dll_loaded, all.dll_unloaded, all.process_dying), (0x10, 0x20, 0x50));
        assert_eq!(
            ShimEngineInterface::resolve(|name| if name == "SE_ProcessDying" { 0 } else { 1 }),
            None
        );
    }
}
