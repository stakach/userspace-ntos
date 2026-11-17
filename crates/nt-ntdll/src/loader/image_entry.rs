//! Which mapped images have an entry point the loader calls.
//!
//! ReactOS `LdrpMapDll` (`dll/ntdll/ldr/ldrutils.c:1290`) sets `LDRP_IMAGE_DLL` only for an
//! image whose file header carries `IMAGE_FILE_DLL`, and clears `EntryPoint` for every other
//! image. A program loaded with `LoadLibrary` (Explorer's RunOnceEx rundll32 loads
//! `iexplore.exe`) is mapped and snapped but its entry point is never called as a `DllMain`.

/// `IMAGE_FILE_DLL`.
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// The entry point RVA the loader may call with `DLL_PROCESS_ATTACH` / `DLL_THREAD_ATTACH`,
/// or 0 when it calls none.
pub fn dll_entry_point_rva(characteristics: u16, address_of_entry_point: u32) -> u32 {
    if characteristics & IMAGE_FILE_DLL != 0 {
        address_of_entry_point
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_dll_images_have_a_loader_called_entry_point() {
        // iexplore.exe: IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE.
        assert_eq!(dll_entry_point_rva(0x0022, 0x1234), 0);
        // A DLL keeps its DllMain.
        assert_eq!(dll_entry_point_rva(0x2022, 0x1234), 0x1234);
        // A resource-only DLL has none.
        assert_eq!(dll_entry_point_rva(0x2022, 0), 0);
    }
}
