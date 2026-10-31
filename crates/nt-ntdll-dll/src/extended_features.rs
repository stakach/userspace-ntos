//! XState feature query from the process's mapped NT shared-data page.

/// `RtlGetEnabledExtendedFeatures(ULONG64 FeatureMask) -> ULONG64`.
///
/// LiberNT reads `SharedUserData->XState.EnabledFeatures`; the executive currently
/// advertises zero until it implements the matching extended-state context switch.
#[export_name = "RtlGetEnabledExtendedFeatures"]
pub extern "system" fn rtl_get_enabled_extended_features(mask: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: every hosted user process maps KUSER_SHARED_DATA at this fixed address.
    unsafe {
        nt_ntdll_layout::kuser::read_enabled_extended_features(0x7ffe_0000 as *const u8, mask)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = mask;
        0
    }
}

#[used]
pub static EXTENDED_FEATURES_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = extended_features_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// This routine is only stored in a `#[used]` static.
pub unsafe extern "C" fn extended_features_export_anchor() {
    core::hint::black_box(rtl_get_enabled_extended_features as *const () as usize);
}
