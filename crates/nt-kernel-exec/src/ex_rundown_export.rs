//! The native rundown export surface. A domain binder maps each export exhaustively to its
//! implementation, so this table is the authoritative list of names a registry receives.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExRundownExport {
    AcquireCacheAware,
    InitializeCacheAware,
    ReInitializeCacheAware,
    ReleaseCacheAware,
    SizeOfCacheAware,
    WaitForReleaseCacheAware,
    Acquire,
    Initialize,
    ReInitialize,
    Release,
    WaitForRelease,
}

impl ExRundownExport {
    pub const ALL: [Self; 11] = [
        Self::AcquireCacheAware, Self::InitializeCacheAware, Self::ReInitializeCacheAware,
        Self::ReleaseCacheAware, Self::SizeOfCacheAware, Self::WaitForReleaseCacheAware,
        Self::Acquire, Self::Initialize, Self::ReInitialize, Self::Release, Self::WaitForRelease,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::AcquireCacheAware => "ExAcquireRundownProtectionCacheAware",
            Self::InitializeCacheAware => "ExInitializeRundownProtectionCacheAware",
            Self::ReInitializeCacheAware => "ExReInitializeRundownProtectionCacheAware",
            Self::ReleaseCacheAware => "ExReleaseRundownProtectionCacheAware",
            Self::SizeOfCacheAware => "ExSizeOfRundownProtectionCacheAware",
            Self::WaitForReleaseCacheAware => "ExWaitForRundownProtectionReleaseCacheAware",
            Self::Acquire => "ExAcquireRundownProtection",
            Self::Initialize => "ExInitializeRundownProtection",
            Self::ReInitialize => "ExReInitializeRundownProtection",
            Self::Release => "ExReleaseRundownProtection",
            Self::WaitForRelease => "ExWaitForRundownProtectionRelease",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExRundownExport;

    #[test]
    fn every_rundown_export_has_one_distinct_nt_name() {
        let mut names = ExRundownExport::ALL.map(ExRundownExport::name).to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ExRundownExport::ALL.len());
        assert!(names.iter().all(|name| name.starts_with("Ex") && name.contains("RundownProtection")));
    }
}
