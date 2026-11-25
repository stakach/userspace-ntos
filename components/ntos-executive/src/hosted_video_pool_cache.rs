//! Preserve the physical source's cache type when a video pool alias is projected to win32k.

use nt_hosted_runtime::ContiguousRamCachePolicy;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VideoAliasBackingCache {
    PoolRam,
    Contiguous(ContiguousRamCachePolicy),
}

pub(super) const fn page_map_rights(backing: VideoAliasBackingCache, rights: u64) -> u64 {
    match backing {
        VideoAliasBackingCache::PoolRam => rights,
        VideoAliasBackingCache::Contiguous(cache) => cache.compressed_map_rights(rights),
    }
}
