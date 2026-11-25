//! The native x86 PageMap encoding for hosted physical page cache attributes.

use nt_pnp_context::resource_mapping::MappingCache;

/// rust-micro's compressed x86 PageMap ABI uses bit 3 for PWT+PCD (strong UC).
/// WC is deliberately unavailable until PAT and all physical aliases are proved safe.
pub(crate) const fn page_map_rights(rights: u64, cache: MappingCache) -> u64 {
    match cache {
        MappingCache::WriteBack => rights,
        MappingCache::Uncached => rights | 0b1000,
    }
}
