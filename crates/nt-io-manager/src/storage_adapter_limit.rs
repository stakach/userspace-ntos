//! The storage adapter's transfer limit, as reported by `IOCTL_STORAGE_QUERY_PROPERTY`.
//!
//! A port driver answers `StorageAdapterProperty` with a `STORAGE_ADAPTER_DESCRIPTOR` built from
//! its miniport's `PORT_CONFIGURATION_INFORMATION`: `MaximumTransferLength` and, from
//! `NumberOfPhysicalBreaks`, `MaximumPhysicalPages`. A class driver bounds every transfer by
//! both: a buffer that does not start on a page boundary spans one page more than its length, so
//! the page bound is `(MaximumPhysicalPages - 1) * PAGE_SIZE`.

/// `IOCTL_STORAGE_QUERY_PROPERTY`: `CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED,
/// FILE_ANY_ACCESS)`.
pub const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002d_1400;
/// `STORAGE_PROPERTY_QUERY`: PropertyId, QueryType, one byte of AdditionalParameters, padded.
pub const STORAGE_PROPERTY_QUERY_LEN: usize = 12;
/// `STORAGE_ADAPTER_DESCRIPTOR` through `MaximumPhysicalPages`.
pub const STORAGE_ADAPTER_DESCRIPTOR_MIN_LEN: usize = 16;
/// The output buffer offered for the descriptor; it covers every field through `BusMinorVersion`.
pub const STORAGE_ADAPTER_DESCRIPTOR_QUERY_LEN: usize = 0x40;

const STORAGE_ADAPTER_PROPERTY: u32 = 1;
const PROPERTY_STANDARD_QUERY: u32 = 0;
const PAGE_SIZE: u64 = 0x1000;
const SECTOR_SIZE: u64 = 512;

/// The `STORAGE_PROPERTY_QUERY` input for the adapter descriptor.
pub fn adapter_property_query() -> [u8; STORAGE_PROPERTY_QUERY_LEN] {
    let mut query = [0; STORAGE_PROPERTY_QUERY_LEN];
    query[0..4].copy_from_slice(&STORAGE_ADAPTER_PROPERTY.to_le_bytes());
    query[4..8].copy_from_slice(&PROPERTY_STANDARD_QUERY.to_le_bytes());
    query
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterTransferLimits {
    pub maximum_transfer_length: u32,
    pub maximum_physical_pages: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterDescriptorError {
    /// Fewer bytes than the fields read, by the driver's `Information` or by `Size`.
    Truncated,
    /// The descriptor reports no transfer at all.
    NoTransfer,
}

/// Parse the descriptor the driver returned. `information` is the IRP's `IoStatus.Information`.
pub fn parse_adapter_descriptor(
    output: &[u8],
    information: u64,
) -> Result<AdapterTransferLimits, AdapterDescriptorError> {
    let returned = usize::try_from(information).unwrap_or(usize::MAX).min(output.len());
    let field = |offset: usize| u32::from_le_bytes(output[offset..offset + 4].try_into().unwrap());
    if returned < STORAGE_ADAPTER_DESCRIPTOR_MIN_LEN
        || (field(4) as usize) < STORAGE_ADAPTER_DESCRIPTOR_MIN_LEN
    {
        return Err(AdapterDescriptorError::Truncated);
    }
    let limits = AdapterTransferLimits {
        maximum_transfer_length: field(8),
        maximum_physical_pages: field(12),
    };
    if limits.maximum_transfer_length < SECTOR_SIZE as u32 || limits.maximum_physical_pages == 1 {
        return Err(AdapterDescriptorError::NoTransfer);
    }
    Ok(limits)
}

/// The most 512-byte sectors one command may move, bounded by the adapter and by `ceiling`, the
/// largest transfer the caller's own buffers accept. `MaximumPhysicalPages` of 0 sets no page
/// bound. Never less than one sector.
pub fn max_transfer_sectors(limits: AdapterTransferLimits, ceiling: u32) -> u32 {
    let mut bytes = u64::from(limits.maximum_transfer_length);
    if limits.maximum_physical_pages != 0 {
        bytes = bytes.min(u64::from(limits.maximum_physical_pages - 1) * PAGE_SIZE);
    }
    u32::try_from(bytes / SECTOR_SIZE).unwrap_or(u32::MAX).clamp(1, ceiling.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(size: u32, mtl: u32, pages: u32) -> [u8; STORAGE_ADAPTER_DESCRIPTOR_QUERY_LEN] {
        let mut bytes = [0; STORAGE_ADAPTER_DESCRIPTOR_QUERY_LEN];
        bytes[0..4].copy_from_slice(&size.to_le_bytes()); // Version
        bytes[4..8].copy_from_slice(&size.to_le_bytes());
        bytes[8..12].copy_from_slice(&mtl.to_le_bytes());
        bytes[12..16].copy_from_slice(&pages.to_le_bytes());
        bytes
    }

    #[test]
    fn the_query_names_the_adapter_property_as_a_standard_query() {
        assert_eq!(adapter_property_query(), [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn storahci_reports_128_kib_and_33_breaks() {
        // ReactOS storport: MaximumPhysicalPages = NumberOfPhysicalBreaks (0x21).
        let limits = parse_adapter_descriptor(&descriptor(0x20, 0x2_0000, 0x21), 0x20).unwrap();
        assert_eq!(limits, AdapterTransferLimits {
            maximum_transfer_length: 0x2_0000, maximum_physical_pages: 0x21 });
        assert_eq!(max_transfer_sectors(limits, 256), 256);
        assert_eq!(max_transfer_sectors(limits, 64), 64, "the caller's buffers bound the result");
    }

    #[test]
    fn the_page_bound_allows_for_an_unaligned_buffer() {
        // 9 pages map 8 pages of data from an unaligned start: 32 KiB, not 36 KiB.
        let limits = parse_adapter_descriptor(&descriptor(0x20, 0x10_0000, 9), 0x20).unwrap();
        assert_eq!(max_transfer_sectors(limits, 4096), 64);
        let unbounded = parse_adapter_descriptor(&descriptor(0x20, 0x1_0000, 0), 0x20).unwrap();
        assert_eq!(max_transfer_sectors(unbounded, 4096), 128);
    }

    #[test]
    fn a_short_or_empty_descriptor_is_refused() {
        assert_eq!(parse_adapter_descriptor(&descriptor(0x20, 0x2_0000, 0x21), 12),
            Err(AdapterDescriptorError::Truncated));
        assert_eq!(parse_adapter_descriptor(&descriptor(8, 0x2_0000, 0x21), 0x20),
            Err(AdapterDescriptorError::Truncated));
        assert_eq!(parse_adapter_descriptor(&descriptor(0x20, 0, 0x21), 0x20),
            Err(AdapterDescriptorError::NoTransfer));
        assert_eq!(parse_adapter_descriptor(&descriptor(0x20, 0x2_0000, 1), 0x20),
            Err(AdapterDescriptorError::NoTransfer));
    }
}
