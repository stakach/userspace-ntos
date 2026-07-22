//! Static-image TLS catalog construction shared by process and thread loader initialization.

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageTlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct StaticTlsEntry {
    pub module_base: u64,
    pub raw_data_address: u64,
    pub raw_data_size: usize,
    pub zero_fill_size: usize,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub index: u32,
}

impl StaticTlsEntry {
    pub fn allocation_size(&self) -> Option<usize> {
        self.raw_data_size.checked_add(self.zero_fill_size)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StaticTlsError {
    InvalidModule,
    InvalidRawDataRange,
    MissingIndexAddress,
    AllocationTooLarge,
    CapacityExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticTlsCatalog<const N: usize> {
    entries: [StaticTlsEntry; N],
    len: usize,
}

impl<const N: usize> StaticTlsCatalog<N> {
    pub const fn new() -> Self {
        Self {
            entries: [StaticTlsEntry {
                module_base: 0,
                raw_data_address: 0,
                raw_data_size: 0,
                zero_fill_size: 0,
                address_of_index: 0,
                address_of_callbacks: 0,
                index: 0,
            }; N],
            len: 0,
        }
    }

    pub fn entries(&self) -> &[StaticTlsEntry] {
        &self.entries[..self.len]
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn add(
        &mut self,
        module_base: u64,
        directory: ImageTlsDirectory,
    ) -> Result<&StaticTlsEntry, StaticTlsError> {
        if module_base == 0 {
            return Err(StaticTlsError::InvalidModule);
        }
        if directory.end_address_of_raw_data < directory.start_address_of_raw_data {
            return Err(StaticTlsError::InvalidRawDataRange);
        }
        if directory.address_of_index == 0 {
            return Err(StaticTlsError::MissingIndexAddress);
        }
        if self.len == N || self.len > u32::MAX as usize {
            return Err(StaticTlsError::CapacityExceeded);
        }
        let raw_data_size = directory
            .end_address_of_raw_data
            .checked_sub(directory.start_address_of_raw_data)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or(StaticTlsError::AllocationTooLarge)?;
        let zero_fill_size = usize::try_from(directory.size_of_zero_fill)
            .map_err(|_| StaticTlsError::AllocationTooLarge)?;
        raw_data_size
            .checked_add(zero_fill_size)
            .ok_or(StaticTlsError::AllocationTooLarge)?;

        let index = self.len as u32;
        self.entries[self.len] = StaticTlsEntry {
            module_base,
            raw_data_address: directory.start_address_of_raw_data,
            raw_data_size,
            zero_fill_size,
            address_of_index: directory.address_of_index,
            address_of_callbacks: directory.address_of_callbacks,
            index,
        };
        self.len += 1;
        Ok(&self.entries[self.len - 1])
    }
}

impl<const N: usize> Default for StaticTlsCatalog<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(start: u64, end: u64, index: u64, zero: u32) -> ImageTlsDirectory {
        ImageTlsDirectory {
            start_address_of_raw_data: start,
            end_address_of_raw_data: end,
            address_of_index: index,
            address_of_callbacks: 0x8000,
            size_of_zero_fill: zero,
        }
    }

    #[test]
    fn catalog_assigns_stable_dense_indices_and_sizes() {
        let mut catalog = StaticTlsCatalog::<2>::new();
        assert_eq!(
            catalog
                .add(0x1000, directory(0x2000, 0x2010, 0x3000, 8))
                .unwrap()
                .index,
            0
        );
        assert_eq!(
            catalog
                .add(0x4000, directory(0x5000, 0x5004, 0x6000, 12))
                .unwrap()
                .index,
            1
        );
        assert_eq!(catalog.len(), 2);
        assert_eq!(catalog.entries()[0].raw_data_size, 16);
        assert_eq!(catalog.entries()[0].allocation_size(), Some(24));
        assert_eq!(catalog.entries()[1].allocation_size(), Some(16));
    }

    #[test]
    fn catalog_rejects_malformed_directories_without_mutation() {
        let mut catalog = StaticTlsCatalog::<2>::new();
        assert_eq!(
            catalog.add(0, directory(1, 2, 3, 0)),
            Err(StaticTlsError::InvalidModule)
        );
        assert_eq!(
            catalog.add(1, directory(3, 2, 4, 0)),
            Err(StaticTlsError::InvalidRawDataRange)
        );
        assert_eq!(
            catalog.add(1, directory(2, 3, 0, 0)),
            Err(StaticTlsError::MissingIndexAddress)
        );
        assert!(catalog.is_empty());
    }

    #[test]
    fn catalog_reports_capacity_before_publishing_an_entry() {
        let mut catalog = StaticTlsCatalog::<1>::new();
        catalog.add(1, directory(2, 3, 4, 0)).unwrap();
        assert_eq!(
            catalog.add(5, directory(6, 7, 8, 0)),
            Err(StaticTlsError::CapacityExceeded)
        );
        assert_eq!(catalog.len(), 1);
    }
}
