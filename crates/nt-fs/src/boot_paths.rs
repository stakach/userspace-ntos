//! DOS paths derived from a validated installation root and an assigned boot drive.

use alloc::vec::Vec;

use crate::InstalledRoot;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootPaths {
    drive: [u8; 2],
    system_root: Vec<u8>,
    system32: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootPathsError {
    InvalidDrive,
    InvalidRoot,
    TooLong,
}

impl BootPaths {
    pub fn new(drive_letter: u8, installed_root: &InstalledRoot) -> Result<Self, BootPathsError> {
        let letter = drive_letter.to_ascii_uppercase();
        if !letter.is_ascii_uppercase() {
            return Err(BootPathsError::InvalidDrive);
        }
        let name = &installed_root.name;
        if name.is_empty()
            || name.iter().any(|&unit| {
                unit == 0 || unit > 0x7f || matches!(unit as u8, b'\\' | b'/' | b':')
            })
        {
            return Err(BootPathsError::InvalidRoot);
        }
        let root_len = 3 + name.len();
        if root_len + 1 > 260 || root_len + b"\\System32".len() + 1 > 0xE0 / 2 {
            return Err(BootPathsError::TooLong);
        }
        let mut system_root = Vec::with_capacity(root_len);
        system_root.extend_from_slice(&[letter, b':', b'\\']);
        system_root.extend(name.iter().map(|&unit| unit as u8));
        let mut system32 = system_root.clone();
        system32.extend_from_slice(b"\\System32");
        Ok(Self {
            drive: [letter, b':'],
            system_root,
            system32,
        })
    }

    pub fn drive(&self) -> &[u8] {
        &self.drive
    }

    pub fn system_root(&self) -> &[u8] {
        &self.system_root
    }

    pub fn system32(&self) -> &[u8] {
        &self.system32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn root_comes_from_validated_directory_not_a_windows_alias() {
        let root = InstalledRoot {
            name: "reactos".encode_utf16().collect(),
            first_cluster: 42,
        };
        let paths = BootPaths::new(b'c', &root).unwrap();
        assert_eq!(paths.drive(), b"C:");
        assert_eq!(paths.system_root(), b"C:\\reactos");
        assert_eq!(paths.system32(), b"C:\\reactos\\System32");
    }

    #[test]
    fn rejects_invalid_or_unrepresentable_paths() {
        let root = InstalledRoot {
            name: "reactos".encode_utf16().collect(),
            first_cluster: 42,
        };
        assert_eq!(BootPaths::new(b'1', &root), Err(BootPathsError::InvalidDrive));
        let bad = InstalledRoot {
            name: "foo\\bar".encode_utf16().collect(),
            first_cluster: 42,
        };
        assert_eq!(BootPaths::new(b'C', &bad), Err(BootPathsError::InvalidRoot));
        let long = InstalledRoot {
            name: vec![b'x' as u16; 110],
            first_cluster: 42,
        };
        assert_eq!(BootPaths::new(b'C', &long), Err(BootPathsError::TooLong));
    }
}
