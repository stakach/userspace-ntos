//! The namespace name of a mounted key: the one name every consumer of a key's identity (overlay
//! storage, change notification) compares, whatever path a caller used to reach the key.

use super::{HiveId, MutableHiveSet, ResolvedHiveKey, String};
use crate::canon_path;

impl MutableHiveSet {
    /// `key`'s full name in [`canon_path`] form: its hive's mount root, then its path inside the
    /// hive. `None` when the hive is not mounted or the cell is not a key of it.
    pub fn key_name(&self, key: ResolvedHiveKey) -> Option<String> {
        let relative = self.hive(key.hive)?.key_path(key.key)?;
        let mut full = String::from(self.mount_root(key.hive)?);
        full.push_str(&relative);
        Some(canon_path(&full))
    }

    /// The [`canon_path`] form of a full NT path, with a mounted hive's namespace aliases
    /// (`CurrentControlSet`) replaced by the identity its mount selected. A path no mount owns
    /// is only canonicalized.
    pub fn canonical_name(&self, full_path: &str) -> String {
        match self.resolve_path(full_path) {
            Some((hive, relative)) => {
                let mut full = String::from(
                    self.mount_root(hive).expect("a resolved hive has a mount root"),
                );
                full.push_str(&relative);
                canon_path(&full)
            }
            None => canon_path(full_path),
        }
    }

    fn mount_root(&self, hive: HiveId) -> Option<&str> {
        self.mounts.mounts.iter()
            .find(|entry| entry.hive == hive)
            .map(|entry| entry.root.as_str())
    }
}
