//! Exact lower-directory path and upper File identity captured before a routed query.

use alloc::vec::Vec;
use nt_fs::LayeredOpenSource;

pub(crate) struct DirectorySource {
    pub(crate) relative: Vec<u8>,
    pub(crate) overlay_file: Option<u64>,
}

pub(crate) fn capture_directory_source(
    source: LayeredOpenSource,
    opened_name: &[u16],
    installed_path: Option<&[u8]>,
) -> Result<DirectorySource, u32> {
    match source {
        LayeredOpenSource::Installed { .. } => {
            let path = installed_path.ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
            let mut relative = Vec::new();
            relative.try_reserve_exact(path.len())
                .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
            relative.extend_from_slice(path);
            Ok(DirectorySource { relative, overlay_file: None })
        }
        LayeredOpenSource::Overlay { file_id } => {
            // CREATE retained the effective device-relative name, including any parent File.
            // It has no installed DirectoryOpen; reconstruct only the lower lookup key from
            // that exact captured name and retain the upper open File for the later callback.
            let name = opened_name.strip_prefix(&[b'\\' as u16]).unwrap_or(opened_name);
            let mut folded = Vec::new();
            folded.try_reserve_exact(name.len())
                .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
            folded.resize(name.len(), 0);
            let mut relative = Vec::new();
            relative.try_reserve_exact(name.len())
                .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
            relative.resize(name.len(), 0);
            let length = if name.is_empty() {
                0
            } else {
                nt_fs::nt_file_relative_path_into(name, &mut folded, &mut relative)
                    .ok_or(nt_fs::STATUS_OBJECT_NAME_INVALID)?
            };
            relative.truncate(length);
            Ok(DirectorySource { relative, overlay_file: Some(file_id) })
        }
    }
}
