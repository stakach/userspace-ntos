//! Report what a completed local SetInformationFile changed on the volume.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetInformationEffect {
    /// Only the open File object changed, or the request left stored metadata unchanged.
    NoVolumeChange,
    /// Complete resolved metadata after a basic-information mutation.
    FileBasic(FileMetadata),
    /// This mutation still needs the ordinary volume snapshot for durability.
    SnapshotRequired,
}

impl FileSystem {
    /// Apply once, then classify the actual durable effect. The status-only Zw surface remains
    /// available to existing callers; neither a native producer nor a replay promise is implied.
    pub fn zw_set_information_file_effect(
        &mut self,
        handle: u64,
        class: u32,
        data: &[u8],
    ) -> (u32, SetInformationEffect) {
        let before = (class == FILE_BASIC_INFORMATION)
            .then(|| self.query_file_object_information(handle).ok().map(|info| info.metadata))
            .flatten();
        let status = self.zw_set_information_file(handle, class, data);
        if status != STATUS_SUCCESS {
            return (status, SetInformationEffect::NoVolumeChange);
        }
        let effect = match class {
            FILE_MODE_INFORMATION | FILE_POSITION_INFORMATION => SetInformationEffect::NoVolumeChange,
            FILE_BASIC_INFORMATION => match self.query_file_object_information(handle) {
                Ok(info) if before == Some(info.metadata) => SetInformationEffect::NoVolumeChange,
                Ok(info) => SetInformationEffect::FileBasic(info.metadata),
                Err(_) => SetInformationEffect::SnapshotRequired,
            },
            _ => SetInformationEffect::SnapshotRequired,
        };
        (status, effect)
    }
}
