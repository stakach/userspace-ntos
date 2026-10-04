//! Local File references retained by Section backing owners.

use crate::ExecNtHandler;

#[must_use = "release the retained local File only after exact Section backing retirement"]
pub(crate) enum LocalSectionFile {
    Disk {
        object_id: u32,
        first_cluster: u32,
        size: u32,
    },
    Overlay {
        object_id: u64,
    },
}

impl LocalSectionFile {
    pub(crate) unsafe fn release(self, handler: &mut ExecNtHandler) {
        match self {
            Self::Disk { object_id, .. } => handler
                .readonly_file_opens
                .release_io(object_id)
                .expect("retained image disk File"),
            Self::Overlay { object_id } => crate::writable_fs::release_io_reference(object_id)
                .expect("retained image overlay File"),
        }
    }
}
