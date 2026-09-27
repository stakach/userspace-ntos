use crate::{
    admit_resident_reprotect, ClientFrameRecord, ClientFrameRegistry, ProcessIdentity,
    SharedImageMappingIdentity, STATUS_INVALID_HANDLE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientCopyBacking {
    pub resident: Option<ClientFrameRecord>,
    pub shared_image: bool,
}

/// Admit both possible recorded sources before a copy can use an alias or clone capability.
pub fn admit_client_copy_backing(
    pi: u64,
    process: ProcessIdentity,
    page: u64,
    frames: &ClientFrameRegistry,
    shared_image: Option<SharedImageMappingIdentity>,
) -> Result<ClientCopyBacking, u32> {
    let resident = admit_resident_reprotect(pi, process, page, frames)?;
    let shared_image = match shared_image {
        Some(identity) => {
            if !identity.admit(pi, process, page)? {
                return Err(STATUS_INVALID_HANDLE);
            }
            true
        }
        None => false,
    };
    Ok(ClientCopyBacking {
        resident,
        shared_image,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryLifetime, ProcessGeneration};

    #[test]
    fn copyin_rejects_foreign_rows_before_source_selection() {
        let old = ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(1),
        };
        let new = ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(2),
        };
        let mut frames = ClientFrameRegistry::new();
        frames
            .insert(7, MemoryLifetime::Process(old), 0x1000, 11, 0x4000, 12, 0, true)
            .unwrap();
        let shared = SharedImageMappingIdentity::new(7, old, 0x2000).unwrap();
        let mut source_selections = 0;
        for (page, mapping) in [(0x1000, None), (0x2000, Some(shared))] {
            let selected = admit_client_copy_backing(7, new, page, &frames, mapping).map(|_| {
                source_selections += 1;
            });
            assert_eq!(selected, Err(STATUS_INVALID_HANDLE));
        }
        assert_eq!(source_selections, 0);
        assert_eq!(frames.get(7, 0x1000).unwrap().frame, 11);
        assert_eq!(admit_client_copy_backing(7, new, 0x3000, &frames, None).unwrap(),
            ClientCopyBacking { resident: None, shared_image: false });
        assert!(admit_client_copy_backing(7, old, 0x1000, &frames, None)
            .unwrap()
            .resident
            .is_some());
        assert!(admit_client_copy_backing(7, old, 0x2000, &frames, Some(shared))
            .unwrap()
            .shared_image);
    }
}
