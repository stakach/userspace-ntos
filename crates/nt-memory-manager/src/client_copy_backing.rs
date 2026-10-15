use crate::{
    admit_resident_reprotect, ClientFrameRecord, ClientFrameRegistry, ProcessIdentity,
    SharedImageMappingIdentity, STATUS_INVALID_HANDLE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientCopyBacking {
    pub resident: Option<ClientFrameRecord>,
    pub shared_image: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientCopyoutBacking {
    Resident(ClientFrameRecord),
    Unrecorded,
}

pub fn admit_client_copyout_backing(
    pi: u64,
    process: ProcessIdentity,
    page: u64,
    frames: &ClientFrameRegistry,
    shared_image: Option<SharedImageMappingIdentity>,
) -> Result<ClientCopyoutBacking, u32> {
    let backing = admit_client_copy_backing(pi, process, page, frames, shared_image)?;
    if let Some(record) = backing.resident {
        Ok(ClientCopyoutBacking::Resident(record))
    } else if backing.shared_image {
        Err(STATUS_INVALID_HANDLE)
    } else {
        Ok(ClientCopyoutBacking::Unrecorded)
    }
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
    fn primary_and_grown_worker_copyout_use_exact_records_not_mirror_geometry() {
        let process = ProcessIdentity { pid: 304, generation: ProcessGeneration::Hosted(2) };
        let stale = ProcessIdentity { generation: ProcessGeneration::Hosted(1), ..process };
        let mut frames = ClientFrameRegistry::new();
        let primary = 0x100105c0000;
        let grown = 0x1003011d000;
        frames.insert(7, MemoryLifetime::Process(process), primary,
            11, 0x10164000000, 12, 0, true).unwrap();
        frames.insert(7, MemoryLifetime::Process(process), grown,
            21, 0, 0, 22, true).unwrap();
        for (page, expected_frame, expected_alias) in [(primary, 11, 0x10164000000), (grown, 21, 0)] {
            let ClientCopyoutBacking::Resident(record) =
                admit_client_copyout_backing(7, process, page, &frames, None).unwrap()
            else { panic!("installed stack page must keep its exact backing"); };
            assert_eq!(record.frame, expected_frame);
            assert_eq!(record.alias, expected_alias);
            if page == grown {
                assert_eq!(record.source_cap, 22,
                    "grown backing retains authority for a temporary alias without a primary mirror");
            }
            assert_eq!(admit_client_copyout_backing(7, stale, page, &frames, None),
                Err(STATUS_INVALID_HANDLE));
        }
        assert_eq!(admit_client_copyout_backing(7, process, grown - 0x1000, &frames, None),
            Ok(ClientCopyoutBacking::Unrecorded),
            "a nearby stack address supplies no mapped mirror authority");
    }

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
            .insert(
                7,
                MemoryLifetime::Process(old),
                0x1000,
                11,
                0x4000,
                12,
                0,
                true,
            )
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
        assert_eq!(
            admit_client_copy_backing(7, new, 0x3000, &frames, None).unwrap(),
            ClientCopyBacking {
                resident: None,
                shared_image: false
            }
        );
        assert!(admit_client_copy_backing(7, old, 0x1000, &frames, None)
            .unwrap()
            .resident
            .is_some());
        assert!(
            admit_client_copy_backing(7, old, 0x2000, &frames, Some(shared))
                .unwrap()
                .shared_image
        );
    }

    #[test]
    fn copyout_rejects_old_lifetime_and_shared_image_without_private_backing() {
        let old = ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(1),
        };
        let current = ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(2),
        };
        let mut frames = ClientFrameRegistry::new();
        frames
            .insert(
                7,
                MemoryLifetime::Process(old),
                0x1000,
                11,
                0x4000,
                12,
                0,
                true,
            )
            .unwrap();
        let shared = SharedImageMappingIdentity::new(7, old, 0x2000).unwrap();
        assert_eq!(
            admit_client_copyout_backing(7, current, 0x1000, &frames, None),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            admit_client_copyout_backing(7, old, 0x2000, &frames, Some(shared)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert!(matches!(
            admit_client_copyout_backing(7, old, 0x1000, &frames, None),
            Ok(ClientCopyoutBacking::Resident(_))
        ));
        assert_eq!(
            admit_client_copyout_backing(7, current, 0x3000, &frames, None),
            Ok(ClientCopyoutBacking::Unrecorded)
        );
    }
}
