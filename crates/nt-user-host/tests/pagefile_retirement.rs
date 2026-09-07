use nt_memory_manager::process_retirement::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Leaves,
    PageTables,
    Vspace,
    Metadata,
}

const RESOURCES: u32 = 0xc000_009a;

#[test]
fn transition_backing_failure_retains_process_roots_until_checked_pool_publication() {
    #[derive(Default)]
    struct FrameIo {
        fail_revoke: bool,
        unmaps: usize,
        revokes: usize,
    }
    impl nt_memory_manager::PagefileRetirementIo for FrameIo {
        fn unmap(&mut self, _: u64) -> Result<(), u32> {
            self.unmaps += 1;
            Ok(())
        }
        fn revoke(&mut self, _: u64) -> Result<(), u32> {
            self.revokes += 1;
            if self.fail_revoke {
                Err(RESOURCES)
            } else {
                Ok(())
            }
        }
    }
    struct ProcessIo {
        store: nt_memory_manager::PagefileStore,
        pool: nt_address_space::RecycledFramePool,
        frame: FrameIo,
        stages: Vec<Stage>,
    }
    impl ProcessVmRetirementIo for ProcessIo {
        fn is_quiescent(&self) -> bool {
            true
        }
        fn retire_leaves(&mut self) -> bool {
            self.stages.push(Stage::Leaves);
            let mut retained = self.store.begin_retirement(7, 0x1000).unwrap().unwrap();
            retained = match self
                .store
                .cleanup_retirement_exact(retained, &mut self.frame)
            {
                Ok(retained) => retained,
                Err(_) => return false,
            };
            self.store
                .complete_retirement_with(retained, |backing| {
                    self.pool.publish_reserved(backing).map_err(|_| RESOURCES)
                })
                .is_ok()
        }
        fn retire_page_tables(&mut self) -> bool {
            assert!(!self.store.contains(7, 0x1000));
            self.stages.push(Stage::PageTables);
            true
        }
        fn retire_vspace(&mut self) -> bool {
            self.stages.push(Stage::Vspace);
            true
        }
        fn commit_metadata(&mut self) {
            assert!(!self.store.contains(7, 0x1000));
            self.stages.push(Stage::Metadata);
        }
    }
    let mut store = nt_memory_manager::PagefileStore::new();
    let publish = store
        .prepare_publish(nt_memory_manager::PagefilePage {
            owner: 7,
            page: 0x1000,
            protection: 4,
            backing: 71,
        })
        .unwrap();
    store.commit_publish(publish).unwrap();
    let mut io = ProcessIo {
        store,
        pool: nt_address_space::RecycledFramePool::new(),
        frame: FrameIo {
            fail_revoke: true,
            ..FrameIo::default()
        },
        stages: Vec::new(),
    };
    assert_eq!(
        retire_process_vm(&mut io),
        ProcessVmRetirement::LeavesPending
    );
    assert_eq!((io.frame.unmaps, io.frame.revokes), (1, 1));
    assert!(io.store.contains(7, 0x1000));
    io.frame.fail_revoke = false;
    assert_eq!(
        retire_process_vm(&mut io),
        ProcessVmRetirement::LeavesPending
    );
    assert_eq!((io.frame.unmaps, io.frame.revokes), (1, 2));
    assert_eq!(io.stages, [Stage::Leaves, Stage::Leaves]);
    assert!(io.store.contains(7, 0x1000));
    assert!(io.pool.reserve(1));
    assert_eq!(retire_process_vm(&mut io), ProcessVmRetirement::Complete);
    assert_eq!((io.frame.unmaps, io.frame.revokes), (1, 2));
    assert_eq!(io.pool.acquire(), Some(71));
    assert_eq!(
        io.stages,
        [
            Stage::Leaves,
            Stage::Leaves,
            Stage::Leaves,
            Stage::PageTables,
            Stage::Vspace,
            Stage::Metadata
        ]
    );
}
