use super::*;
use crate::{MemoryLifetime, ProcessGeneration, ProcessIdentity};

struct Io;
impl ClientFrameReclaimIo for Io {
    fn unmap(&mut self, _: u64) -> Result<(), u32> {
        Ok(())
    }
    fn delete(&mut self, _: u64) -> Result<(), u32> {
        Ok(())
    }
    fn recycle_empty(&mut self, _: u64) -> Result<(), u32> {
        Ok(())
    }
    fn revoke(&mut self, _: u64) -> Result<(), u32> {
        Ok(())
    }
}

#[test]
fn indexed_cleanup_does_not_rescan_unrelated_owners() {
    let mut registry = ClientFrameRegistry::new();
    let lifetime = MemoryLifetime::Process(ProcessIdentity {
        pid: 41,
        generation: ProcessGeneration::Hosted(9),
    });
    for i in 0..1024 {
        registry
            .insert(
                8 + i % 3,
                lifetime,
                0x1000 + i * 0x1000,
                10 + i,
                0,
                0,
                0,
                false,
            )
            .unwrap();
    }
    registry
        .insert(7, lifetime, 0x1000, 2000, 0, 0, 0, false)
        .unwrap();
    let index = registry.len() - 1;
    let row = registry.record_at(index).unwrap();
    registry.lookup_steps.set(0);
    let intent = ClientFrameReclaimIntent::Release;
    let row = registry.begin_reclaim_at_exact(index, row, intent).unwrap();
    let row = registry
        .cleanup_reclaim_at_exact(index, row, intent, &mut Io)
        .unwrap();
    registry
        .commit_reclaim_at_exact(index, row, intent, |_| Ok(()))
        .unwrap();
    assert_eq!(
        registry.lookup_steps.get(),
        0,
        "an exact index/full-record witness needs no key search"
    );
    assert_eq!(registry.len(), 1024);
}
