//! Bounded diagnostics for failed loader File-to-Section operations.

use core::fmt::Write;
use nt_printf::record::RecordBuffer;

#[derive(Clone, Copy)]
pub enum FileMapFailureStage {
    Open,
    CreateSection,
    MapView,
}

pub fn record_failure(stage: FileMapFailureStage, status: u32) -> Option<RecordBuffer<96>> {
    if status as i32 >= 0 {
        return None;
    }
    let stage = match stage {
        FileMapFailureStage::Open => "open",
        FileMapFailureStage::CreateSection => "create-section",
        FileMapFailureStage::MapView => "map-view",
    };
    let mut record = RecordBuffer::new();
    core::write!(
        &mut record,
        "[ldr-file-map-failed] stage={stage} status=0x{status:08x}\n"
    )
    .expect("fixed loader failure record fits its bounded buffer");
    Some(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_exact_failure_status_and_stage() {
        for (stage, status, expected) in [
            (
                FileMapFailureStage::Open,
                0xc000_0005,
                &b"[ldr-file-map-failed] stage=open status=0xc0000005\n"[..],
            ),
            (
                FileMapFailureStage::Open,
                0xc000_0034,
                &b"[ldr-file-map-failed] stage=open status=0xc0000034\n"[..],
            ),
            (
                FileMapFailureStage::CreateSection,
                0xc000_0005,
                &b"[ldr-file-map-failed] stage=create-section status=0xc0000005\n"[..],
            ),
            (
                FileMapFailureStage::CreateSection,
                0xc000_0034,
                &b"[ldr-file-map-failed] stage=create-section status=0xc0000034\n"[..],
            ),
        ] {
            let record = record_failure(stage, status).expect("negative status is captured");
            assert_eq!(record.bytes(), expected);
            assert!(!record.overflowed());
        }
    }

    #[test]
    fn successful_and_informational_statuses_emit_nothing() {
        for stage in [
            FileMapFailureStage::Open,
            FileMapFailureStage::CreateSection,
            FileMapFailureStage::MapView,
        ] {
            for status in [0, 0x103, 0x4000_0000, 0x7fff_ffff] {
                assert!(record_failure(stage, status).is_none());
            }
        }
    }

    #[test]
    fn captures_exact_map_view_failure_without_overflow() {
        let record = record_failure(FileMapFailureStage::MapView, 0xc000_0008)
            .expect("negative MapView status is captured");
        assert_eq!(
            record.bytes(),
            b"[ldr-file-map-failed] stage=map-view status=0xc0000008\n"
        );
        assert!(!record.overflowed());
    }
}
