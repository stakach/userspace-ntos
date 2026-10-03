//! Geometry evidence from real mode enumeration and successful mode-selection completions.

extern crate alloc;

use alloc::vec::Vec;
use crate::{parse_video_mode_information, VideoModeSpec, IOCTL_VIDEO_QUERY_AVAIL_MODES,
    IOCTL_VIDEO_QUERY_CURRENT_MODE, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES,
    IOCTL_VIDEO_SET_CURRENT_MODE, VIDEO_MODE_INFORMATION_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeEvidenceError {
    Malformed,
    MissingAnnouncement,
    Allocation,
}

struct DeviceEvidence<K> {
    identity: K,
    count: usize,
    modes: Vec<(u32, VideoModeSpec)>,
}

/// Observational metadata only: callers must independently revalidate resource authority.
pub struct ModeEvidence<K> {
    devices: Vec<DeviceEvidence<K>>,
}

impl<K: PartialEq> ModeEvidence<K> {
    pub const fn new() -> Self {
        Self { devices: Vec::new() }
    }

    pub fn observe(&mut self, identity: K, code: u32, input: &[u8], status: u32,
        information: u64, output: &[u8]) -> Result<Option<VideoModeSpec>, ModeEvidenceError> {
        if status != 0 { return Ok(None); }
        match code {
            IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES | IOCTL_VIDEO_QUERY_AVAIL_MODES
                | IOCTL_VIDEO_QUERY_CURRENT_MODE if information != output.len() as u64 => {
                return Err(ModeEvidenceError::Malformed);
            }
            IOCTL_VIDEO_SET_CURRENT_MODE if information != 0 || !output.is_empty() => {
                return Err(ModeEvidenceError::Malformed);
            }
            _ => {}
        }
        if code == IOCTL_VIDEO_QUERY_CURRENT_MODE {
            if output.len() != VIDEO_MODE_INFORMATION_SIZE {
                return Err(ModeEvidenceError::Malformed);
            }
            return parse_video_mode_information(output).map(Some)
                .map_err(|_| ModeEvidenceError::Malformed);
        }
        let existing = self.devices.iter().position(|row| row.identity == identity);
        match code {
            IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES => {
                if output.len() != 8 { return Err(ModeEvidenceError::Malformed); }
                let count = word(output, 0) as usize;
                if count == 0 || word(output, 4) as usize != VIDEO_MODE_INFORMATION_SIZE
                    || count.checked_mul(VIDEO_MODE_INFORMATION_SIZE).is_none() {
                    return Err(ModeEvidenceError::Malformed);
                }
                if let Some(index) = existing {
                    self.devices[index].count = count;
                    self.devices[index].modes.clear();
                } else {
                    self.devices.try_reserve(1).map_err(|_| ModeEvidenceError::Allocation)?;
                    self.devices.push(DeviceEvidence { identity, count, modes: Vec::new() });
                }
                Ok(None)
            }
            IOCTL_VIDEO_QUERY_AVAIL_MODES => {
                let index = existing.ok_or(ModeEvidenceError::MissingAnnouncement)?;
                let count = self.devices[index].count;
                if count.checked_mul(VIDEO_MODE_INFORMATION_SIZE) != Some(output.len()) {
                    return Err(ModeEvidenceError::Malformed);
                }
                let mut modes = Vec::new();
                modes.try_reserve_exact(count).map_err(|_| ModeEvidenceError::Allocation)?;
                for record in output.chunks_exact(VIDEO_MODE_INFORMATION_SIZE) {
                    let mode = parse_video_mode_information(record)
                        .map_err(|_| ModeEvidenceError::Malformed)?;
                    let id = word(record, 4);
                    if id & 0xc000_0000 != 0 || modes.iter().any(|(prior, _)| *prior == id) {
                        return Err(ModeEvidenceError::Malformed);
                    }
                    modes.push((id, mode));
                }
                // Publish only after every record is validated and storage is admitted.
                self.devices[index].modes = modes;
                Ok(None)
            }
            IOCTL_VIDEO_SET_CURRENT_MODE => {
                if input.len() != 4 { return Err(ModeEvidenceError::Malformed); }
                let requested = word(input, 0) & 0x3fff_ffff;
                Ok(existing.and_then(|index| self.devices[index].modes.iter()
                    .find(|(id, _)| *id == requested).map(|(_, mode)| *mode)))
            }
            _ => Ok(None),
        }
    }
}

impl<K: PartialEq> Default for ModeEvidence<K> {
    fn default() -> Self { Self::new() }
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::ModeEvidence;
    use crate::{
        VideoModeSpec, IOCTL_VIDEO_QUERY_AVAIL_MODES, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES,
        IOCTL_VIDEO_SET_CURRENT_MODE, VIDEO_MODE_INFORMATION_SIZE,
    };

    type Identity = (u64, u64, u64);
    const FIRST: Identity = (1, 7, 31);
    const SECOND: Identity = (2, 7, 42);
    const FIRST_REUSED: Identity = (1, 8, 32);

    fn mode(index: u32, width: u32, height: u32) -> [u8; VIDEO_MODE_INFORMATION_SIZE] {
        let mut bytes = [0; VIDEO_MODE_INFORMATION_SIZE];
        for (offset, value) in [(0, VIDEO_MODE_INFORMATION_SIZE as u32), (4, index),
            (8, width), (12, height), (16, width * 4), (20, 1), (24, 32)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn announce(evidence: &mut ModeEvidence<Identity>, identity: Identity, count: u32) {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&count.to_le_bytes());
        bytes[4..].copy_from_slice(&(VIDEO_MODE_INFORMATION_SIZE as u32).to_le_bytes());
        assert_eq!(evidence.observe(identity, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES,
            &[], 0, 8, &bytes), Ok(None));
    }

    fn select(evidence: &mut ModeEvidence<Identity>, identity: Identity, requested: u32)
        -> Option<VideoModeSpec> {
        evidence.observe(identity, IOCTL_VIDEO_SET_CURRENT_MODE,
            &requested.to_le_bytes(), 0, 0, &[]).unwrap()
    }

    #[test]
    fn mode_evidence_selects_mode_id_not_enumeration_position_and_masks_both_set_flags() {
        let mut evidence = ModeEvidence::new();
        announce(&mut evidence, FIRST, 2);
        let records = [mode(17, 640, 480), mode(3, 1024, 768)].concat();
        assert_eq!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
            &[], 0, records.len() as u64, &records), Ok(None));
        let expected = Some(VideoModeSpec { width: 1024, height: 768,
            stride: 4096, bits_per_plane: 32 });
        for flags in [0, 0x4000_0000, 0x8000_0000, 0xc000_0000] {
            assert_eq!(select(&mut evidence, FIRST, flags | 3), expected);
        }
        assert_eq!(select(&mut evidence, FIRST, 1), None);
    }

    #[test]
    fn mode_evidence_keeps_devices_and_registration_generations_independent() {
        let mut evidence = ModeEvidence::new();
        announce(&mut evidence, FIRST, 1);
        announce(&mut evidence, SECOND, 1);
        evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
            &[], 0, 80, &mode(3, 1024, 768)).unwrap();
        evidence.observe(SECOND, IOCTL_VIDEO_QUERY_AVAIL_MODES,
            &[], 0, 80, &mode(3, 800, 600)).unwrap();
        assert_eq!(select(&mut evidence, FIRST, 3).unwrap().width, 1024);
        assert_eq!(select(&mut evidence, SECOND, 3).unwrap().width, 800);
        assert_eq!(select(&mut evidence, FIRST_REUSED, 3), None);
        announce(&mut evidence, FIRST_REUSED, 1);
        evidence.observe(FIRST_REUSED, IOCTL_VIDEO_QUERY_AVAIL_MODES,
            &[], 0, 80, &mode(3, 1280, 720)).unwrap();
        assert_eq!(select(&mut evidence, FIRST_REUSED, 3).unwrap().width, 1280);
        assert_eq!(select(&mut evidence, FIRST, 3).unwrap().width, 1024);
    }

    #[test]
    fn mode_evidence_requires_complete_announced_records_and_unique_ids() {
        for records in [mode(3, 1024, 768).to_vec(),
            [mode(3, 1024, 768), mode(3, 800, 600)].concat(),
            [mode(3, 1024, 768), mode(17, 800, 600)].concat()[..159].to_vec()] {
            let mut evidence = ModeEvidence::new();
            announce(&mut evidence, FIRST, 2);
            assert!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
                &[], 0, records.len() as u64, &records).is_err());
            assert_eq!(select(&mut evidence, FIRST, 3), None);
        }
        for offset in [0, 8, 12, 16, 20, 24] {
            let mut evidence = ModeEvidence::new();
            announce(&mut evidence, FIRST, 1);
            let mut record = mode(3, 1024, 768);
            record[offset..offset + 4].fill(0);
            assert!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
                &[], 0, record.len() as u64, &record).is_err());
            assert_eq!(select(&mut evidence, FIRST, 3), None);
        }
    }

    #[test]
    fn mode_evidence_rejects_malformed_count_stride_and_set_payloads() {
        let mut evidence = ModeEvidence::new();
        for (count, stride) in [(0u32, 80u32), (1, 0), (1, 79), (1, 81)] {
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&count.to_le_bytes());
            bytes[4..].copy_from_slice(&stride.to_le_bytes());
            assert!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES,
                &[], 0, 8, &bytes).is_err());
        }
        assert!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES,
            &[], 0, 7, &[0; 7]).is_err());
        assert!(evidence.observe(FIRST, IOCTL_VIDEO_SET_CURRENT_MODE,
            &[0; 3], 0, 0, &[]).is_err());
        assert_eq!(select(&mut evidence, FIRST, 3), None);
    }

    #[test]
    fn mode_evidence_failed_terminals_do_not_publish_or_replace_successful_evidence() {
        let mut evidence = ModeEvidence::new();
        announce(&mut evidence, FIRST, 1);
        evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
            &[], 0, 80, &mode(3, 1024, 768)).unwrap();
        for status in [0xc000_000du32, 0x8000_0005, 0x103] {
            assert_eq!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES,
                &[], status, 8, &[0; 8]), Ok(None));
            assert_eq!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
                &[], status, 80, &mode(3, 800, 600)), Ok(None));
            assert_eq!(evidence.observe(FIRST, IOCTL_VIDEO_SET_CURRENT_MODE,
                &3u32.to_le_bytes(), status, 0, &[]), Ok(None));
            assert_eq!(select(&mut evidence, FIRST, 3).unwrap().width, 1024);
        }
    }

    #[test]
    fn mode_evidence_new_announcement_cannot_replay_an_old_or_partial_enumeration() {
        let mut evidence = ModeEvidence::new();
        announce(&mut evidence, FIRST, 1);
        evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
            &[], 0, 80, &mode(3, 1024, 768)).unwrap();
        assert!(select(&mut evidence, FIRST, 3).is_some());
        announce(&mut evidence, FIRST, 2);
        assert_eq!(select(&mut evidence, FIRST, 3), None);
        assert!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
            &[], 0, 80, &mode(3, 800, 600)).is_err());
        assert_eq!(select(&mut evidence, FIRST, 3), None);
        assert_eq!(select(&mut evidence, SECOND, 3), None);
    }

    #[test]
    fn mode_evidence_current_mode_is_direct_real_evidence_without_enumeration() {
        let mut evidence = ModeEvidence::new();
        assert_eq!(evidence.observe(FIRST, crate::IOCTL_VIDEO_QUERY_CURRENT_MODE,
            &[], 0, 80, &mode(31, 1024, 768)).unwrap().unwrap().width, 1024);
        assert_eq!(select(&mut evidence, FIRST, 31), None);
        assert!(evidence.observe(FIRST, crate::IOCTL_VIDEO_QUERY_CURRENT_MODE,
            &[], 0, VIDEO_MODE_INFORMATION_SIZE as u64, &[0; VIDEO_MODE_INFORMATION_SIZE]).is_err());
    }

    #[test]
    fn mode_evidence_rejected_replacement_preserves_complete_prior_records() {
        let mut evidence = ModeEvidence::new();
        announce(&mut evidence, FIRST, 2);
        let valid = [mode(3, 1024, 768), mode(17, 800, 600)].concat();
        evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES, &[], 0, valid.len() as u64, &valid).unwrap();
        let invalid = [mode(3, 640, 480), mode(3, 800, 600)].concat();
        assert!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
            &[], 0, invalid.len() as u64, &invalid).is_err());
        assert_eq!(select(&mut evidence, FIRST, 3).unwrap().width, 1024);
        assert_eq!(select(&mut evidence, FIRST, 17).unwrap().width, 800);
    }

    #[test]
    fn mode_evidence_requires_exact_unclamped_terminal_information() {
        let mut evidence = ModeEvidence::new();
        let mut count = [0; 8];
        count[..4].copy_from_slice(&1u32.to_le_bytes());
        count[4..].copy_from_slice(&80u32.to_le_bytes());
        // Captured capacity must not hide a provider claiming more bytes than it supplied.
        for information in [7u64, 9, u64::MAX] {
            assert!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES,
                &[], 0, information, &count).is_err());
        }
        evidence.observe(FIRST, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES,
            &[], 0, 8, &count).unwrap();
        let record = mode(3, 1024, 768);
        for information in [79u64, 81, u64::MAX] {
            assert!(evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
                &[], 0, information, &record).is_err());
            assert!(evidence.observe(FIRST, crate::IOCTL_VIDEO_QUERY_CURRENT_MODE,
                &[], 0, information, &record).is_err());
        }
        let oversized = [record.as_slice(), &[0; 4]].concat();
        assert!(evidence.observe(FIRST, crate::IOCTL_VIDEO_QUERY_CURRENT_MODE,
            &[], 0, 84, &oversized).is_err());
        evidence.observe(FIRST, IOCTL_VIDEO_QUERY_AVAIL_MODES,
            &[], 0, 80, &record).unwrap();
        assert!(evidence.observe(FIRST, IOCTL_VIDEO_SET_CURRENT_MODE,
            &3u32.to_le_bytes(), 0, 1, &[]).is_err());
        assert!(evidence.observe(FIRST, IOCTL_VIDEO_SET_CURRENT_MODE,
            &3u32.to_le_bytes(), 0, 4, &[0; 4]).is_err());
        assert_eq!(evidence.observe(FIRST, IOCTL_VIDEO_SET_CURRENT_MODE,
            &3u32.to_le_bytes(), 0, 0, &[]).unwrap().unwrap().width, 1024);
        assert_eq!(evidence.observe(FIRST, IOCTL_VIDEO_SET_CURRENT_MODE,
            &3u32.to_le_bytes(), 0xc000_000d, u64::MAX, &[]), Ok(None));
    }
}
