use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::CmIdentitySource;

use nt_config_abi::{
    device_action_kind, hive_mutation_flags, hive_mutation_kind, CmHiveMutationRecord,
    CM_HIVE_MUTATION_RECORD_HEADER_BYTES, CM_MAX_HIVE_PATH_UNITS, CM_MAX_HIVE_VALUE_NAME_UNITS,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HiveMutation {
    CreateChild {
        parent: String,
        name: String,
        class_name: Option<String>,
        descriptor: Vec<u8>,
    },
    CreateKey {
        path: String,
    },
    SetValue {
        path: String,
        name: String,
        value_type: u32,
        data: Vec<u8>,
    },
    DeleteValue {
        path: String,
        name: String,
    },
    DeleteKey {
        path: String,
    },
    SetKeyClass {
        path: String,
        class_name: Option<String>,
    },
    SetKeySecurity {
        path: String,
        descriptor: Vec<u8>,
    },
    PublishDeviceAction {
        kind: u16,
        instance_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutationLeaseError {
    Busy,
    Exhausted,
    Invalid,
    Incomplete,
}

struct MutationLease {
    token: u64,
    generation: u64,
    total_len: usize,
    journal: Vec<u8>,
}

pub(crate) struct MutationLeaseBank {
    lease: Option<MutationLease>,
    identities: Rc<CmIdentitySource>,
}

impl MutationLeaseBank {
    pub(crate) fn new(identities: Rc<CmIdentitySource>) -> Self {
        Self {
            lease: None,
            identities,
        }
    }

    pub(crate) fn begin(
        &mut self,
        generation: u64,
        total_len: usize,
    ) -> Result<u64, MutationLeaseError> {
        if total_len == 0 {
            return Err(MutationLeaseError::Invalid);
        }
        if self.lease.is_some() {
            return Err(MutationLeaseError::Busy);
        }
        let mut journal = Vec::new();
        journal
            .try_reserve_exact(total_len)
            .map_err(|_| MutationLeaseError::Exhausted)?;
        let token = self
            .identities
            .take()
            .ok_or(MutationLeaseError::Exhausted)?;
        self.lease = Some(MutationLease {
            token,
            generation,
            total_len,
            journal,
        });
        Ok(token)
    }

    pub(crate) fn append(
        &mut self,
        token: u64,
        generation: u64,
        total_len: usize,
        offset: usize,
        chunk: &[u8],
    ) -> Result<(), MutationLeaseError> {
        let lease = self.lease.as_mut().ok_or(MutationLeaseError::Invalid)?;
        if token == 0
            || lease.token != token
            || lease.generation != generation
            || lease.total_len != total_len
            || chunk.is_empty()
            || offset
                .checked_add(chunk.len())
                .is_none_or(|end| end > total_len)
        {
            return Err(MutationLeaseError::Invalid);
        }
        let end = offset + chunk.len();
        if end <= lease.journal.len() {
            return if lease.journal[offset..end] == *chunk {
                Ok(())
            } else {
                Err(MutationLeaseError::Invalid)
            };
        }
        if offset != lease.journal.len() {
            return Err(MutationLeaseError::Invalid);
        }
        lease.journal.extend_from_slice(chunk);
        Ok(())
    }

    /// Borrow a complete upload through every fallible validation/encoding step. Only successful
    /// preparation may consume it; an error leaves the exact bytes available for retry or abort.
    pub(crate) fn complete_bytes(
        &self,
        token: u64,
        generation: u64,
        total_len: usize,
    ) -> Result<&[u8], MutationLeaseError> {
        let lease = self.lease.as_ref().ok_or(MutationLeaseError::Invalid)?;
        if token == 0
            || lease.token != token
            || lease.generation != generation
            || lease.total_len != total_len
        {
            return Err(MutationLeaseError::Invalid);
        }
        if lease.journal.len() != total_len {
            return Err(MutationLeaseError::Incomplete);
        }
        Ok(&lease.journal)
    }

    pub(crate) fn take_complete(
        &mut self,
        token: u64,
        generation: u64,
        total_len: usize,
    ) -> Result<Vec<u8>, MutationLeaseError> {
        self.complete_bytes(token, generation, total_len)?;
        Ok(self.lease.take().unwrap().journal)
    }

    pub(crate) fn abort(&mut self, token: u64, generation: u64, total_len: usize) -> bool {
        let matches = self.lease.as_ref().is_some_and(|lease| {
            token != 0
                && lease.token == token
                && lease.generation == generation
                && lease.total_len == total_len
        });
        if matches {
            self.lease = None;
        }
        matches
    }

    pub(crate) fn is_busy(&self) -> bool {
        self.lease.is_some()
    }
}

fn decode_utf16(bytes: &[u8], max_units: usize) -> Option<String> {
    if bytes.len() % 2 != 0 || bytes.len() / 2 > max_units {
        return None;
    }
    let mut text = String::new();
    text.try_reserve_exact((bytes.len() / 2).checked_mul(3)?)
        .ok()?;
    for scalar in char::decode_utf16(
        bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
    ) {
        let scalar = scalar.ok()?;
        if scalar == '\0' {
            return None;
        }
        text.push(scalar);
    }
    Some(text)
}

pub(crate) fn decode_mutation_journal(bytes: &[u8]) -> Option<Vec<HiveMutation>> {
    let mut offset = 0usize;
    let mut mutations = Vec::new();
    while offset < bytes.len() {
        let header_end = offset.checked_add(CM_HIVE_MUTATION_RECORD_HEADER_BYTES)?;
        let header = CmHiveMutationRecord::from_bytes(bytes.get(offset..header_end)?)?;
        if header._reserved != 0 {
            return None;
        }
        let path_len = usize::try_from(header.path_len_bytes).ok()?;
        let name_len = usize::try_from(header.name_len_bytes).ok()?;
        let data_len = usize::try_from(header.data_len_bytes).ok()?;
        let path_start = header_end;
        let name_start = path_start.checked_add(path_len)?;
        let data_start = name_start.checked_add(name_len)?;
        let record_end = data_start.checked_add(data_len)?;
        let path = decode_utf16(bytes.get(path_start..name_start)?, CM_MAX_HIVE_PATH_UNITS)?;
        let name = decode_utf16(
            bytes.get(name_start..data_start)?,
            CM_MAX_HIVE_VALUE_NAME_UNITS,
        )?;
        let data = bytes.get(data_start..record_end)?;
        let mutation = match header.kind {
            hive_mutation_kind::CREATE_CHILD
                if header.flags & !hive_mutation_flags::CLASS_PRESENT == 0
                    && header.value_type == 0
                    && !name.is_empty()
                    && !name.contains('\\') =>
            {
                let present = header.flags & hive_mutation_flags::CLASS_PRESENT != 0;
                let (class, descriptor) =
                    nt_config_abi::hive_create_child_metadata::split(data, present)?;
                let class_name = if present {
                    Some(decode_utf16(class, CM_MAX_HIVE_VALUE_NAME_UNITS)?)
                } else {
                    None
                };
                let mut owned = Vec::new();
                owned.try_reserve_exact(descriptor.len()).ok()?;
                owned.extend_from_slice(descriptor);
                HiveMutation::CreateChild {
                    parent: path,
                    name,
                    class_name,
                    descriptor: owned,
                }
            }
            hive_mutation_kind::CREATE_KEY
                if header.flags == 0
                    && header.value_type == 0
                    && name.is_empty()
                    && data.is_empty() =>
            {
                HiveMutation::CreateKey { path }
            }
            hive_mutation_kind::SET_VALUE if header.flags == 0 => HiveMutation::SetValue {
                path,
                name,
                value_type: header.value_type,
                data: data.to_vec(),
            },
            hive_mutation_kind::DELETE_VALUE
                if header.flags == 0 && header.value_type == 0 && data.is_empty() =>
            {
                HiveMutation::DeleteValue { path, name }
            }
            hive_mutation_kind::DELETE_KEY
                if header.flags == 0
                    && header.value_type == 0
                    && name.is_empty()
                    && data.is_empty() =>
            {
                HiveMutation::DeleteKey { path }
            }
            hive_mutation_kind::SET_KEY_CLASS
                if header.flags & !hive_mutation_flags::CLASS_PRESENT == 0
                    && header.value_type == 0
                    && name.is_empty() =>
            {
                let class_name = if header.flags & hive_mutation_flags::CLASS_PRESENT != 0 {
                    Some(decode_utf16(data, CM_MAX_HIVE_VALUE_NAME_UNITS)?)
                } else if data.is_empty() {
                    None
                } else {
                    return None;
                };
                HiveMutation::SetKeyClass { path, class_name }
            }
            hive_mutation_kind::SET_KEY_SECURITY
                if header.flags == 0 && header.value_type == 0 && name.is_empty() =>
            {
                HiveMutation::SetKeySecurity {
                    path,
                    descriptor: data.to_vec(),
                }
            }
            hive_mutation_kind::PUBLISH_DEVICE_ACTION
                if header.flags == 0
                    && [
                        device_action_kind::ARRIVAL,
                        device_action_kind::CHANGE,
                        device_action_kind::REMOVAL,
                    ]
                    .iter()
                    .any(|kind| header.value_type == u32::from(*kind))
                    && !path.is_empty()
                    && name.is_empty()
                    && data.is_empty() =>
            {
                HiveMutation::PublishDeviceAction {
                    kind: header.value_type as u16,
                    instance_id: path,
                }
            }
            _ => return None,
        };
        mutations.try_reserve(1).ok()?;
        mutations.push(mutation);
        offset = record_end;
    }
    (!mutations.is_empty() && offset == bytes.len()).then_some(mutations)
}

#[cfg(test)]
mod tests {
    use super::{MutationLeaseBank, MutationLeaseError};

    fn bank() -> MutationLeaseBank {
        MutationLeaseBank::new(alloc::rc::Rc::new(crate::CmIdentitySource::new(
            core::num::NonZeroU32::new(1).unwrap(),
        )))
    }

    #[test]
    fn lease_requires_ordered_complete_upload_and_exact_identity() {
        let mut bank = bank();
        let token = bank.begin(7, 4).unwrap();
        assert_eq!(bank.begin(7, 4), Err(MutationLeaseError::Busy));
        assert_eq!(
            bank.append(token, 7, 4, 1, &[1]),
            Err(MutationLeaseError::Invalid)
        );
        bank.append(token, 7, 4, 0, &[1, 2]).unwrap();
        assert_eq!(
            bank.take_complete(token, 7, 4),
            Err(MutationLeaseError::Incomplete)
        );
        bank.append(token, 7, 4, 2, &[3, 4]).unwrap();
        assert_eq!(bank.take_complete(token, 7, 4), Ok(alloc::vec![1, 2, 3, 4]));
    }

    #[test]
    fn abort_retires_only_the_exact_live_lease() {
        let mut bank = bank();
        let first = bank.begin(1, 1).unwrap();
        assert!(!bank.abort(first + 1, 1, 1));
        assert!(bank.abort(first, 1, 1));
        let second = bank.begin(1, 1).unwrap();
        assert!(!bank.abort(first, 1, 1));
        assert!(bank.abort(second, 1, 1));
    }

    #[test]
    fn append_replays_only_exact_accepted_ranges_without_changing_extent() {
        let mut bank = bank();
        let token = bank.begin(7, 8).unwrap();
        bank.append(token, 7, 8, 0, &[0, 1, 2, 3]).unwrap();
        for start in 0..4 {
            for end in start + 1..=4 {
                let bytes: alloc::vec::Vec<u8> = (start as u8..end as u8).collect();
                bank.append(token, 7, 8, start, &bytes).unwrap();
            }
        }
        for (offset, bytes) in [
            (0, &[9][..]),
            (3, &[3, 4][..]),
            (5, &[5][..]),
            (usize::MAX, &[0][..]),
            (4, &[][..]),
        ] {
            assert_eq!(
                bank.append(token, 7, 8, offset, bytes),
                Err(MutationLeaseError::Invalid)
            );
            assert_eq!(bank.lease.as_ref().unwrap().journal, [0, 1, 2, 3]);
        }
        for (wrong_token, generation, len) in
            [(0, 7, 8), (token + 1, 7, 8), (token, 8, 8), (token, 7, 9)]
        {
            assert_eq!(
                bank.append(wrong_token, generation, len, 0, &[0]),
                Err(MutationLeaseError::Invalid)
            );
        }
        bank.append(token, 7, 8, 4, &[4, 5, 6, 7]).unwrap();
        bank.append(token, 7, 8, 0, &[0, 1]).unwrap();
        assert_eq!(
            bank.take_complete(token, 7, 8).unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7]
        );
    }

    #[test]
    fn complete_borrow_and_failed_take_retain_exact_upload() {
        let mut bank = bank();
        let token = bank.begin(1, 2).unwrap();
        bank.append(token, 1, 2, 0, &[4]).unwrap();
        assert_eq!(
            bank.complete_bytes(token, 1, 2),
            Err(MutationLeaseError::Incomplete)
        );
        bank.append(token, 1, 2, 1, &[5]).unwrap();
        let address = bank.complete_bytes(token, 1, 2).unwrap().as_ptr();
        for (token, generation, len) in [(token + 1, 1, 2), (token, 2, 2), (token, 1, 3)] {
            assert_eq!(
                bank.take_complete(token, generation, len),
                Err(MutationLeaseError::Invalid)
            );
        }
        assert_eq!(bank.complete_bytes(token, 1, 2).unwrap(), [4, 5]);
        let bytes = bank.take_complete(token, 1, 2).unwrap();
        assert_eq!(bytes.as_ptr(), address);
        assert!(!bank.is_busy());
    }
}

#[cfg(test)]
#[path = "child_mutation_tests.rs"]
mod child_tests;
