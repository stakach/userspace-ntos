use alloc::string::String;
use alloc::vec::Vec;

use nt_config_abi::{
    hive_mutation_flags, hive_mutation_kind, CmHiveMutationRecord,
    CM_HIVE_MUTATION_RECORD_HEADER_BYTES, CM_MAX_HIVE_PATH_UNITS, CM_MAX_HIVE_VALUE_NAME_UNITS,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HiveMutation {
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
    next_token: u64,
}

impl MutationLeaseBank {
    pub(crate) const fn new() -> Self {
        Self {
            lease: None,
            next_token: 1,
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
        let token = self.next_token;
        if token == 0 {
            return Err(MutationLeaseError::Exhausted);
        }
        let mut journal = Vec::new();
        journal
            .try_reserve_exact(total_len)
            .map_err(|_| MutationLeaseError::Exhausted)?;
        self.next_token = token.checked_add(1).unwrap_or(0);
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
            || lease.journal.len() != offset
            || chunk.is_empty()
            || offset
                .checked_add(chunk.len())
                .is_none_or(|end| end > total_len)
        {
            return Err(MutationLeaseError::Invalid);
        }
        lease.journal.extend_from_slice(chunk);
        Ok(())
    }

    pub(crate) fn commit(
        &mut self,
        token: u64,
        generation: u64,
        total_len: usize,
    ) -> Result<Vec<u8>, MutationLeaseError> {
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

    pub(crate) fn invalidate(&mut self) {
        self.lease = None;
    }
}

fn decode_utf16(bytes: &[u8], max_units: usize) -> Option<String> {
    if bytes.len() % 2 != 0 || bytes.len() / 2 > max_units {
        return None;
    }
    let mut units = Vec::new();
    units.try_reserve_exact(bytes.len() / 2).ok()?;
    for pair in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    if units.contains(&0) {
        return None;
    }
    String::from_utf16(&units).ok()
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

    #[test]
    fn lease_requires_ordered_complete_upload_and_exact_identity() {
        let mut bank = MutationLeaseBank::new();
        let token = bank.begin(7, 4).unwrap();
        assert_eq!(bank.begin(7, 4), Err(MutationLeaseError::Busy));
        assert_eq!(
            bank.append(token, 7, 4, 1, &[1]),
            Err(MutationLeaseError::Invalid)
        );
        bank.append(token, 7, 4, 0, &[1, 2]).unwrap();
        assert_eq!(
            bank.commit(token, 7, 4),
            Err(MutationLeaseError::Incomplete)
        );
        bank.append(token, 7, 4, 2, &[3, 4]).unwrap();
        assert_eq!(bank.commit(token, 7, 4), Ok(alloc::vec![1, 2, 3, 4]));
    }

    #[test]
    fn abort_and_invalidate_retire_only_the_live_lease() {
        let mut bank = MutationLeaseBank::new();
        let first = bank.begin(1, 1).unwrap();
        assert!(!bank.abort(first + 1, 1, 1));
        assert!(bank.abort(first, 1, 1));
        let second = bank.begin(1, 1).unwrap();
        bank.invalidate();
        assert!(!bank.abort(second, 1, 1));
    }
}
