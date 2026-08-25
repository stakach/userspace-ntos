//! Authenticated, monotonic bank transfer for one immutable hosted-device property snapshot.

use alloc::vec::Vec;

use crate::{BankedTransferCursor, DeviceId, HostedDomainIdentity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedDevicePropertyOwner {
    pub domain: HostedDomainIdentity,
    pub pdo_device_id: DeviceId,
    pub pdo_address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedDevicePropertyPull {
    pub token: u64,
    pub total_len: usize,
    pub written: usize,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedDevicePropertyTransferError {
    InvalidOwner,
    EmptyBank,
    Busy,
    UnknownTransfer,
    WrongOwner,
    OutOfOrder,
    InsufficientResources,
}

struct Transfer {
    token: u64,
    owner: HostedDevicePropertyOwner,
    value: Vec<u8>,
    cursor: BankedTransferCursor,
}

/// Generation-independent tokens are never reused during one boot. A completed, aborted, or
/// owner-torn-down transfer therefore cannot alias a later property snapshot.
#[derive(Default)]
pub struct HostedDevicePropertyTransferTable {
    next_token: u64,
    entries: Vec<Option<Transfer>>,
}

impl HostedDevicePropertyTransferTable {
    pub const fn new() -> Self {
        Self {
            next_token: 1,
            entries: Vec::new(),
        }
    }

    fn valid_owner(owner: HostedDevicePropertyOwner) -> bool {
        owner.domain.domain_id.raw() != 0
            && owner.domain.cookie != 0
            && owner.pdo_device_id.raw() != 0
            && owner.pdo_address != 0
    }

    fn allocate_token(&mut self) -> Result<u64, HostedDevicePropertyTransferError> {
        let token = self.next_token;
        if token == 0 {
            return Err(HostedDevicePropertyTransferError::InsufficientResources);
        }
        self.next_token = token.checked_add(1).unwrap_or(0);
        Ok(token)
    }

    pub fn begin(
        &mut self,
        owner: HostedDevicePropertyOwner,
        value: Vec<u8>,
        bank: &mut [u8],
    ) -> Result<HostedDevicePropertyPull, HostedDevicePropertyTransferError> {
        if !Self::valid_owner(owner) {
            return Err(HostedDevicePropertyTransferError::InvalidOwner);
        }
        if bank.is_empty() && !value.is_empty() {
            return Err(HostedDevicePropertyTransferError::EmptyBank);
        }
        let total_len = value.len();
        let written = core::cmp::min(total_len, bank.len());
        if written == total_len {
            bank[..written].copy_from_slice(&value[..written]);
            return Ok(HostedDevicePropertyPull {
                token: 0,
                total_len,
                written,
                complete: true,
            });
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.owner.domain == owner.domain)
        {
            return Err(HostedDevicePropertyTransferError::Busy);
        }

        let mut cursor = BankedTransferCursor::new(total_len as u64);
        cursor
            .claim(0, written as u64, bank.len() as u64)
            .map_err(|_| HostedDevicePropertyTransferError::OutOfOrder)?;
        let vacant = self.entries.iter().position(Option::is_none);
        if vacant.is_none() {
            self.entries
                .try_reserve(1)
                .map_err(|_| HostedDevicePropertyTransferError::InsufficientResources)?;
        }
        let token = self.allocate_token()?;
        let transfer = Transfer {
            token,
            owner,
            value,
            cursor,
        };
        bank[..written].copy_from_slice(&transfer.value[..written]);
        if let Some(index) = vacant {
            self.entries[index] = Some(transfer);
        } else {
            self.entries.push(Some(transfer));
        }
        Ok(HostedDevicePropertyPull {
            token,
            total_len,
            written,
            complete: false,
        })
    }

    pub fn pull(
        &mut self,
        owner: HostedDevicePropertyOwner,
        token: u64,
        offset: usize,
        bank: &mut [u8],
    ) -> Result<HostedDevicePropertyPull, HostedDevicePropertyTransferError> {
        if token == 0 {
            return Err(HostedDevicePropertyTransferError::UnknownTransfer);
        }
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.token == token))
        else {
            return Err(HostedDevicePropertyTransferError::UnknownTransfer);
        };
        let entry = self.entries[index].as_mut().unwrap();
        if entry.owner != owner {
            return Err(HostedDevicePropertyTransferError::WrongOwner);
        }
        if bank.is_empty() {
            return Err(HostedDevicePropertyTransferError::EmptyBank);
        }
        let remaining = entry.value.len().saturating_sub(offset);
        let written = core::cmp::min(remaining, bank.len());
        let range = entry
            .cursor
            .claim(offset as u64, written as u64, bank.len() as u64)
            .map_err(|_| HostedDevicePropertyTransferError::OutOfOrder)?;
        bank[..written].copy_from_slice(&entry.value[range]);
        let complete = entry.cursor.is_complete();
        let total_len = entry.value.len();
        if complete {
            self.entries[index] = None;
        }
        Ok(HostedDevicePropertyPull {
            token,
            total_len,
            written,
            complete,
        })
    }

    pub fn abort(&mut self, owner: HostedDevicePropertyOwner, token: u64) -> bool {
        let Some(index) = self.entries.iter().position(|entry| {
            entry
                .as_ref()
                .is_some_and(|entry| entry.token == token && entry.owner == owner)
        }) else {
            return false;
        };
        self.entries[index] = None;
        true
    }

    pub fn remove_owner(&mut self, owner: HostedDevicePropertyOwner) -> usize {
        let mut removed = 0;
        for entry in &mut self.entries {
            if entry.as_ref().is_some_and(|entry| entry.owner == owner) {
                *entry = None;
                removed += 1;
            }
        }
        removed
    }

    pub fn remove_domain(&mut self, domain: HostedDomainIdentity) -> usize {
        let mut removed = 0;
        for entry in &mut self.entries {
            if entry
                .as_ref()
                .is_some_and(|entry| entry.owner.domain == domain)
            {
                *entry = None;
                removed += 1;
            }
        }
        removed
    }

    pub fn domain_busy(&self, domain: HostedDomainIdentity) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|entry| entry.owner.domain == domain)
    }

    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostedDomainId;
    use alloc::vec;

    fn owner(cookie: u64, pdo: u64) -> HostedDevicePropertyOwner {
        HostedDevicePropertyOwner {
            domain: HostedDomainIdentity {
                domain_id: HostedDomainId::new(1, 2),
                cookie,
            },
            pdo_device_id: DeviceId::new(3, 4),
            pdo_address: pdo,
        }
    }

    #[test]
    fn transfers_exact_banks_and_retires_on_completion() {
        let mut table = HostedDevicePropertyTransferTable::new();
        let expected: Vec<u8> = (0..19).collect();
        let mut bank = [0u8; 8];
        let first = table
            .begin(owner(7, 0x1000), expected.clone(), &mut bank)
            .unwrap();
        assert_eq!(&bank, &expected[..8]);
        assert_ne!(first.token, 0);
        let second = table
            .pull(owner(7, 0x1000), first.token, 8, &mut bank)
            .unwrap();
        assert_eq!(&bank, &expected[8..16]);
        assert!(!second.complete);
        let last = table
            .pull(owner(7, 0x1000), first.token, 16, &mut bank)
            .unwrap();
        assert_eq!(&bank[..3], &expected[16..]);
        assert!(last.complete);
        assert!(table.is_empty());
        assert_eq!(
            table.pull(owner(7, 0x1000), first.token, 19, &mut bank),
            Err(HostedDevicePropertyTransferError::UnknownTransfer)
        );
    }

    #[test]
    fn rejects_wrong_owner_skips_replays_and_supports_abort_teardown() {
        let mut table = HostedDevicePropertyTransferTable::new();
        let mut bank = [0u8; 4];
        let first = table
            .begin(owner(7, 0x1000), vec![1; 12], &mut bank)
            .unwrap();
        assert_eq!(
            table.pull(owner(8, 0x1000), first.token, 4, &mut bank),
            Err(HostedDevicePropertyTransferError::WrongOwner)
        );
        assert_eq!(
            table.pull(owner(7, 0x1000), first.token, 8, &mut bank),
            Err(HostedDevicePropertyTransferError::OutOfOrder)
        );
        table
            .pull(owner(7, 0x1000), first.token, 4, &mut bank)
            .unwrap();
        assert_eq!(
            table.pull(owner(7, 0x1000), first.token, 4, &mut bank),
            Err(HostedDevicePropertyTransferError::OutOfOrder)
        );
        assert!(!table.abort(owner(8, 0x1000), first.token));
        assert!(table.abort(owner(7, 0x1000), first.token));

        let second = table
            .begin(owner(7, 0x1000), vec![2; 12], &mut bank)
            .unwrap();
        assert_ne!(second.token, first.token);
        assert_eq!(
            table.begin(owner(7, 0x2000), vec![3; 12], &mut bank),
            Err(HostedDevicePropertyTransferError::Busy)
        );
        assert_eq!(table.remove_domain(owner(7, 0).domain), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn validates_owners_banks_and_non_retained_transfers() {
        let mut table = HostedDevicePropertyTransferTable::new();
        let mut invalid = owner(0, 0x1000);
        let mut bank = [0xa5; 4];
        assert_eq!(
            table.begin(invalid, vec![1], &mut bank),
            Err(HostedDevicePropertyTransferError::InvalidOwner)
        );
        invalid = owner(7, 0);
        assert_eq!(
            table.begin(invalid, vec![1], &mut bank),
            Err(HostedDevicePropertyTransferError::InvalidOwner)
        );
        assert_eq!(
            table.begin(owner(7, 0x1000), vec![1], &mut []),
            Err(HostedDevicePropertyTransferError::EmptyBank)
        );

        let empty = table.begin(owner(7, 0x1000), Vec::new(), &mut []).unwrap();
        assert!(empty.complete);
        assert_eq!(empty.token, 0);
        let single = table
            .begin(owner(7, 0x1000), vec![1, 2, 3], &mut bank)
            .unwrap();
        assert!(single.complete);
        assert_eq!(single.token, 0);
        assert_eq!(&bank[..3], &[1, 2, 3]);
        assert!(table.is_empty());
    }

    #[test]
    fn tokens_exhaust_without_reuse() {
        let mut table = HostedDevicePropertyTransferTable::new();
        table.next_token = u64::MAX;
        let mut bank = [0u8; 1];
        let last = table
            .begin(owner(7, 0x1000), vec![1, 2], &mut bank)
            .unwrap();
        assert_eq!(last.token, u64::MAX);
        assert!(table.abort(owner(7, 0x1000), last.token));
        assert_eq!(
            table.begin(owner(7, 0x1000), vec![1, 2], &mut bank),
            Err(HostedDevicePropertyTransferError::InsufficientResources)
        );
        assert!(table.is_empty());
    }
}
