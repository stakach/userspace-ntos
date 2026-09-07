//! Failure-atomic collection of immutable device-property snapshots from a banked transport.

use nt_status::NtStatus;

pub const PROPERTY_QUERY_CHUNK_BYTES: usize = 928;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyQueryRequest {
    Begin {
        pdo: u64,
        property: u32,
        capacity: u32,
    },
    Pull {
        pdo: u64,
        token: u64,
        offset: u32,
    },
    Abort {
        pdo: u64,
        token: u64,
    },
}

/// The transport must copy the shared-bank bytes before returning, including before any allocator
/// IPC. A malformed envelope carrying a token must remain a reply so cleanup can abort that token.
pub struct PropertyQueryReply {
    pub status: NtStatus,
    pub total_len: u64,
    pub token: u64,
    pub chunk_len: u64,
    pub data: [u8; PROPERTY_QUERY_CHUNK_BYTES],
}

pub trait PropertyQueryTransport {
    type Scratch: AsRef<[u8]> + AsMut<[u8]>;

    /// `Err` is only for failures with no decoded reply/token. A received error status belongs in
    /// `PropertyQueryReply`, even when the rest of its envelope is malformed.
    fn exchange(&mut self, request: PropertyQueryRequest) -> Result<PropertyQueryReply, NtStatus>;
    fn allocate(&mut self, bytes: usize) -> Option<Self::Scratch>;
    /// Consume the scratch owner exactly once. Dropping a scratch value is not a release contract.
    fn release(&mut self, scratch: Self::Scratch);
}

/// Only a complete, successful nonempty result owns a snapshot. The consumer must explicitly
/// release that owner through its transport, after publishing at most `required_len` bytes.
#[must_use]
pub struct PropertyQueryResult<S> {
    pub status: NtStatus,
    pub required_len: u32,
    pub snapshot: Option<S>,
}

fn failure<S>(status: NtStatus, required_len: u32) -> PropertyQueryResult<S> {
    PropertyQueryResult {
        status,
        required_len,
        snapshot: None,
    }
}

fn transport_error(status: NtStatus) -> NtStatus {
    if status == NtStatus::SUCCESS {
        NtStatus::INVALID_PARAMETER
    } else {
        status
    }
}

fn abort(client: &mut impl PropertyQueryTransport, pdo: u64, token: u64) {
    if token != 0 {
        let _ = client.exchange(PropertyQueryRequest::Abort { pdo, token });
    }
}

/// Query an opaque PDO identity without exposing partial data. Authentication and native pointer
/// probing belong to the adapter. Every exchange returns an owned bank snapshot, and no borrow of
/// scratch bytes spans allocation or transport calls that may re-enter a native provider.
pub fn query_device_property<T: PropertyQueryTransport>(
    client: &mut T,
    pdo: u64,
    property: u32,
    capacity: u32,
) -> PropertyQueryResult<T::Scratch> {
    let first = match client.exchange(PropertyQueryRequest::Begin {
        pdo,
        property,
        capacity,
    }) {
        Ok(reply) => reply,
        Err(status) => return failure(transport_error(status), 0),
    };
    let token = first.token;
    let total = match u32::try_from(first.total_len) {
        Ok(total) => total,
        Err(_) => {
            abort(client, pdo, token);
            return failure(NtStatus::INVALID_PARAMETER, 0);
        }
    };
    if first.status != NtStatus::SUCCESS {
        abort(client, pdo, token);
        return failure(first.status, total);
    }
    if total > capacity {
        abort(client, pdo, token);
        return failure(NtStatus::BUFFER_TOO_SMALL, total);
    }
    if first.chunk_len > first.total_len
        || first.chunk_len > PROPERTY_QUERY_CHUNK_BYTES as u64
        || (total != 0 && first.chunk_len == 0)
        || (first.chunk_len < first.total_len && token == 0)
        || (first.chunk_len == first.total_len && token != 0)
    {
        abort(client, pdo, token);
        return failure(NtStatus::INVALID_PARAMETER, total);
    }
    if total == 0 {
        return failure(NtStatus::SUCCESS, 0);
    }
    let Some(mut scratch) = client.allocate(total as usize) else {
        abort(client, pdo, token);
        return failure(NtStatus::INSUFFICIENT_RESOURCES, total);
    };
    if scratch.as_ref().len() < total as usize || scratch.as_mut().len() < total as usize {
        abort(client, pdo, token);
        client.release(scratch);
        return failure(NtStatus::INSUFFICIENT_RESOURCES, total);
    }
    let mut offset = first.chunk_len as u32;
    scratch.as_mut()[..offset as usize].copy_from_slice(&first.data[..offset as usize]);
    while offset < total {
        let pull = match client.exchange(PropertyQueryRequest::Pull { pdo, token, offset }) {
            Ok(reply) => reply,
            Err(status) => {
                abort(client, pdo, token);
                client.release(scratch);
                return failure(transport_error(status), total);
            }
        };
        if pull.status != NtStatus::SUCCESS
            || pull.total_len != u64::from(total)
            || pull.token != token
            || pull.chunk_len == 0
            || pull.chunk_len > u64::from(total - offset)
            || pull.chunk_len > PROPERTY_QUERY_CHUNK_BYTES as u64
        {
            abort(client, pdo, token);
            client.release(scratch);
            return failure(
                if pull.status == NtStatus::SUCCESS {
                    NtStatus::INVALID_PARAMETER
                } else {
                    pull.status
                },
                total,
            );
        }
        let end = offset + pull.chunk_len as u32;
        scratch.as_mut()[offset as usize..end as usize]
            .copy_from_slice(&pull.data[..pull.chunk_len as usize]);
        offset = end;
    }
    PropertyQueryResult {
        status: NtStatus::SUCCESS,
        required_len: total,
        snapshot: Some(scratch),
    }
}

#[cfg(test)]
mod tests;
