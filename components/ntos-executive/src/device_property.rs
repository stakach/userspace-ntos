//! Shared native device-property transfer, independent of the requesting provider's address space.

use super::*;

pub(crate) use nt_io_manager::{
    PropertyQueryReply, PropertyQueryRequest, PropertyQueryTransport,
    PROPERTY_QUERY_CHUNK_BYTES as PROPERTY_CHUNK_BYTES,
};

pub(crate) struct PropertyScratch {
    address: u64,
    bytes: usize,
}

impl PropertyScratch {
    /// The allocation is owned by the matching transport until it consumes this snapshot.
    pub(crate) unsafe fn from_allocation(address: u64, bytes: usize) -> Option<Self> {
        (address != 0).then_some(Self { address, bytes })
    }

    pub(crate) fn address(&self) -> u64 {
        self.address
    }
}

impl AsRef<[u8]> for PropertyScratch {
    fn as_ref(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.address as *const u8, self.bytes) }
    }
}

impl AsMut<[u8]> for PropertyScratch {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.address as *mut u8, self.bytes) }
    }
}

pub(crate) fn request_words(request: PropertyQueryRequest) -> (u64, u64, u64, u64) {
    match request {
        PropertyQueryRequest::Begin {
            pdo,
            property,
            capacity,
        } => (
            HOSTED_DEVICE_OP_QUERY_PROPERTY_BEGIN,
            pdo,
            property as u64,
            capacity as u64,
        ),
        PropertyQueryRequest::Pull { pdo, token, offset } => (
            HOSTED_DEVICE_OP_QUERY_PROPERTY_PULL,
            pdo,
            token,
            offset as u64,
        ),
        PropertyQueryRequest::Abort { pdo, token } => {
            (HOSTED_DEVICE_OP_QUERY_PROPERTY_ABORT, pdo, token, 0)
        }
    }
}

pub(super) struct DriverPropertyClient;

impl PropertyQueryTransport for DriverPropertyClient {
    type Scratch = PropertyScratch;

    fn exchange(
        &mut self,
        request: PropertyQueryRequest,
    ) -> Result<PropertyQueryReply, nt_status::NtStatus> {
        let (op, pdo, arg2, arg3) = request_words(request);
        let (_, status, total_len, token, chunk_len) =
            unsafe { call_on4((FSD_SERVICE_DEVICE_LABEL << 12) | 4, op, pdo, arg2, arg3) };
        let mut reply = PropertyQueryReply {
            status: nt_status::NtStatus(status as i32),
            total_len,
            token,
            chunk_len,
            data: [0u8; PROPERTY_CHUNK_BYTES],
        };
        if reply.status == nt_status::NtStatus::SUCCESS && chunk_len <= PROPERTY_CHUNK_BYTES as u64
        {
            unsafe {
                copy_bytes_unchecked(
                    reply.data.as_mut_ptr() as u64,
                    FSD_ARG_VADDR + HOSTED_DEVICE_ARG_DATA_OFF,
                    chunk_len,
                );
            }
        }
        Ok(reply)
    }

    fn allocate(&mut self, bytes: usize) -> Option<PropertyScratch> {
        unsafe { PropertyScratch::from_allocation(pool_alloc(bytes as u64), bytes) }
    }

    fn release(&mut self, scratch: PropertyScratch) {
        unsafe { pool_free(scratch.address()) }
    }
}

/// Native pointer validation/publication surrounds the host-tested collection transaction.
pub(crate) unsafe fn query(
    client: &mut impl PropertyQueryTransport,
    pdo: u64,
    property: u32,
    buffer_len: u32,
    buffer: u64,
    result_len: u64,
) -> i32 {
    if result_len == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    write_unaligned(result_len as *mut u32, 0);
    if buffer_len != 0 && buffer == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let result = nt_io_manager::query_device_property(client, pdo, property, buffer_len);
    write_unaligned(result_len as *mut u32, result.required_len);
    if let Some(snapshot) = result.snapshot {
        if result.status == nt_status::NtStatus::SUCCESS {
            copy_bytes_unchecked(
                buffer,
                snapshot.as_ref().as_ptr() as u64,
                result.required_len as u64,
            );
        }
        client.release(snapshot);
    }
    result.status.raw()
}

pub(crate) trait PropertyTransfers {
    fn busy(&self, domain: HostedDomainIdentity) -> Result<bool, i32>;
    fn begin(
        &mut self,
        owner: HostedDevicePropertyOwner,
        value: Vec<u8>,
        data: &mut [u8],
    ) -> Result<(usize, u64, usize), i32>;
    fn pull(
        &mut self,
        owner: HostedDevicePropertyOwner,
        token: u64,
        offset: usize,
        data: &mut [u8],
    ) -> Result<(usize, u64, usize), i32>;
    fn abort(&mut self, owner: HostedDevicePropertyOwner, token: u64) -> bool;
}

pub(super) struct DriverPropertyTransfers;

impl PropertyTransfers for DriverPropertyTransfers {
    fn busy(&self, domain: HostedDomainIdentity) -> Result<bool, i32> {
        Ok(unsafe { hosted_device_property_transfers_mut().domain_busy(domain) })
    }

    fn begin(
        &mut self,
        owner: HostedDevicePropertyOwner,
        value: Vec<u8>,
        data: &mut [u8],
    ) -> Result<(usize, u64, usize), i32> {
        unsafe { hosted_device_property_transfers_mut().begin(owner, value, data) }
            .map(|pull| (pull.total_len, pull.token, pull.written))
            .map_err(hosted_device_property_transfer_status)
    }

    fn pull(
        &mut self,
        owner: HostedDevicePropertyOwner,
        token: u64,
        offset: usize,
        data: &mut [u8],
    ) -> Result<(usize, u64, usize), i32> {
        unsafe { hosted_device_property_transfers_mut().pull(owner, token, offset, data) }
            .map(|pull| (pull.total_len, pull.token, pull.written))
            .map_err(hosted_device_property_transfer_status)
    }

    fn abort(&mut self, owner: HostedDevicePropertyOwner, token: u64) -> bool {
        unsafe { hosted_device_property_transfers_mut().abort(owner, token) }
    }
}

/// The caller resolves the exact live PDO projection before every request. The access object must
/// carry only identity, not a mutable table borrow: a configuration snapshot performs CM IPC.
pub(crate) fn service(
    owner: HostedDevicePropertyOwner,
    op: u64,
    arg2: u64,
    arg3: u64,
    data: &mut [u8],
    transfers: &mut impl PropertyTransfers,
) -> (i32, u64, u64, u64) {
    let reply = |result: Result<(usize, u64, usize), i32>| match result {
        Ok((total, token, written)) => (STATUS_SUCCESS, total as u64, token, written as u64),
        Err(status) => (status, 0, 0, 0),
    };
    if op == HOSTED_DEVICE_OP_QUERY_PROPERTY_PULL {
        let Ok(offset) = usize::try_from(arg3) else {
            return (STATUS_INVALID_PARAMETER, 0, 0, 0);
        };
        return reply(transfers.pull(owner, arg2, offset, data));
    }
    if op == HOSTED_DEVICE_OP_QUERY_PROPERTY_ABORT {
        return if transfers.abort(owner, arg2) {
            (STATUS_SUCCESS, 0, 0, 0)
        } else {
            (STATUS_INVALID_PARAMETER, 0, 0, 0)
        };
    }
    if op != HOSTED_DEVICE_OP_QUERY_PROPERTY_BEGIN {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    }
    let (Ok(property), Ok(capacity)) = (u32::try_from(arg2), u32::try_from(arg3)) else {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    };
    match transfers.busy(owner.domain) {
        Ok(false) => {}
        Ok(true) => return (STATUS_DEVICE_NOT_READY, 0, 0, 0),
        Err(status) => return (status, 0, 0, 0),
    }
    let value = match nt_config_manager::device_property::source(property) {
        nt_config_manager::DevicePropertySource::Invalid => {
            return (STATUS_INVALID_PARAMETER_2, 0, 0, 0);
        }
        nt_config_manager::DevicePropertySource::Configuration => {
            let path = unsafe {
                let pnp = hosted_pnp_manager_mut();
                let source = pnp
                    .devnode_for_pdo(owner.pdo_device_id.raw())
                    .and_then(|id| pnp.instance_id(id));
                let Some(source) = source else {
                    return (STATUS_INVALID_DEVICE_REQUEST, 0, 0, 0);
                };
                let mut path = String::new();
                if path.try_reserve_exact(source.len()).is_err() {
                    return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0);
                }
                path.push_str(source);
                path
            };
            match unsafe { config_device_property_snapshot(&path, property) } {
                Ok(value) => value,
                Err(error) => return (error.status, error.required_len as u64, 0, 0),
            }
        }
        nt_config_manager::DevicePropertySource::External => {
            match unsafe { pnp_device_property_snapshot(owner.pdo_device_id, property) } {
                Ok(value) => value,
                Err(status) => return (status, 0, 0, 0),
            }
        }
    };
    if value.len() > capacity as usize {
        return (STATUS_BUFFER_TOO_SMALL, value.len() as u64, 0, 0);
    }
    reply(transfers.begin(owner, value, data))
}
