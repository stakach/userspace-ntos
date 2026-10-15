use super::{ConnState, NtStatus, PortCore, PortHandleEndpoint};

/// Current references to one canonical communication endpoint, not a lifetime pin.
/// Connection identifiers are broker-issued and never reused. A peer's closure does not
/// delete this endpoint; mappings belong to the endpoint's own mapping process.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortEndpointLifetime {
    pub connection_id: u64,
    pub endpoint: PortHandleEndpoint,
    pub owner_process: u64,
    pub endpoint_handle: u64,
    pub user_open: bool,
    pub kernel_references: u32,
    pub construction_references: u32,
}

impl PortEndpointLifetime {
    pub const fn is_deleted(self) -> bool {
        !self.user_open && self.kernel_references == 0 && self.construction_references == 0
    }
}

impl PortCore {
    /// Query the actual endpoint even after its user handle has closed. All key fields
    /// must match; a missing connection is not proof that a known endpoint was deleted.
    pub fn communication_endpoint_lifetime(
        &self,
        connection_id: u64,
        endpoint: PortHandleEndpoint,
        owner_process: u64,
    ) -> Result<PortEndpointLifetime, NtStatus> {
        let connection = self
            .conn(connection_id)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let (owner, handle, user_open, kernel_references, construction_references) = match endpoint
        {
            PortHandleEndpoint::ClientCommPort => (
                connection.client_id.process,
                connection.client_handle,
                connection.client_open,
                connection.client_kernel_refs,
                u32::from(matches!(
                    connection.state,
                    ConnState::Pending | ConnState::Received | ConnState::Accepted
                )),
            ),
            PortHandleEndpoint::ServerCommPort if connection.server_handle != 0 => (
                connection.server_id.process,
                connection.server_handle,
                connection.server_open,
                0,
                0,
            ),
            _ => return Err(NtStatus::INVALID_PORT_HANDLE),
        };
        if owner != owner_process {
            return Err(NtStatus::INVALID_PORT_HANDLE);
        }
        Ok(PortEndpointLifetime {
            connection_id,
            endpoint,
            owner_process: owner,
            endpoint_handle: handle,
            user_open,
            kernel_references,
            construction_references,
        })
    }

    /// Close exactly one live handle and report its communication endpoint's remaining
    /// references. Listen ports do not own communication views and return `None`.
    pub fn close_port_checked(
        &mut self,
        handle: u64,
    ) -> Result<Option<PortEndpointLifetime>, NtStatus> {
        if handle == 0
            || (!self
                .ports
                .iter()
                .any(|port| port.user_open && port.handle == handle)
                && !self.connections.iter().any(|connection| {
                    (connection.client_open && connection.client_handle == handle)
                        || (connection.server_open && connection.server_handle == handle)
                }))
        {
            return Err(NtStatus::INVALID_PORT_HANDLE);
        }
        let info = self
            .handle_info(handle)
            .ok_or(NtStatus::INVALID_PORT_HANDLE)?;
        let key = match info.endpoint {
            PortHandleEndpoint::ListenPort => None,
            PortHandleEndpoint::ClientCommPort => Some((
                info.connection_id,
                info.endpoint,
                info.client_id.ok_or(NtStatus::INVALID_PORT_HANDLE)?.process,
            )),
            PortHandleEndpoint::ServerCommPort => {
                Some((info.connection_id, info.endpoint, info.server_id.process))
            }
        };
        self.close_port_inner(handle);
        key.map(|(id, endpoint, owner)| self.communication_endpoint_lifetime(id, endpoint, owner))
            .transpose()
    }

    /// Release a checked existing kernel reference. Refusal leaves the reference retained;
    /// a successful final release reports deletion of only the client endpoint it referenced.
    pub fn release_port_object_with_lifetime(
        &mut self,
        handle: u64,
    ) -> Result<Option<PortEndpointLifetime>, NtStatus> {
        let key = self
            .kernel_communication_endpoints
            .iter()
            .find(|endpoint| endpoint.handle == handle)
            .map(|endpoint| endpoint.connection_id)
            .map(|id| {
                self.conn(id)
                    .map(|connection| (id, connection.client_id.process))
                    .ok_or(NtStatus::INVALID_PORT_HANDLE)
            })
            .transpose()?;
        self.release_port_object(handle)?;
        key.map(|(id, owner)| {
            self.communication_endpoint_lifetime(id, PortHandleEndpoint::ClientCommPort, owner)
        })
        .transpose()
    }

    /// Drain the canonical user's handles during an authenticated process teardown. The
    /// adapter validates the exact process incarnation before calling; this core never
    /// invents a hosted generation. Kernel-held references are deliberately not released.
    pub fn close_process_ports(&mut self, owner_process: u64) -> Result<u64, NtStatus> {
        if owner_process == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let mut closed = 0;
        loop {
            let handle = self
                .ports
                .iter()
                .find(|port| port.user_open && port.owner.process == owner_process)
                .map(|port| port.handle)
                .or_else(|| {
                    self.connections.iter().find_map(|connection| {
                        if connection.client_open
                            && connection.client_handle != 0
                            && connection.client_id.process == owner_process
                        {
                            Some(connection.client_handle)
                        } else if connection.server_open
                            && connection.server_handle != 0
                            && connection.server_id.process == owner_process
                        {
                            Some(connection.server_handle)
                        } else {
                            None
                        }
                    })
                });
            let Some(handle) = handle else {
                break;
            };
            self.close_port_checked(handle)?;
            closed += 1;
        }
        // A connector can own a real construction reference before Complete creates its
        // user handle. Exit cannot leave that reference available for later publication.
        for index in 0..self.connections.len() {
            if self.connections[index].client_id.process == owner_process
                && matches!(
                    self.connections[index].state,
                    ConnState::Pending | ConnState::Received | ConnState::Accepted
                )
            {
                self.release_connection_storage(index, true, true, true);
                self.connections[index].state = ConnState::Refused;
            }
        }
        self.retire_unreferenced_ports();
        Ok(closed)
    }
}
