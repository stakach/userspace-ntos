//! Captured LPC connection views and their native mapping transaction.

use super::*;

static REFERENCE_RELEASED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Scheduling hint only; cleanup reconstructs authority from current broker snapshots.
pub(crate) fn note_reference_release() {
    REFERENCE_RELEASED.store(true, Ordering::Release);
}

/// An observational stack projection. The phased canonical wait pins its durable buffer.
pub(crate) struct LpcConnectCompletionView<'a> {
    pub(crate) connection_id: u64,
    pub(crate) status: u32,
    pub(crate) client_handle: u64,
    pub(crate) connection_information: &'a [u8],
}

impl PendingLpcConnectCompletion {
    pub(crate) fn view(&self) -> LpcConnectCompletionView<'_> {
        LpcConnectCompletionView {
            connection_id: self.connection_id,
            status: self.status,
            client_handle: self.client_handle,
            connection_information: &self.connection_information,
        }
    }
}

/// Kernel-captured native `PORT_VIEW` and resolved section identity. The user buffer is retained
/// only as an output destination; all input fields come from the captured bytes.
#[derive(Clone, Copy)]
pub(crate) struct CapturedLpcPortView {
    pointer: u64,
    native: [u8; nt_lpc_abi::PORT_VIEW_LEN],
    section_index: usize,
    section_offset: u64,
    view_size: u64,
}

/// Kernel-captured native `REMOTE_PORT_VIEW` output descriptor.
#[derive(Clone, Copy)]
pub(crate) struct CapturedLpcRemoteView {
    pointer: u64,
    native: [u8; nt_lpc_abi::REMOTE_PORT_VIEW_LEN],
}

/// One offered section mapped into its owner and peer processes.
#[derive(Clone, Copy)]
pub(crate) struct MappedLpcPortView {
    owner_view: Option<nt_memory_manager::GenericSectionView>,
    peer_view: Option<nt_memory_manager::GenericSectionView>,
    owner_base: u64,
    peer_base: u64,
    view_size: u64,
}

impl MappedLpcPortView {
    fn abi(self) -> Option<nt_lpc_abi::MappedPortView> {
        (self.owner_view.is_some() && self.peer_view.is_some()).then_some(
            nt_lpc_abi::MappedPortView {
                owner_base: self.owner_base,
                peer_base: self.peer_base,
                view_size: self.view_size,
            },
        )
    }
}

/// Kernel-owned connection-view transaction. A broker connection id, never an image role or a
/// most-recent slot, is the durable identity across connect, accept, and complete.
#[derive(Clone, Copy)]
pub(crate) struct PendingLpcConnectionViews {
    connection_id: u64,
    aborting: bool,
    connector_pi: usize,
    connector_process: nt_user_host::process_identity::ProcessIdentity,
    connector_broker_process: u64,
    acceptor_process: Option<nt_user_host::process_identity::ProcessIdentity>,
    acceptor_broker_process: Option<u64>,
    completed: bool,
    failed_accept: bool,
    retirement_pending: bool,
    connector_close: Option<LpcEndpointClose>,
    acceptor_close: Option<LpcEndpointClose>,
    connector_memory: SyscallUserMemory,
    connector_view: Option<CapturedLpcPortView>,
    connector_remote_view: Option<CapturedLpcRemoteView>,
    connector_mapping: Option<MappedLpcPortView>,
    acceptor_mapping: Option<MappedLpcPortView>,
}

/// A close attempt is published before broker IPC. An unacknowledged attempt is never replayed.
#[derive(Clone, Copy)]
struct LpcEndpointClose {
    handle: u64,
    acknowledged: bool,
}

impl ExecNtHandler {
    pub(super) fn reserve_lpc_connection_storage(&mut self) -> Result<(), u32> {
        let _durable = crate::allocator::enter_durable();
        let pending_results = self
            .lpc_connection_views
            .len()
            .checked_add(self.lpc_connect_completions.len())
            .and_then(|count| count.checked_add(1))
            .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
        self.lpc_connect_completions
            .try_reserve(pending_results - self.lpc_connect_completions.len())
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
        self.lpc_connection_views
            .try_reserve(1)
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }

    pub(super) fn admit_completed_lpc_connection_owner(
        &mut self,
        connector_pi: usize,
        metadata: &nt_lpc_client::HandleQueryResult,
    ) -> Result<(), u32> {
        if metadata.endpoint != nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT
            || metadata.state != nt_lpc_abi::connection_state::CONNECTED
            || metadata.connection_id == 0
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let connector = self
            .capture_process_identity(connector_pi)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if let Some(row) = self
            .lpc_connection_views
            .iter()
            .find(|row| row.connection_id == metadata.connection_id)
        {
            return if row.connector_process == connector
                && row.connector_broker_process == metadata.client_process
            {
                Ok(())
            } else {
                Err(STATUS_INVALID_HANDLE)
            };
        }
        if metadata.endpoint != nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT
            || metadata.connection_id == 0
            || metadata.client_process != u64::from(connector.pid)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.stage_lpc_connection_views(
            metadata.connection_id,
            connector_pi,
            metadata.client_process,
            SyscallUserMemory::CurrentProcess,
            None,
            None,
        )?;
        let row = self.lpc_connection_views.last_mut().unwrap();
        row.completed = true;
        row.acceptor_broker_process = Some(metadata.server_process);
        Ok(())
    }

    pub(super) unsafe fn admit_completed_lpc_handle(
        &mut self,
        connector_pi: usize,
        connection_id: u64,
        handle: u64,
    ) -> Result<(), u32> {
        let metadata = lpc_client()
            .ok_or(STATUS_UNSUCCESSFUL)?
            .query_handle(handle)
            .map_err(|status| status.raw() as u32)?;
        if metadata.connection_id != connection_id {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.admit_completed_lpc_connection_owner(connector_pi, &metadata)
    }

    pub(crate) fn queue_lpc_connect_completion(&mut self, completion: PendingLpcConnectCompletion) {
        assert!(
            self.lpc_connect_completions.len() < self.lpc_connect_completions.capacity(),
            "LPC connection completion storage reserved before connection admission"
        );
        self.lpc_connect_completions.push_back(completion);
    }

    pub(crate) unsafe fn release_lpc_port_object(
        &mut self,
        handle: u64,
    ) -> Result<(), nt_status::NtStatus> {
        let receipt = lpc_client()
            .ok_or(nt_status::NtStatus::UNSUCCESSFUL)?
            .release_port_object_with_lifetime(handle)?;
        if let Some(receipt) = receipt {
            self.retire_lpc_endpoint_release(receipt);
        }
        Ok(())
    }

    pub(crate) unsafe fn retire_lpc_endpoint_release(
        &mut self,
        receipt: nt_lpc_abi::LpcEndpointLifetime,
    ) {
        let Some(index) = self
            .lpc_connection_views
            .iter()
            .position(|row| row.connection_id == receipt.connection_id)
        else {
            return;
        };
        let row = self.lpc_connection_views[index];
        let expected = match receipt.endpoint {
            nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT => Some(row.connector_broker_process),
            nt_lpc_abi::handle_endpoint::SERVER_COMM_PORT => row.acceptor_broker_process,
            _ => None,
        };
        if expected != Some(receipt.owner_process) {
            return;
        }
        self.lpc_connection_views[index].retirement_pending = true;
        self.retire_deleted_lpc_endpoints(receipt.connection_id);
    }

    pub(super) fn prepare_lpc_accept_owner(
        &mut self,
        connection_id: u64,
        acceptor_pi: usize,
        broker_process: u64,
    ) -> Result<(), u32> {
        let process = self
            .capture_process_identity(acceptor_pi)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let row = self
            .lpc_connection_views
            .iter_mut()
            .find(|row| row.connection_id == connection_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if row.aborting
            || row.completed
            || row.failed_accept
            || row.acceptor_process.is_some_and(|owner| owner != process)
            || row
                .acceptor_broker_process
                .is_some_and(|owner| owner != broker_process)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        row.acceptor_process = Some(process);
        row.acceptor_broker_process = Some(broker_process);
        Ok(())
    }

    pub(crate) unsafe fn retire_lpc_process_handles(
        &mut self,
        pi: usize,
        process: nt_user_host::process_identity::ProcessIdentity,
    ) -> Result<(), u32> {
        if self.capture_process_identity(pi) != Some(process) {
            return Err(STATUS_INVALID_HANDLE);
        }
        // Canonical broker rundown is an idempotent drain, not replay of an individual close.
        lpc_client()
            .ok_or(STATUS_UNSUCCESSFUL)?
            .close_process_ports(u64::from(process.pid))
            .map_err(|status| status.raw() as u32)?;
        if self.capture_process_identity(pi) != Some(process) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let mut index = 0;
        while index < self.lpc_connection_views.len() {
            let id = self.lpc_connection_views[index].connection_id;
            if self.lpc_connection_views[index].connector_process == process
                || self.lpc_connection_views[index].acceptor_process == Some(process)
                || self.lpc_connection_views[index].acceptor_broker_process
                    == Some(u64::from(process.pid))
            {
                self.lpc_connection_views[index].retirement_pending = true;
                self.retire_deleted_lpc_endpoints(id);
            }
            if self
                .lpc_connection_views
                .get(index)
                .is_some_and(|row| row.connection_id == id)
            {
                index += 1;
            }
        }
        Ok(())
    }

    pub(crate) unsafe fn close_lpc_endpoint_owned(
        &mut self,
        connection_id: u64,
        endpoint: u16,
        handle: u64,
    ) -> Result<(), u32> {
        let index = self
            .lpc_connection_views
            .iter()
            .position(|row| row.connection_id == connection_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let row = self.lpc_connection_views[index];
        let expected_broker_process = match endpoint {
            nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT => row.connector_broker_process,
            nt_lpc_abi::handle_endpoint::SERVER_COMM_PORT => {
                row.acceptor_broker_process.ok_or(STATUS_INVALID_HANDLE)?
            }
            _ => return Err(STATUS_INVALID_HANDLE),
        };
        let metadata = lpc_client()
            .ok_or(STATUS_UNSUCCESSFUL)?
            .query_handle(handle)
            .map_err(|status| status.raw() as u32)?;
        let owner_process = if endpoint == nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT {
            metadata.client_process
        } else {
            metadata.server_process
        };
        if metadata.connection_id != connection_id
            || metadata.endpoint != endpoint
            || owner_process != expected_broker_process
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let close = match endpoint {
            nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT => {
                &mut self.lpc_connection_views[index].connector_close
            }
            nt_lpc_abi::handle_endpoint::SERVER_COMM_PORT => {
                &mut self.lpc_connection_views[index].acceptor_close
            }
            _ => return Err(STATUS_INVALID_HANDLE),
        };
        if let Some(attempt) = close {
            return if attempt.handle == handle && attempt.acknowledged {
                Ok(())
            } else {
                Err(STATUS_UNSUCCESSFUL)
            };
        }
        *close = Some(LpcEndpointClose {
            handle,
            acknowledged: false,
        });
        self.lpc_connection_views[index].retirement_pending = true;
        let result = lpc_client()
            .ok_or(STATUS_UNSUCCESSFUL)?
            .close_port_with_lifetime(handle)
            .map_err(|status| status.raw() as u32)?;
        let Some(receipt) = result else {
            return Err(STATUS_UNSUCCESSFUL);
        };
        if receipt.connection_id != connection_id
            || receipt.endpoint != endpoint
            || receipt.endpoint_handle != handle
            || receipt.owner_process != expected_broker_process
        {
            return Err(STATUS_UNSUCCESSFUL);
        }
        let close = if endpoint == nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT {
            &mut self.lpc_connection_views[index].connector_close
        } else {
            &mut self.lpc_connection_views[index].acceptor_close
        };
        close.as_mut().unwrap().acknowledged = true;
        self.retire_deleted_lpc_endpoints(connection_id);
        Ok(())
    }

    unsafe fn retire_lpc_process_views(
        &mut self,
        index: usize,
        endpoint: u16,
        process: nt_user_host::process_identity::ProcessIdentity,
    ) -> bool {
        let Some(ctx) = self.loop_ctx else {
            return false;
        };
        for connector_offer in [true, false] {
            let mapping = if connector_offer {
                self.lpc_connection_views[index].connector_mapping
            } else {
                self.lpc_connection_views[index].acceptor_mapping
            };
            let Some(mut mapping) = mapping else {
                continue;
            };
            let client_endpoint = endpoint == nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT;
            let slot = if connector_offer == client_endpoint {
                &mut mapping.owner_view
            } else {
                &mut mapping.peer_view
            };
            {
                let Some(view) = *slot else {
                    continue;
                };
                if view.lifetime != nt_memory_manager::MemoryLifetime::Process(process) {
                    continue;
                }
                // Canonical process teardown removes this exact receipt only after leaf ACKs.
                // A replacement process/view is never a cleanup target.
                let still_owned = (&*ctx.generic_sections)
                    .view_for_page(view.pi, view.base)
                    .is_some_and(|(_, current)| current == view);
                if !still_owned {
                    *slot = None;
                } else {
                    let writeback =
                        crate::service_sec_image::service_generic_section_writeback_view(
                            &mut *ctx.generic_sections,
                            view,
                            ctx.scratch_base,
                            Some(ctx),
                        );
                    if writeback.bytes_written != 0 {
                        self.writable_fs_dirty = true;
                    }
                    if writeback.status == 0 && self.rollback_generic_section_view(view).is_ok() {
                        *slot = None;
                    }
                }
            }
            let mapping =
                (mapping.owner_view.is_some() || mapping.peer_view.is_some()).then_some(mapping);
            if connector_offer {
                self.lpc_connection_views[index].connector_mapping = mapping;
            } else {
                self.lpc_connection_views[index].acceptor_mapping = mapping;
            }
        }
        let row = self.lpc_connection_views[index];
        [row.connector_mapping, row.acceptor_mapping]
            .into_iter()
            .enumerate()
            .all(|(offer, mapping)| {
                mapping.is_none_or(|mapping| {
                    let client = endpoint == nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT;
                    if (offer == 0) == client {
                        mapping.owner_view.is_none()
                    } else {
                        mapping.peer_view.is_none()
                    }
                })
            })
    }

    unsafe fn retire_deleted_lpc_endpoints(&mut self, connection_id: u64) {
        let Some(index) = self
            .lpc_connection_views
            .iter()
            .position(|row| row.connection_id == connection_id)
        else {
            return;
        };
        let row = self.lpc_connection_views[index];
        let mut all_deleted = true;
        let mut retry_needed = false;
        for (endpoint, process) in [
            (
                nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT,
                Some(row.connector_process),
            ),
            (
                nt_lpc_abi::handle_endpoint::SERVER_COMM_PORT,
                row.acceptor_process,
            ),
        ] {
            let broker_process = if endpoint == nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT {
                row.connector_broker_process
            } else {
                let Some(owner) = row.acceptor_broker_process else {
                    all_deleted = false;
                    continue;
                };
                owner
            };
            let receipt = lpc_client().and_then(|client| {
                client
                    .query_endpoint_lifetime(connection_id, endpoint, broker_process)
                    .ok()
            });
            let Some(receipt) = receipt.filter(|receipt| {
                receipt.connection_id == connection_id
                    && receipt.endpoint == endpoint
                    && receipt.owner_process == broker_process
            }) else {
                all_deleted = false;
                retry_needed = true;
                continue;
            };
            if !receipt.is_deleted() {
                all_deleted = false;
                continue;
            }
            if let Some(process) = process {
                if !self.retire_lpc_process_views(index, endpoint, process) {
                    retry_needed = true;
                }
            } else if row.connector_mapping.is_some() || row.acceptor_mapping.is_some() {
                all_deleted = false;
                retry_needed = true;
                continue;
            }
            if endpoint == nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT {
                let mut cache_index = 0;
                while cache_index < self.lpc_connections.len() {
                    let cached = self.lpc_connections[cache_index];
                    if cached.connection_id != connection_id
                        || cached.client_process != broker_process
                    {
                        cache_index += 1;
                        continue;
                    }
                    if let Some(context) = cached.static_security {
                        if self.token_store.release(context.token).is_err() {
                            all_deleted = false;
                            retry_needed = true;
                            break;
                        }
                    }
                    self.lpc_connections.swap_remove(cache_index);
                }
            }
        }
        let settled = self.lpc_connection_views[index].connector_mapping.is_none()
            && self.lpc_connection_views[index].acceptor_mapping.is_none();
        self.lpc_connection_views[index].retirement_pending = retry_needed;
        if all_deleted && settled {
            if row.failed_accept
                && crate::service_sec_image::lpc_connect_wait_is_pending(connection_id)
            {
                self.queue_lpc_connect_completion(PendingLpcConnectCompletion {
                    connection_id,
                    status: nt_status::NtStatus::PORT_CONNECTION_REFUSED.raw() as u32,
                    client_handle: 0,
                    connection_information: alloc::vec::Vec::new(),
                    retained_refusal: false,
                });
            }
            self.lpc_connection_views.swap_remove(index);
            print_str(b"[lpc-view] retired conn=");
            print_u64(connection_id);
            print_str(b"\n");
        }
    }

    pub(crate) unsafe fn settle_lpc_accept_failure(
        &mut self,
        connection_id: u64,
        server_handle: u64,
    ) {
        let Some(index) = self
            .lpc_connection_views
            .iter()
            .position(|row| row.connection_id == connection_id)
        else {
            return;
        };
        self.lpc_connection_views[index].failed_accept = true;
        self.lpc_connection_views[index].retirement_pending = true;
        let _ = self.close_lpc_endpoint_owned(
            connection_id,
            nt_lpc_abi::handle_endpoint::SERVER_COMM_PORT,
            server_handle,
        );
        self.retire_deleted_lpc_endpoints(connection_id);
    }

    pub(super) unsafe fn capture_lpc_port_view(
        &mut self,
        owner_pi: usize,
        memory: SyscallUserMemory,
        pointer: u64,
    ) -> Result<Option<CapturedLpcPortView>, u32> {
        if pointer == 0 {
            return Ok(None);
        }
        if pointer & 3 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        let mut native = [0u8; nt_lpc_abi::PORT_VIEW_LEN];
        if !self.lpc_user_memory_read(owner_pi, memory, pointer, &mut native)
            || !self.lpc_user_memory_write(owner_pi, memory, pointer, &native)
        {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let raw_handle = u64::from_le_bytes(native[8..16].try_into().unwrap());
        let handle = nt_process::Handle::try_from(raw_handle)
            .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
        let owner_pid = self
            .pm_pid_for_pi(owner_pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let section_index = match self.pm.lookup_handle(owner_pid, handle) {
            Some(nt_process::HandleObject::Section(section)) => section as usize,
            _ => return Err(nt_process::STATUS_INVALID_HANDLE),
        };
        const SECTION_MAP_WRITE: u32 = 0x0002;
        const SECTION_MAP_READ: u32 = 0x0004;
        let required_access = SECTION_MAP_READ | SECTION_MAP_WRITE;
        if self
            .pm
            .handle_access(owner_pid, handle)
            .is_none_or(|access| access & required_access != required_access)
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        let section_size = self
            .loop_ctx
            .and_then(|ctx| (&*ctx.generic_sections).section(section_index))
            .map(|section| section.size)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let captured = nt_lpc_abi::capture_port_view(&native, section_size)
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
        Ok(Some(CapturedLpcPortView {
            pointer,
            native,
            section_index,
            section_offset: captured.section_offset,
            view_size: captured.view_size,
        }))
    }

    pub(super) unsafe fn capture_lpc_remote_view(
        &mut self,
        owner_pi: usize,
        memory: SyscallUserMemory,
        pointer: u64,
    ) -> Result<Option<CapturedLpcRemoteView>, u32> {
        if pointer == 0 {
            return Ok(None);
        }
        if pointer & 3 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        let mut native = [0u8; nt_lpc_abi::REMOTE_PORT_VIEW_LEN];
        if !self.lpc_user_memory_read(owner_pi, memory, pointer, &mut native)
            || !self.lpc_user_memory_write(owner_pi, memory, pointer, &native)
        {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        if !nt_lpc_abi::validate_remote_port_view(&native) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Some(CapturedLpcRemoteView { pointer, native }))
    }

    pub(super) fn stage_lpc_connection_views(
        &mut self,
        connection_id: u64,
        connector_pi: usize,
        connector_broker_process: u64,
        connector_memory: SyscallUserMemory,
        connector_view: Option<CapturedLpcPortView>,
        connector_remote_view: Option<CapturedLpcRemoteView>,
    ) -> Result<(), u32> {
        if connection_id == 0
            || self
                .lpc_connection_views
                .iter()
                .any(|pending| pending.connection_id == connection_id)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.reserve_lpc_connection_storage()?;
        let connector_process = self
            .capture_process_identity(connector_pi)
            .ok_or(STATUS_INVALID_HANDLE)?;
        self.lpc_connection_views.push(PendingLpcConnectionViews {
            connection_id,
            aborting: false,
            connector_pi,
            connector_process,
            connector_broker_process,
            acceptor_process: None,
            acceptor_broker_process: None,
            completed: false,
            failed_accept: false,
            retirement_pending: false,
            connector_close: None,
            acceptor_close: None,
            connector_memory,
            connector_view,
            connector_remote_view,
            connector_mapping: None,
            acceptor_mapping: None,
        });
        Ok(())
    }

    unsafe fn map_lpc_port_view(
        &mut self,
        connection_index: usize,
        connector_offer: bool,
        captured: CapturedLpcPortView,
        owner_pi: usize,
        peer_pi: usize,
    ) -> Result<MappedLpcPortView, u32> {
        let peer_view = match self.map_generic_section_view_internal(
            captured.section_index,
            peer_pi,
            0,
            captured.view_size,
            captured.section_offset,
            0,
            0,
            nt_address_space::PAGE_READWRITE,
        ) {
            Ok(view) => view,
            Err(status) => {
                self.trace_lpc_view_map_failure(connection_index, connector_offer, peer_pi, status);
                return Err(status);
            }
        };
        let partial = MappedLpcPortView {
            owner_view: None,
            peer_view: Some(peer_view),
            owner_base: 0,
            peer_base: peer_view.base,
            view_size: peer_view.size,
        };
        if connector_offer {
            self.lpc_connection_views[connection_index].connector_mapping = Some(partial);
        } else {
            self.lpc_connection_views[connection_index].acceptor_mapping = Some(partial);
        }
        let owner_view = match self.map_generic_section_view_internal(
            captured.section_index,
            owner_pi,
            0,
            captured.view_size,
            captured.section_offset,
            0,
            0,
            nt_address_space::PAGE_READWRITE,
        ) {
            Ok(view) => view,
            Err(status) => {
                self.trace_lpc_view_map_failure(
                    connection_index,
                    connector_offer,
                    owner_pi,
                    status,
                );
                return Err(status);
            }
        };
        let mapped = MappedLpcPortView {
            owner_view: Some(owner_view),
            peer_view: Some(peer_view),
            owner_base: owner_view.base,
            peer_base: peer_view.base,
            view_size: owner_view.size,
        };
        if connector_offer {
            self.lpc_connection_views[connection_index].connector_mapping = Some(mapped);
        } else {
            self.lpc_connection_views[connection_index].acceptor_mapping = Some(mapped);
        }
        if owner_view.size != peer_view.size {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(mapped)
    }

    fn trace_lpc_view_map_failure(
        &self,
        connection_index: usize,
        connector_offer: bool,
        pi: usize,
        status: u32,
    ) {
        print_str(b"[lpc-view] map failed conn=");
        print_u64(self.lpc_connection_views[connection_index].connection_id);
        print_str(if connector_offer {
            b" offer=connector pi="
        } else {
            b" offer=server pi="
        });
        print_u64(pi as u64);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
    }

    pub(crate) unsafe fn rollback_or_defer_generic_section_view(
        &mut self,
        view: nt_memory_manager::GenericSectionView,
    ) {
        if self.rollback_generic_section_view(view).is_err() {
            // Capacity was reserved before the map, so failed cleanup never needs allocation.
            self.pending_section_view_rollbacks.push(view);
        }
    }

    pub(crate) unsafe fn abort_lpc_connection_views(&mut self, connection_id: u64) {
        let Some(index) = self
            .lpc_connection_views
            .iter()
            .position(|pending| pending.connection_id == connection_id)
        else {
            return;
        };
        self.lpc_connection_views[index].aborting = true;
        if self.lpc_connection_views[index].acceptor_process.is_some() {
            self.lpc_connection_views[index].retirement_pending = true;
            self.retire_deleted_lpc_endpoints(connection_id);
            return;
        }
        let pending = self.lpc_connection_views[index];
        // Reply cancellation does not acknowledge broker refusal or construction retirement.
        let receipt = lpc_client().and_then(|client| {
            client
                .query_endpoint_lifetime(
                    connection_id,
                    nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT,
                    pending.connector_broker_process,
                )
                .ok()
        });
        let Some(receipt) = receipt.filter(|receipt| {
            receipt.connection_id == connection_id
                && receipt.endpoint == nt_lpc_abi::handle_endpoint::CLIENT_COMM_PORT
                && receipt.owner_process == pending.connector_broker_process
        }) else {
            return;
        };
        if !receipt.is_deleted() {
            return;
        }
        if self.lpc_connection_views[index].connector_mapping.is_none()
            && self.lpc_connection_views[index].acceptor_mapping.is_none()
        {
            self.lpc_connection_views.swap_remove(index);
        }
    }

    pub(crate) unsafe fn retry_pending_section_view_rollbacks(&mut self) {
        if REFERENCE_RELEASED.swap(false, Ordering::AcqRel) {
            for row in &mut self.lpc_connection_views {
                row.retirement_pending = true;
            }
        }
        let mut index = 0;
        while index < self.pending_section_view_rollbacks.len() {
            let view = self.pending_section_view_rollbacks[index];
            if self.rollback_generic_section_view(view).is_ok() {
                self.pending_section_view_rollbacks.swap_remove(index);
            } else {
                index += 1;
            }
        }
        let mut index = 0;
        while index < self.lpc_connection_views.len() {
            if self.lpc_connection_views[index].aborting {
                let connection_id = self.lpc_connection_views[index].connection_id;
                self.abort_lpc_connection_views(connection_id);
                if self
                    .lpc_connection_views
                    .get(index)
                    .is_none_or(|pending| pending.connection_id != connection_id)
                {
                    continue;
                }
            }
            let connection_id = self.lpc_connection_views[index].connection_id;
            if self.lpc_connection_views[index].retirement_pending {
                self.retire_deleted_lpc_endpoints(connection_id);
            }
            if self
                .lpc_connection_views
                .get(index)
                .is_none_or(|pending| pending.connection_id != connection_id)
            {
                continue;
            }
            index += 1;
        }
    }

    pub(crate) unsafe fn accept_lpc_connection_views(
        &mut self,
        connection_id: u64,
        acceptor_pi: usize,
        acceptor_memory: SyscallUserMemory,
        server_view_pointer: u64,
        client_view_pointer: u64,
    ) -> Result<(), u32> {
        let index = self
            .lpc_connection_views
            .iter()
            .position(|pending| pending.connection_id == connection_id)
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        let mut pending = self.lpc_connection_views[index];
        if pending.aborting
            || pending.connector_mapping.is_some()
            || pending.acceptor_mapping.is_some()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.capture_process_identity(pending.connector_pi) != Some(pending.connector_process) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let acceptor_process = self
            .capture_process_identity(acceptor_pi)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if pending.acceptor_process != Some(acceptor_process) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.lpc_connection_views[index] = pending;
        let server_view =
            self.capture_lpc_port_view(acceptor_pi, acceptor_memory, server_view_pointer)?;
        let client_view =
            self.capture_lpc_remote_view(acceptor_pi, acceptor_memory, client_view_pointer)?;

        if let Some(connector_view) = pending.connector_view {
            match self.map_lpc_port_view(
                index,
                true,
                connector_view,
                pending.connector_pi,
                acceptor_pi,
            ) {
                Ok(mapped) => {
                    pending.connector_mapping = Some(mapped);
                    self.lpc_connection_views[index] = pending;
                }
                Err(status) => return Err(status),
            }
        }
        if let Some(server_view) = server_view {
            match self.map_lpc_port_view(
                index,
                false,
                server_view,
                acceptor_pi,
                pending.connector_pi,
            ) {
                Ok(mapped) => {
                    pending.acceptor_mapping = Some(mapped);
                    self.lpc_connection_views[index] = pending;
                }
                Err(status) => {
                    return Err(status);
                }
            }
        }

        let results = nt_lpc_abi::connection_view_results(
            pending.connector_mapping.and_then(MappedLpcPortView::abi),
            pending.acceptor_mapping.and_then(MappedLpcPortView::abi),
        );
        let mut outputs_ok = true;
        if let Some(mut server_view) = server_view {
            let mapped = results.acceptor_view.unwrap();
            nt_lpc_abi::publish_port_view(
                &mut server_view.native,
                mapped.view_size,
                mapped.view_base,
                mapped.view_remote_base,
            );
            outputs_ok &= self.lpc_user_memory_write(
                acceptor_pi,
                acceptor_memory,
                server_view.pointer,
                &server_view.native,
            );
        }
        if let Some(mut client_view) = client_view {
            let (view_size, view_base) = results
                .acceptor_client_view
                .map(|mapped| (mapped.view_size, mapped.view_base))
                .unwrap_or((0, 0));
            nt_lpc_abi::publish_remote_port_view(&mut client_view.native, view_size, view_base);
            outputs_ok &= self.lpc_user_memory_write(
                acceptor_pi,
                acceptor_memory,
                client_view.pointer,
                &client_view.native,
            );
        }
        if !outputs_ok {
            return Err(STATUS_ACCESS_VIOLATION);
        }

        self.lpc_connection_views[index] = pending;
        print_str(b"[lpc-view] accepted conn=");
        print_u64(connection_id);
        print_str(b" connector-pi=");
        print_u64(pending.connector_pi as u64);
        print_str(b" acceptor-pi=");
        print_u64(acceptor_pi as u64);
        print_str(b" connector-view=");
        print_u64(pending.connector_mapping.is_some() as u64);
        print_str(b" acceptor-view=");
        print_u64(pending.acceptor_mapping.is_some() as u64);
        print_str(b"\n");
        Ok(())
    }

    pub(crate) unsafe fn complete_lpc_connection_views(
        &mut self,
        connection_id: u64,
    ) -> Result<(), u32> {
        let Some(index) = self
            .lpc_connection_views
            .iter()
            .position(|pending| pending.connection_id == connection_id)
        else {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        };
        let pending = self.lpc_connection_views[index];
        if pending.aborting || pending.completed || pending.failed_accept {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.capture_process_identity(pending.connector_pi) != Some(pending.connector_process) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let results = nt_lpc_abi::connection_view_results(
            pending.connector_mapping.and_then(MappedLpcPortView::abi),
            pending.acceptor_mapping.and_then(MappedLpcPortView::abi),
        );
        let mut outputs_ok = true;
        if let Some(mut connector_view) = pending.connector_view {
            let Some(mapped) = results.connector_view else {
                self.abort_lpc_connection_views(connection_id);
                return Err(STATUS_INVALID_PARAMETER);
            };
            nt_lpc_abi::publish_port_view(
                &mut connector_view.native,
                mapped.view_size,
                mapped.view_base,
                mapped.view_remote_base,
            );
            outputs_ok &= self.lpc_user_memory_write(
                pending.connector_pi,
                pending.connector_memory,
                connector_view.pointer,
                &connector_view.native,
            );
        }
        if let Some(mut remote_view) = pending.connector_remote_view {
            let (view_size, view_base) = results
                .connector_server_view
                .map(|mapped| (mapped.view_size, mapped.view_base))
                .unwrap_or((0, 0));
            nt_lpc_abi::publish_remote_port_view(&mut remote_view.native, view_size, view_base);
            outputs_ok &= self.lpc_user_memory_write(
                pending.connector_pi,
                pending.connector_memory,
                remote_view.pointer,
                &remote_view.native,
            );
        }
        if !outputs_ok {
            self.abort_lpc_connection_views(connection_id);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        self.lpc_connection_views[index].completed = true;
        print_str(b"[lpc-view] completed conn=");
        print_u64(connection_id);
        print_str(b"\n");
        Ok(())
    }
}
