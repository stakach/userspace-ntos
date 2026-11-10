//! Root-owned observation of the exact native install-pipe exchange.
//! File, IRP, Reply and process lifetime remain with their existing managers.

use super::*;

const PIPE_NAME_CAP: usize = 96;
const PRINT_DEVICE_CAP: u64 = 128;
const PRINT_RPC_CAP: u64 = 32;

fn plugplay_pipe_name_hash() -> u64 {
    const LEAF: [u16; 9] = [b'\\' as u16, b'p' as u16, b'l' as u16, b'u' as u16,
        b'g' as u16, b'p' as u16, b'l' as u16, b'a' as u16, b'y' as u16];
    nt_io_manager::pipe_name_hash(&LEAF)
}

fn exact_pipe_name(file_id: u64, out: &mut [u16; PIPE_NAME_CAP]) -> Option<usize> {
    let file = driver_launch::io_manager_mut().file(nt_io_manager::FileId(file_id))?;
    let units = file.file_name.as_units();
    if units.is_empty() || units.len() >= out.len() { return None; }
    out[..units.len()].copy_from_slice(units);
    out[units.len()] = 0;
    Some(units.len() + 1)
}

fn trace_device(observation: &nt_hosted_runtime::InstallPipeObservation) {
    print_str(b"[pnp-install-batch] child-pid/gen/file/ordinal/total=");
    print_u64(u64::from(observation.child.pid));
    print_str(b"/");
    print_u64(observation.child.generation);
    print_str(b"/");
    print_hex_u64(observation.client_file_id);
    print_str(b"/");
    print_u64(u64::from(observation.device_ordinal));
    print_str(b"/");
    print_u64(u64::from(observation.device_total));
    print_str(b" server-file=");
    print_hex_u64(observation.pipe.file_id);
    print_str(b" device=\"");
    print_sanitized_utf16_ascii(&observation.device[..observation.device_len], 180);
    print_str(b"\"\n");
}

impl ExecNtHandler {
    pub(crate) fn rpc_op6_client_key(
        &self, pi: usize, file_id: u64,
    ) -> Option<nt_hosted_runtime::RpcClientKey> {
        let (device_id, npfs_fid) = driver_launch::hosted_file_route(file_id)?;
        if driver_launch::device_id_by_name("\\Device\\NamedPipe") != Some(device_id)
            || crate::pipe_fid_name_hash(npfs_fid) != plugplay_pipe_name_hash()
        { return None; }
        Some(nt_hosted_runtime::RpcClientKey {
            pid: self.pm_pid_for_pi(pi)?,
            generation: self.hosted_process_generation(pi)?,
            file_id, npfs_fid,
        })
    }

    pub(crate) fn stage_rpc_op6_client_write(
        &mut self, pi: usize, file_id: u64, irp_id: u64, bytes: &[u8],
    ) {
        if let Some(key) = self.rpc_op6_client_key(pi, file_id) {
            let _ = self.rpc_op6_client_capture.stage_write(key, irp_id, bytes);
            self.print_rpc_op6_client_overflow();
        }
    }

    pub(crate) fn stage_rpc_op6_client_transceive(
        &mut self, pi: usize, file_id: u64, irp_id: u64, bytes: &[u8],
    ) {
        if let Some(key) = self.rpc_op6_client_key(pi, file_id) {
            let _ = self.rpc_op6_client_capture.stage_transceive(key, irp_id, bytes);
            self.print_rpc_op6_client_overflow();
        }
    }

    pub(crate) fn complete_rpc_op6_client_write(
        &mut self, pi: usize, file_id: u64, irp_id: u64, status: u32, information: u64,
    ) {
        if let Some(key) = self.rpc_op6_client_key(pi, file_id) {
            if let Some(event) = self.rpc_op6_client_capture.complete_write(key, irp_id, status, information) {
                self.print_rpc_op6_client_event(&event);
            }
            self.print_rpc_op6_client_overflow();
        }
    }

    pub(crate) fn observe_rpc_op6_client_write(
        &mut self, pi: usize, file_id: u64, bytes: &[u8], status: u32, information: u64,
    ) {
        if let Some(key) = self.rpc_op6_client_key(pi, file_id) {
            if let Some(event) = self.rpc_op6_client_capture.write(key, bytes, status, information) {
                self.print_rpc_op6_client_event(&event);
            }
            self.print_rpc_op6_client_overflow();
        }
    }

    pub(crate) fn observe_rpc_op6_client_transceive(
        &mut self, pi: usize, file_id: u64, bytes: &[u8], status: u32,
    ) {
        if let Some(key) = self.rpc_op6_client_key(pi, file_id) {
            if let Some(event) = self.rpc_op6_client_capture.transceive(key, bytes, status) {
                self.print_rpc_op6_client_event(&event);
            }
            self.print_rpc_op6_client_overflow();
        }
    }

    pub(crate) fn print_rpc_op6_client_overflow(&mut self) {
        let count = self.rpc_op6_client_capture.overflow();
        if count != 0 && count != self.rpc_op6_client_overflow_reported {
            self.rpc_op6_client_overflow_reported = count;
            if count.is_power_of_two() {
                print_str(b"[pnp-rpc-op6-client] capture-overflow=");
                print_u64(count);
                print_str(b"\n");
            }
        }
        let ambiguous = self.rpc_op6_client_capture.ambiguities();
        if ambiguous != 0 && ambiguous != self.rpc_op6_client_ambiguity_reported {
            self.rpc_op6_client_ambiguity_reported = ambiguous;
            if ambiguous.is_power_of_two() {
                print_str(b"[pnp-rpc-op6-client] ambiguous-overlap=");
                print_u64(ambiguous);
                print_str(b"\n");
            }
        }
    }

    pub(crate) fn print_rpc_op6_client_event(&mut self, event: &nt_hosted_runtime::RpcCaptureEvent) {
        if self.rpc_op6_client_printed >= PRINT_RPC_CAP { return; }
        self.rpc_op6_client_printed += 1;
        print_str(b"[pnp-rpc-op6-client] pid/gen/file/fid=");
        print_u64(u64::from(event.key.pid)); print_str(b"/");
        print_u64(event.key.generation); print_str(b"/");
        print_hex_u64(event.key.file_id); print_str(b"/");
        print_hex_u64(event.key.npfs_fid);
        print_str(if event.direction == nt_hosted_runtime::RpcCaptureDirection::Request {
            b" request" as &[u8]
        } else { b" response" as &[u8] });
        print_str(b" call/len/status/sample=");
        print_u64(u64::from(event.call_id)); print_str(b"/");
        print_u64(event.length as u64); print_str(b"/");
        print_hex(event.status); print_str(b"/");
        for &byte in &event.sample[..event.sample_len] {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            debug_put_char(HEX[(byte >> 4) as usize]);
            debug_put_char(HEX[(byte & 15) as usize]);
        }
        print_str(b"\n");
    }

    /// Observe only a completed native registry open by a live, attached child generation.
    pub(crate) fn observe_install_pipe_enum_open(&mut self, pi: usize, path: &str, status: u32) {
        let Some(pid) = self.pm_pid_for_pi(pi) else { return; };
        let Some(generation) = self.hosted_process_generation(pi) else { return; };
        let child = nt_hosted_runtime::InstallChildIdentity { pid, generation };
        if !self.install_pipe_diagnostic.child_is_tracked(child) { return; }
        let Some(open) = self.install_pipe_diagnostic.observe_enum_open(child, path, status)
            else { return; };
        print_str(b"[pnp-install-enum-open] child-pid/gen/server-file/ordinal/status=");
        print_u64(u64::from(pid));
        print_str(b"/");
        print_u64(generation);
        print_str(b"/");
        print_hex_u64(open.pipe.file_id);
        print_str(b"/");
        print_u64(u64::from(open.device_ordinal));
        print_str(b"/0x");
        print_hex(status);
        print_str(b"\n");
    }

    fn install_pipe_published_file(&self, pi: usize, handle: u64) -> Option<u64> {
        let pid = self.pm_pid_for_pi(pi)?;
        self.hosted_file_route_for_pid(pid, handle).map(|route| route.file_id)
    }

    fn install_pipe_identity(&self, pi: usize, file_id: u64)
        -> Option<nt_hosted_runtime::InstallPipeIdentity>
    {
        Some(nt_hosted_runtime::InstallPipeIdentity {
            owner_pid: self.pm_pid_for_pi(pi)?,
            owner_generation: self.hosted_process_generation(pi)?,
            file_id,
        })
    }

    /// Call after a successful native server CREATE has published its canonical File.
    pub(crate) fn observe_install_pipe_server(&mut self, pi: usize, file_id: u64) -> bool {
        let Some(pipe) = self.install_pipe_identity(pi, file_id) else { return false; };
        let mut name = [0u16; PIPE_NAME_CAP];
        let Some(len) = exact_pipe_name(file_id, &mut name) else { return false; };
        if !nt_hosted_runtime::is_install_pipe_name(&name[..len]) { return false; }
        self.install_pipe_diagnostic.register_server(pipe, &name[..len])
    }

    pub(crate) fn observe_install_pipe_server_handle(&mut self, pi: usize, handle: u64) -> bool {
        let Some(file_id) = self.install_pipe_published_file(pi, handle) else { return false; };
        self.observe_install_pipe_server(pi, file_id)
    }

    /// Call after a successful native client CREATE has published its canonical File.
    pub(crate) fn observe_install_pipe_child(&mut self, pi: usize, client_file_id: u64) -> bool {
        let Some(child_pid) = self.pm_pid_for_pi(pi) else { return false; };
        let Some(generation) = self.hosted_process_generation(pi) else { return false; };
        let child = nt_hosted_runtime::InstallChildIdentity { pid: child_pid, generation };
        let mut name = [0u16; PIPE_NAME_CAP];
        let Some(len) = exact_pipe_name(client_file_id, &mut name) else { return false; };
        let Some((_, client_context)) = driver_launch::hosted_file_route(client_file_id) else {
            return false;
        };
        let Some(server_context) = nt_io_manager::pipe_server_file_id_for_endpoint(client_context)
            else { return false; };
        let Some(server) = self.install_pipe_diagnostic.server_for_name_with(&name[..len], |candidate| {
            driver_launch::hosted_file_route(candidate.file_id)
                .is_some_and(|(_, context)| context == server_context)
        }) else {
            return false;
        };
        self.install_pipe_diagnostic.attach_child(server, &name[..len], child, client_file_id)
    }

    pub(crate) fn observe_install_pipe_child_handle(&mut self, pi: usize, handle: u64) -> bool {
        let Some(file_id) = self.install_pipe_published_file(pi, handle) else { return false; };
        self.observe_install_pipe_child(pi, file_id)
    }

    /// Snapshot only an accepted pending native WRITE, under its exact canonical IRP.
    pub(crate) fn stage_install_pipe_write(
        &mut self, pi: usize, file_id: u64, irp_id: u64, payload: &[u8],
    ) -> bool {
        let Some(pipe) = self.install_pipe_identity(pi, file_id) else { return false; };
        if self.install_pipe_diagnostic.server_for_file(
            pipe.owner_pid, pipe.owner_generation, pipe.file_id,
        ) != Some(pipe) { return false; }
        self.install_pipe_diagnostic.stage_server_write(pipe, irp_id, payload)
    }

    /// One exact terminal consumes a staged WRITE; a wrong IRP never advances the parser.
    pub(crate) fn complete_install_pipe_write(
        &mut self, pi: usize, file_id: u64, irp_id: u64, status: u32, information: u64,
    ) -> bool {
        let Some(pipe) = self.install_pipe_identity(pi, file_id) else { return false; };
        if !self.install_pipe_diagnostic.has_staged_write(pipe, irp_id) { return false; }
        let observation = self.install_pipe_diagnostic.complete_server_write(
            pipe, irp_id, status, information,
        );
        if let Some(observation) = observation {
            if self.install_pipe_diagnostic.counts().published <= PRINT_DEVICE_CAP {
                trace_device(&observation);
            }
        }
        true
    }

    /// Immediate WRITE data are visible only after the exact full-byte success receipt.
    pub(crate) fn observe_install_pipe_write(
        &mut self, pi: usize, file_id: u64, payload: &[u8], status: u32, information: u64,
    ) -> bool {
        let Some(pipe) = self.install_pipe_identity(pi, file_id) else { return false; };
        if self.install_pipe_diagnostic.server_for_file(
            pipe.owner_pid, pipe.owner_generation, pipe.file_id,
        ) != Some(pipe) || status != 0 || information != payload.len() as u64 {
            return false;
        }
        let observation = self.install_pipe_diagnostic.record_server_write(pipe, payload);
        if let Some(observation) = observation {
            if self.install_pipe_diagnostic.counts().published <= PRINT_DEVICE_CAP {
                trace_device(&observation);
            }
        }
        true
    }

    /// Observe a real process terminal for the exact attached child generation.
    pub(crate) fn observe_install_pipe_child_terminal(
        &mut self, pi: usize, exit_status: u32,
    ) -> bool {
        let Some(pid) = self.pm_pid_for_pi(pi) else { return false; };
        let Some(generation) = self.hosted_process_generation(pi) else { return false; };
        let child = nt_hosted_runtime::InstallChildIdentity { pid, generation };
        if !self.install_pipe_diagnostic.child_is_tracked(child) { return false; }
        let Some(terminal) = self.install_pipe_diagnostic.record_child_terminal(child, exit_status)
            else { return false; };
        print_str(b"[pnp-install-batch] child-terminal pid/gen/server-file/client-file/status=");
        print_u64(u64::from(pid));
        print_str(b"/");
        print_u64(generation);
        print_str(b"/");
        print_hex_u64(terminal.pipe.file_id);
        print_str(b"/");
        print_hex_u64(terminal.client_file_id);
        print_str(b"/0x");
        print_hex(exit_status);
        print_str(b"\n");
        true
    }
}
