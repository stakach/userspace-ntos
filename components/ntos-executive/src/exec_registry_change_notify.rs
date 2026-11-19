//! `NtNotifyChangeKey` / `NtNotifyChangeMultipleKeys`: the executive's side of registry change
//! notification. Which requests a change completes is decided by `nt-config-notify`; this file
//! captures a request's completion surfaces, reports committed changes and delivers
//! completions (NT `ntos/config/ntapi.c` `NtNotifyChangeMultipleKeys`, `cmnotify.c`).

use super::*;
use nt_config_notify::{ArmError, Armed, ChangeNotifier, Completion, KeyBody, PostId};

const KEY_NOTIFY: u32 = 0x0010;
const STATUS_KEY_DELETED: u32 = 0xC000_017C;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
/// Completions traced per boot; watchers re-arm for the life of the system.
const TRACE_LIMIT: u32 = 96;

/// Where one request's completion goes.
enum Surface {
    /// `PostAsyncUser`: optional Event and APC; the caller was answered `STATUS_PENDING`.
    Asynchronous {
        event: Option<nt_io_manager::FileTransferEvent>,
        apc_routine: u64,
        apc_context: u64,
    },
    /// `PostSynchronous`: the caller is parked until the status is known.
    Synchronous,
}

pub(crate) struct RegistryNotifyRequest {
    pi: usize,
    pid: nt_process::ProcessId,
    iosb: u64,
    surface: Surface,
}

/// Registry change-notification state owned by the handler.
pub(crate) struct RegistryChangeNotifications {
    notifier: ChangeNotifier<RegistryNotifyRequest>,
    /// Statuses of completed synchronous requests not yet collected by their parked callers.
    synchronous_results: Vec<(PostId, u32)>,
    traced: u32,
}

impl RegistryChangeNotifications {
    pub(crate) const fn new() -> Self {
        Self { notifier: ChangeNotifier::new(), synchronous_results: Vec::new(), traced: 0 }
    }
}

impl ExecNtHandler {
    /// `NtNotifyChangeKey(KeyHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
    /// CompletionFilter, WatchTree, Buffer, Length, Asynchronous)`.
    pub(super) unsafe fn nt_notify_change_key_service(&mut self, args: &[u64]) -> u32 {
        self.nt_notify_change_multiple_keys(
            args[0], 0, args[1], args[2], args[3], args[4], nt_ulong_arg(args[5]),
            nt_boolean_arg(args[6]), args[7], nt_ulong_arg(args[8]), nt_boolean_arg(args[9]),
        )
    }

    /// `NtNotifyChangeMultipleKeys(MasterKeyHandle, Count, SlaveObjects, Event, ApcRoutine,
    /// ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, Length, Asynchronous)`.
    pub(super) unsafe fn nt_notify_change_multiple_keys_service(&mut self, args: &[u64]) -> u32 {
        self.nt_notify_change_multiple_keys(
            args[0], nt_ulong_arg(args[1]), args[3], args[4], args[5], args[6],
            nt_ulong_arg(args[7]), nt_boolean_arg(args[8]), args[9], nt_ulong_arg(args[10]),
            nt_boolean_arg(args[11]),
        )
    }

    unsafe fn nt_notify_change_multiple_keys(
        &mut self,
        key_handle: u64,
        slave_count: u32,
        event: u64,
        apc_routine: u64,
        apc_context: u64,
        iosb: u64,
        filter: u32,
        watch_tree: bool,
        buffer: u64,
        length: u32,
        asynchronous: bool,
    ) -> u32 {
        if slave_count > 1 {
            return STATUS_INVALID_PARAMETER;
        }
        if slave_count == 1 {
            // A second key in another hive needs a linked pair of requests; nothing here
            // watches the slave, so the request is refused rather than half armed.
            print_str(b"[cm-notify] slave key not supported pi=");
            print_u64(self.pi as u64);
            print_str(b"\n");
            return STATUS_NOT_IMPLEMENTED;
        }
        if iosb & 3 != 0 || (length != 0 && buffer & 3 != 0) {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if iosb == 0
            || !self.probe_user_output(iosb, 16)
            || (length != 0 && !self.probe_user_output(buffer, length as usize))
        {
            return STATUS_ACCESS_VIOLATION;
        }
        if let Err(status) = self.write_registry_notify_iosb(self.pi, iosb, STATUS_PENDING) {
            return status;
        }
        if filter & !nt_config_notify::REG_LEGAL_CHANGE_FILTER != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let key = match self.resolve_registry_key(key_handle, KEY_NOTIFY) {
            Ok(key) => key,
            Err(status) => return status,
        };
        let Some(pid) = self.pm_pid_for_pi(self.pi) else {
            return STATUS_INVALID_HANDLE;
        };
        // A handle whose key no longer has a name is a handle to a deleted key.
        let Some(path) = self.registry_target_path(key) else {
            return STATUS_KEY_DELETED;
        };
        let surface = if asynchronous {
            let event = if event != 0 {
                match self.lease_event_for_operation(event, EVENT_MODIFY_STATE) {
                    Ok(lease) => {
                        // KeClearEvent: the Event reports this request from now on.
                        let _ = self.events.reset_existing(lease.native_identity);
                        Some(lease)
                    }
                    Err(status) => return status,
                }
            } else {
                None
            };
            Surface::Asynchronous { event, apc_routine, apc_context }
        } else {
            Surface::Synchronous
        };
        let body = KeyBody { process: u64::from(pid), handle: key_handle };
        let request = RegistryNotifyRequest { pi: self.pi, pid, iosb, surface };
        let armed = {
            let _durable = allocator::enter_durable();
            self.registry_change_notifications.notifier.arm(
                body, &path, filter, watch_tree, self.current_tid, request,
            )
        };
        match armed {
            Ok(Armed::Pending(post)) if asynchronous => {
                let _ = post;
                STATUS_PENDING
            }
            Ok(Armed::Pending(post)) => {
                match crate::mutable_hive_mutation_work::submit_hosted_change_notify(self, post) {
                    // The caller's Reply now belongs to the parked request.
                    Ok(()) => STATUS_PENDING,
                    Err(status) => {
                        drop(self.registry_change_notifications.notifier.withdraw(post));
                        status
                    }
                }
            }
            // The key changed since this handle's last request (NotifyPending). The request
            // completes through its own surfaces; a synchronous caller gets the status itself.
            Ok(Armed::Posted(completion)) => {
                let status = completion.status;
                let synchronous = matches!(completion.request.surface, Surface::Synchronous);
                if synchronous {
                    self.trace_registry_notify_completion(&completion, true);
                    let _ = self.write_registry_notify_iosb(self.pi, iosb, status);
                    status
                } else {
                    self.deliver_registry_notifications(alloc::vec![completion]);
                    0
                }
            }
            Err(ArmError::InvalidFilter(request)) => {
                self.release_registry_notify_request(request);
                STATUS_INVALID_PARAMETER
            }
            Err(ArmError::InsufficientResources(request)) => {
                self.release_registry_notify_request(request);
                STATUS_INSUFFICIENT_RESOURCES
            }
        }
    }

    unsafe fn write_registry_notify_iosb(&mut self, pi: usize, iosb: u64, status: u32) -> Result<(), u32> {
        let mut block = [0u8; 16];
        block[..4].copy_from_slice(&status.to_le_bytes());
        self.process_memory_write_status(pi, iosb, &block)
    }

    fn release_registry_notify_request(&mut self, request: RegistryNotifyRequest) {
        if let Surface::Asynchronous { event: Some(event), .. } = request.surface {
            self.release_transfer_event(event);
        }
    }

    /// Report a change of a mutable-hive key by its live name.
    pub(crate) fn mutable_registry_key_values_changed(&mut self, key: ResolvedHiveKey) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        if let Some(path) = self.mutable_key_path(key) {
            unsafe { self.registry_key_values_changed(&path) };
        }
    }

    pub(crate) fn mutable_registry_key_security_changed(&mut self, key: ResolvedHiveKey) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        if let Some(path) = self.mutable_key_path(key) {
            unsafe { self.registry_key_security_changed(&path) };
        }
    }

    pub(crate) fn mutable_registry_subkey_created(&mut self, child: ResolvedHiveKey) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        if let Some(path) = self.mutable_key_path(child) {
            unsafe { self.registry_subkey_created(&path) };
        }
    }

    /// Report a change of the key a handle target names.
    pub(super) fn registry_target_values_changed(&mut self, target: KeyRef) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        if let Some(path) = self.registry_target_path(target) {
            unsafe { self.registry_key_values_changed(&path) };
        }
    }

    pub(super) fn registry_target_security_changed(&mut self, target: KeyRef) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        if let Some(path) = self.registry_target_path(target) {
            unsafe { self.registry_key_security_changed(&path) };
        }
    }

    /// A value of `key` was set or deleted.
    pub(crate) unsafe fn registry_key_values_changed(&mut self, key: &str) {
        self.registry_key_changed(key, nt_config_notify::REG_NOTIFY_CHANGE_LAST_SET);
    }

    /// The security descriptor of `key` was replaced (`CmpSetSecurityDescriptorInfo`).
    pub(crate) unsafe fn registry_key_security_changed(&mut self, key: &str) {
        self.registry_key_changed(
            key,
            nt_config_notify::REG_NOTIFY_CHANGE_ATTRIBUTES
                | nt_config_notify::REG_NOTIFY_CHANGE_SECURITY,
        );
    }

    unsafe fn registry_key_changed(&mut self, key: &str, filter: u32) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        let completions = self.registry_change_notifications.notifier.report_key_changed(key, filter);
        self.deliver_registry_notifications(completions);
    }

    /// `subkey` was created (or a hive was linked at that name).
    pub(crate) unsafe fn registry_subkey_created(&mut self, subkey: &str) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        let completions = self.registry_change_notifications.notifier.report_subkey_changed(subkey);
        self.deliver_registry_notifications(completions);
    }

    /// `key` was deleted.
    pub(crate) unsafe fn registry_key_deleted(&mut self, key: &str) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        let completions = self.registry_change_notifications.notifier.key_deleted(key);
        self.deliver_registry_notifications(completions);
    }

    /// The hive mounted at `root` was unloaded.
    pub(crate) unsafe fn registry_hive_unloaded(&mut self, root: &str) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        let completions = self.registry_change_notifications.notifier.subtree_removed(root);
        self.deliver_registry_notifications(completions);
    }

    /// A registry handle left `pid`'s handle table.
    pub(crate) unsafe fn registry_notify_handle_closed(&mut self, pid: nt_process::ProcessId, handle: u64) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        let completions = self.registry_change_notifications.notifier
            .close_key_body(KeyBody { process: u64::from(pid), handle });
        self.deliver_registry_notifications(completions);
    }

    /// Every handle of `pid` is being closed.
    pub(crate) unsafe fn registry_notify_process_closed(&mut self, pid: nt_process::ProcessId) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        let completions = self.registry_change_notifications.notifier.close_process(u64::from(pid));
        self.deliver_registry_notifications(completions);
    }

    /// `tid` is gone (`CmNotifyRunDown`).
    pub(crate) unsafe fn registry_notify_thread_exited(&mut self, tid: u64) {
        if self.registry_change_notifications.notifier.is_idle() {
            return;
        }
        let Some(pid) = nt_process::ThreadId::try_from(tid).ok()
            .and_then(|thread| self.pm.thread(thread)).map(|thread| thread.process_id)
        else {
            return;
        };
        let completions = self.registry_change_notifications.notifier
            .thread_exited(u64::from(pid), tid);
        self.deliver_registry_notifications(completions);
    }

    /// Publish each finished request: IO_STATUS_BLOCK, then Event, then APC, or the status a
    /// parked synchronous caller returns with. A surface whose owner is gone is only released.
    unsafe fn deliver_registry_notifications(
        &mut self,
        completions: Vec<Completion<RegistryNotifyRequest>>,
    ) {
        for completion in completions {
            let request = &completion.request;
            let process_live = self.pm_pid_for_pi(request.pi) == Some(request.pid)
                && self.pm.process(request.pid)
                    .is_some_and(|process| process.state != nt_process::ProcessState::Terminated);
            let thread_id = nt_process::ThreadId::try_from(completion.thread).ok();
            let thread_live = process_live && thread_id
                .and_then(|thread| self.pm.thread(thread))
                .is_some_and(|thread| thread.process_id == request.pid
                    && thread.state != nt_process::ThreadState::Terminated);
            self.trace_registry_notify_completion(&completion, thread_live);
            let Completion { post, thread, status, request, .. } = completion;
            match request.surface {
                Surface::Synchronous => {
                    if !thread_live {
                        // Its parked row finds the caller gone on its next turn.
                        crate::mutable_hive_mutation_work::wake_change_notify();
                        continue;
                    }
                    let _ = self.write_registry_notify_iosb(request.pi, request.iosb, status);
                    let recorded = {
                        let _durable = allocator::enter_durable();
                        let results = &mut self.registry_change_notifications.synchronous_results;
                        results.try_reserve(1).map(|()| results.push((post, status))).is_ok()
                    };
                    // Without a recorded status the parked caller could never return.
                    assert!(recorded, "registry notify status storage exhausted");
                    crate::mutable_hive_mutation_work::wake_change_notify();
                }
                Surface::Asynchronous { event, apc_routine, apc_context } => {
                    if process_live {
                        let _ = self.write_registry_notify_iosb(request.pi, request.iosb, status);
                    }
                    if let Some(event) = event {
                        let _ = self.signal_event_index(event.native_identity as usize);
                        self.release_transfer_event(event);
                    }
                    if apc_routine != 0 && thread_live {
                        let apc = nt_process::UserApc {
                            routine: apc_routine,
                            normal_context: apc_context,
                            system_argument1: request.iosb,
                            system_argument2: 0,
                        };
                        if let Some(target) = thread_id {
                            if self.pm.queue_kernel_user_apc(target, apc).is_ok() {
                                let _ = crate::service_sec_image::reconcile_user_apc_waits(self, thread);
                            }
                        }
                    }
                }
            }
        }
    }

    /// One `[cm-notify] complete` line per finished request, for the first `TRACE_LIMIT`.
    fn trace_registry_notify_completion(
        &mut self,
        completion: &Completion<RegistryNotifyRequest>,
        thread_live: bool,
    ) {
        if self.registry_change_notifications.traced >= TRACE_LIMIT {
            return;
        }
        self.registry_change_notifications.traced += 1;
        print_str(b"[cm-notify] complete pi=");
        print_u64(completion.request.pi as u64);
        print_str(b" tid=");
        print_u64(completion.thread);
        print_str(b" status=0x");
        print_hex(completion.status);
        print_str(match completion.request.surface {
            Surface::Synchronous => b" sync",
            Surface::Asynchronous { event: Some(_), .. } => b" event",
            Surface::Asynchronous { .. } => b" async",
        });
        print_str(if thread_live { b"\n" } else { b" owner-gone\n" });
    }

    /// The status of a parked synchronous request, once.
    pub(crate) fn take_registry_notify_wait_status(&mut self, post: PostId) -> Option<u32> {
        let results = &mut self.registry_change_notifications.synchronous_results;
        let index = results.iter().position(|(recorded, _)| *recorded == post)?;
        Some(results.swap_remove(index).1)
    }

    /// A parked synchronous caller is gone: forget its request and any uncollected status.
    pub(crate) fn abandon_registry_notify_wait(&mut self, post: PostId) {
        drop(self.registry_change_notifications.notifier.withdraw(post));
        let _ = self.take_registry_notify_wait_status(post);
    }
}
