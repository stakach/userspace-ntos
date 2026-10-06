//! Bounded acceptance evidence. None of these receipts admit or route native execution.

use crate::*;
use nt_user_host::process_observation::{
    ObservationKey, ObservationLimits, ProcessObservations, PublicationFact,
};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

const PROCESS_BUDGET: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DesktopGuiFact {
    GdiMapped,
    WindowCreated,
    MessageRegistered,
    BeginPaint,
    EndPaint,
    DirectDraw,
    BatchFlush,
    BatchRecords,
    CallbackCompleted,
    CallbackFailed,
    WndProcCompleted,
}

impl DesktopGuiFact {
    pub(crate) const COUNT: usize = 11;
    const fn index(self) -> usize {
        self as usize
    }
}

pub(crate) use nt_user_host::desktop_launch::DesktopLaunchContract;

#[derive(Clone, Copy)]
pub(crate) struct DesktopProcessReceipt {
    pub(crate) key: ObservationKey,
    pub(crate) parent: Option<ObservationKey>,
    pub(crate) main: Option<ProviderLogicalCaller>,
    pub(crate) fully_published: bool,
    pub(crate) workers: usize,
    pub(crate) terminal_status: Option<u32>,
    pub(crate) retired: bool,
    gui: [u64; DesktopGuiFact::COUNT],
}

impl DesktopProcessReceipt {
    pub(crate) fn gui_count(self, fact: DesktopGuiFact) -> u64 {
        self.gui[fact.index()]
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DesktopAcceptanceReport {
    pub(crate) evidence_available: bool,
    pub(crate) userinit: Option<DesktopProcessReceipt>,
    pub(crate) explorer: Option<DesktopProcessReceipt>,
    launch: DesktopLaunchContract,
}

impl DesktopAcceptanceReport {
    pub(crate) const fn unavailable() -> Self {
        Self {
            evidence_available: false,
            userinit: None,
            explorer: None,
            launch: DesktopLaunchContract::Unavailable,
        }
    }
    pub(crate) const fn launch_contract(self) -> DesktopLaunchContract {
        self.launch
    }
    pub(crate) fn coherent_shell_chain(self) -> bool {
        self.evidence_available
            && self
                .userinit
                .zip(self.explorer)
                .is_some_and(|(parent, child)| {
                    parent.fully_published
                        && child.fully_published
                        && child.parent == Some(parent.key)
                })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ImageReceipt {
    configured: nt_exe_image::CapturedImageObservation,
    generation: u64,
    top_badge: u64,
    parent: Option<ObservationKey>,
}

pub(crate) struct DesktopObservations {
    rows: ProcessObservations<nt_exe_image::HostedProcessRole, ImageReceipt, DesktopGuiFact>,
    // This fixed index selects snapshots only; the store owns all receipt and identity checks.
    keys: [Option<ObservationKey>; PROCESS_BUDGET],
    available: bool,
    launch: DesktopLaunchContract,
    launch_captured: bool,
}

impl DesktopObservations {
    pub(crate) const fn new() -> Self {
        Self {
            rows: ProcessObservations::new(ObservationLimits {
                processes: PROCESS_BUDGET,
                workers_per_process: 128,
                gui_kinds_per_process: DesktopGuiFact::COUNT,
            }),
            keys: [None; PROCESS_BUDGET],
            available: true,
            launch: DesktopLaunchContract::Unavailable,
            launch_captured: false,
        }
    }
    fn contains(&self, key: ObservationKey) -> bool {
        self.keys.contains(&Some(key))
    }
}

impl ExecNtHandler {
    fn desktop_key(&self, pi: usize) -> Option<ObservationKey> {
        Some(ObservationKey {
            pi,
            process: self.capture_process_identity(pi)?,
        })
    }

    pub(crate) fn observe_desktop_catalog(&mut self, pi: usize) {
        let Some((configured, generation, top_badge)) = self
            .hosted_process_image(pi)
            .and_then(|image| Some((image.observation?, image.generation, image.top_badge)))
        else {
            return;
        };
        let Some(key) = self.desktop_key(pi) else {
            self.desktop_observations.available = false;
            return;
        };
        if key.process.generation
            != nt_user_host::process_identity::ProcessGeneration::Hosted(generation)
        {
            self.desktop_observations.available = false;
            return;
        }
        let parent_pid = self
            .pm
            .process(key.process.pid)
            .and_then(|process| process.parent);
        let parent = parent_pid
            .and_then(|pid| self.process_mechanisms.pi_for_pid(pid))
            .and_then(|pi| self.desktop_key(pi));
        let identity = ImageReceipt {
            configured,
            generation,
            top_badge,
            parent,
        };
        let _durable = allocator::enter_durable();
        if self
            .desktop_observations
            .rows
            .register(key, configured.target().role, identity)
            .is_err()
        {
            self.desktop_observations.available = false;
            return;
        }
        if !self.desktop_observations.contains(key) {
            let Some(slot) = self
                .desktop_observations
                .keys
                .iter_mut()
                .find(|slot| slot.is_none())
            else {
                self.desktop_observations.available = false;
                return;
            };
            *slot = Some(key);
        }
        if self
            .desktop_observations
            .rows
            .record_publication(key, PublicationFact::ProcessCatalog)
            .is_err()
        {
            self.desktop_observations.available = false;
        }
        if self.hosted_process_vspace(pi).is_some() {
            self.observe_desktop_vspace(pi);
        }
    }

    pub(crate) fn observe_desktop_vspace(&mut self, pi: usize) {
        let Some(key) = self.desktop_key(pi) else {
            return;
        };
        if !self.desktop_observations.contains(key) {
            return;
        }
        if self.hosted_process_vspace(pi).is_none()
            || self
                .desktop_observations
                .rows
                .record_publication(key, PublicationFact::VSpace)
                .is_err()
        {
            self.desktop_observations.available = false;
        }
    }

    /// Called after actual Resume/initial-start ACK, never for a merely mapped dormant thread.
    pub(crate) fn observe_desktop_thread_activation(&mut self, tid: u64) {
        let Some(runtime) = self.thread_runtime.executable_by_tid(tid) else {
            return;
        };
        let Some(key) = self.desktop_key(runtime.pi) else {
            return;
        };
        if !self.desktop_observations.contains(key) {
            return;
        }
        let Some(caller) =
            self.capture_provider_logical_caller(runtime.pi, tid, runtime.badge, runtime.tcb)
        else {
            self.desktop_observations.available = false;
            return;
        };
        let _durable = allocator::enter_durable();
        let result = if runtime.role == HostedThreadRole::Main {
            self.desktop_observations
                .rows
                .record_main_publication(key, caller, caller.thread())
        } else {
            self.desktop_observations
                .rows
                .record_worker_activation(key, caller, caller.thread())
        };
        if result.is_err() {
            self.desktop_observations.available = false;
        }
    }

    pub(crate) fn observe_desktop_gui_for(
        &mut self,
        caller: ProviderLogicalCaller,
        fact: DesktopGuiFact,
        amount: u64,
    ) {
        let key = ObservationKey {
            pi: caller.pi(),
            process: caller.process(),
        };
        if !self.desktop_observations.contains(key) {
            return;
        }
        if !self.validate_provider_logical_caller(caller)
            || self.desktop_key(caller.pi()) != Some(key)
        {
            self.desktop_observations.available = false;
            return;
        }
        let _durable = allocator::enter_durable();
        if self
            .desktop_observations
            .rows
            .record_gui_fact(key, caller, caller.thread(), fact, amount)
            .is_err()
        {
            self.desktop_observations.available = false;
        }
    }

    pub(crate) fn observe_desktop_terminal(&mut self, pi: usize) -> Option<ObservationKey> {
        let key = self.desktop_key(pi)?;
        if !self.desktop_observations.contains(key) || !self.pm.is_process_signaled(key.process.pid)
        {
            return Some(key);
        }
        let Some(status) = self
            .pm
            .process(key.process.pid)
            .and_then(|process| process.exit_status)
        else {
            self.desktop_observations.available = false;
            return Some(key);
        };
        if self
            .desktop_observations
            .rows
            .record_terminal(key, status)
            .is_err()
        {
            self.desktop_observations.available = false;
        }
        Some(key)
    }

    pub(crate) fn observe_desktop_retirement(&mut self, key: ObservationKey) {
        if self.desktop_observations.contains(key)
            && self.desktop_observations.rows.retire(key).is_err()
        {
            self.desktop_observations.available = false;
        }
    }

    pub(crate) fn capture_desktop_acceptance_report(&mut self) -> DesktopAcceptanceReport {
        // Reconcile still-retained signaled bodies before copying; historical rows survive delete.
        for pi in 0..MAX_PI {
            self.observe_desktop_terminal(pi);
        }
        let launch = self.desktop_observations.launch;
        let mut report = DesktopAcceptanceReport {
            evidence_available: self.desktop_observations.available,
            userinit: None,
            explorer: None,
            launch,
        };
        let mut current = [ObservationKey {
            pi: 0,
            process: nt_user_host::process_identity::ProcessIdentity {
                pid: 0,
                generation: nt_user_host::process_identity::ProcessGeneration::Hosted(0),
            },
        }; MAX_PI];
        let mut current_count = 0;
        for pi in 0..MAX_PI {
            if let Some(key) = self.desktop_key(pi) {
                if !self.pm.is_process_signaled(key.process.pid) {
                    current[current_count] = key;
                    current_count += 1;
                }
            }
        }
        let live_explorer = self
            .desktop_observations
            .rows
            .live_for_role(
                nt_exe_image::HostedProcessRole::InteractiveShell,
                &current[..current_count],
            )
            .ok()
            .flatten();
        if let Some(explorer) = live_explorer {
            report.explorer = Some(copy_receipt(explorer));
            if let Some(parent) = explorer.image().parent {
                if let Some(userinit) = self.desktop_observations.rows.historical_snapshot(parent) {
                    if userinit.role() == nt_exe_image::HostedProcessRole::InteractiveShellBootstrap
                    {
                        report.userinit = Some(copy_receipt(userinit));
                    }
                }
            }
        }
        if report.userinit.is_none() || report.explorer.is_none() {
            report.evidence_available = false;
        }
        report
    }

    pub(crate) unsafe fn capture_desktop_launch_contract(&mut self) {
        if self.desktop_observations.launch_captured {
            return;
        }
        self.desktop_observations.launch = capture_launch_contract();
        self.desktop_observations.launch_captured = true;
    }
}

fn copy_receipt(
    row: &nt_user_host::process_observation::ProcessObservation<
        nt_exe_image::HostedProcessRole,
        ImageReceipt,
        DesktopGuiFact,
    >,
) -> DesktopProcessReceipt {
    DesktopProcessReceipt {
        key: row.key(),
        parent: row.image().parent,
        main: row.main_publication(),
        fully_published: row.fully_published(),
        workers: row.worker_activations().len(),
        terminal_status: row.terminal_status(),
        retired: row.is_retired(),
        gui: [
            row.gui_count(DesktopGuiFact::GdiMapped),
            row.gui_count(DesktopGuiFact::WindowCreated),
            row.gui_count(DesktopGuiFact::MessageRegistered),
            row.gui_count(DesktopGuiFact::BeginPaint),
            row.gui_count(DesktopGuiFact::EndPaint),
            row.gui_count(DesktopGuiFact::DirectDraw),
            row.gui_count(DesktopGuiFact::BatchFlush),
            row.gui_count(DesktopGuiFact::BatchRecords),
            row.gui_count(DesktopGuiFact::CallbackCompleted),
            row.gui_count(DesktopGuiFact::CallbackFailed),
            row.gui_count(DesktopGuiFact::WndProcCompleted),
        ],
    }
}

unsafe fn capture_launch_contract() -> DesktopLaunchContract {
    let Ok(snapshot) = config_manager_query_system_hive_key(r"\Registry\Machine\SYSTEM\Setup")
    else {
        return DesktopLaunchContract::Unavailable;
    };
    nt_user_host::desktop_launch::capture_desktop_launch_contract(snapshot.values.iter().map(
        |value| nt_user_host::desktop_launch::SetupValue {
            name: &value.name,
            value_type: value.value_type,
            data: &value.data,
        },
    ))
}
