//! Physical PCI controller DMA grants and the boot-to-native operation handoff.

use alloc::vec::Vec;

const PAGE_BYTES: u64 = 0x1000;

/// Physical PCI function and the discovery generation that authorized it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciController {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub generation: u64,
}

impl PciController {
    pub const fn new(bus: u8, device: u8, function: u8, generation: u64) -> Option<Self> {
        if device >= 32 || function >= 8 || generation == 0 {
            return None;
        }
        Some(Self {
            bus,
            device,
            function,
            generation,
        })
    }

    const fn same_function(self, other: Self) -> bool {
        self.bus == other.bus && self.device == other.device && self.function == other.function
    }
}

/// A bus-validated PDO identity remains authoritative while its optional queried PCI
/// properties and native DMA grant are pending. Either observation identifies the same
/// physical controller; a missing property query cannot turn off its media proof.
pub fn relation_requires_native_disk_proof(
    controller: PciController,
    relation_pdo: u64,
    accepted_pdo: Option<u64>,
    observed_pci_location: Option<(u32, u32)>,
) -> bool {
    accepted_pdo == Some(relation_pdo)
        || observed_pci_location.is_some_and(|(bus, address)| {
            bus == u32::from(controller.bus)
                && address == ((u32::from(controller.device) << 16)
                    | u32::from(controller.function))
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidController,
    InvalidWindow,
    ControllerExists,
    RootExists,
    WrongController,
    WrongRoot,
    Overlap,
    InsufficientResources,
    IdExhausted,
    UnknownWindow,
    UnknownBootIo,
    WrongPhase,
    BootIoOutstanding,
    NoNativeWindow,
    UncertainDma,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerState {
    BootActive,
    BootDraining,
    NativeStarting,
    NativeActive,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowPhase {
    Prepared,
    Mapping,
    Mapped,
    Unmapping,
    Uncertain,
}

/// Opaque identifier for one native IOVA grant. IDs never recycle in a ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowId(u64);

impl WindowId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Opaque identifier for one admitted direct boot-controller operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootIoTicket(u64);

impl BootIoTicket {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub id: WindowId,
    pub iova: u64,
    pub pages: u64,
    pub phase: WindowPhase,
}

struct ControllerRecord {
    key: PciController,
    root: u64,
    boot_start: u64,
    boot_end: u64,
    state: ControllerState,
    native_route: Option<u64>,
    boot_io: Vec<BootIoTicket>,
    windows: Vec<Window>,
}

/// Pure authority ledger. Callers retain the actual caps, mappings, and I/O continuations.
/// An entered effect must be confirmed or quarantined; quarantine keeps its IOVA occupied.
pub struct PciDmaHandoff {
    controllers: Vec<ControllerRecord>,
    next_window: u64,
    next_boot_io: u64,
}

impl Default for PciDmaHandoff {
    fn default() -> Self {
        Self::new()
    }
}

impl PciDmaHandoff {
    pub const fn new() -> Self {
        Self {
            controllers: Vec::new(),
            next_window: 1,
            next_boot_io: 1,
        }
    }

    fn range(start: u64, pages: u64) -> Result<u64, Error> {
        if start == 0 || start & (PAGE_BYTES - 1) != 0 || pages == 0 {
            return Err(Error::InvalidWindow);
        }
        start
            .checked_add(pages.checked_mul(PAGE_BYTES).ok_or(Error::InvalidWindow)?)
            .ok_or(Error::InvalidWindow)
    }

    pub fn register(
        &mut self,
        key: PciController,
        root: u64,
        boot_iova: u64,
        boot_pages: u64,
    ) -> Result<(), Error> {
        if key.device >= 32 || key.function >= 8 || key.generation == 0 || root == 0 {
            return Err(Error::InvalidController);
        }
        let boot_end = Self::range(boot_iova, boot_pages)?;
        if self
            .controllers
            .iter()
            .any(|row| row.key.same_function(key))
        {
            return Err(Error::ControllerExists);
        }
        if self.controllers.iter().any(|row| row.root == root) {
            return Err(Error::RootExists);
        }
        self.controllers
            .try_reserve(1)
            .map_err(|_| Error::InsufficientResources)?;
        self.controllers.push(ControllerRecord {
            key,
            root,
            boot_start: boot_iova,
            boot_end,
            state: ControllerState::BootActive,
            native_route: None,
            boot_io: Vec::new(),
            windows: Vec::new(),
        });
        Ok(())
    }

    fn record(&self, key: PciController, root: u64) -> Result<&ControllerRecord, Error> {
        let row = self
            .controllers
            .iter()
            .find(|row| row.key.same_function(key))
            .ok_or(Error::WrongController)?;
        if row.key != key {
            return Err(Error::WrongController);
        }
        if row.root != root {
            return Err(Error::WrongRoot);
        }
        Ok(row)
    }

    fn record_mut(
        &mut self,
        key: PciController,
        root: u64,
    ) -> Result<&mut ControllerRecord, Error> {
        let row = self
            .controllers
            .iter_mut()
            .find(|row| row.key.same_function(key))
            .ok_or(Error::WrongController)?;
        if row.key != key {
            return Err(Error::WrongController);
        }
        if row.root != root {
            return Err(Error::WrongRoot);
        }
        Ok(row)
    }

    pub fn state(&self, key: PciController, root: u64) -> Result<ControllerState, Error> {
        Ok(self.record(key, root)?.state)
    }

    pub fn native_route(&self, key: PciController, root: u64) -> Result<Option<u64>, Error> {
        Ok(self.record(key, root)?.native_route)
    }

    pub fn reserve_window(
        &mut self,
        key: PciController,
        root: u64,
        iova: u64,
        pages: u64,
    ) -> Result<WindowId, Error> {
        let end = Self::range(iova, pages)?;
        let id = WindowId(self.next_window);
        let next = self.next_window.checked_add(1).ok_or(Error::IdExhausted)?;
        let row = self.record_mut(key, root)?;
        if row.state == ControllerState::Uncertain {
            return Err(Error::WrongPhase);
        }
        if iova < row.boot_end && row.boot_start < end
            || row.windows.iter().any(|window| {
                let window_end = window.iova + window.pages * PAGE_BYTES;
                iova < window_end && window.iova < end
            })
        {
            return Err(Error::Overlap);
        }
        row.windows
            .try_reserve(1)
            .map_err(|_| Error::InsufficientResources)?;
        row.windows.push(Window {
            id,
            iova,
            pages,
            phase: WindowPhase::Prepared,
        });
        self.next_window = next;
        Ok(id)
    }

    pub fn window_phase(
        &self,
        key: PciController,
        root: u64,
        id: WindowId,
    ) -> Result<WindowPhase, Error> {
        self.record(key, root)?
            .windows
            .iter()
            .find(|window| window.id == id)
            .map(|window| window.phase)
            .ok_or(Error::UnknownWindow)
    }

    fn window_mut(
        &mut self,
        key: PciController,
        root: u64,
        id: WindowId,
    ) -> Result<&mut Window, Error> {
        self.record_mut(key, root)?
            .windows
            .iter_mut()
            .find(|window| window.id == id)
            .ok_or(Error::UnknownWindow)
    }

    fn change_window(
        &mut self,
        key: PciController,
        root: u64,
        id: WindowId,
        from: WindowPhase,
        to: WindowPhase,
    ) -> Result<(), Error> {
        let window = self.window_mut(key, root, id)?;
        if window.phase != from {
            return Err(Error::WrongPhase);
        }
        window.phase = to;
        Ok(())
    }

    pub fn begin_map(&mut self, key: PciController, root: u64, id: WindowId) -> Result<(), Error> {
        self.change_window(key, root, id, WindowPhase::Prepared, WindowPhase::Mapping)
    }

    pub fn confirm_map(
        &mut self,
        key: PciController,
        root: u64,
        id: WindowId,
    ) -> Result<(), Error> {
        self.change_window(key, root, id, WindowPhase::Mapping, WindowPhase::Mapped)
    }

    pub fn begin_unmap(
        &mut self,
        key: PciController,
        root: u64,
        id: WindowId,
    ) -> Result<(), Error> {
        self.change_window(key, root, id, WindowPhase::Mapped, WindowPhase::Unmapping)
    }

    pub fn quarantine(&mut self, key: PciController, root: u64, id: WindowId) -> Result<(), Error> {
        let window = self.window_mut(key, root, id)?;
        if !matches!(window.phase, WindowPhase::Mapping | WindowPhase::Unmapping) {
            return Err(Error::WrongPhase);
        }
        window.phase = WindowPhase::Uncertain;
        Ok(())
    }

    fn remove_window(
        &mut self,
        key: PciController,
        root: u64,
        id: WindowId,
        phase: WindowPhase,
    ) -> Result<(), Error> {
        let row = self.record_mut(key, root)?;
        let index = row
            .windows
            .iter()
            .position(|window| window.id == id)
            .ok_or(Error::UnknownWindow)?;
        if row.windows[index].phase != phase {
            return Err(Error::WrongPhase);
        }
        row.windows.swap_remove(index);
        Ok(())
    }

    pub fn cancel_window(
        &mut self,
        key: PciController,
        root: u64,
        id: WindowId,
    ) -> Result<(), Error> {
        self.remove_window(key, root, id, WindowPhase::Prepared)
    }

    pub fn confirm_unmap(
        &mut self,
        key: PciController,
        root: u64,
        id: WindowId,
    ) -> Result<(), Error> {
        self.remove_window(key, root, id, WindowPhase::Unmapping)
    }

    pub fn enter_boot_io(&mut self, key: PciController, root: u64) -> Result<BootIoTicket, Error> {
        let ticket = BootIoTicket(self.next_boot_io);
        let next = self.next_boot_io.checked_add(1).ok_or(Error::IdExhausted)?;
        let row = self.record_mut(key, root)?;
        if row.state != ControllerState::BootActive {
            return Err(Error::WrongPhase);
        }
        row.boot_io
            .try_reserve(1)
            .map_err(|_| Error::InsufficientResources)?;
        row.boot_io.push(ticket);
        self.next_boot_io = next;
        Ok(ticket)
    }

    pub fn complete_boot_io(
        &mut self,
        key: PciController,
        root: u64,
        ticket: BootIoTicket,
    ) -> Result<(), Error> {
        let row = self.record_mut(key, root)?;
        let index = row
            .boot_io
            .iter()
            .position(|active| *active == ticket)
            .ok_or(Error::UnknownBootIo)?;
        row.boot_io.swap_remove(index);
        Ok(())
    }

    pub fn begin_drain(&mut self, key: PciController, root: u64) -> Result<(), Error> {
        let row = self.record_mut(key, root)?;
        if row.state != ControllerState::BootActive {
            return Err(Error::WrongPhase);
        }
        row.state = ControllerState::BootDraining;
        Ok(())
    }

    pub fn begin_native_start(&mut self, key: PciController, root: u64) -> Result<(), Error> {
        self.begin_native_start_selected(key, root, None)
    }

    /// Enter native START only for the exact window granted to this controller's provider.
    /// Another mapped window in the same RID domain cannot stand in for a stale receipt.
    pub fn begin_native_start_exact(
        &mut self,
        key: PciController,
        root: u64,
        expected_window: WindowId,
    ) -> Result<(), Error> {
        self.begin_native_start_selected(key, root, Some(expected_window))
    }

    fn begin_native_start_selected(
        &mut self,
        key: PciController,
        root: u64,
        expected_window: Option<WindowId>,
    ) -> Result<(), Error> {
        let row = self.record_mut(key, root)?;
        if row.state != ControllerState::BootDraining {
            return Err(Error::WrongPhase);
        }
        if !row.boot_io.is_empty() {
            return Err(Error::BootIoOutstanding);
        }
        if row
            .windows
            .iter()
            .any(|window| window.phase == WindowPhase::Uncertain)
        {
            return Err(Error::UncertainDma);
        }
        if !row
            .windows
            .iter()
            .any(|window| window.phase == WindowPhase::Mapped
                && expected_window.is_none_or(|id| window.id == id))
        {
            return Err(Error::NoNativeWindow);
        }
        row.state = ControllerState::NativeStarting;
        Ok(())
    }

    /// Complete only after a real native block route has been authenticated and can service the mount.
    pub fn can_activate_native(
        &self,
        key: PciController,
        root: u64,
        route: u64,
    ) -> Result<(), Error> {
        if route == 0 { return Err(Error::InvalidController); }
        let row = self.record(key, root)?;
        if row.state != ControllerState::NativeStarting || row.native_route.is_some() {
            return Err(Error::WrongPhase);
        }
        Ok(())
    }

    /// Complete only after a real native block route has been authenticated and can service the mount.
    pub fn activate_native(
        &mut self,
        key: PciController,
        root: u64,
        route: u64,
    ) -> Result<(), Error> {
        self.can_activate_native(key, root, route)?;
        let row = self.record_mut(key, root)?;
        if row.state != ControllerState::NativeStarting {
            return Err(Error::WrongPhase);
        }
        row.native_route = Some(route);
        row.state = ControllerState::NativeActive;
        Ok(())
    }

    /// An uncertain native start cannot grant the controller back to the boot path.
    pub fn quarantine_controller(&mut self, key: PciController, root: u64) -> Result<(), Error> {
        let row = self.record_mut(key, root)?;
        if row.state != ControllerState::NativeStarting {
            return Err(Error::WrongPhase);
        }
        row.state = ControllerState::Uncertain;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AHCI: PciController = PciController::new(0, 2, 0, 7).unwrap();
    const NEXT_GENERATION: PciController = PciController::new(0, 2, 0, 8).unwrap();

    fn ledger() -> PciDmaHandoff {
        let mut ledger = PciDmaHandoff::new();
        ledger.register(AHCI, 41, 0x1000, 1).unwrap();
        ledger
    }

    #[test]
    fn boot_controller_relation_requires_proof_before_dma_ready_or_properties_arrive() {
        let pdo = 91;
        assert!(relation_requires_native_disk_proof(AHCI, pdo, Some(pdo), None));
        assert!(relation_requires_native_disk_proof(AHCI, pdo, Some(pdo), Some((0, 2 << 16))));
        assert!(relation_requires_native_disk_proof(AHCI, pdo, None, Some((0, 2 << 16))));
        assert!(!relation_requires_native_disk_proof(AHCI, 92, Some(pdo), None));
        assert!(!relation_requires_native_disk_proof(AHCI, 92, None, Some((0, 3 << 16))));
    }

    #[test]
    fn one_root_per_physical_function_across_generations() {
        let mut ledger = ledger();
        assert_eq!(
            ledger.register(AHCI, 42, 0x2000, 1),
            Err(Error::ControllerExists)
        );
        assert_eq!(
            ledger.register(NEXT_GENERATION, 43, 0x2000, 1),
            Err(Error::ControllerExists)
        );
        assert_eq!(
            ledger.register(PciController::new(0, 3, 0, 7).unwrap(), 41, 0x2000, 1),
            Err(Error::RootExists)
        );
        assert_eq!(ledger.state(AHCI, 41), Ok(ControllerState::BootActive));
        assert_eq!(
            ledger.state(NEXT_GENERATION, 41),
            Err(Error::WrongController)
        );
        assert_eq!(ledger.state(AHCI, 42), Err(Error::WrongRoot));
    }

    #[test]
    fn disjoint_windows_are_reserved_and_uncertain_effects_remain_quarantined() {
        let mut ledger = ledger();
        assert_eq!(
            ledger.reserve_window(AHCI, 41, 0x1000, 1),
            Err(Error::Overlap)
        );
        let first = ledger.reserve_window(AHCI, 41, 0x2000, 68).unwrap();
        assert_eq!(
            ledger.reserve_window(AHCI, 41, 0x2000, 1),
            Err(Error::Overlap)
        );
        assert_eq!(
            ledger.reserve_window(AHCI, 41, 0x43000, 1),
            Err(Error::Overlap)
        );
        ledger.begin_map(AHCI, 41, first).unwrap();
        assert_eq!(
            ledger.cancel_window(AHCI, 41, first),
            Err(Error::WrongPhase)
        );
        ledger.quarantine(AHCI, 41, first).unwrap();
        assert_eq!(
            ledger.window_phase(AHCI, 41, first),
            Ok(WindowPhase::Uncertain)
        );
        assert_eq!(
            ledger.reserve_window(AHCI, 41, 0x2000, 1),
            Err(Error::Overlap)
        );
        assert_eq!(ledger.begin_unmap(AHCI, 41, first), Err(Error::WrongPhase));
        assert_eq!(
            ledger.reserve_window(NEXT_GENERATION, 41, 0x50000, 1),
            Err(Error::WrongController)
        );
    }

    #[test]
    fn certain_map_and_unmap_release_only_exact_window() {
        let mut ledger = ledger();
        let lease = ledger.reserve_window(AHCI, 41, 0x2000, 1).unwrap();
        ledger.begin_map(AHCI, 41, lease).unwrap();
        ledger.confirm_map(AHCI, 41, lease).unwrap();
        assert_eq!(
            ledger.window_phase(AHCI, 41, lease),
            Ok(WindowPhase::Mapped)
        );
        ledger.begin_unmap(AHCI, 41, lease).unwrap();
        assert_eq!(
            ledger.reserve_window(AHCI, 41, 0x2000, 1),
            Err(Error::Overlap)
        );
        ledger.confirm_unmap(AHCI, 41, lease).unwrap();
        assert_eq!(
            ledger.window_phase(AHCI, 41, lease),
            Err(Error::UnknownWindow)
        );
        assert!(ledger.reserve_window(AHCI, 41, 0x2000, 1).is_ok());
    }

    #[test]
    fn boot_io_drains_before_native_start_and_never_reopens_after_activation() {
        let mut ledger = ledger();
        let ticket = ledger.enter_boot_io(AHCI, 41).unwrap();
        let native = ledger.reserve_window(AHCI, 41, 0x2000, 1).unwrap();
        ledger.begin_map(AHCI, 41, native).unwrap();
        ledger.confirm_map(AHCI, 41, native).unwrap();
        ledger.begin_drain(AHCI, 41).unwrap();
        assert_eq!(ledger.enter_boot_io(AHCI, 41), Err(Error::WrongPhase));
        assert_eq!(
            ledger.begin_native_start(AHCI, 41),
            Err(Error::BootIoOutstanding)
        );
        assert_eq!(
            ledger.complete_boot_io(NEXT_GENERATION, 41, ticket),
            Err(Error::WrongController)
        );
        ledger.complete_boot_io(AHCI, 41, ticket).unwrap();
        ledger.begin_native_start(AHCI, 41).unwrap();
        assert_eq!(ledger.state(AHCI, 41), Ok(ControllerState::NativeStarting));
        assert_eq!(ledger.enter_boot_io(AHCI, 41), Err(Error::WrongPhase));
        ledger.activate_native(AHCI, 41, 81).unwrap();
        assert_eq!(ledger.state(AHCI, 41), Ok(ControllerState::NativeActive));
        assert_eq!(ledger.enter_boot_io(AHCI, 41), Err(Error::WrongPhase));
        assert_eq!(ledger.activate_native(AHCI, 41, 82), Err(Error::WrongPhase));
        assert!(ledger.reserve_window(AHCI, 41, 0x3000, 1).is_ok());
    }

    #[test]
    fn native_start_requires_a_mapped_window_and_exact_boot_command_retirement() {
        let mut ledger = ledger();
        let command = ledger.enter_boot_io(AHCI, 41).unwrap();
        let native = ledger.reserve_window(AHCI, 41, 0x2000, 1).unwrap();
        let other = ledger.reserve_window(AHCI, 41, 0x3000, 1).unwrap();
        ledger.begin_drain(AHCI, 41).unwrap();
        assert_eq!(ledger.enter_boot_io(AHCI, 41), Err(Error::WrongPhase));
        assert_eq!(ledger.begin_native_start_exact(AHCI, 41, native), Err(Error::BootIoOutstanding));
        ledger.complete_boot_io(AHCI, 41, command).unwrap();
        assert_eq!(ledger.begin_native_start_exact(AHCI, 41, native), Err(Error::NoNativeWindow));
        ledger.begin_map(AHCI, 41, native).unwrap();
        assert_eq!(ledger.begin_native_start_exact(AHCI, 41, native), Err(Error::NoNativeWindow));
        ledger.confirm_map(AHCI, 41, native).unwrap();
        assert_eq!(ledger.begin_native_start_exact(AHCI, 41, other), Err(Error::NoNativeWindow));
        ledger.begin_native_start_exact(AHCI, 41, native).unwrap();
        assert_eq!(ledger.state(AHCI, 41), Ok(ControllerState::NativeStarting));
        assert_eq!(ledger.enter_boot_io(AHCI, 41), Err(Error::WrongPhase));
    }

    #[test]
    fn unacknowledged_boot_command_keeps_native_handoff_fenced() {
        let mut ledger = ledger();
        let completed = ledger.enter_boot_io(AHCI, 41).unwrap();
        let unacknowledged = ledger.enter_boot_io(AHCI, 41).unwrap();
        let native = ledger.reserve_window(AHCI, 41, 0x2000, 1).unwrap();
        ledger.begin_map(AHCI, 41, native).unwrap();
        ledger.confirm_map(AHCI, 41, native).unwrap();
        ledger.complete_boot_io(AHCI, 41, completed).unwrap();
        ledger.begin_drain(AHCI, 41).unwrap();
        assert_eq!(ledger.enter_boot_io(AHCI, 41), Err(Error::WrongPhase));
        assert_eq!(
            ledger.begin_native_start(AHCI, 41),
            Err(Error::BootIoOutstanding)
        );
        // Recovery may later prove that the command retired. Until then its exact
        // ticket remains owned by the boot controller, even if other I/O finished.
        ledger.complete_boot_io(AHCI, 41, unacknowledged).unwrap();
        ledger.begin_native_start(AHCI, 41).unwrap();
    }

    #[test]
    fn uncertain_dma_or_native_start_never_reopens_boot_controller() {
        let mut handoff = ledger();
        let mapped = handoff.reserve_window(AHCI, 41, 0x2000, 1).unwrap();
        handoff.begin_map(AHCI, 41, mapped).unwrap();
        handoff.confirm_map(AHCI, 41, mapped).unwrap();
        let uncertain = handoff.reserve_window(AHCI, 41, 0x3000, 1).unwrap();
        handoff.begin_map(AHCI, 41, uncertain).unwrap();
        handoff.quarantine(AHCI, 41, uncertain).unwrap();
        handoff.begin_drain(AHCI, 41).unwrap();
        assert_eq!(
            handoff.begin_native_start(AHCI, 41),
            Err(Error::UncertainDma)
        );
        assert_eq!(handoff.enter_boot_io(AHCI, 41), Err(Error::WrongPhase));

        let mut clean = ledger();
        let native = clean.reserve_window(AHCI, 41, 0x2000, 1).unwrap();
        clean.begin_map(AHCI, 41, native).unwrap();
        clean.confirm_map(AHCI, 41, native).unwrap();
        clean.begin_drain(AHCI, 41).unwrap();
        clean.begin_native_start(AHCI, 41).unwrap();
        clean.quarantine_controller(AHCI, 41).unwrap();
        assert_eq!(clean.enter_boot_io(AHCI, 41), Err(Error::WrongPhase));
        assert_eq!(clean.activate_native(AHCI, 41, 81), Err(Error::WrongPhase));
    }

    #[test]
    fn invalid_ranges_and_unknown_completions_never_mutate_authority() {
        let mut ledger = ledger();
        assert_eq!(
            ledger.reserve_window(AHCI, 41, 0, 1),
            Err(Error::InvalidWindow)
        );
        assert_eq!(
            ledger.reserve_window(AHCI, 41, 0x2100, 1),
            Err(Error::InvalidWindow)
        );
        assert_eq!(
            ledger.reserve_window(AHCI, 41, u64::MAX & !0xfff, 2),
            Err(Error::InvalidWindow)
        );
        assert_eq!(
            ledger.complete_boot_io(AHCI, 41, BootIoTicket(999)),
            Err(Error::UnknownBootIo)
        );
        let ticket = ledger.enter_boot_io(AHCI, 41).unwrap();
        ledger.complete_boot_io(AHCI, 41, ticket).unwrap();
        assert_eq!(
            ledger.complete_boot_io(AHCI, 41, ticket),
            Err(Error::UnknownBootIo)
        );
    }
}
