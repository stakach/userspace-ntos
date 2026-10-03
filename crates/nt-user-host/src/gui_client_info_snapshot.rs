//! Value-only GUI client-info copyout from an authenticated win32k dispatch.
//!
//! This does not acquire provider, thread, desktop, or mapping ownership. The native adapter must
//! retain those owners and compare them with the canonical live identities at publication time.

use nt_process::ThreadLifetime;
use nt_provider_wait::ProviderDomainIdentity;
use nt_types::ProcessIdentity;

const DESKTOPINFO_BYTES: u64 = 0x158;
const CLIENTTHREADINFO_BYTES: u64 = 0x20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuiClientInfoOwner<D> {
    pub process: ProcessIdentity,
    pub thread: ThreadLifetime,
    pub provider: ProviderDomainIdentity,
    pub dispatch: D,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopClientMapping {
    pub server_base: u64,
    pub client_base: u64,
    pub bytes: u64,
    pub server_deskinfo: u64,
    pub server_client_thread_info: u64,
    /// Delta returned after the client USER heap mapping was installed.
    pub mapped_delta: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyboardLayoutClientInfo {
    pub hkl: u64,
    /// Zero is CP_ACP, the caller's default ANSI codepage.
    pub codepage: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuiClientInfoValues {
    /// TEB+0x78: opaque server THREADINFO identity.
    pub win32_thread_info: u64,
    /// TEB+0x820: client-mapped DESKTOPINFO pointer.
    pub client_deskinfo: u64,
    /// TEB+0x828: server-to-client desktop heap delta.
    pub desktop_delta: u64,
    /// TEB+0x860: client-mapped CLIENTTHREADINFO pointer.
    pub client_thread_info: u64,
    /// None leaves TEB+0x890/+0x898 unchanged, as the current seed path does.
    pub keyboard_layout: Option<KeyboardLayoutClientInfo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiClientInfoError {
    InvalidOwner,
    StaleOwner,
    InvalidThreadInfo,
    InvalidMapping,
    AddressOutOfRange,
    InvalidKeyboardLayout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuiClientInfoSnapshot<D> {
    owner: GuiClientInfoOwner<D>,
    values: GuiClientInfoValues,
}

impl<D: Copy + Eq> GuiClientInfoSnapshot<D> {
    /// `admitted` must come from the retained canonical owner, not from a second wire copy.
    pub fn capture(
        claimed: GuiClientInfoOwner<D>,
        admitted: GuiClientInfoOwner<D>,
        win32_thread_info: u64,
        mapping: DesktopClientMapping,
        keyboard_layout: Option<KeyboardLayoutClientInfo>,
    ) -> Result<Self, GuiClientInfoError> {
        if !claimed.process.is_valid()
            || claimed.thread.thread_id() == 0
            || claimed.thread.generation() == 0
            || claimed.thread.process_id() != claimed.process.pid
            || !claimed.provider.is_valid()
        {
            return Err(GuiClientInfoError::InvalidOwner);
        }
        if claimed != admitted {
            return Err(GuiClientInfoError::StaleOwner);
        }
        if win32_thread_info == 0 {
            return Err(GuiClientInfoError::InvalidThreadInfo);
        }
        if keyboard_layout.is_some_and(|layout| layout.hkl == 0) {
            return Err(GuiClientInfoError::InvalidKeyboardLayout);
        }
        let (client_deskinfo, client_thread_info, desktop_delta) = mapping.translate()?;
        Ok(Self {
            owner: claimed,
            values: GuiClientInfoValues {
                win32_thread_info,
                client_deskinfo,
                desktop_delta,
                client_thread_info,
                keyboard_layout,
            },
        })
    }

    /// Reject a stale capture immediately before TEB publication.
    pub fn values_for(
        &self,
        current: GuiClientInfoOwner<D>,
    ) -> Result<GuiClientInfoValues, GuiClientInfoError> {
        if current != self.owner {
            return Err(GuiClientInfoError::StaleOwner);
        }
        Ok(self.values)
    }
}

impl DesktopClientMapping {
    fn translate(self) -> Result<(u64, u64, u64), GuiClientInfoError> {
        if self.server_base == 0 || self.client_base == 0 || self.bytes == 0 {
            return Err(GuiClientInfoError::InvalidMapping);
        }
        self.server_base
            .checked_add(self.bytes)
            .ok_or(GuiClientInfoError::InvalidMapping)?;
        self.client_base
            .checked_add(self.bytes)
            .ok_or(GuiClientInfoError::InvalidMapping)?;
        let delta = self
            .server_base
            .checked_sub(self.client_base)
            .filter(|delta| *delta != 0 && *delta == self.mapped_delta)
            .ok_or(GuiClientInfoError::InvalidMapping)?;
        let deskinfo = self.translate_span(self.server_deskinfo, DESKTOPINFO_BYTES)?;
        let client_thread_info =
            self.translate_span(self.server_client_thread_info, CLIENTTHREADINFO_BYTES)?;
        Ok((deskinfo, client_thread_info, delta))
    }

    fn translate_span(self, address: u64, bytes: u64) -> Result<u64, GuiClientInfoError> {
        let offset = address
            .checked_sub(self.server_base)
            .ok_or(GuiClientInfoError::AddressOutOfRange)?;
        let end = offset
            .checked_add(bytes)
            .ok_or(GuiClientInfoError::AddressOutOfRange)?;
        if end > self.bytes {
            return Err(GuiClientInfoError::AddressOutOfRange);
        }
        self.client_base
            .checked_add(offset)
            .ok_or(GuiClientInfoError::InvalidMapping)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use nt_object_manager::win32k_ob::{ObHandleTable, ObKind};
    use nt_process::ProcessManager;
    use nt_provider_wait::{
        ProviderAllocationCatalog, ProviderAllocationError, ProviderArenaIdentity,
    };
    use nt_types::ProcessGeneration;

    fn owner() -> (ProcessManager, GuiClientInfoOwner<u64>) {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("gui.exe", None, None);
        let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
        let owner = GuiClientInfoOwner {
            process: ProcessIdentity {
                pid,
                generation: ProcessGeneration::Hosted(7),
            },
            thread: pm.thread_lifetime(tid).unwrap(),
            provider: ProviderDomainIdentity {
                domain: 3,
                generation: 9,
            },
            dispatch: 11,
        };
        (pm, owner)
    }

    fn mapping() -> DesktopClientMapping {
        DesktopClientMapping {
            server_base: 0x8000_0000,
            client_base: 0x4000_0000,
            bytes: 0x1000,
            server_deskinfo: 0x8000_0100,
            server_client_thread_info: 0x8000_0300,
            mapped_delta: 0x4000_0000,
        }
    }

    #[test]
    fn translates_only_checked_desktop_spans_and_preserves_absent_layout() {
        let (_, owner) = owner();
        let snapshot =
            GuiClientInfoSnapshot::capture(owner, owner, 0x1234, mapping(), None).unwrap();
        assert_eq!(
            snapshot.values_for(owner).unwrap(),
            GuiClientInfoValues {
                win32_thread_info: 0x1234,
                client_deskinfo: 0x4000_0100,
                desktop_delta: 0x4000_0000,
                client_thread_info: 0x4000_0300,
                keyboard_layout: None,
            }
        );
    }

    #[test]
    fn rejects_stale_provider_process_and_dispatch_generations() {
        let (_, owner) = owner();
        let snapshot = GuiClientInfoSnapshot::capture(owner, owner, 1, mapping(), None).unwrap();
        let mut stale = owner;
        stale.provider.generation += 1;
        assert_eq!(
            snapshot.values_for(stale),
            Err(GuiClientInfoError::StaleOwner)
        );
        assert_eq!(
            GuiClientInfoSnapshot::capture(owner, stale, 1, mapping(), None),
            Err(GuiClientInfoError::StaleOwner)
        );
        stale = owner;
        stale.process.generation = ProcessGeneration::Hosted(8);
        assert_eq!(
            snapshot.values_for(stale),
            Err(GuiClientInfoError::StaleOwner)
        );
        stale = owner;
        stale.dispatch += 1;
        assert_eq!(
            snapshot.values_for(stale),
            Err(GuiClientInfoError::StaleOwner)
        );
    }

    #[test]
    fn rejects_mismatched_thread_lifetime() {
        let (mut pm, owner) = owner();
        let other_tid = pm
            .create_thread(owner.process.pid, 0x2000, 0, false)
            .unwrap();
        let mut other = owner;
        other.thread = pm.thread_lifetime(other_tid).unwrap();
        assert_eq!(
            GuiClientInfoSnapshot::capture(owner, other, 1, mapping(), None),
            Err(GuiClientInfoError::StaleOwner)
        );
    }

    #[test]
    fn rejects_overflow_and_out_of_range_desktop_mapping() {
        let (_, owner) = owner();
        let mut bad = mapping();
        bad.server_base = u64::MAX - 0x10;
        assert_eq!(
            GuiClientInfoSnapshot::capture(owner, owner, 1, bad, None),
            Err(GuiClientInfoError::InvalidMapping)
        );
        bad = mapping();
        bad.server_deskinfo = bad.server_base + bad.bytes - DESKTOPINFO_BYTES + 1;
        assert_eq!(
            GuiClientInfoSnapshot::capture(owner, owner, 1, bad, None),
            Err(GuiClientInfoError::AddressOutOfRange)
        );
        bad = mapping();
        bad.server_client_thread_info = bad.server_base - 1;
        assert_eq!(
            GuiClientInfoSnapshot::capture(owner, owner, 1, bad, None),
            Err(GuiClientInfoError::AddressOutOfRange)
        );
    }

    #[test]
    fn requires_nonzero_fields_and_exact_mapped_delta() {
        let (_, owner) = owner();
        let mut bad = mapping();
        bad.mapped_delta += 1;
        assert_eq!(
            GuiClientInfoSnapshot::capture(owner, owner, 1, bad, None),
            Err(GuiClientInfoError::InvalidMapping)
        );
        assert_eq!(
            GuiClientInfoSnapshot::capture(owner, owner, 0, mapping(), None),
            Err(GuiClientInfoError::InvalidThreadInfo)
        );
        assert_eq!(
            GuiClientInfoSnapshot::capture(
                owner,
                owner,
                1,
                mapping(),
                Some(KeyboardLayoutClientInfo {
                    hkl: 0,
                    codepage: 1252
                })
            ),
            Err(GuiClientInfoError::InvalidKeyboardLayout)
        );
    }

    #[test]
    fn cp_acp_is_a_valid_keyboard_layout_codepage() {
        let (_, owner) = owner();
        let keyboard = KeyboardLayoutClientInfo {
            hkl: 0x0409_0409,
            codepage: 0,
        };
        let snapshot = GuiClientInfoSnapshot::capture(
            owner,
            owner,
            1,
            mapping(),
            Some(keyboard),
        )
        .expect("CP_ACP is represented by zero");
        assert_eq!(snapshot.values_for(owner).unwrap().keyboard_layout, Some(keyboard));
    }

    #[test]
    fn copyout_owners_survive_reentrant_retirement_until_reply() {
        let (_, owner) = owner();
        let mut allocations = ProviderAllocationCatalog::new();
        let arena = ProviderArenaIdentity {
            id: 1,
            generation: 1,
        };
        let spans = [
            (0x1230, 0x100),
            (0x8000_0100, DESKTOPINFO_BYTES),
            (0x8000_0300, CLIENTTHREADINFO_BYTES),
            (0x2000, 0x100),
        ];
        let mut pins = Vec::new();
        for (base, bytes) in spans {
            let snapshot = allocations.register(arena, base, bytes).unwrap();
            let (pinned, pin) = allocations.pin_containing(base, bytes).unwrap();
            assert_eq!(pinned.identity, snapshot.identity);
            pins.push((snapshot.identity, pin));
        }

        let desktop_body = 0x3000;
        let mut objects = ObHandleTable::new();
        let desktop_handle = objects.register(ObKind::Desktop, desktop_body);
        assert_ne!(desktop_handle, 0);
        assert_eq!(objects.reference_by_body(desktop_body), Some(2));
        let snapshot = GuiClientInfoSnapshot::capture(owner, owner, 0x1234, mapping(), None)
            .unwrap();

        for (identity, _) in &pins {
            assert_eq!(allocations.begin_retirement(*identity), Err(ProviderAllocationError::Pinned));
        }
        assert_eq!(objects.counts_by_body(desktop_body), Some((2, 1)));
        assert_eq!(snapshot.values_for(owner).unwrap().client_deskinfo, 0x4000_0100);

        // The synchronous component Reply acknowledges the root copyout before these owners go.
        for (_, pin) in pins.iter().rev() {
            allocations.release_pin(*pin).unwrap();
        }
        assert_eq!(objects.dereference_by_body(desktop_body), Some(1));
        for (identity, _) in pins {
            allocations.begin_retirement(identity).unwrap();
        }
    }
}
