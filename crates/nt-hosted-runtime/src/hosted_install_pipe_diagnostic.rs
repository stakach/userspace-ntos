//! Temporary, bounded observation of the umpnpmgr install-pipe exchange.
//! Keys label measurements only; the File and Process managers retain all authority.

const PIPE_NAME_CAP: usize = 96;
const DEVICE_UNIT_CAP: usize = 200;
const PIPE_PREFIX: &[u8] = b"PNP_Device_Install_Pipe_0.";
const EVENT_PREFIX: &[u8] = b"Global\\PNP_Device_Install_Event_0.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallPipeIdentity {
    pub owner_pid: u32,
    pub owner_generation: u64,
    /// Canonical FileId, including its packed generation.
    pub file_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallChildIdentity { pub pid: u32, pub generation: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallPipeObservation {
    pub pipe: InstallPipeIdentity,
    pub child: InstallChildIdentity,
    pub client_file_id: u64,
    pub device: [u16; DEVICE_UNIT_CAP],
    pub device_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallPipeTerminal {
    pub pipe: InstallPipeIdentity,
    pub child: InstallChildIdentity,
    pub client_file_id: u64,
    pub exit_status: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstallPipeCounts { pub published: u64, pub terminal: u64, pub rejected: u64, pub overflow: u64 }

#[derive(Clone, Copy)]
struct Slot {
    pipe: InstallPipeIdentity,
    name: [u16; PIPE_NAME_CAP],
    name_len: usize,
    child: Option<InstallChildIdentity>,
    client_file_id: u64,
    step: u8,
    expected_bytes: usize,
    staged: Option<(u64, usize, [u8; DEVICE_UNIT_CAP * 2])>,
    observation: Option<InstallPipeObservation>,
}

pub struct InstallPipeDiagnostic<const N: usize> {
    slots: [Option<Slot>; N],
    counts: InstallPipeCounts,
}

fn valid_ascii_name(name: &[u16]) -> Option<usize> {
    let end = name.iter().position(|unit| *unit == 0)?;
    (end + 1 == name.len() && end < PIPE_NAME_CAP
        && name[..end].iter().all(|unit| *unit > 0x20 && *unit < 0x7f)).then_some(end)
}

fn matches_prefix(name: &[u16], prefix: &[u8]) -> bool {
    name.len() >= prefix.len() && name.iter().zip(prefix).all(|(unit, byte)| *unit == u16::from(*byte))
}

pub fn is_install_pipe_name(name: &[u16]) -> bool {
    let name = name.strip_prefix(&[b'\\' as u16]).unwrap_or(name);
    matches_prefix(name, PIPE_PREFIX)
}

fn u32_payload(payload: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(payload.try_into().ok()?))
}

impl<const N: usize> InstallPipeDiagnostic<N> {
    pub const fn new() -> Self {
        Self { slots: [None; N], counts: InstallPipeCounts { published: 0, terminal: 0, rejected: 0, overflow: 0 } }
    }

    pub fn register_server(&mut self, pipe: InstallPipeIdentity, name: &[u16]) -> bool {
        let name = name.strip_prefix(&[b'\\' as u16]).unwrap_or(name);
        let Some(end) = valid_ascii_name(name) else { self.reject(); return false };
        if pipe.file_id == 0 || !is_install_pipe_name(name)
            || end <= PIPE_PREFIX.len() || self.slots.iter().flatten().any(|slot| slot.pipe == pipe)
        { self.reject(); return false; }
        let Some(target) = self.slots.iter_mut().find(|slot| slot.is_none()) else {
            self.counts.overflow = self.counts.overflow.saturating_add(1);
            return false;
        };
        let mut copied = [0u16; PIPE_NAME_CAP];
        copied[..name.len()].copy_from_slice(name);
        *target = Some(Slot { pipe, name: copied, name_len: name.len(), child: None,
            client_file_id: 0, step: 0, expected_bytes: 0, staged: None,
            observation: None });
        true
    }

    pub fn server_for_name(&self, name: &[u16]) -> Option<InstallPipeIdentity> {
        let name = name.strip_prefix(&[b'\\' as u16]).unwrap_or(name);
        self.slots.iter().flatten().find(|slot| slot.name_len == name.len()
            && &slot.name[..slot.name_len] == name).map(|slot| slot.pipe)
    }

    pub fn server_for_file(&self, owner_pid: u32, owner_generation: u64, file_id: u64)
        -> Option<InstallPipeIdentity> {
        self.slots.iter().flatten().find(|slot| slot.pipe.owner_pid == owner_pid
            && slot.pipe.owner_generation == owner_generation && slot.pipe.file_id == file_id)
            .map(|slot| slot.pipe)
    }

    pub fn child_is_tracked(&self, child: InstallChildIdentity) -> bool {
        self.slots.iter().flatten().any(|slot| slot.child == Some(child))
    }

    pub fn has_staged_write(&self, pipe: InstallPipeIdentity, irp_id: u64) -> bool {
        self.slots.iter().flatten().any(|slot| slot.pipe == pipe
            && slot.staged.is_some_and(|staged| staged.0 == irp_id))
    }

    pub fn attach_child(&mut self, pipe: InstallPipeIdentity, name: &[u16], child: InstallChildIdentity,
        client_file_id: u64) -> bool {
        let name = name.strip_prefix(&[b'\\' as u16]).unwrap_or(name);
        let Some(slot) = self.slots.iter_mut().flatten().find(|slot| slot.pipe == pipe) else {
            self.reject(); return false;
        };
        if child.pid == 0 || child.generation == 0 || client_file_id == 0
            || client_file_id == pipe.file_id || slot.child.is_some()
            || slot.name_len != name.len() || &slot.name[..slot.name_len] != name {
            self.reject(); return false;
        }
        slot.child = Some(child);
        slot.client_file_id = client_file_id;
        true
    }

    /// Snapshot only the already captured File input, under a canonical pending IrpId.
    /// The snapshot is discarded unless the exact terminal reports full successful transfer.
    pub fn stage_server_write(&mut self, pipe: InstallPipeIdentity, irp_id: u64, payload: &[u8]) -> bool {
        let Some(slot) = self.slots.iter_mut().flatten().find(|slot| slot.pipe == pipe) else {
            self.reject(); return false;
        };
        if irp_id == 0 || slot.staged.is_some() || payload.len() > DEVICE_UNIT_CAP * 2 {
            self.counts.rejected = self.counts.rejected.saturating_add(1);
            return false;
        }
        let mut copied = [0; DEVICE_UNIT_CAP * 2];
        copied[..payload.len()].copy_from_slice(payload);
        slot.staged = Some((irp_id, payload.len(), copied));
        true
    }

    pub fn complete_server_write(&mut self, pipe: InstallPipeIdentity, irp_id: u64,
        status: u32, information: u64) -> Option<InstallPipeObservation> {
        let Some(slot) = self.slots.iter_mut().flatten().find(|slot| slot.pipe == pipe) else {
            self.reject(); return None;
        };
        let Some((staged_id, len, copied)) = slot.staged else {
            self.reject(); return None;
        };
        if staged_id != irp_id {
            self.counts.rejected = self.counts.rejected.saturating_add(1);
            return None;
        }
        slot.staged = None;
        if status != 0 || information != len as u64 { return None; }
        self.record_server_write(pipe, &copied[..len])
    }

    /// Call only after NtWriteFile has completed successfully with the exact committed bytes.
    pub fn record_server_write(&mut self, pipe: InstallPipeIdentity, payload: &[u8])
        -> Option<InstallPipeObservation> {
        let Some(slot) = self.slots.iter_mut().flatten().find(|slot| slot.pipe == pipe) else {
            self.reject(); return None;
        };
        let valid = match slot.step {
            0 => u32_payload(payload).is_some_and(|len| {
                len >= 4 && len <= 2 * PIPE_NAME_CAP as u32 && len % 2 == 0
            }),
            1 => payload.len() == slot.expected_bytes && {
                let units = payload.chunks_exact(2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
                let event: [u16; PIPE_NAME_CAP] = {
                    let mut out = [0; PIPE_NAME_CAP];
                    for (index, unit) in units.enumerate() { out[index] = unit; }
                    out
                };
                let event_len = payload.len() / 2;
                let suffix = &slot.name[PIPE_PREFIX.len()..slot.name_len];
                matches_prefix(&event[..event_len], EVENT_PREFIX)
                    && event_len == EVENT_PREFIX.len() + suffix.len()
                    && &event[EVENT_PREFIX.len()..event_len] == suffix
            },
            2 => u32_payload(payload).is_some_and(|show| show <= 1),
            3 => u32_payload(payload).is_some_and(|len| {
                len >= 2 && len <= 2 * DEVICE_UNIT_CAP as u32 && len % 2 == 0
            }),
            4 => payload.len() == slot.expected_bytes && payload.len() % 2 == 0
                && payload.len() >= 2 && payload[payload.len() - 2..] == [0, 0],
            _ => false,
        };
        if !valid {
            self.counts.rejected = self.counts.rejected.saturating_add(1);
            return None;
        }
        if slot.step == 0 || slot.step == 3 {
            slot.expected_bytes = u32_payload(payload).unwrap_or(0) as usize;
        }
        slot.step += 1;
        if slot.step != 5 { return None; }
        let Some(child) = slot.child else {
            self.counts.rejected = self.counts.rejected.saturating_add(1);
            return None;
        };
        let mut device = [0u16; DEVICE_UNIT_CAP];
        let device_len = payload.len() / 2;
        for (index, bytes) in payload.chunks_exact(2).enumerate() {
            device[index] = u16::from_le_bytes([bytes[0], bytes[1]]);
        }
        let observation = InstallPipeObservation { pipe, child, client_file_id: slot.client_file_id,
            device, device_len };
        slot.observation = Some(observation);
        self.counts.published = self.counts.published.saturating_add(1);
        Some(observation)
    }

    pub fn record_child_terminal(&mut self, child: InstallChildIdentity, exit_status: u32)
        -> Option<InstallPipeTerminal> {
        let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_some_and(|slot| {
            slot.child == Some(child)
        })) else { self.reject(); return None; };
        let slot = slot.take()?;
        self.counts.terminal = self.counts.terminal.saturating_add(1);
        Some(InstallPipeTerminal { pipe: slot.pipe, child, client_file_id: slot.client_file_id,
            exit_status })
    }

    pub fn counts(&self) -> InstallPipeCounts { self.counts }

    fn reject(&mut self) { self.counts.rejected = self.counts.rejected.saturating_add(1); }
}

impl<const N: usize> Default for InstallPipeDiagnostic<N> {
    fn default() -> Self { Self::new() }
}
