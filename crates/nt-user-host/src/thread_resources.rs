//! Target geometry and physical ownership of a hosted thread's private memory.
use alloc::vec::Vec;

use crate::thread_rollback::{
    ThreadRollbackError, ThreadRollbackResource, ThreadRollbackResourceKind,
};

const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadMemoryRange {
    pub base: u64,
    pub size: u64,
}

impl ThreadMemoryRange {
    /// Overflowing requests are refused by the exclusion caller, never treated as disjoint.
    pub fn overlaps(self, base: u64, size: u64) -> bool {
        if size == 0 {
            return false;
        }
        let Some(end) = base.checked_add(size) else {
            return true;
        };
        let Some(own_end) = self.base.checked_add(self.size) else {
            return true;
        };
        self.size != 0 && base < own_end && self.base < end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadMemoryLayout {
    stack: ThreadMemoryRange,
    ipc: ThreadMemoryRange,
    teb: ThreadMemoryRange,
    trampoline: ThreadMemoryRange,
}

impl ThreadMemoryLayout {
    /// TEB memory includes both TEB pages and its private activation-context-stack page.
    pub const fn new(
        stack_base: u64,
        stack_frames: u64,
        ipc_base: u64,
        teb_base: u64,
        trampoline_base: u64,
    ) -> Option<Self> {
        let stack_size = match stack_frames.checked_mul(PAGE_SIZE) {
            Some(size) if size != 0 => size,
            _ => return None,
        };
        let ranges = [
            ThreadMemoryRange {
                base: stack_base,
                size: stack_size,
            },
            ThreadMemoryRange {
                base: ipc_base,
                size: PAGE_SIZE,
            },
            ThreadMemoryRange {
                base: teb_base,
                size: 3 * PAGE_SIZE,
            },
            ThreadMemoryRange {
                base: trampoline_base,
                size: PAGE_SIZE,
            },
        ];
        let mut i = 0;
        while i < ranges.len() {
            let a = ranges[i];
            if a.base == 0 || a.base % PAGE_SIZE != 0 || a.base.checked_add(a.size).is_none() {
                return None;
            }
            let mut j = 0;
            while j < i {
                let b = ranges[j];
                if a.base < b.base + b.size && b.base < a.base + a.size {
                    return None;
                }
                j += 1;
            }
            i += 1;
        }
        Some(Self {
            stack: ranges[0],
            ipc: ranges[1],
            teb: ranges[2],
            trampoline: ranges[3],
        })
    }

    pub const fn stack(self) -> ThreadMemoryRange {
        self.stack
    }
    pub const fn teb(self) -> ThreadMemoryRange {
        self.teb
    }
    pub const fn ipc(self) -> ThreadMemoryRange {
        self.ipc
    }
    pub const fn trampoline(self) -> ThreadMemoryRange {
        self.trampoline
    }

    pub const fn ranges(self) -> [ThreadMemoryRange; 4] {
        [self.stack, self.ipc, self.teb, self.trampoline]
    }

    pub fn overlaps(self, base: u64, size: u64) -> bool {
        self.ranges().iter().any(|range| range.overlaps(base, size))
    }
}

/// Copyable construction/runtime description, not the non-cloneable rollback owner. Capturing an
/// inventory does not transfer ownership or release anything. Only the runtime adapter can transfer
/// it, after retaining reservations, publishing access exclusions, and reconciling registry aliases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadMemoryResources<const STACK: usize> {
    layout: Option<ThreadMemoryLayout>,
    pub client_pi: usize,
    pub stack_owner: [u64; STACK],
    pub stack_target: [u64; STACK],
    pub stack_mirror: [u64; STACK],
    pub teb_owner: u64,
    pub teb_target: u64,
    pub teb_scratch: u64,
    pub teb2_owner: u64,
    pub teb2_target: u64,
    pub teb2_scratch: u64,
    pub acs_owner: u64,
    pub acs_target: u64,
    /// Directly allocated physical backing, mapped into the target, not a copied target alias.
    pub ipc_owner: u64,
    pub tramp_owner: u64,
    pub tramp_target: u64,
}

impl<const STACK: usize> ThreadMemoryResources<STACK> {
    pub const fn empty() -> Self {
        Self {
            layout: None,
            client_pi: 0,
            stack_owner: [0; STACK],
            stack_target: [0; STACK],
            stack_mirror: [0; STACK],
            teb_owner: 0,
            teb_target: 0,
            teb_scratch: 0,
            teb2_owner: 0,
            teb2_target: 0,
            teb2_scratch: 0,
            acs_owner: 0,
            acs_target: 0,
            ipc_owner: 0,
            tramp_owner: 0,
            tramp_target: 0,
        }
    }

    pub const fn new(client_pi: usize, layout: ThreadMemoryLayout) -> Option<Self> {
        if layout.stack.size / PAGE_SIZE > STACK as u64 {
            return None;
        }
        let mut result = Self::empty();
        result.layout = Some(layout);
        result.client_pi = client_pi;
        Some(result)
    }

    pub const fn is_live(&self) -> bool {
        self.layout.is_some()
    }
    pub const fn layout(&self) -> Option<ThreadMemoryLayout> {
        self.layout
    }
    pub const fn stack_base(&self) -> u64 {
        match self.layout {
            Some(layout) => layout.stack.base,
            None => 0,
        }
    }
    pub const fn stack_frames(&self) -> u64 {
        match self.layout {
            Some(layout) => layout.stack.size / PAGE_SIZE,
            None => 0,
        }
    }
    pub const fn teb_va(&self) -> u64 {
        match self.layout {
            Some(layout) => layout.teb.base,
            None => 0,
        }
    }

    /// One physical owner per private page; copied target/mirror caps are aliases. Includes absent
    /// construction slots as zero, then validates and removes them. Registry and mechanism caps are
    /// intentionally not inferred: the native adapter must capture those additional owners exactly.
    pub fn rollback_resources(&self) -> Result<Vec<ThreadRollbackResource>, ThreadRollbackError> {
        let mut result = Vec::new();
        let capacity = STACK
            .checked_mul(3)
            .and_then(|n| n.checked_add(11))
            .ok_or(ThreadRollbackError::InsufficientResources)?;
        result
            .try_reserve(capacity)
            .map_err(|_| ThreadRollbackError::InsufficientResources)?;
        for index in 0..STACK {
            let owner = self.stack_owner[index];
            let aliases = [self.stack_target[index], self.stack_mirror[index]];
            if index >= self.stack_frames() as usize && (owner != 0 || aliases != [0, 0]) {
                return Err(ThreadRollbackError::InvalidIdentity);
            }
            append_frame(&mut result, owner, &aliases)?;
        }
        for (owner, aliases) in [
            (self.teb_owner, [self.teb_target, self.teb_scratch]),
            (self.teb2_owner, [self.teb2_target, self.teb2_scratch]),
            (self.acs_owner, [self.acs_target, 0]),
            (self.ipc_owner, [0, 0]),
            (self.tramp_owner, [self.tramp_target, 0]),
        ] {
            append_frame(&mut result, owner, &aliases)?;
        }
        if !self.is_live() && !result.is_empty() {
            return Err(ThreadRollbackError::InvalidIdentity);
        }
        Ok(result)
    }
}

fn append_frame(
    result: &mut Vec<ThreadRollbackResource>,
    owner: u64,
    aliases: &[u64],
) -> Result<(), ThreadRollbackError> {
    use ThreadRollbackResourceKind::{Alias, Frame};
    if owner == 0 {
        return if aliases.iter().all(|&cap| cap == 0) {
            Ok(())
        } else {
            Err(ThreadRollbackError::ConflictingOwnership)
        };
    }
    if result.iter().any(|entry| entry.cap == owner) {
        return Err(ThreadRollbackError::ConflictingOwnership);
    }
    result.push(ThreadRollbackResource {
        cap: owner,
        kind: Frame,
    });
    let first_alias = result.len();
    for &cap in aliases {
        if cap == 0 || cap == owner || result[first_alias..].iter().any(|entry| entry.cap == cap) {
            continue;
        }
        if result[..first_alias].iter().any(|entry| entry.cap == cap) {
            return Err(ThreadRollbackError::ConflictingOwnership);
        }
        result.push(ThreadRollbackResource { cap, kind: Alias });
    }
    Ok(())
}

#[cfg(test)]
#[path = "thread_resources_tests.rs"]
mod tests;
