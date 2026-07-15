#![no_std]

pub const NO_REGISTRY_SLOT: u8 = u8::MAX;
pub const PATH_CAP: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LoaderOp {
    QueryAttributesFile = 0,
    OpenFile = 1,
    CreateSection = 2,
    MapViewOfSection = 3,
    ProtectVirtualMemory = 4,
    FlushInstructionCache = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoaderEvent {
    pub op: LoaderOp,
    pub registry_slot: u8,
    pub path_len: u8,
    pub status: u32,
    pub repetitions: u32,
    pub input: u64,
    pub output: u64,
    path: [u8; PATH_CAP],
}

impl LoaderEvent {
    const EMPTY: Self = Self {
        op: LoaderOp::QueryAttributesFile,
        registry_slot: 0,
        path_len: 0,
        status: 0,
        repetitions: 0,
        input: 0,
        output: 0,
        path: [0; PATH_CAP],
    };

    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }

    fn new(
        op: LoaderOp,
        status: u32,
        registry_slot: u8,
        input: u64,
        output: u64,
        path: &[u8],
    ) -> Self {
        let mut event = Self {
            op,
            registry_slot,
            path_len: path.len().min(PATH_CAP) as u8,
            status,
            repetitions: 1,
            input,
            output,
            path: [0; PATH_CAP],
        };
        let tail = &path[path.len().saturating_sub(PATH_CAP)..];
        event.path_len = tail.len() as u8;
        for (dst, src) in event.path.iter_mut().zip(tail.iter()) {
            *dst = src.to_ascii_lowercase();
        }
        event
    }

    fn same_transition(&self, other: &Self) -> bool {
        self.op == other.op
            && self.registry_slot == other.registry_slot
            && self.status == other.status
            && self.input == other.input
            && self.output == other.output
            && self.path() == other.path()
    }
}

pub struct LoaderTrace<const N: usize> {
    entries: [LoaderEvent; N],
    write: usize,
    len: usize,
    omitted: u64,
    first_failure: LoaderEvent,
    has_first_failure: bool,
}

impl<const N: usize> LoaderTrace<N> {
    pub const fn new() -> Self {
        Self {
            entries: [LoaderEvent::EMPTY; N],
            write: 0,
            len: 0,
            omitted: 0,
            first_failure: LoaderEvent::EMPTY,
            has_first_failure: false,
        }
    }

    pub fn clear(&mut self) {
        self.write = 0;
        self.len = 0;
        self.omitted = 0;
        self.has_first_failure = false;
    }

    pub fn record(
        &mut self,
        op: LoaderOp,
        status: u32,
        registry_slot: u8,
        input: u64,
        output: u64,
        path: &[u8],
    ) {
        if N == 0 {
            self.omitted = self.omitted.saturating_add(1);
            return;
        }
        let event = LoaderEvent::new(op, status, registry_slot, input, output, path);
        if status != 0 && !self.has_first_failure {
            self.first_failure = event;
            self.has_first_failure = true;
        }
        if self.len != 0 {
            let previous = (self.write + N - 1) % N;
            if self.entries[previous].same_transition(&event) {
                self.entries[previous].repetitions =
                    self.entries[previous].repetitions.saturating_add(1);
                return;
            }
        }
        if self.len == N {
            self.omitted = self.omitted.saturating_add(1);
        } else {
            self.len += 1;
        }
        self.entries[self.write] = event;
        self.write = (self.write + 1) % N;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn omitted(&self) -> u64 {
        self.omitted
    }

    pub fn first_failure(&self) -> Option<&LoaderEvent> {
        self.has_first_failure.then_some(&self.first_failure)
    }

    pub fn get(&self, chronological_index: usize) -> Option<&LoaderEvent> {
        if chronological_index >= self.len || N == 0 {
            return None;
        }
        let oldest = if self.len == N { self.write } else { 0 };
        Some(&self.entries[(oldest + chronological_index) % N])
    }
}

impl<const N: usize> Default for LoaderTrace<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_bounded_tail_in_chronological_order() {
        let mut trace = LoaderTrace::<3>::new();
        for handle in 1..=5 {
            trace.record(LoaderOp::OpenFile, 0, 2, handle, handle + 10, b"SFC.DLL");
        }
        assert_eq!(trace.len(), 3);
        assert_eq!(trace.omitted(), 2);
        assert_eq!(trace.get(0).unwrap().input, 3);
        assert_eq!(trace.get(2).unwrap().input, 5);
    }

    #[test]
    fn folds_only_consecutive_identical_transitions() {
        let mut trace = LoaderTrace::<4>::new();
        trace.record(LoaderOp::QueryAttributesFile, 0, 1, 0, 0, b"SFC.DLL");
        trace.record(LoaderOp::QueryAttributesFile, 0, 1, 0, 0, b"sfc.dll");
        trace.record(LoaderOp::OpenFile, 0, 1, 4, 8, b"sfc.dll");
        trace.record(LoaderOp::QueryAttributesFile, 0, 1, 0, 0, b"sfc.dll");
        assert_eq!(trace.len(), 3);
        assert_eq!(trace.get(0).unwrap().repetitions, 2);
        assert_eq!(trace.get(2).unwrap().repetitions, 1);
    }

    #[test]
    fn stores_folded_path_tail_without_allocation() {
        let mut trace = LoaderTrace::<1>::new();
        trace.record(
            LoaderOp::OpenFile,
            0xc000_0034,
            NO_REGISTRY_SLOT,
            0,
            0,
            b"\\SystemRoot\\System32\\A-Very-Long-Prefix\\SFC_OS.DLL",
        );
        let event = trace.get(0).unwrap();
        assert!(event.path().ends_with(b"sfc_os.dll"));
        assert!(event.path().len() <= PATH_CAP);
        assert_eq!(event.status, 0xc000_0034);
    }

    #[test]
    fn clear_resets_metadata() {
        let mut trace = LoaderTrace::<1>::new();
        trace.record(LoaderOp::OpenFile, 0, 0, 1, 2, b"x.dll");
        trace.record(LoaderOp::CreateSection, 0, 0, 2, 3, b"");
        trace.clear();
        assert!(trace.is_empty());
        assert_eq!(trace.omitted(), 0);
        assert!(trace.first_failure().is_none());
    }

    #[test]
    fn first_failure_survives_tail_wraparound() {
        let mut trace = LoaderTrace::<2>::new();
        trace.record(
            LoaderOp::OpenFile,
            0xc000_0034,
            NO_REGISTRY_SLOT,
            0,
            0,
            b"first.dll",
        );
        for handle in 1..=4 {
            trace.record(LoaderOp::OpenFile, 0, 1, 0, handle, b"later.dll");
        }
        let failure = trace.first_failure().unwrap();
        assert_eq!(failure.status, 0xc000_0034);
        assert_eq!(failure.path(), b"first.dll");
    }
}
