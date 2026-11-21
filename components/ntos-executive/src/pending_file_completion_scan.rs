//! When one pending-File redrive pass polls providers for completions.
//!
//! A pass visits every retained pending File row. A provider marks an IRP complete in its own
//! memory, and that completion is visible to a row only after an I/O Manager pump has
//! published it. Lookups here read only published completions; the scan owns the pumps.
//!
//! The scan pumps once before the first row and once after the last. Pumping before every
//! lookup cost each idle long-pending row (pipe listen, input read) two full polls of every
//! provider on every pass. A completion published by the final pump may belong to a row
//! already visited, so `finish` reports it and the caller has this boundary redrive the pass.

pub(crate) struct CompletionScan<P: FnMut() -> usize> {
    pump: P,
}

impl<P: FnMut() -> usize> CompletionScan<P> {
    /// Start a pass. `pump` publishes ready provider completions and returns how many.
    pub(crate) fn begin(mut pump: P) -> Self {
        pump();
        Self { pump }
    }

    /// Look up one row's completion through `published`, which must not poll providers.
    pub(crate) fn lookup<T>(&mut self, published: impl FnOnce() -> Option<T>) -> Option<T> {
        published()
    }

    /// Whether one row's IRP is complete but its output copy must be retried.
    pub(crate) fn copy_requires_retry(&mut self, published: impl FnOnce() -> bool) -> bool {
        published()
    }

    /// End the pass. True when completions were published after rows were visited, so a row
    /// may have missed its terminal and the pass must be redriven.
    pub(crate) fn finish(mut self) -> bool {
        (self.pump)() != 0
    }
}
