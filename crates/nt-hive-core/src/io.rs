//! The `HiveIoProvider` abstraction + v0.1 backends + the `HiveManager` boot/mutate/flush
//! engine (spec §10, §13, §16).

use alloc::vec::Vec;

use crate::codec::{
    decode_image, encode_image, encode_log_record, replay_log, try_encode_image, HiveDecodeError,
    HiveEncodeError, HiveLogOp,
};
use crate::hive::{Hive, HiveKind};

/// Why a hive I/O operation failed (spec §10).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HiveIoError {
    /// The backend injected a fault / the medium is unavailable.
    Io,
    /// The provider cannot support this operation.
    NotSupported,
}

/// Why a manager checkpoint failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HiveFlushError {
    Io(HiveIoError),
    Encode(HiveEncodeError),
}

/// Why a manager boot failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HiveBootError {
    Io(HiveIoError),
    Decode(HiveDecodeError),
}

/// Which backend a provider is (spec §10.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HiveIoProviderKind {
    Memory,
    Fixture,
    FaultInjection,
    NtFile,
}

/// A provider's observable status (spec §10.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HiveIoStatus {
    pub image_present: bool,
    pub log_len: usize,
}

/// Backing store for a hive's primary image + log (spec §10.1). Mirrors the Configuration
/// Manager's `ConfigStore`, but for the hive image/log format.
pub trait HiveIoProvider {
    fn provider_kind(&self) -> HiveIoProviderKind;
    fn read_primary_image(&mut self) -> Result<Option<Vec<u8>>, HiveIoError>;
    fn write_primary_image_atomic(&mut self, bytes: &[u8]) -> Result<(), HiveIoError>;
    fn write_primary_image_atomic_owned(&mut self, bytes: Vec<u8>) -> Result<(), HiveIoError> {
        self.write_primary_image_atomic(&bytes)
    }
    fn read_log(&mut self) -> Result<Vec<u8>, HiveIoError>;
    fn append_log_record(&mut self, bytes: &[u8]) -> Result<(), HiveIoError>;
    fn truncate_log(&mut self) -> Result<(), HiveIoError>;
    fn flush_image(&mut self) -> Result<(), HiveIoError>;
    fn flush_log(&mut self) -> Result<(), HiveIoError>;
    fn get_status(&self) -> HiveIoStatus;
}

/// In-RAM image/log — unit tests + early seL4 boot before a filesystem exists (spec §10.3).
#[derive(Default)]
pub struct MemoryHiveIoProvider {
    image: Option<Vec<u8>>,
    log: Vec<u8>,
}

impl MemoryHiveIoProvider {
    pub fn new() -> Self {
        Self::default()
    }
    /// Preload a primary image (the fixture provider's `FreshOnly` boot, spec §10.4).
    pub fn with_image(image: Vec<u8>) -> Self {
        Self {
            image: Some(image),
            log: Vec::new(),
        }
    }
    /// Simulate power loss: keep the committed image + log bytes (a fresh manager re-reads them).
    pub fn crash(&mut self) {}
}

impl HiveIoProvider for MemoryHiveIoProvider {
    fn provider_kind(&self) -> HiveIoProviderKind {
        HiveIoProviderKind::Memory
    }
    fn read_primary_image(&mut self) -> Result<Option<Vec<u8>>, HiveIoError> {
        Ok(self.image.clone())
    }
    fn write_primary_image_atomic(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.image = Some(bytes.to_vec());
        Ok(())
    }
    fn write_primary_image_atomic_owned(&mut self, bytes: Vec<u8>) -> Result<(), HiveIoError> {
        self.image = Some(bytes);
        Ok(())
    }
    fn read_log(&mut self) -> Result<Vec<u8>, HiveIoError> {
        Ok(self.log.clone())
    }
    fn append_log_record(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.log.extend_from_slice(bytes);
        Ok(())
    }
    fn truncate_log(&mut self) -> Result<(), HiveIoError> {
        self.log.clear();
        Ok(())
    }
    fn flush_image(&mut self) -> Result<(), HiveIoError> {
        Ok(())
    }
    fn flush_log(&mut self) -> Result<(), HiveIoError> {
        Ok(())
    }
    fn get_status(&self) -> HiveIoStatus {
        HiveIoStatus {
            image_present: self.image.is_some(),
            log_len: self.log.len(),
        }
    }
}

/// Fault injection for crash tests (spec §10.2, §18). Fails the Nth primary-image write; a
/// failed atomic write leaves the previous image intact (spec §18.1).
pub struct FaultInjectionHiveIoProvider {
    inner: MemoryHiveIoProvider,
    fail_image_write_after: Option<u32>,
    image_writes: u32,
}

impl FaultInjectionHiveIoProvider {
    pub fn new() -> Self {
        Self {
            inner: MemoryHiveIoProvider::new(),
            fail_image_write_after: None,
            image_writes: 0,
        }
    }
    pub fn fail_image_write_after(mut self, n: u32) -> Self {
        self.fail_image_write_after = Some(n);
        self
    }
}

impl Default for FaultInjectionHiveIoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HiveIoProvider for FaultInjectionHiveIoProvider {
    fn provider_kind(&self) -> HiveIoProviderKind {
        HiveIoProviderKind::FaultInjection
    }
    fn read_primary_image(&mut self) -> Result<Option<Vec<u8>>, HiveIoError> {
        self.inner.read_primary_image()
    }
    fn write_primary_image_atomic(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.image_writes += 1;
        if Some(self.image_writes) == self.fail_image_write_after {
            return Err(HiveIoError::Io); // previous image left intact
        }
        self.inner.write_primary_image_atomic(bytes)
    }
    fn write_primary_image_atomic_owned(&mut self, bytes: Vec<u8>) -> Result<(), HiveIoError> {
        self.image_writes += 1;
        if Some(self.image_writes) == self.fail_image_write_after {
            return Err(HiveIoError::Io); // previous image left intact
        }
        self.inner.write_primary_image_atomic_owned(bytes)
    }
    fn read_log(&mut self) -> Result<Vec<u8>, HiveIoError> {
        self.inner.read_log()
    }
    fn append_log_record(&mut self, bytes: &[u8]) -> Result<(), HiveIoError> {
        self.inner.append_log_record(bytes)
    }
    fn truncate_log(&mut self) -> Result<(), HiveIoError> {
        self.inner.truncate_log()
    }
    fn flush_image(&mut self) -> Result<(), HiveIoError> {
        self.inner.flush_image()
    }
    fn flush_log(&mut self) -> Result<(), HiveIoError> {
        self.inner.flush_log()
    }
    fn get_status(&self) -> HiveIoStatus {
        self.inner.get_status()
    }
}

/// Flush policy (spec §13.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FlushMode {
    /// Flush the log on every mutation (correctness default).
    Strict,
    /// Explicit flush only.
    Lazy,
}

/// The boot / mutate / flush engine over a [`HiveIoProvider`] (spec §13, §16).
pub struct HiveManager<P: HiveIoProvider> {
    provider: P,
    next_log_sequence: u64,
    flush_mode: FlushMode,
}

impl<P: HiveIoProvider> HiveManager<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            next_log_sequence: 1,
            flush_mode: FlushMode::Strict,
        }
    }
    pub fn for_live_hive(provider: P, hive: &Hive) -> Self {
        Self {
            provider,
            next_log_sequence: hive.sequence.saturating_add(1),
            flush_mode: FlushMode::Strict,
        }
    }
    pub fn with_flush_mode(mut self, mode: FlushMode) -> Self {
        self.flush_mode = mode;
        self
    }

    /// Boot a hive (spec §16): load + validate the primary image (or a fresh hive of `kind` if
    /// none), then replay the log after the image's sequence. Returns the mounted hive.
    pub fn boot(&mut self, kind: HiveKind) -> Result<Hive, HiveBootError> {
        let mut hive = match self
            .provider
            .read_primary_image()
            .map_err(HiveBootError::Io)?
        {
            Some(bytes) => decode_image(&bytes).map_err(HiveBootError::Decode)?,
            None => Hive::new(kind),
        };
        let base = hive.sequence;
        let log = self.provider.read_log().map_err(HiveBootError::Io)?;
        let last = replay_log(&mut hive, &log, base);
        self.next_log_sequence = last + 1;
        hive.clear_dirty();
        Ok(hive)
    }

    /// Journal + apply one mutation (spec §13.2): append the log record (flushed in Strict mode),
    /// then apply it to `hive`. On an I/O fault the mutation is not applied.
    pub fn mutate(&mut self, hive: &mut Hive, op: HiveLogOp) -> Result<(), HiveIoError> {
        let seq = self.next_log_sequence;
        let rec = encode_log_record(&op, seq);
        self.provider.append_log_record(&rec)?;
        if self.flush_mode == FlushMode::Strict {
            self.provider.flush_log()?;
        }
        replay_log(hive, &rec, seq - 1);
        self.next_log_sequence += 1;
        Ok(())
    }

    /// Journal one mutation, then let the caller apply an equivalent live mutation.
    ///
    /// This keeps the durable record in the canonical replay format while allowing live hives to
    /// use richer in-memory operations, such as sharing an already-owned value payload during a
    /// subtree copy. If the live fast path declines the mutation, the journal record is replayed so
    /// the caller still observes the logged state.
    pub fn mutate_with_live_apply<F>(
        &mut self,
        hive: &mut Hive,
        op: HiveLogOp,
        apply: F,
    ) -> Result<(), HiveIoError>
    where
        F: FnOnce(&mut Hive) -> bool,
    {
        let seq = self.next_log_sequence;
        let rec = encode_log_record(&op, seq);
        self.provider.append_log_record(&rec)?;
        if self.flush_mode == FlushMode::Strict {
            self.provider.flush_log()?;
        }
        if !apply(hive) {
            replay_log(hive, &rec, seq - 1);
        }
        self.next_log_sequence += 1;
        Ok(())
    }

    /// Checkpoint / lazy flush (spec §13.4): write a fresh image + truncate the log + clear the
    /// dirty set. Leaves the previous image intact on a write fault (spec §18.1).
    pub fn flush(&mut self, hive: &mut Hive) -> Result<(), HiveIoError> {
        let previous_generation = hive.generation;
        hive.generation = hive.generation.saturating_add(1);
        let bytes = encode_image(hive);
        if let Err(err) = self.provider.write_primary_image_atomic_owned(bytes) {
            hive.generation = previous_generation;
            return Err(err);
        }
        self.provider.flush_image()?;
        self.provider.truncate_log()?;
        self.provider.flush_log()?;
        hive.clear_dirty();
        self.next_log_sequence = hive.sequence + 1;
        Ok(())
    }

    /// Fallible checkpoint for kernel paths where allocation failure must return a status instead
    /// of panicking. I/O failures preserve the previous image and the current log, matching
    /// [`Self::flush`].
    pub fn try_flush(&mut self, hive: &mut Hive) -> Result<(), HiveFlushError> {
        let previous_generation = hive.generation;
        hive.generation = hive.generation.saturating_add(1);
        let bytes = match try_encode_image(hive) {
            Ok(bytes) => bytes,
            Err(err) => {
                hive.generation = previous_generation;
                return Err(HiveFlushError::Encode(err));
            }
        };
        if let Err(err) = self.provider.write_primary_image_atomic_owned(bytes) {
            hive.generation = previous_generation;
            return Err(HiveFlushError::Io(err));
        }
        self.provider.flush_image().map_err(HiveFlushError::Io)?;
        self.provider.truncate_log().map_err(HiveFlushError::Io)?;
        self.provider.flush_log().map_err(HiveFlushError::Io)?;
        hive.clear_dirty();
        self.next_log_sequence = hive.sequence + 1;
        Ok(())
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }
    pub fn into_provider(self) -> P {
        self.provider
    }
}
