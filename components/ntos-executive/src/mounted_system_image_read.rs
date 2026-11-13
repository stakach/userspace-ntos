//! Retained mounted File snapshots for system images.
//!
//! A caller keeps this owner through exact File completion and strict IRP acknowledgement.

use alloc::{string::String, vec::Vec};
use nt_io_manager::{
    CreateOptions, CreateParameters, DeviceId, ExternalDispatchResult, FileId,
    InformationParameters, IoParameters, ReadWriteParameters, ShareAccess,
};
use nt_memory_manager::{routed_image_read::RoutedImageRead, CompletedFileQuery};
use nt_types::{AccessMask, ClientId, UnicodeString};

use crate::{driver_launch, hosted_file_capture, installed_layout, mounted_volume};

const INVALID: u32 = 0xc000_000d;
const CANCELLED: u32 = 0xc000_0120;
const RESOURCES: u32 = 0xc000_009a;
const IO_ERROR: u32 = nt_memory_manager::routed_image_read::STATUS_IO_DEVICE_ERROR;
const CLIENT: ClientId = ClientId(driver_launch::IO_MANAGER_COMPONENT_ID);

pub(crate) struct MountedSystemImageSnapshot {
    pub path: Vec<u8>,
    pub bytes: Vec<u8>,
}

pub(crate) enum SnapshotStep {
    Progress,
    Wait,
    Ready(Result<MountedSystemImageSnapshot, u32>),
    Indeterminate,
}

enum Phase {
    Allocate,
    Create,
    CreatePending(u64),
    CreateAck(u64, u32, Option<u64>),
    Query,
    QueryPending(u64),
    QueryCopy(u64, [u8; 24], usize),
    QueryAck(u64, Result<u64, u32>),
    Reading,
    Closing(Result<Vec<u8>, u32>),
    CloseWait(Result<Vec<u8>, u32>),
    Done,
    Indeterminate,
}

#[must_use = "retain through terminal I/O and exact File cleanup"]
pub(crate) struct MountedSystemImageRead {
    name: String,
    path: Vec<u8>,
    drivers_path: bool,
    device: u64,
    driver: u64,
    file: Option<FileId>,
    capture: Option<hosted_file_capture::Capture>,
    read: Option<RoutedImageRead<u64, u64, hosted_file_capture::Capture>>,
    phase: Phase,
    cancelled: bool,
    cancel_sent: bool,
}

impl MountedSystemImageRead {
    pub(crate) fn new(name: &str) -> Result<Self, u32> {
        let name = nt_pe_loader::module_namespace::module_leaf(name).map_err(|_| INVALID)?;
        let path = make_path(&name, false)?;
        Ok(Self {
            name,
            path,
            drivers_path: false,
            device: 0,
            driver: 0,
            file: None,
            capture: None,
            read: None,
            phase: Phase::Allocate,
            cancelled: false,
            cancel_sent: false,
        })
    }

    pub(crate) unsafe fn request_cancel(&mut self) {
        self.cancelled = true;
    }

    fn exact(&self, completion: &driver_launch::HostedCompletedIrp, major: u8) -> bool {
        completion.client_id == driver_launch::IO_MANAGER_COMPONENT_ID
            && completion.driver_id == self.driver
            && completion.file_id == self.file.map(FileId::raw).unwrap_or(0)
            && completion.device_id == self.device
            && completion.completion_driver_id == self.driver
            && completion.completion_device_id == self.device
            && completion.requestor_tid == 0
            && completion.major == major
    }

    unsafe fn cancel_pending(&mut self, irp: u64) -> SnapshotStep {
        if !self.cancelled || self.cancel_sent {
            return SnapshotStep::Wait;
        }
        self.cancel_sent = true;
        if driver_launch::cancel_irp_if_pending(irp).is_err() {
            self.phase = Phase::Indeterminate;
            return SnapshotStep::Indeterminate;
        }
        SnapshotStep::Progress
    }

    fn close(&mut self, result: Result<Vec<u8>, u32>) -> SnapshotStep {
        self.capture.take();
        self.read = None;
        self.phase = Phase::Closing(result);
        SnapshotStep::Progress
    }

    fn created(&mut self, status: u32, context: Option<u64>) -> SnapshotStep {
        if status != 0 {
            return self.close(Err(status));
        }
        if context.is_none() {
            return self.close(Err(IO_ERROR));
        }
        let file = self.file.expect("created image File");
        match hosted_file_capture::capture(file.raw(), self.device, AccessMask::GENERIC_READ.bits())
        {
            Ok(capture) => {
                self.capture = Some(capture);
                self.phase = Phase::Query;
                SnapshotStep::Progress
            }
            Err(status) => self.close(Err(status)),
        }
    }

    fn read_ready(&mut self, extent: u64) -> SnapshotStep {
        if extent == 0 || u32::try_from(extent).is_err() {
            return self.close(Err(IO_ERROR));
        }
        let Some(capture) = self.capture.take() else {
            self.phase = Phase::Indeterminate;
            return SnapshotStep::Indeterminate;
        };
        match RoutedImageRead::new(
            self.device,
            extent,
            nt_memory_manager::routed_image_read::MAX_IMAGE_READ_WINDOW,
            capture,
        ) {
            Ok(read) => {
                self.read = Some(read);
                self.phase = Phase::Reading;
                SnapshotStep::Progress
            }
            Err(capture) => {
                self.capture = Some(capture);
                self.close(Err(RESOURCES))
            }
        }
    }

    fn queried(&mut self, status: u32, information: u64, bytes: &[u8]) -> SnapshotStep {
        if status != 0 {
            return self.close(Err(status));
        }
        let query = CompletedFileQuery {
            status,
            information,
            output: bytes,
        };
        match nt_memory_manager::routed_section_metadata::decode_standard_query(query) {
            Ok((extent, false)) => self.read_ready(extent),
            _ => self.close(Err(IO_ERROR)),
        }
    }

    pub(crate) unsafe fn advance(&mut self) -> SnapshotStep {
        let phase = core::mem::replace(&mut self.phase, Phase::Indeterminate);
        match phase {
            Phase::Allocate => {
                if self.cancelled {
                    self.phase = Phase::Done;
                    return SnapshotStep::Ready(Err(CANCELLED));
                }
                let Some(device) = mounted_volume::exec_volume_device() else {
                    self.phase = Phase::Done;
                    return SnapshotStep::Ready(Err(IO_ERROR));
                };
                let Some(driver) = driver_launch::io_manager_mut()
                    .device(DeviceId(device))
                    .map(|record| record.driver_id.raw())
                else {
                    self.phase = Phase::Done;
                    return SnapshotStep::Ready(Err(IO_ERROR));
                };
                let Ok(path) = core::str::from_utf8(&self.path) else {
                    self.phase = Phase::Done;
                    return SnapshotStep::Ready(Err(INVALID));
                };
                match driver_launch::io_manager_mut().allocate_external_file(
                    CLIENT,
                    DeviceId(device),
                    AccessMask::GENERIC_READ,
                    ShareAccess::READ,
                    CreateOptions::NON_DIRECTORY_FILE,
                    UnicodeString::from_str(path),
                ) {
                    Ok(file) => {
                        self.device = device;
                        self.driver = driver;
                        self.file = Some(file);
                        self.cancel_sent = false;
                        self.phase = Phase::Create;
                        SnapshotStep::Progress
                    }
                    Err(status) => {
                        self.phase = Phase::Done;
                        SnapshotStep::Ready(Err(status.raw() as u32))
                    }
                }
            }
            Phase::Create => {
                if self.cancelled {
                    return self.close(Err(CANCELLED));
                }
                let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
                    CLIENT,
                    DeviceId(self.device),
                    self.file,
                    0,
                    0,
                    nt_io_abi::major::IRP_MJ_CREATE,
                    IoParameters::Create(CreateParameters {
                        desired_access: AccessMask::GENERIC_READ,
                        share_access: ShareAccess::READ,
                        create_disposition: nt_fs::FILE_OPEN,
                        ..CreateParameters::default()
                    }),
                    0,
                    0,
                    &mut [],
                );
                match result {
                    Ok(ExternalDispatchResult::Completed {
                        status,
                        file_context,
                        ..
                    }) => self.created(status.raw() as u32, file_context),
                    Ok(ExternalDispatchResult::Pending { irp_id }) => {
                        self.phase = Phase::CreatePending(irp_id.raw());
                        SnapshotStep::Progress
                    }
                    Err(status) => self.close(Err(status.raw() as u32)),
                }
            }
            Phase::CreatePending(irp) => {
                let Some(completion) = driver_launch::completed_irp_exact(irp) else {
                    self.phase = Phase::CreatePending(irp);
                    return self.cancel_pending(irp);
                };
                if !self.exact(&completion, nt_io_abi::major::IRP_MJ_CREATE) {
                    self.phase = Phase::Indeterminate;
                    return SnapshotStep::Indeterminate;
                }
                self.phase = Phase::CreateAck(irp, completion.status, completion.file_context);
                SnapshotStep::Progress
            }
            Phase::CreateAck(irp, status, context) => {
                if driver_launch::acknowledge_completed_irp_strict(irp).is_err() {
                    self.phase = Phase::Indeterminate;
                    return SnapshotStep::Indeterminate;
                }
                if self.cancelled {
                    self.close(Err(CANCELLED))
                } else {
                    self.created(status, context)
                }
            }
            Phase::Query => {
                if self.cancelled {
                    return self.close(Err(CANCELLED));
                }
                let mut output = [0u8; 24];
                let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
                    CLIENT,
                    DeviceId(self.device),
                    self.file,
                    0,
                    0,
                    nt_io_abi::major::IRP_MJ_QUERY_INFORMATION,
                    IoParameters::QueryInformation(InformationParameters {
                        info_class: nt_fs::FILE_STANDARD_INFORMATION,
                        length: 24,
                    }),
                    0,
                    24,
                    &mut output,
                );
                match result {
                    Ok(ExternalDispatchResult::Completed {
                        status,
                        information,
                        ..
                    }) => self.queried(status.raw() as u32, information, &output),
                    Ok(ExternalDispatchResult::Pending { irp_id }) => {
                        self.phase = Phase::QueryPending(irp_id.raw());
                        SnapshotStep::Progress
                    }
                    Err(status) => self.close(Err(status.raw() as u32)),
                }
            }
            Phase::QueryPending(irp) => {
                let Some(completion) = driver_launch::completed_irp_exact(irp) else {
                    self.phase = Phase::QueryPending(irp);
                    return self.cancel_pending(irp);
                };
                if !self.exact(&completion, nt_io_abi::major::IRP_MJ_QUERY_INFORMATION) {
                    self.phase = Phase::Indeterminate;
                    return SnapshotStep::Indeterminate;
                }
                self.phase = if completion.status == 0 && completion.information == 24 {
                    Phase::QueryCopy(irp, [0; 24], 0)
                } else {
                    Phase::QueryAck(
                        irp,
                        Err(if completion.status == 0 {
                            IO_ERROR
                        } else {
                            completion.status
                        }),
                    )
                };
                SnapshotStep::Progress
            }
            Phase::QueryCopy(irp, mut bytes, copied) => {
                let copied_now = match driver_launch::copy_completed_irp_output_exact(
                    irp,
                    copied as u64,
                    &mut bytes[copied..],
                ) {
                    Ok(n) if n != 0 && n <= 24 - copied => n,
                    Ok(_) => {
                        self.phase = Phase::QueryAck(irp, Err(IO_ERROR));
                        return SnapshotStep::Progress;
                    }
                    Err(status) => {
                        self.phase = Phase::QueryAck(irp, Err(status));
                        return SnapshotStep::Progress;
                    }
                };
                let copied = copied + copied_now;
                self.phase = if copied == 24 {
                    let query = CompletedFileQuery {
                        status: 0,
                        information: 24,
                        output: &bytes,
                    };
                    let result =
                        nt_memory_manager::routed_section_metadata::decode_standard_query(query)
                            .and_then(
                                |(extent, directory)| {
                                    if directory {
                                        Err(IO_ERROR)
                                    } else {
                                        Ok(extent)
                                    }
                                },
                            );
                    Phase::QueryAck(irp, result)
                } else {
                    Phase::QueryCopy(irp, bytes, copied)
                };
                SnapshotStep::Progress
            }
            Phase::QueryAck(irp, result) => {
                if driver_launch::acknowledge_completed_irp_strict(irp).is_err() {
                    self.phase = Phase::Indeterminate;
                    return SnapshotStep::Indeterminate;
                }
                match result {
                    Ok(extent) if !self.cancelled => self.read_ready(extent),
                    Ok(_) => self.close(Err(CANCELLED)),
                    Err(status) => self.close(Err(status)),
                }
            }
            Phase::Reading => {
                self.phase = Phase::Reading;
                self.advance_read()
            }
            Phase::Closing(result) => self.start_close(result),
            Phase::CloseWait(result) => self.finish_close(result),
            Phase::Done => {
                self.phase = Phase::Done;
                SnapshotStep::Indeterminate
            }
            Phase::Indeterminate => {
                self.phase = Phase::Indeterminate;
                SnapshotStep::Indeterminate
            }
        }
    }

    unsafe fn advance_read(&mut self) -> SnapshotStep {
        if self
            .read
            .as_ref()
            .is_some_and(|read| read.terminal_result().is_some())
        {
            let read = self.read.take().expect("terminal routed image read");
            let (capture, result) = match read.into_terminal() {
                Ok(terminal) => terminal,
                Err(read) => {
                    self.read = Some(read);
                    self.phase = Phase::Indeterminate;
                    return SnapshotStep::Indeterminate;
                }
            };
            drop(capture);
            return self.close(if self.cancelled {
                Err(CANCELLED)
            } else {
                result
            });
        }
        if let Some((irp, offset, remaining)) =
            self.read.as_ref().and_then(RoutedImageRead::copy_position)
        {
            let mut output = Vec::new();
            if output.try_reserve_exact(remaining).is_err() {
                self.read.as_mut().unwrap().fail_copy(irp, RESOURCES);
                return SnapshotStep::Progress;
            }
            output.resize(remaining, 0);
            let copied = match driver_launch::copy_completed_irp_output_exact(
                irp,
                offset as u64,
                &mut output,
            ) {
                Ok(n) if n != 0 && n <= remaining => n,
                Ok(_) => {
                    assert!(self.read.as_mut().unwrap().fail_copy(irp, IO_ERROR));
                    return SnapshotStep::Progress;
                }
                Err(status) => {
                    assert!(self.read.as_mut().unwrap().fail_copy(irp, status));
                    return SnapshotStep::Progress;
                }
            };
            if !self
                .read
                .as_mut()
                .unwrap()
                .copy_fragment(irp, offset, &output[..copied])
            {
                self.read.as_mut().unwrap().quarantine();
                self.phase = Phase::Indeterminate;
                return SnapshotStep::Indeterminate;
            }
            return SnapshotStep::Progress;
        }
        if let Some(irp) = self
            .read
            .as_ref()
            .and_then(RoutedImageRead::acknowledgment_key)
        {
            if driver_launch::acknowledge_completed_irp_strict(irp).is_err() {
                self.read.as_mut().unwrap().quarantine();
                self.phase = Phase::Indeterminate;
                return SnapshotStep::Indeterminate;
            }
            if !self.read.as_mut().unwrap().acknowledge(irp) {
                self.phase = Phase::Indeterminate;
                return SnapshotStep::Indeterminate;
            }
            return SnapshotStep::Progress;
        }
        if let Some(irp) = self.read.as_ref().and_then(RoutedImageRead::pending_key) {
            let Some(completion) = driver_launch::completed_irp_exact(irp) else {
                return self.cancel_pending(irp);
            };
            if !self.exact(&completion, nt_io_abi::major::IRP_MJ_READ)
                || !self.read.as_mut().unwrap().terminal(
                    irp,
                    completion.status,
                    completion.information,
                )
            {
                self.read.as_mut().unwrap().quarantine();
                self.phase = Phase::Indeterminate;
                return SnapshotStep::Indeterminate;
            }
            return SnapshotStep::Progress;
        }
        if self.cancelled {
            let read = self.read.take().expect("cancelled routed image read");
            match read.abort_ready() {
                Ok(capture) => {
                    drop(capture);
                    return self.close(Err(CANCELLED));
                }
                Err(read) => {
                    self.read = Some(read);
                    return SnapshotStep::Wait;
                }
            }
        }
        let Some(window) = self.read.as_mut().and_then(RoutedImageRead::enter_window) else {
            self.phase = Phase::Indeterminate;
            return SnapshotStep::Indeterminate;
        };
        let mut output = Vec::new();
        if output.try_reserve_exact(window.length).is_err() {
            self.read.as_mut().unwrap().reject_entry(RESOURCES);
            return SnapshotStep::Progress;
        }
        output.resize(window.length, 0);
        let result = driver_launch::io_manager_mut().build_and_dispatch_external_to_device(
            CLIENT,
            DeviceId(self.device),
            self.file,
            0,
            0,
            nt_io_abi::major::IRP_MJ_READ,
            IoParameters::Read(ReadWriteParameters {
                length: window.length as u32,
                key: 0,
                offset: window.offset,
            }),
            0,
            window.length as u32,
            &mut output,
        );
        let read = self.read.as_mut().expect("entered routed image read");
        match result {
            Ok(ExternalDispatchResult::Completed {
                status,
                information,
                ..
            }) => {
                if read.complete_inline(status.raw() as u32, information, &output) {
                    SnapshotStep::Progress
                } else {
                    read.quarantine();
                    self.phase = Phase::Indeterminate;
                    SnapshotStep::Indeterminate
                }
            }
            Ok(ExternalDispatchResult::Pending { irp_id }) => {
                if read.bind_pending(irp_id.raw()) {
                    SnapshotStep::Progress
                } else {
                    read.quarantine();
                    self.phase = Phase::Indeterminate;
                    SnapshotStep::Indeterminate
                }
            }
            Err(status) => {
                if read.reject_entry(status.raw() as u32) {
                    SnapshotStep::Progress
                } else {
                    read.quarantine();
                    self.phase = Phase::Indeterminate;
                    SnapshotStep::Indeterminate
                }
            }
        }
    }

    unsafe fn start_close(&mut self, result: Result<Vec<u8>, u32>) -> SnapshotStep {
        let Some(file) = self.file else {
            self.phase = Phase::Indeterminate;
            return SnapshotStep::Indeterminate;
        };
        if driver_launch::io_manager_mut()
            .queue_external_file_release(CLIENT, file)
            .is_err()
        {
            self.phase = Phase::Indeterminate;
            return SnapshotStep::Indeterminate;
        }
        self.phase = Phase::CloseWait(result);
        SnapshotStep::Progress
    }

    unsafe fn finish_close(&mut self, result: Result<Vec<u8>, u32>) -> SnapshotStep {
        let progress = driver_launch::pump_hosted_file_lifecycle();
        if driver_launch::io_manager_mut()
            .file(self.file.expect("closing image File"))
            .is_some()
        {
            self.phase = Phase::CloseWait(result);
            return if progress == 0 {
                SnapshotStep::Wait
            } else {
                SnapshotStep::Progress
            };
        }
        self.file = None;
        if !self.cancelled
            && !self.drivers_path
            && result
                .as_ref()
                .err()
                .copied()
                .is_some_and(nt_pe_loader::system_image_load_plan::retry_driver_path)
        {
            self.drivers_path = true;
            self.path = match make_path(&self.name, true) {
                Ok(path) => path,
                Err(status) => {
                    self.phase = Phase::Done;
                    return SnapshotStep::Ready(Err(status));
                }
            };
            self.phase = Phase::Allocate;
            return SnapshotStep::Progress;
        }
        self.phase = Phase::Done;
        SnapshotStep::Ready(if self.cancelled {
            Err(CANCELLED)
        } else {
            result.map(|bytes| MountedSystemImageSnapshot {
                path: core::mem::take(&mut self.path),
                bytes,
            })
        })
    }
}

fn make_path(name: &str, drivers: bool) -> Result<Vec<u8>, u32> {
    let prefix = if drivers {
        installed_layout::DRIVERS_PREFIX
    } else {
        installed_layout::SYSTEM32_PREFIX
    };
    let mut path = Vec::new();
    path.try_reserve_exact(prefix.len().saturating_add(name.len()))
        .map_err(|_| RESOURCES)?;
    path.extend_from_slice(prefix);
    path.extend_from_slice(name.as_bytes());
    Ok(path)
}
