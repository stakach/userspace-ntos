//! # `nt-wdf-request` — WDFREQUEST lifecycle + buffer retrieval
//!
//! A WDF request wraps one WDM IRP presented to a driver's I/O callback (spec: NT
//! KMDF/WDF Runtime, §16). This crate owns the host-testable logic: the
//! presented→completed state machine (a request completes exactly once, spec §16.3) and
//! the input/output buffer selection + minimum-length validation the driver drives via
//! `WdfRequestRetrieveInputBuffer` / `…OutputBuffer` (spec §16.4). Buffers are opaque
//! `(address, length)` pairs the Driver Host filled from the IRP. `no_std`, no allocation.

#![no_std]

/// NTSTATUS values a buffer-retrieval / completion path returns (WDK).
pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;

/// Where a request's data buffers live (from the IRP's transfer method).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RequestBuffers {
    /// Input buffer address + length (`AssociatedIrp.SystemBuffer` for a buffered IOCTL).
    pub input_ptr: u64,
    pub input_len: u64,
    /// Output buffer address + length.
    pub output_ptr: u64,
    pub output_len: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RequestState {
    Presented,
    Completed,
}

/// Why a request operation was rejected.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WdfRequestError {
    /// The request was already completed (spec §16.3 — complete exactly once).
    AlreadyCompleted,
}

/// A single WDF request in flight.
#[derive(Copy, Clone, Debug)]
pub struct WdfRequest {
    /// The underlying IRP (opaque to this crate).
    pub irp: u64,
    /// The IOCTL control code (`Parameters.DeviceIoControl.IoControlCode`).
    pub io_control_code: u32,
    buffers: RequestBuffers,
    state: RequestState,
    status: i32,
    information: u64,
}

impl WdfRequest {
    /// Wrap a freshly-presented request.
    pub fn new(irp: u64, io_control_code: u32, buffers: RequestBuffers) -> Self {
        Self {
            irp,
            io_control_code,
            buffers,
            state: RequestState::Presented,
            status: STATUS_SUCCESS,
            information: 0,
        }
    }

    pub fn is_completed(&self) -> bool {
        self.state == RequestState::Completed
    }

    /// `WdfRequestRetrieveInputBuffer(Request, MinimumRequiredLength, &Buffer, &Length)` —
    /// returns `(buffer, length)` or an NTSTATUS (spec §16.4). Rejects a null/short buffer.
    pub fn retrieve_input_buffer(&self, minimum_length: u64) -> Result<(u64, u64), i32> {
        Self::retrieve(
            self.buffers.input_ptr,
            self.buffers.input_len,
            minimum_length,
        )
    }

    /// `WdfRequestRetrieveOutputBuffer(Request, MinimumRequiredSize, &Buffer, &Length)`.
    pub fn retrieve_output_buffer(&self, minimum_length: u64) -> Result<(u64, u64), i32> {
        Self::retrieve(
            self.buffers.output_ptr,
            self.buffers.output_len,
            minimum_length,
        )
    }

    fn retrieve(ptr: u64, len: u64, minimum_length: u64) -> Result<(u64, u64), i32> {
        if ptr == 0 || len == 0 {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        if len < minimum_length {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        Ok((ptr, len))
    }

    /// `WdfRequestCompleteWithInformation(Request, Status, Information)` — record the
    /// completion status + bytes transferred. Rejects a second completion (spec §16.3).
    pub fn complete(&mut self, status: i32, information: u64) -> Result<(), WdfRequestError> {
        if self.state == RequestState::Completed {
            return Err(WdfRequestError::AlreadyCompleted);
        }
        self.state = RequestState::Completed;
        self.status = status;
        self.information = information;
        Ok(())
    }

    /// `WdfRequestComplete(Request, Status)` — completes with zero information.
    pub fn complete_status(&mut self, status: i32) -> Result<(), WdfRequestError> {
        self.complete(status, 0)
    }

    /// The recorded completion status (valid once completed).
    pub fn status(&self) -> i32 {
        self.status
    }
    /// The recorded `Information` (bytes transferred).
    pub fn information(&self) -> u64 {
        self.information
    }
    pub fn buffers(&self) -> RequestBuffers {
        self.buffers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> WdfRequest {
        WdfRequest::new(
            0x1000,
            0x0022_2400,
            RequestBuffers {
                input_ptr: 0x5000,
                input_len: 16,
                output_ptr: 0x6000,
                output_len: 8,
            },
        )
    }

    #[test]
    fn retrieve_validates_length_and_null() {
        let r = req();
        assert_eq!(r.retrieve_input_buffer(16), Ok((0x5000, 16)));
        assert_eq!(r.retrieve_input_buffer(32), Err(STATUS_BUFFER_TOO_SMALL));
        assert_eq!(r.retrieve_output_buffer(4), Ok((0x6000, 8)));
        // A request with no output buffer.
        let empty = WdfRequest::new(
            0x1,
            0,
            RequestBuffers {
                input_ptr: 0,
                input_len: 0,
                output_ptr: 0,
                output_len: 0,
            },
        );
        assert_eq!(
            empty.retrieve_input_buffer(1),
            Err(STATUS_INVALID_DEVICE_REQUEST)
        );
    }

    #[test]
    fn complete_once_only() {
        let mut r = req();
        assert!(!r.is_completed());
        r.complete(STATUS_SUCCESS, 8).unwrap();
        assert!(r.is_completed());
        assert_eq!(r.status(), STATUS_SUCCESS);
        assert_eq!(r.information(), 8);
        assert_eq!(
            r.complete(STATUS_SUCCESS, 0),
            Err(WdfRequestError::AlreadyCompleted)
        );
    }
}
