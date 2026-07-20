#![no_std]

pub const CALLBACK_MAGIC: u32 = u32::from_le_bytes(*b"UCBK");
pub const CALLBACK_VERSION: u16 = 1;
pub const CALLBACK_KIND_USER_MODE: u16 = 1;
pub const CALLBACK_PAYLOAD_MAX: usize = 0xD80;
pub const CALLBACK_FRAME_SIZE: usize = core::mem::size_of::<CallbackFrame>();
pub const NO_PAYLOAD_REFERENCE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CallbackState {
    Idle = 0,
    Request = 1,
    Reply = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CallbackHeader {
    pub magic: u32,
    pub version: u16,
    pub kind: u16,
    pub state: u32,
    pub api_index: u32,
    pub input_length: u32,
    pub output_capacity: u32,
    pub output_length: u32,
    pub status: i32,
    pub client_pi: u32,
    pub callback_id: u32,
    /// Optional offset of an embedded buffer referenced by callback arguments. Component stubs
    /// scrub the original component-local pointer and describe the copied bytes by offset instead.
    pub payload_reference_offset: u32,
    pub dispatch_id: u64,
    pub client_tid: u64,
    pub client_badge: u64,
}

impl CallbackHeader {
    pub const fn idle(
        dispatch_id: u64,
        client_pi: u32,
        client_tid: u64,
        client_badge: u64,
    ) -> Self {
        Self {
            magic: CALLBACK_MAGIC,
            version: CALLBACK_VERSION,
            kind: CALLBACK_KIND_USER_MODE,
            state: CallbackState::Idle as u32,
            api_index: 0,
            input_length: 0,
            output_capacity: 0,
            output_length: 0,
            status: 0,
            client_pi,
            callback_id: 0,
            payload_reference_offset: NO_PAYLOAD_REFERENCE,
            dispatch_id,
            client_tid,
            client_badge,
        }
    }

    pub fn begin_request(
        &mut self,
        api_index: u32,
        input_length: usize,
        output_capacity: usize,
    ) -> Result<(), ValidationError> {
        validate_common(self)?;
        if self.state != CallbackState::Idle as u32 && self.state != CallbackState::Reply as u32 {
            return Err(ValidationError::State);
        }
        checked_payload_length(input_length)?;
        checked_payload_length(output_capacity)?;
        self.callback_id = self
            .callback_id
            .checked_add(1)
            .ok_or(ValidationError::Sequence)?;
        self.api_index = api_index;
        self.input_length = input_length as u32;
        self.output_capacity = output_capacity as u32;
        self.output_length = 0;
        self.payload_reference_offset = NO_PAYLOAD_REFERENCE;
        self.status = STATUS_PENDING;
        self.state = CallbackState::Request as u32;
        Ok(())
    }
}

#[repr(C, align(8))]
pub struct CallbackFrame {
    pub header: CallbackHeader,
    pub payload: [u8; CALLBACK_PAYLOAD_MAX],
}

impl CallbackFrame {
    pub const fn new() -> Self {
        Self {
            header: CallbackHeader::idle(0, 0, 0, 0),
            payload: [0; CALLBACK_PAYLOAD_MAX],
        }
    }
}

impl Default for CallbackFrame {
    fn default() -> Self {
        Self::new()
    }
}

pub const STATUS_PENDING: i32 = 0x0000_0103;

/// ReactOS `USER32_CALLBACK_CLIENTTHREADSTARTUP` / `apfnDispatch[7]`.
pub const USER32_CALLBACK_CLIENTTHREADSTARTUP: u32 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ControlledTransitionPhase {
    Idle = 0,
    ComponentSuspended = 1,
    ClientRedirected = 2,
    CallbackReturned = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlledTransitionEvent {
    SuspendComponent,
    RedirectClient,
    ReturnFromClient,
    ResumeComponent,
}

impl ControlledTransitionPhase {
    pub const fn advance(
        self,
        event: ControlledTransitionEvent,
    ) -> Result<Self, ValidationError> {
        match (self, event) {
            (Self::Idle, ControlledTransitionEvent::SuspendComponent) => {
                Ok(Self::ComponentSuspended)
            }
            (Self::ComponentSuspended, ControlledTransitionEvent::RedirectClient) => {
                Ok(Self::ClientRedirected)
            }
            (Self::ClientRedirected, ControlledTransitionEvent::ReturnFromClient) => {
                Ok(Self::CallbackReturned)
            }
            (Self::CallbackReturned, ControlledTransitionEvent::ResumeComponent) => Ok(Self::Idle),
            _ => Err(ValidationError::State),
        }
    }
}

/// Translate a seL4 x86-64 `UserContext` snapshot into the 18-word reply shape for an
/// `UnknownSyscall` fault. This completes the suspended outer syscall without copying the
/// callback's SSN-22 register frame over the original caller context.
pub const fn outer_syscall_reply(
    saved: &[u64; 20],
    result: u64,
    resume_ip: u64,
    resume_sp: u64,
    resume_flags: u64,
) -> [u64; 18] {
    [
        result, saved[4], saved[5], saved[6], saved[7], saved[8], saved[9], saved[10], saved[11],
        saved[12], saved[13], saved[14], saved[15], saved[16], saved[17], resume_ip, resume_sp,
        resume_flags,
    ]
}

/// The x64 `MACHINE_FRAME` tail of a ReactOS `UCALLOUT_FRAME`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct UserCallbackMachineFrame {
    pub rip: u64,
    pub seg_cs: u16,
    pub fill1: [u16; 3],
    pub eflags: u32,
    pub fill2: u32,
    pub rsp: u64,
    pub seg_ss: u16,
    pub fill3: [u16; 3],
}

/// Exact ReactOS AMD64 `UCALLOUT_FRAME` consumed by `KiUserCallbackDispatcher`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct UserCalloutFrame {
    pub home: [u64; 4],
    pub input: u64,
    pub input_length: u32,
    pub api_index: u32,
    pub machine_frame: UserCallbackMachineFrame,
}

impl UserCalloutFrame {
    /// Build the no-input Phase-2B callback frame for the real user32 client-thread-startup thunk.
    pub const fn client_thread_startup(prior_rip: u64, prior_rsp: u64, prior_eflags: u32) -> Self {
        Self {
            home: [0; 4],
            input: 0,
            input_length: 0,
            api_index: USER32_CALLBACK_CLIENTTHREADSTARTUP,
            machine_frame: UserCallbackMachineFrame {
                rip: prior_rip,
                seg_cs: 0x33,
                fill1: [0; 3],
                eflags: prior_eflags,
                fill2: 0,
                rsp: prior_rsp,
                seg_ss: 0x2b,
                fill3: [0; 3],
            },
        }
    }
}

/// Pointer-free identity which correlates the component request, redirected client, and SSN 22.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallbackCorrelation {
    pub dispatch_id: u64,
    pub callback_id: u32,
    pub client_pi: u32,
    pub client_tid: u64,
    pub client_badge: u64,
}

impl CallbackCorrelation {
    pub const fn from_request(request: &CallbackHeader) -> Self {
        Self {
            dispatch_id: request.dispatch_id,
            callback_id: request.callback_id,
            client_pi: request.client_pi,
            client_tid: request.client_tid,
            client_badge: request.client_badge,
        }
    }

    pub const fn matches_client(&self, client_pi: u32, client_tid: u64, client_badge: u64) -> bool {
        self.client_pi == client_pi
            && self.client_tid == client_tid
            && self.client_badge == client_badge
    }

    pub const fn matches_request(&self, request: &CallbackHeader) -> bool {
        self.dispatch_id == request.dispatch_id
            && self.callback_id == request.callback_id
            && self.matches_client(request.client_pi, request.client_tid, request.client_badge)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    Magic,
    Version,
    Kind,
    State,
    Length,
    OutputLength,
    Sequence,
    Correlation,
}

pub fn checked_payload_range(length: usize) -> Result<core::ops::Range<usize>, ValidationError> {
    checked_payload_length(length)?;
    let start = core::mem::size_of::<CallbackHeader>();
    let end = start.checked_add(length).ok_or(ValidationError::Length)?;
    if end > CALLBACK_FRAME_SIZE {
        return Err(ValidationError::Length);
    }
    Ok(start..end)
}

pub fn validate_request(header: &CallbackHeader) -> Result<(), ValidationError> {
    validate_common(header)?;
    if header.state != CallbackState::Request as u32 {
        return Err(ValidationError::State);
    }
    if header.dispatch_id == 0 || header.callback_id == 0 {
        return Err(ValidationError::Sequence);
    }
    checked_payload_length(header.input_length as usize)?;
    checked_payload_length(header.output_capacity as usize)?;
    if header.payload_reference_offset != NO_PAYLOAD_REFERENCE {
        let offset = header.payload_reference_offset as usize;
        let end = offset.checked_add(8).ok_or(ValidationError::Length)?;
        if end > header.input_length as usize {
            return Err(ValidationError::Length);
        }
    }
    if header.output_length != 0 {
        return Err(ValidationError::OutputLength);
    }
    Ok(())
}

pub fn validate_reply(
    request: &CallbackHeader,
    reply: &CallbackHeader,
) -> Result<(), ValidationError> {
    validate_request(request)?;
    validate_common(reply)?;
    if reply.state != CallbackState::Reply as u32 {
        return Err(ValidationError::State);
    }
    if reply.dispatch_id != request.dispatch_id
        || reply.callback_id != request.callback_id
        || reply.client_pi != request.client_pi
        || reply.client_tid != request.client_tid
        || reply.client_badge != request.client_badge
        || reply.api_index != request.api_index
        || reply.input_length != request.input_length
        || reply.output_capacity != request.output_capacity
        || reply.payload_reference_offset != request.payload_reference_offset
    {
        return Err(ValidationError::Correlation);
    }
    checked_payload_length(reply.output_length as usize)?;
    if reply.output_length > reply.output_capacity {
        return Err(ValidationError::OutputLength);
    }
    Ok(())
}

fn validate_common(header: &CallbackHeader) -> Result<(), ValidationError> {
    if header.magic != CALLBACK_MAGIC {
        return Err(ValidationError::Magic);
    }
    if header.version != CALLBACK_VERSION {
        return Err(ValidationError::Version);
    }
    if header.kind != CALLBACK_KIND_USER_MODE {
        return Err(ValidationError::Kind);
    }
    Ok(())
}

fn checked_payload_length(length: usize) -> Result<(), ValidationError> {
    if length > CALLBACK_PAYLOAD_MAX {
        Err(ValidationError::Length)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> CallbackHeader {
        let mut header = CallbackHeader::idle(7, 2, 44, 4);
        header.begin_request(0, 64, 80).unwrap();
        header
    }

    #[test]
    fn user_callout_frame_matches_reactos_amd64_layout() {
        assert_eq!(core::mem::size_of::<UserCallbackMachineFrame>(), 0x28);
        assert_eq!(core::mem::size_of::<UserCalloutFrame>(), 0x58);
        let frame = UserCalloutFrame::client_thread_startup(0x1111, 0x2222, 0x246);
        let base = core::ptr::addr_of!(frame) as usize;
        assert_eq!(core::ptr::addr_of!(frame.input) as usize - base, 0x20);
        assert_eq!(
            core::ptr::addr_of!(frame.input_length) as usize - base,
            0x28
        );
        assert_eq!(core::ptr::addr_of!(frame.api_index) as usize - base, 0x2c);
        assert_eq!(
            core::ptr::addr_of!(frame.machine_frame) as usize - base,
            0x30
        );
        assert_eq!(frame.api_index, USER32_CALLBACK_CLIENTTHREADSTARTUP);
        assert_eq!(frame.machine_frame.rip, 0x1111);
        assert_eq!(frame.machine_frame.rsp, 0x2222);
    }

    #[test]
    fn callback_correlation_rejects_stale_client_or_sequence() {
        let request = request();
        let correlation = CallbackCorrelation::from_request(&request);
        assert!(correlation.matches_request(&request));
        assert!(correlation.matches_client(2, 44, 4));
        assert!(!correlation.matches_client(2, 45, 4));
        let mut stale = request;
        stale.callback_id += 1;
        assert!(!correlation.matches_request(&stale));
    }

    #[test]
    fn layout_fits_reserved_shared_page_tail() {
        assert_eq!(core::mem::size_of::<CallbackHeader>(), 72);
        assert_eq!(CALLBACK_FRAME_SIZE, 0xDC8);
        assert!(0x200usize.checked_add(CALLBACK_FRAME_SIZE).unwrap() <= 0x1000);
    }

    #[test]
    fn request_validates_lengths_state_and_sequence() {
        let header = request();
        assert_eq!(validate_request(&header), Ok(()));

        let mut bad = header;
        bad.state = CallbackState::Idle as u32;
        assert_eq!(validate_request(&bad), Err(ValidationError::State));
        bad = header;
        bad.input_length = CALLBACK_PAYLOAD_MAX as u32 + 1;
        assert_eq!(validate_request(&bad), Err(ValidationError::Length));
        bad = header;
        bad.callback_id = 0;
        assert_eq!(validate_request(&bad), Err(ValidationError::Sequence));
        bad = header;
        bad.payload_reference_offset = 60;
        assert_eq!(validate_request(&bad), Err(ValidationError::Length));
    }

    #[test]
    fn reply_is_bounded_and_correlated() {
        let request = request();
        let mut reply = request;
        reply.state = CallbackState::Reply as u32;
        reply.output_length = 80;
        reply.status = 0;
        assert_eq!(validate_reply(&request, &reply), Ok(()));

        reply.output_length = 81;
        assert_eq!(
            validate_reply(&request, &reply),
            Err(ValidationError::OutputLength)
        );
        reply.output_length = 80;
        reply.client_tid += 1;
        assert_eq!(
            validate_reply(&request, &reply),
            Err(ValidationError::Correlation)
        );
    }

    #[test]
    fn payload_range_rejects_large_and_overflowing_lengths() {
        assert_eq!(
            checked_payload_range(CALLBACK_PAYLOAD_MAX).unwrap().end,
            CALLBACK_FRAME_SIZE
        );
        assert_eq!(
            checked_payload_range(CALLBACK_PAYLOAD_MAX + 1),
            Err(ValidationError::Length)
        );
        assert_eq!(
            checked_payload_range(usize::MAX),
            Err(ValidationError::Length)
        );
    }

    #[test]
    fn embedded_payload_reference_must_stay_inside_copied_input() {
        let mut header = CallbackHeader::idle(3, 2, 6, 4);
        header.begin_request(0, 128, 128).unwrap();
        header.payload_reference_offset = 0x40;
        assert_eq!(validate_request(&header), Ok(()));
        header.payload_reference_offset = 124;
        assert_eq!(validate_request(&header), Err(ValidationError::Length));
    }

    #[test]
    fn request_ids_advance_without_losing_dispatch_identity() {
        let mut header = CallbackHeader::idle(9, 2, 100, 4);
        header.begin_request(3, 8, 16).unwrap();
        assert_eq!((header.dispatch_id, header.callback_id), (9, 1));
        header.state = CallbackState::Reply as u32;
        header.begin_request(0, 64, 64).unwrap();
        assert_eq!((header.dispatch_id, header.callback_id), (9, 2));
    }

    #[test]
    fn controlled_transition_keeps_client_and_component_phases_distinct() {
        let phase = ControlledTransitionPhase::Idle
            .advance(ControlledTransitionEvent::SuspendComponent)
            .unwrap();
        assert_eq!(phase, ControlledTransitionPhase::ComponentSuspended);
        let phase = phase
            .advance(ControlledTransitionEvent::RedirectClient)
            .unwrap();
        assert_eq!(phase, ControlledTransitionPhase::ClientRedirected);
        let phase = phase
            .advance(ControlledTransitionEvent::ReturnFromClient)
            .unwrap();
        assert_eq!(phase, ControlledTransitionPhase::CallbackReturned);
        assert_eq!(
            phase
                .advance(ControlledTransitionEvent::ResumeComponent)
                .unwrap(),
            ControlledTransitionPhase::Idle
        );
    }

    #[test]
    fn controlled_transition_rejects_reply_cap_reuse() {
        let suspended = ControlledTransitionPhase::Idle
            .advance(ControlledTransitionEvent::SuspendComponent)
            .unwrap();
        assert_eq!(
            suspended.advance(ControlledTransitionEvent::ResumeComponent),
            Err(ValidationError::State)
        );
        assert_eq!(
            suspended.advance(ControlledTransitionEvent::SuspendComponent),
            Err(ValidationError::State)
        );
    }

    #[test]
    fn outer_syscall_reply_preserves_the_saved_context_layout() {
        let mut saved = [0u64; 20];
        let mut index = 0;
        while index < saved.len() {
            saved[index] = 0x1000 + index as u64;
            index += 1;
        }
        let reply = outer_syscall_reply(&saved, 0xfeed, 0xaaaa, 0xbbbb, 0x246);
        assert_eq!(reply[0], 0xfeed);
        assert_eq!(reply[1], saved[4]);
        assert_eq!(reply[3], saved[6]);
        assert_eq!(reply[9], saved[12]);
        assert_eq!(reply[11], saved[14]);
        assert_eq!(reply[14], saved[17]);
        assert_eq!(reply[15], 0xaaaa);
        assert_eq!(reply[16], 0xbbbb);
        assert_eq!(reply[17], 0x246);
    }
}
