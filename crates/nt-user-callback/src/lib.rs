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
    /// Optional offset of an embedded buffer referenced by callback arguments. The transport
    /// boundary must scrub the original component-local pointer and describe the copied bytes by
    /// offset instead; the executive rebases that offset into the client-visible copy.
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
/// ReactOS `USER32_CALLBACK_WINDOWPROC` / `apfnDispatch[0]`.
pub const USER32_CALLBACK_WINDOWPROC: u32 = 0;
pub const NTUSER_SET_WINDOW_LONG_PTR_SSN: u64 = 0x1298;
pub const NTUSER_REGISTER_HOT_KEY_SSN: u64 = 0x126b;
pub const NTUSER_PEEK_MESSAGE_SSN: u64 = 0x1001;
pub const NTUSER_GET_MESSAGE_SSN: u64 = 0x1006;
pub const NTUSER_DISPATCH_MESSAGE_SSN: u64 = 0x1035;
pub const WM_PAINT: u32 = 0x000f;
pub const WLX_WM_SAS: u32 = 0x0659;
pub const WLX_SAS_TYPE_CTRL_ALT_DEL: u64 = 1;
pub const WC_DIALOG_ATOM: u64 = 0x8002;
pub const WINLOGON_STATE_LOGGED_OFF: u32 = 1;
pub const IDD_LOGON_CAPTION: [u16; 5] = [
    b'L' as u16,
    b'o' as u16,
    b'g' as u16,
    b'o' as u16,
    b'n' as u16,
];
pub const MAX_DIALOG_CAPTION_CODE_UNITS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LargeUnicodeStringDescriptor {
    pub length_bytes: u32,
    pub buffer: u64,
}

impl LargeUnicodeStringDescriptor {
    pub fn parse(raw: &[u8; 16]) -> Result<Self, ValidationError> {
        let length_bytes = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let maximum_and_ansi = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let maximum_length = maximum_and_ansi & 0x7fff_ffff;
        let buffer = u64::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        let max_bytes = (MAX_DIALOG_CAPTION_CODE_UNITS * 2) as u32;
        if maximum_and_ansi & 0x8000_0000 != 0
            || length_bytes & 1 != 0
            || length_bytes > max_bytes
            || maximum_length < length_bytes
            || (length_bytes != 0 && buffer == 0)
            || buffer.checked_add(length_bytes as u64).is_none()
        {
            return Err(ValidationError::Length);
        }
        Ok(Self {
            length_bytes,
            buffer,
        })
    }

    pub const fn code_units(self) -> usize {
        self.length_bytes as usize / 2
    }
}

pub fn decode_utf16le_bounded(
    bytes: &[u8],
    output: &mut [u16; MAX_DIALOG_CAPTION_CODE_UNITS],
) -> Result<usize, ValidationError> {
    if bytes.len() & 1 != 0 || bytes.len() / 2 > output.len() {
        return Err(ValidationError::Length);
    }
    let count = bytes.len() / 2;
    for index in 0..count {
        output[index] = u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    }
    Ok(count)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WinlogonDialogCorrelation {
    sas_session: u64,
    sas_hwnd: u64,
    sas_messages: u8,
    logged_off: bool,
    idd_logon_hwnd: u64,
}

impl WinlogonDialogCorrelation {
    pub const fn new() -> Self {
        Self {
            sas_session: 0,
            sas_hwnd: 0,
            sas_messages: 0,
            logged_off: false,
            idd_logon_hwnd: 0,
        }
    }

    pub fn latch_sas_window(&mut self, session: u64, hwnd: u64) -> Result<(), ValidationError> {
        if session == 0 || hwnd == 0 {
            return Err(ValidationError::Sequence);
        }
        if self.sas_session != 0 && (self.sas_session != session || self.sas_hwnd != hwnd) {
            return Err(ValidationError::Sequence);
        }
        self.sas_session = session;
        self.sas_hwnd = hwnd;
        Ok(())
    }

    pub fn observe_sas_message(
        &mut self,
        session: u64,
        hwnd: u64,
        message: u32,
        wparam: u64,
    ) -> Result<(), ValidationError> {
        if session != self.sas_session
            || hwnd != self.sas_hwnd
            || message != WLX_WM_SAS
            || wparam != WLX_SAS_TYPE_CTRL_ALT_DEL
            || self.sas_messages >= 2
            || (self.sas_messages == 1 && !self.logged_off)
        {
            return Err(ValidationError::Sequence);
        }
        self.sas_messages += 1;
        Ok(())
    }

    pub fn observe_logged_off(&mut self, session: u64, state: u32) -> Result<(), ValidationError> {
        if session != self.sas_session
            || self.sas_messages != 1
            || state != WINLOGON_STATE_LOGGED_OFF
        {
            return Err(ValidationError::Sequence);
        }
        self.logged_off = true;
        Ok(())
    }

    pub fn capture_idd_logon(
        &mut self,
        session: u64,
        hwnd: u64,
        class_atom: u64,
        caption: &[u16],
        top_level: bool,
        winlogon_key_advanced: bool,
    ) -> Result<(), ValidationError> {
        if session != self.sas_session
            || self.sas_messages != 2
            || !self.logged_off
            || hwnd == 0
            || hwnd == self.sas_hwnd
            || class_atom != WC_DIALOG_ATOM
            || caption != IDD_LOGON_CAPTION
            || !top_level
            || !winlogon_key_advanced
            || (self.idd_logon_hwnd != 0 && self.idd_logon_hwnd != hwnd)
        {
            return Err(ValidationError::Sequence);
        }
        self.idd_logon_hwnd = hwnd;
        Ok(())
    }

    pub const fn sas_session(self) -> u64 {
        self.sas_session
    }

    pub const fn sas_hwnd(self) -> u64 {
        self.sas_hwnd
    }

    pub const fn sas_messages(self) -> u8 {
        self.sas_messages
    }

    pub const fn logged_off(self) -> bool {
        self.logged_off
    }

    pub const fn idd_logon_hwnd(self) -> u64 {
        self.idd_logon_hwnd
    }

    pub const fn modal_ready(self) -> bool {
        self.logged_off && self.sas_messages == 2 && self.idd_logon_hwnd != 0
    }
}

impl Default for WinlogonDialogCorrelation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DialogModalPumpSequence {
    completed_steps: u8,
    paint_dispatches: u16,
    phase: u8,
    drained: bool,
}

impl DialogModalPumpSequence {
    pub const fn new() -> Self {
        Self {
            completed_steps: 0,
            paint_dispatches: 0,
            phase: 0,
            drained: false,
        }
    }

    pub const fn expected_ssn(self) -> Option<u64> {
        if self.drained {
            return None;
        }
        match self.phase {
            0 => Some(NTUSER_PEEK_MESSAGE_SSN),
            1 => Some(NTUSER_GET_MESSAGE_SSN),
            2 => Some(NTUSER_DISPATCH_MESSAGE_SSN),
            _ => None,
        }
    }

    pub fn complete(
        &mut self,
        ssn: u64,
        result: i32,
        message: Option<u32>,
    ) -> Result<(), ValidationError> {
        if self.expected_ssn() != Some(ssn) {
            return Err(ValidationError::Sequence);
        }
        match self.phase {
            0 if result == 0 && message.is_none() => {
                if self.paint_dispatches != 0 {
                    self.drained = true;
                } else {
                    self.phase = 1;
                }
            }
            0 | 1 if result == 1 && message == Some(WM_PAINT) => self.phase = 2,
            0 | 1 if result == 1 && message.is_some() => self.phase = 0,
            2 if message == Some(WM_PAINT) => {
                self.paint_dispatches = self
                    .paint_dispatches
                    .checked_add(1)
                    .ok_or(ValidationError::Sequence)?;
                self.phase = 0;
            }
            _ => return Err(ValidationError::Sequence),
        }
        self.completed_steps = match (self.paint_dispatches, self.phase) {
            (0, 0) => 0,
            (0, 1) => 1,
            (0, 2) => 2,
            _ => 3,
        };
        Ok(())
    }

    pub const fn is_complete(self) -> bool {
        self.paint_dispatches != 0
    }

    pub const fn completed_steps(self) -> u8 {
        self.completed_steps
    }

    pub const fn paint_dispatches(self) -> u16 {
        self.paint_dispatches
    }

    pub const fn is_drained(self) -> bool {
        self.drained
    }
}

impl Default for DialogModalPumpSequence {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SasWmCreateNestedSequence {
    set_window_long_ptr_seen: bool,
    register_hot_key_count: u8,
}

impl SasWmCreateNestedSequence {
    pub const fn new() -> Self {
        Self {
            set_window_long_ptr_seen: false,
            register_hot_key_count: 0,
        }
    }

    pub fn accept(&mut self, ssn: u64) -> Result<(), ValidationError> {
        if !self.set_window_long_ptr_seen {
            if ssn != NTUSER_SET_WINDOW_LONG_PTR_SSN {
                return Err(ValidationError::Sequence);
            }
            self.set_window_long_ptr_seen = true;
            return Ok(());
        }
        if ssn != NTUSER_REGISTER_HOT_KEY_SSN || self.register_hot_key_count == 4 {
            return Err(ValidationError::Sequence);
        }
        self.register_hot_key_count += 1;
        Ok(())
    }

    pub const fn can_complete(self) -> bool {
        self.set_window_long_ptr_seen && self.register_hot_key_count >= 1
    }

    pub const fn register_hot_key_count(self) -> u8 {
        self.register_hot_key_count
    }
}

impl Default for SasWmCreateNestedSequence {
    fn default() -> Self {
        Self::new()
    }
}

/// Hard bound for the alternating win32k-dispatch / user-callback continuation stack.
///
/// ReactOS callbacks are synchronous and may re-enter win32k, but an invalid client must not be
/// able to grow executive state without limit. Eight alternating frames permit four complete
/// dispatch/callback levels, which is deliberately more than the create-time SAS paths need.
pub const MAX_CONTINUATION_DEPTH: usize = 8;
pub const MAX_ACTIVE_CALLBACK_DEPTH: usize = MAX_CONTINUATION_DEPTH / 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientThreadIdentity {
    pub client_pi: u32,
    pub client_tid: u64,
    pub client_badge: u64,
}

impl ClientThreadIdentity {
    pub const fn new(client_pi: u32, client_tid: u64, client_badge: u64) -> Self {
        Self {
            client_pi,
            client_tid,
            client_badge,
        }
    }

    pub const fn matches_correlation(&self, correlation: &CallbackCorrelation) -> bool {
        self.client_pi == correlation.client_pi
            && self.client_tid == correlation.client_tid
            && self.client_badge == correlation.client_badge
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationKind {
    Win32kDispatch,
    UserCallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationState {
    Running,
    Suspended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuationFrame {
    pub kind: ContinuationKind,
    pub state: ContinuationState,
    pub client: ClientThreadIdentity,
    pub dispatch_id: u64,
    pub callback_id: u32,
}

impl ContinuationFrame {
    const fn dispatch(client: ClientThreadIdentity, dispatch_id: u64) -> Self {
        Self {
            kind: ContinuationKind::Win32kDispatch,
            state: ContinuationState::Running,
            client,
            dispatch_id,
            callback_id: 0,
        }
    }

    const fn callback(correlation: CallbackCorrelation) -> Self {
        Self {
            kind: ContinuationKind::UserCallback,
            state: ContinuationState::Running,
            client: ClientThreadIdentity::new(
                correlation.client_pi,
                correlation.client_tid,
                correlation.client_badge,
            ),
            dispatch_id: correlation.dispatch_id,
            callback_id: correlation.callback_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationError {
    Overflow,
    Underflow,
    Sequence,
    Kind,
    State,
    Client,
    Correlation,
}

/// Pointer-free, bounded model of one client thread's alternating continuation chain.
///
/// The expected order is `dispatch -> callback -> nested dispatch -> callback ...`. Pushing a child
/// suspends its parent; completing the child makes that exact parent runnable again. Correlation is
/// checked before mutation, so stale `NtCallbackReturn`s and cross-thread nested syscalls cannot pop
/// another client's continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuationStack<const DEPTH: usize = MAX_CONTINUATION_DEPTH> {
    frames: [Option<ContinuationFrame>; DEPTH],
    len: usize,
}

impl<const DEPTH: usize> ContinuationStack<DEPTH> {
    pub const fn new() -> Self {
        Self {
            frames: [None; DEPTH],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn top(&self) -> Option<&ContinuationFrame> {
        if self.len == 0 {
            None
        } else {
            self.frames[self.len - 1].as_ref()
        }
    }

    pub fn push_dispatch(
        &mut self,
        client: ClientThreadIdentity,
        dispatch_id: u64,
    ) -> Result<(), ContinuationError> {
        if dispatch_id == 0 {
            return Err(ContinuationError::Sequence);
        }
        if self.len == DEPTH {
            return Err(ContinuationError::Overflow);
        }
        if self.len != 0 {
            let parent = self.frames[self.len - 1]
                .as_mut()
                .ok_or(ContinuationError::Underflow)?;
            if parent.kind != ContinuationKind::UserCallback {
                return Err(ContinuationError::Kind);
            }
            if parent.state != ContinuationState::Running {
                return Err(ContinuationError::State);
            }
            if parent.client != client {
                return Err(ContinuationError::Client);
            }
            parent.state = ContinuationState::Suspended;
        }
        self.frames[self.len] = Some(ContinuationFrame::dispatch(client, dispatch_id));
        self.len += 1;
        Ok(())
    }

    pub fn push_callback(
        &mut self,
        correlation: CallbackCorrelation,
    ) -> Result<(), ContinuationError> {
        if correlation.dispatch_id == 0 || correlation.callback_id == 0 {
            return Err(ContinuationError::Sequence);
        }
        if self.len == DEPTH {
            return Err(ContinuationError::Overflow);
        }
        let parent = self
            .frames
            .get_mut(
                self.len
                    .checked_sub(1)
                    .ok_or(ContinuationError::Underflow)?,
            )
            .and_then(Option::as_mut)
            .ok_or(ContinuationError::Underflow)?;
        if parent.kind != ContinuationKind::Win32kDispatch {
            return Err(ContinuationError::Kind);
        }
        if parent.state != ContinuationState::Running {
            return Err(ContinuationError::State);
        }
        if parent.dispatch_id != correlation.dispatch_id
            || !parent.client.matches_correlation(&correlation)
        {
            return Err(ContinuationError::Correlation);
        }
        parent.state = ContinuationState::Suspended;
        self.frames[self.len] = Some(ContinuationFrame::callback(correlation));
        self.len += 1;
        Ok(())
    }

    pub fn complete_dispatch(
        &mut self,
        client: ClientThreadIdentity,
        dispatch_id: u64,
    ) -> Result<(), ContinuationError> {
        let top = self.top().copied().ok_or(ContinuationError::Underflow)?;
        if top.kind != ContinuationKind::Win32kDispatch {
            return Err(ContinuationError::Kind);
        }
        if top.state != ContinuationState::Running {
            return Err(ContinuationError::State);
        }
        if top.client != client || top.dispatch_id != dispatch_id {
            return Err(ContinuationError::Correlation);
        }
        self.pop_and_resume_parent(ContinuationKind::UserCallback)
    }

    pub fn return_callback(
        &mut self,
        correlation: CallbackCorrelation,
    ) -> Result<(), ContinuationError> {
        let top = self.top().copied().ok_or(ContinuationError::Underflow)?;
        if top.kind != ContinuationKind::UserCallback {
            return Err(ContinuationError::Kind);
        }
        if top.state != ContinuationState::Running {
            return Err(ContinuationError::State);
        }
        if top.dispatch_id != correlation.dispatch_id
            || top.callback_id != correlation.callback_id
            || !top.client.matches_correlation(&correlation)
        {
            return Err(ContinuationError::Correlation);
        }
        self.pop_and_resume_parent(ContinuationKind::Win32kDispatch)
    }

    fn pop_and_resume_parent(
        &mut self,
        expected_parent: ContinuationKind,
    ) -> Result<(), ContinuationError> {
        self.len = self
            .len
            .checked_sub(1)
            .ok_or(ContinuationError::Underflow)?;
        self.frames[self.len] = None;
        if self.len != 0 {
            let parent = self.frames[self.len - 1]
                .as_mut()
                .ok_or(ContinuationError::Underflow)?;
            if parent.kind != expected_parent {
                return Err(ContinuationError::Kind);
            }
            if parent.state != ContinuationState::Suspended {
                return Err(ContinuationError::State);
            }
            parent.state = ContinuationState::Running;
        }
        Ok(())
    }
}

impl<const DEPTH: usize> Default for ContinuationStack<DEPTH> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveCallbackFrame {
    request: CallbackHeader,
    saved_user_context: [u64; 20],
    outer_resume_ip: u64,
    redirected: bool,
}

impl ActiveCallbackFrame {
    const fn empty() -> Self {
        Self {
            request: CallbackHeader::idle(0, 0, 0, 0),
            saved_user_context: [0; 20],
            outer_resume_ip: 0,
            redirected: false,
        }
    }

    pub const fn request(&self) -> &CallbackHeader {
        &self.request
    }

    pub const fn saved_user_context(&self) -> &[u64; 20] {
        &self.saved_user_context
    }

    pub const fn outer_resume_ip(&self) -> u64 {
        self.outer_resume_ip
    }

    pub const fn is_redirected(&self) -> bool {
        self.redirected
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveCallbackStack<const DEPTH: usize = MAX_ACTIVE_CALLBACK_DEPTH> {
    frames: [ActiveCallbackFrame; DEPTH],
    len: usize,
}

impl<const DEPTH: usize> ActiveCallbackStack<DEPTH> {
    pub const fn new() -> Self {
        Self {
            frames: [ActiveCallbackFrame::empty(); DEPTH],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn top(&self) -> Option<&ActiveCallbackFrame> {
        if self.len == 0 {
            None
        } else {
            Some(&self.frames[self.len - 1])
        }
    }

    pub fn push(&mut self, request: CallbackHeader) -> Result<(), ValidationError> {
        validate_request(&request)?;
        if self.len == DEPTH {
            return Err(ValidationError::Length);
        }
        self.frames[self.len] = ActiveCallbackFrame {
            request,
            saved_user_context: [0; 20],
            outer_resume_ip: 0,
            redirected: false,
        };
        self.len += 1;
        Ok(())
    }

    pub fn record_redirect(
        &mut self,
        correlation: CallbackCorrelation,
        saved_user_context: [u64; 20],
        outer_resume_ip: u64,
    ) -> Result<(), ValidationError> {
        let frame = self
            .len
            .checked_sub(1)
            .map(|index| &mut self.frames[index])
            .ok_or(ValidationError::State)?;
        if !correlation.matches_request(&frame.request) {
            return Err(ValidationError::Correlation);
        }
        if frame.redirected || outer_resume_ip == 0 {
            return Err(ValidationError::State);
        }
        frame.saved_user_context = saved_user_context;
        frame.outer_resume_ip = outer_resume_ip;
        frame.redirected = true;
        Ok(())
    }

    pub fn pop(
        &mut self,
        correlation: CallbackCorrelation,
    ) -> Result<ActiveCallbackFrame, ValidationError> {
        let index = self.len.checked_sub(1).ok_or(ValidationError::State)?;
        let frame = self.frames[index];
        if !frame.redirected {
            return Err(ValidationError::State);
        }
        if !correlation.matches_request(&frame.request) {
            return Err(ValidationError::Correlation);
        }
        self.frames[index] = ActiveCallbackFrame::empty();
        self.len = index;
        Ok(frame)
    }

    pub fn cancel_pending(
        &mut self,
        correlation: CallbackCorrelation,
    ) -> Result<ActiveCallbackFrame, ValidationError> {
        let index = self.len.checked_sub(1).ok_or(ValidationError::State)?;
        let frame = self.frames[index];
        if frame.redirected {
            return Err(ValidationError::State);
        }
        if !correlation.matches_request(&frame.request) {
            return Err(ValidationError::Correlation);
        }
        self.frames[index] = ActiveCallbackFrame::empty();
        self.len = index;
        Ok(frame)
    }
}

impl<const DEPTH: usize> Default for ActiveCallbackStack<DEPTH> {
    fn default() -> Self {
        Self::new()
    }
}

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
    pub const fn advance(self, event: ControlledTransitionEvent) -> Result<Self, ValidationError> {
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
        result,
        saved[4],
        saved[5],
        saved[6],
        saved[7],
        saved[8],
        saved[9],
        saved[10],
        saved[11],
        saved[12],
        saved[13],
        saved[14],
        saved[15],
        saved[16],
        saved[17],
        resume_ip,
        resume_sp,
        resume_flags,
    ]
}

/// seL4 x86-64 `UserContext` register indices used by the controlled callback transition.
pub const USER_CONTEXT_RIP: usize = 0;
pub const USER_CONTEXT_RSP: usize = 1;
pub const USER_CONTEXT_RFLAGS: usize = 2;
pub const USER_CONTEXT_RAX: usize = 3;
pub const USER_CONTEXT_RCX: usize = 5;
pub const USER_CONTEXT_R10: usize = 12;
pub const USER_CONTEXT_R11: usize = 13;

/// Build the context which starts `KiUserCallbackDispatcher` through the kernel's normal sysret
/// path. The original outer syscall context remains untouched in the caller's saved copy.
pub const fn callback_redirect_context(
    saved: &[u64; 20],
    dispatcher: u64,
    callback_sp: u64,
) -> [u64; 20] {
    let mut redirected = *saved;
    redirected[USER_CONTEXT_RIP] = dispatcher;
    redirected[USER_CONTEXT_RSP] = callback_sp;
    redirected[USER_CONTEXT_RAX] = 0;
    redirected[USER_CONTEXT_RCX] = dispatcher;
    redirected[USER_CONTEXT_R10] = 0;
    redirected[USER_CONTEXT_R11] = redirected[USER_CONTEXT_RFLAGS];
    redirected
}

/// Complete the suspended outer syscall after `NtCallbackReturn`. `TCB_ReadRegisters` reports the
/// instruction address for a thread blocked on an `UnknownSyscall`, so the caller supplies the
/// captured post-`syscall` return address and this helper rebuilds its sysret aliases. RAX receives
/// the completed win32k result rather than the old SSN; all other general registers are preserved.
pub const fn completed_outer_context(
    saved: &[u64; 20],
    result: u64,
    outer_resume_ip: u64,
) -> [u64; 20] {
    let mut completed = *saved;
    completed[USER_CONTEXT_RIP] = outer_resume_ip;
    completed[USER_CONTEXT_RAX] = result;
    completed[USER_CONTEXT_RCX] = outer_resume_ip;
    completed[USER_CONTEXT_R11] = completed[USER_CONTEXT_RFLAGS];
    completed
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
    /// Build the exact AMD64 callout frame for any validated user32 callback payload.
    pub const fn callback(
        input: u64,
        input_length: u32,
        api_index: u32,
        prior_rip: u64,
        prior_rsp: u64,
        prior_eflags: u32,
    ) -> Self {
        Self {
            home: [0; 4],
            input,
            input_length,
            api_index,
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

    /// Build the no-input Phase-2B callback frame for the real user32 client-thread-startup thunk.
    pub const fn client_thread_startup(prior_rip: u64, prior_rsp: u64, prior_eflags: u32) -> Self {
        Self::callback(
            0,
            0,
            USER32_CALLBACK_CLIENTTHREADSTARTUP,
            prior_rip,
            prior_rsp,
            prior_eflags,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserCallbackStackLayout {
    pub frame_pointer: u64,
    pub input_pointer: u64,
}

impl UserCallbackStackLayout {
    /// Place the fixed callout frame and bounded input copy below the client's saved RSP.
    pub fn below(prior_rsp: u64, input_length: usize) -> Result<Self, ValidationError> {
        checked_payload_length(input_length)?;
        let frame_size = core::mem::size_of::<UserCalloutFrame>() as u64;
        let total_size = frame_size
            .checked_add(input_length as u64)
            .and_then(|size| size.checked_add(15))
            .ok_or(ValidationError::Length)?
            & !15;
        let frame_pointer = prior_rsp
            .checked_sub(total_size)
            .ok_or(ValidationError::Length)?
            & !15;
        let input_pointer = if input_length == 0 {
            0
        } else {
            frame_pointer
                .checked_add(frame_size)
                .ok_or(ValidationError::Length)?
        };
        let end = frame_pointer
            .checked_add(frame_size)
            .and_then(|address| address.checked_add(input_length as u64))
            .ok_or(ValidationError::Length)?;
        if end > prior_rsp {
            return Err(ValidationError::Length);
        }
        Ok(Self {
            frame_pointer,
            input_pointer,
        })
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

pub fn client_payload_reference(
    input_pointer: u64,
    input_length: usize,
    reference_offset: u32,
) -> Result<u64, ValidationError> {
    checked_payload_length(input_length)?;
    let offset = reference_offset as usize;
    if input_pointer == 0
        || reference_offset == NO_PAYLOAD_REFERENCE
        || offset
            .checked_add(core::mem::size_of::<u64>())
            .is_none_or(|end| end > input_length)
    {
        return Err(ValidationError::Length);
    }
    input_pointer
        .checked_add(offset as u64)
        .ok_or(ValidationError::Length)
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
    fn windowproc_callout_frame_carries_client_visible_payload() {
        let frame = UserCalloutFrame::callback(
            0x7fff_1000,
            0x90,
            USER32_CALLBACK_WINDOWPROC,
            0x1111,
            0x2222,
            0x246,
        );
        assert_eq!(frame.input, 0x7fff_1000);
        assert_eq!(frame.input_length, 0x90);
        assert_eq!(frame.api_index, USER32_CALLBACK_WINDOWPROC);
        assert_eq!(frame.machine_frame.rip, 0x1111);
        assert_eq!(frame.machine_frame.rsp, 0x2222);
    }

    #[test]
    fn sas_wm_create_nested_sequence_accepts_one_to_four_hotkeys() {
        for hot_key_count in 1..=4 {
            let mut sequence = SasWmCreateNestedSequence::new();
            assert!(!sequence.can_complete());
            assert_eq!(sequence.accept(NTUSER_SET_WINDOW_LONG_PTR_SSN), Ok(()));
            assert!(!sequence.can_complete());
            for _ in 0..hot_key_count {
                assert_eq!(sequence.accept(NTUSER_REGISTER_HOT_KEY_SSN), Ok(()));
            }
            assert!(sequence.can_complete());
            assert_eq!(sequence.register_hot_key_count(), hot_key_count);
        }
    }

    #[test]
    fn sas_wm_create_nested_sequence_rejects_wrong_order_and_overflow() {
        let mut sequence = SasWmCreateNestedSequence::new();
        assert_eq!(
            sequence.accept(NTUSER_REGISTER_HOT_KEY_SSN),
            Err(ValidationError::Sequence)
        );
        assert_eq!(sequence.accept(NTUSER_SET_WINDOW_LONG_PTR_SSN), Ok(()));
        assert_eq!(
            sequence.accept(NTUSER_SET_WINDOW_LONG_PTR_SSN),
            Err(ValidationError::Sequence)
        );
        for _ in 0..4 {
            assert_eq!(sequence.accept(NTUSER_REGISTER_HOT_KEY_SSN), Ok(()));
        }
        assert_eq!(
            sequence.accept(NTUSER_REGISTER_HOT_KEY_SSN),
            Err(ValidationError::Sequence)
        );
        assert_eq!(sequence.accept(0x1080), Err(ValidationError::Sequence));
    }

    #[test]
    fn dialog_modal_pump_sequence_reaches_one_paint_dispatch() {
        let mut sequence = DialogModalPumpSequence::new();
        assert_eq!(sequence.expected_ssn(), Some(NTUSER_PEEK_MESSAGE_SSN));
        assert_eq!(sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 0, None), Ok(()));
        assert_eq!(sequence.expected_ssn(), Some(NTUSER_GET_MESSAGE_SSN));
        assert_eq!(
            sequence.complete(NTUSER_GET_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Ok(())
        );
        assert_eq!(sequence.expected_ssn(), Some(NTUSER_DISPATCH_MESSAGE_SSN));
        assert_eq!(
            sequence.complete(NTUSER_DISPATCH_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Ok(())
        );
        assert!(sequence.is_complete());
        assert_eq!(sequence.paint_dispatches(), 1);
        assert_eq!(sequence.expected_ssn(), Some(NTUSER_PEEK_MESSAGE_SSN));
        assert_eq!(
            sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 0, None),
            Ok(())
        );
        assert!(sequence.is_drained());
        assert_eq!(sequence.expected_ssn(), None);
    }

    #[test]
    fn dialog_modal_pump_sequence_rejects_invalid_or_mismatched_dispatch() {
        let mut sequence = DialogModalPumpSequence::new();
        assert_eq!(
            sequence.complete(NTUSER_GET_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Err(ValidationError::Sequence)
        );
        assert_eq!(
            sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 1, None),
            Err(ValidationError::Sequence)
        );
        assert_eq!(sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 0, None), Ok(()));
        assert_eq!(
            sequence.complete(NTUSER_GET_MESSAGE_SSN, 1, Some(0x0110)),
            Ok(())
        );
        assert_eq!(
            sequence.complete(NTUSER_DISPATCH_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Err(ValidationError::Sequence)
        );
    }

    #[test]
    fn dialog_modal_pump_allows_unrelated_messages_before_real_paint() {
        let mut sequence = DialogModalPumpSequence::new();
        assert_eq!(
            sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 1, Some(WLX_WM_SAS)),
            Ok(())
        );
        assert_eq!(sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 0, None), Ok(()));
        assert_eq!(
            sequence.complete(NTUSER_GET_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Ok(())
        );
        assert_eq!(
            sequence.complete(NTUSER_DISPATCH_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Ok(())
        );
        assert_eq!(sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 0, None), Ok(()));
        assert_eq!(sequence.paint_dispatches(), 1);
        assert!(sequence.is_drained());
    }

    #[test]
    fn dialog_modal_pump_ignores_normalized_unrelated_paint() {
        let mut sequence = DialogModalPumpSequence::new();
        assert_eq!(
            sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 1, Some(u32::MAX)),
            Ok(())
        );
        assert_eq!(sequence.paint_dispatches(), 0);
        assert_eq!(sequence.expected_ssn(), Some(NTUSER_PEEK_MESSAGE_SSN));
        assert!(!sequence.is_complete());
    }

    #[test]
    fn dialog_modal_pump_drains_multiple_real_paints() {
        let mut sequence = DialogModalPumpSequence::new();
        assert_eq!(sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 0, None), Ok(()));
        assert_eq!(
            sequence.complete(NTUSER_GET_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Ok(())
        );
        assert_eq!(
            sequence.complete(NTUSER_DISPATCH_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Ok(())
        );
        assert_eq!(
            sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Ok(())
        );
        assert_eq!(
            sequence.complete(NTUSER_DISPATCH_MESSAGE_SSN, 1, Some(WM_PAINT)),
            Ok(())
        );
        assert_eq!(sequence.paint_dispatches(), 2);
        assert_eq!(sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 0, None), Ok(()));
        assert!(sequence.is_drained());
    }

    #[test]
    fn winlogon_dialog_correlation_binds_sas_session_messages_and_logon_hwnd() {
        let mut correlation = WinlogonDialogCorrelation::new();
        assert_eq!(correlation.latch_sas_window(0xc15bc0, 0x2002e), Ok(()));
        assert_eq!(
            correlation.observe_sas_message(0xc15bc0, 0x2002e, WLX_WM_SAS, 1),
            Ok(())
        );
        assert_eq!(
            correlation.observe_logged_off(0xc15bc0, WINLOGON_STATE_LOGGED_OFF),
            Ok(())
        );
        assert_eq!(
            correlation.observe_sas_message(0xc15bc0, 0x2002e, WLX_WM_SAS, 1),
            Ok(())
        );
        assert_eq!(
            correlation.capture_idd_logon(
                0xc15bc0,
                0x20040,
                WC_DIALOG_ATOM,
                &IDD_LOGON_CAPTION,
                true,
                true,
            ),
            Ok(())
        );
        assert!(correlation.modal_ready());
        assert_eq!(correlation.sas_hwnd(), 0x2002e);
        assert_eq!(correlation.idd_logon_hwnd(), 0x20040);
    }

    #[test]
    fn winlogon_dialog_correlation_rejects_stale_session_or_wrong_hwnd() {
        let mut correlation = WinlogonDialogCorrelation::new();
        assert_eq!(correlation.latch_sas_window(0xc15bc0, 0x2002e), Ok(()));
        assert_eq!(
            correlation.observe_sas_message(0xdead, 0x2002e, WLX_WM_SAS, 1),
            Err(ValidationError::Sequence)
        );
        assert_eq!(
            correlation.observe_sas_message(0xc15bc0, 0x20030, WLX_WM_SAS, 1),
            Err(ValidationError::Sequence)
        );
        assert_eq!(
            correlation.observe_sas_message(0xc15bc0, 0x2002e, WLX_WM_SAS, 1),
            Ok(())
        );
        assert_eq!(
            correlation.observe_logged_off(0xdead, WINLOGON_STATE_LOGGED_OFF),
            Err(ValidationError::Sequence)
        );
        assert_eq!(
            correlation.observe_logged_off(0xc15bc0, WINLOGON_STATE_LOGGED_OFF),
            Ok(())
        );
        assert_eq!(
            correlation.observe_sas_message(0xc15bc0, 0x2002e, WLX_WM_SAS, 1),
            Ok(())
        );
        assert_eq!(
            correlation.capture_idd_logon(
                0xc15bc0,
                0x2002e,
                WC_DIALOG_ATOM,
                &IDD_LOGON_CAPTION,
                true,
                true,
            ),
            Err(ValidationError::Sequence)
        );
        assert_eq!(
            correlation.capture_idd_logon(
                0xc15bc0,
                0x20040,
                WC_DIALOG_ATOM,
                &[
                    b'L' as u16,
                    b'o' as u16,
                    b'g' as u16,
                    b'o' as u16,
                    b'f' as u16
                ],
                true,
                true,
            ),
            Err(ValidationError::Sequence)
        );
        assert!(!correlation.modal_ready());
    }

    #[test]
    fn large_unicode_string_descriptor_validates_bounded_unicode_input() {
        let mut raw = [0u8; 16];
        raw[0..4].copy_from_slice(&10u32.to_le_bytes());
        raw[4..8].copy_from_slice(&12u32.to_le_bytes());
        raw[8..16].copy_from_slice(&0x80ff_f000u64.to_le_bytes());
        let descriptor = LargeUnicodeStringDescriptor::parse(&raw).unwrap();
        assert_eq!(descriptor.length_bytes, 10);
        assert_eq!(descriptor.code_units(), 5);
        assert_eq!(descriptor.buffer, 0x80ff_f000);

        let mut output = [0u16; MAX_DIALOG_CAPTION_CODE_UNITS];
        let count = decode_utf16le_bounded(b"L\0o\0g\0o\0n\0", &mut output).unwrap();
        assert_eq!(&output[..count], &IDD_LOGON_CAPTION);
    }

    #[test]
    fn large_unicode_string_descriptor_rejects_ansi_odd_overflow_or_unbounded_input() {
        let mut raw = [0u8; 16];
        raw[0..4].copy_from_slice(&3u32.to_le_bytes());
        raw[4..8].copy_from_slice(&4u32.to_le_bytes());
        raw[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        assert_eq!(
            LargeUnicodeStringDescriptor::parse(&raw),
            Err(ValidationError::Length)
        );

        raw[0..4].copy_from_slice(&2u32.to_le_bytes());
        raw[4..8].copy_from_slice(&0x8000_0004u32.to_le_bytes());
        assert_eq!(
            LargeUnicodeStringDescriptor::parse(&raw),
            Err(ValidationError::Length)
        );

        raw[0..4].copy_from_slice(&((MAX_DIALOG_CAPTION_CODE_UNITS as u32 + 1) * 2).to_le_bytes());
        raw[4..8].copy_from_slice(&((MAX_DIALOG_CAPTION_CODE_UNITS as u32 + 1) * 2).to_le_bytes());
        assert_eq!(
            LargeUnicodeStringDescriptor::parse(&raw),
            Err(ValidationError::Length)
        );

        raw[0..4].copy_from_slice(&4u32.to_le_bytes());
        raw[4..8].copy_from_slice(&4u32.to_le_bytes());
        raw[8..16].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        assert_eq!(
            LargeUnicodeStringDescriptor::parse(&raw),
            Err(ValidationError::Length)
        );

        let mut output = [0u16; MAX_DIALOG_CAPTION_CODE_UNITS];
        assert_eq!(
            decode_utf16le_bounded(&[0; 3], &mut output),
            Err(ValidationError::Length)
        );
    }

    #[test]
    fn callback_stack_layout_is_aligned_bounded_and_nonoverlapping() {
        let layout = UserCallbackStackLayout::below(0x8000, 0x90).unwrap();
        assert_eq!(layout.frame_pointer & 0xf, 0);
        assert_eq!(layout.input_pointer, layout.frame_pointer + 0x58);
        assert!(layout.input_pointer + 0x90 <= 0x8000);
        assert_eq!(
            UserCallbackStackLayout::below(0x40, 0x90),
            Err(ValidationError::Length)
        );
        assert_eq!(
            UserCallbackStackLayout::below(0x8000, CALLBACK_PAYLOAD_MAX + 1),
            Err(ValidationError::Length)
        );
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
    fn embedded_payload_reference_rebases_into_client_copy() {
        assert_eq!(
            client_payload_reference(0x7fff_1000, 0x90, 0x40),
            Ok(0x7fff_1040)
        );
        assert_eq!(
            client_payload_reference(0x7fff_1000, 0x40, 0x40),
            Err(ValidationError::Length)
        );
        assert_eq!(
            client_payload_reference(0, 0x90, 0x40),
            Err(ValidationError::Length)
        );
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
    fn continuation_stack_models_two_nested_callback_levels() {
        let client = ClientThreadIdentity::new(2, 44, 4);
        let outer = CallbackCorrelation {
            dispatch_id: 7,
            callback_id: 1,
            client_pi: 2,
            client_tid: 44,
            client_badge: 4,
        };
        let inner = CallbackCorrelation {
            dispatch_id: 8,
            callback_id: 1,
            client_pi: 2,
            client_tid: 44,
            client_badge: 4,
        };
        let mut stack = ContinuationStack::<8>::new();

        stack.push_dispatch(client, outer.dispatch_id).unwrap();
        stack.push_callback(outer).unwrap();
        stack.push_dispatch(client, inner.dispatch_id).unwrap();
        stack.push_callback(inner).unwrap();
        assert_eq!(stack.len(), 4);
        assert_eq!(stack.top().unwrap().kind, ContinuationKind::UserCallback);

        stack.return_callback(inner).unwrap();
        assert_eq!(stack.top().unwrap().state, ContinuationState::Running);
        stack.complete_dispatch(client, inner.dispatch_id).unwrap();
        assert_eq!(stack.top().unwrap().state, ContinuationState::Running);
        stack.return_callback(outer).unwrap();
        stack.complete_dispatch(client, outer.dispatch_id).unwrap();
        assert!(stack.is_empty());
    }

    #[test]
    fn continuation_stack_accepts_sequential_callbacks_in_one_dispatch() {
        let client = ClientThreadIdentity::new(2, 44, 4);
        let first = CallbackCorrelation {
            dispatch_id: 7,
            callback_id: 1,
            client_pi: 2,
            client_tid: 44,
            client_badge: 4,
        };
        let mut second = first;
        second.callback_id = 2;
        let mut stack = ContinuationStack::<4>::new();

        stack.push_dispatch(client, first.dispatch_id).unwrap();
        stack.push_callback(first).unwrap();
        stack.return_callback(first).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack.top().unwrap().state, ContinuationState::Running);

        stack.push_callback(second).unwrap();
        stack.return_callback(second).unwrap();
        stack.complete_dispatch(client, second.dispatch_id).unwrap();
        assert!(stack.is_empty());
    }

    #[test]
    fn continuation_stack_rejects_stale_or_cross_thread_unwind() {
        let client = ClientThreadIdentity::new(2, 44, 4);
        let correlation = CallbackCorrelation {
            dispatch_id: 7,
            callback_id: 1,
            client_pi: 2,
            client_tid: 44,
            client_badge: 4,
        };
        let mut stack = ContinuationStack::<4>::new();
        stack
            .push_dispatch(client, correlation.dispatch_id)
            .unwrap();
        stack.push_callback(correlation).unwrap();

        let mut stale = correlation;
        stale.callback_id += 1;
        assert_eq!(
            stack.return_callback(stale),
            Err(ContinuationError::Correlation)
        );
        assert_eq!(stack.len(), 2);

        let mut wrong_thread = correlation;
        wrong_thread.client_tid += 1;
        assert_eq!(
            stack.return_callback(wrong_thread),
            Err(ContinuationError::Correlation)
        );
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.return_callback(correlation), Ok(()));
    }

    #[test]
    fn continuation_stack_is_bounded_and_alternating() {
        let client = ClientThreadIdentity::new(2, 44, 4);
        let callback = CallbackCorrelation {
            dispatch_id: 7,
            callback_id: 1,
            client_pi: 2,
            client_tid: 44,
            client_badge: 4,
        };
        let mut stack = ContinuationStack::<2>::new();
        stack.push_dispatch(client, callback.dispatch_id).unwrap();
        assert_eq!(stack.push_dispatch(client, 8), Err(ContinuationError::Kind));
        stack.push_callback(callback).unwrap();
        assert_eq!(
            stack.push_dispatch(client, 8),
            Err(ContinuationError::Overflow)
        );
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn continuation_stack_rejects_callback_for_another_dispatch() {
        let client = ClientThreadIdentity::new(2, 44, 4);
        let mut stack = ContinuationStack::<4>::new();
        stack.push_dispatch(client, 7).unwrap();
        let stale = CallbackCorrelation {
            dispatch_id: 8,
            callback_id: 1,
            client_pi: 2,
            client_tid: 44,
            client_badge: 4,
        };
        assert_eq!(
            stack.push_callback(stale),
            Err(ContinuationError::Correlation)
        );
        assert_eq!(stack.len(), 1);
        assert_eq!(stack.top().unwrap().state, ContinuationState::Running);
    }

    #[test]
    fn active_callback_stack_restores_nested_user_contexts_lifo() {
        let mut outer = CallbackHeader::idle(7, 2, 44, 4);
        outer.begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40).unwrap();
        let mut inner = CallbackHeader::idle(8, 2, 44, 4);
        inner.begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40).unwrap();
        let outer_correlation = CallbackCorrelation::from_request(&outer);
        let inner_correlation = CallbackCorrelation::from_request(&inner);
        let mut stack = ActiveCallbackStack::<2>::new();

        stack.push(outer).unwrap();
        stack
            .record_redirect(outer_correlation, [0x11; 20], 0x1111)
            .unwrap();
        stack.push(inner).unwrap();
        stack
            .record_redirect(inner_correlation, [0x22; 20], 0x2222)
            .unwrap();

        let completed_inner = stack.pop(inner_correlation).unwrap();
        assert_eq!(completed_inner.saved_user_context(), &[0x22; 20]);
        assert_eq!(completed_inner.outer_resume_ip(), 0x2222);
        assert_eq!(stack.top().unwrap().request(), &outer);
        let completed_outer = stack.pop(outer_correlation).unwrap();
        assert_eq!(completed_outer.saved_user_context(), &[0x11; 20]);
        assert!(stack.is_empty());
    }

    #[test]
    fn active_callback_stack_rejects_stale_return_and_overflow() {
        let mut request = CallbackHeader::idle(7, 2, 44, 4);
        request
            .begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40)
            .unwrap();
        let correlation = CallbackCorrelation::from_request(&request);
        let mut stack = ActiveCallbackStack::<1>::new();
        stack.push(request).unwrap();
        assert_eq!(stack.push(request), Err(ValidationError::Length));
        let mut stale = correlation;
        stale.callback_id += 1;
        assert_eq!(
            stack.record_redirect(stale, [0; 20], 0x1000),
            Err(ValidationError::Correlation)
        );
        stack
            .record_redirect(correlation, [0; 20], 0x1000)
            .unwrap();
        assert_eq!(stack.pop(stale), Err(ValidationError::Correlation));
        assert_eq!(stack.len(), 1);
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

    #[test]
    fn callback_redirect_context_uses_sysret_register_aliases() {
        let mut saved = [0u64; 20];
        let mut index = 0;
        while index < saved.len() {
            saved[index] = 0x1000 + index as u64;
            index += 1;
        }
        let redirected = callback_redirect_context(&saved, 0x7000, 0x8000);
        assert_eq!(redirected[USER_CONTEXT_RIP], 0x7000);
        assert_eq!(redirected[USER_CONTEXT_RSP], 0x8000);
        assert_eq!(redirected[USER_CONTEXT_RAX], 0);
        assert_eq!(redirected[USER_CONTEXT_RCX], 0x7000);
        assert_eq!(redirected[USER_CONTEXT_R10], 0);
        assert_eq!(redirected[USER_CONTEXT_R11], saved[USER_CONTEXT_RFLAGS]);
        assert_eq!(redirected[4], saved[4]);
        assert_eq!(redirected[17], saved[17]);
    }

    #[test]
    fn completed_outer_context_restores_result_and_sysret_resume_aliases() {
        let mut saved = [0u64; 20];
        let mut index = 0;
        while index < saved.len() {
            saved[index] = 0x2000 + index as u64;
            index += 1;
        }
        let completed = completed_outer_context(&saved, 0xcafe_babe, 0x7fff_1234);
        assert_eq!(completed[USER_CONTEXT_RIP], 0x7fff_1234);
        assert_eq!(completed[USER_CONTEXT_RAX], 0xcafe_babe);
        assert_eq!(completed[USER_CONTEXT_RCX], 0x7fff_1234);
        assert_eq!(completed[USER_CONTEXT_R11], saved[USER_CONTEXT_RFLAGS]);
        assert_eq!(completed[USER_CONTEXT_R10], saved[USER_CONTEXT_R10]);
        let mut index = 0;
        while index < saved.len() {
            if index != USER_CONTEXT_RIP
                && index != USER_CONTEXT_RAX
                && index != USER_CONTEXT_RCX
                && index != USER_CONTEXT_R11
            {
                assert_eq!(completed[index], saved[index]);
            }
            index += 1;
        }
    }
}
