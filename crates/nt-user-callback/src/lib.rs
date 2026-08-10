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
/// ReactOS `USER32_CALLBACK_LOADDEFAULTCURSORS` / `apfnDispatch[3]`.
pub const USER32_CALLBACK_LOADDEFAULTCURSORS: u32 = 3;
/// ReactOS `USER32_CALLBACK_SETWNDICONS` / `apfnDispatch[11]`.
pub const USER32_CALLBACK_SETWNDICONS: u32 = 11;
/// ReactOS `USER32_CALLBACK_SETOBM` / `apfnDispatch[15]`.
pub const USER32_CALLBACK_SETOBM: u32 = 15;
/// ReactOS `USER32_CALLBACK_LPK` / `apfnDispatch[16]`.
pub const USER32_CALLBACK_LPK: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserCallbackContract {
    WindowProc,
    Lpk,
    Fixed {
        input_length: u32,
        result_length: u32,
    },
}

impl UserCallbackContract {
    pub const fn for_api(api_index: u32) -> Option<Self> {
        match api_index {
            USER32_CALLBACK_WINDOWPROC => Some(Self::WindowProc),
            USER32_CALLBACK_CLIENTTHREADSTARTUP => Some(Self::Fixed {
                input_length: 0,
                result_length: 0,
            }),
            USER32_CALLBACK_LOADDEFAULTCURSORS => Some(Self::Fixed {
                input_length: 4,
                result_length: 8,
            }),
            USER32_CALLBACK_SETWNDICONS => Some(Self::Fixed {
                input_length: 0x38,
                result_length: 0x38,
            }),
            USER32_CALLBACK_SETOBM => Some(Self::Fixed {
                input_length: 0x5d0,
                result_length: 0x5d0,
            }),
            USER32_CALLBACK_LPK => Some(Self::Lpk),
            _ => None,
        }
    }

    pub const fn accepts_request(
        self,
        input_length: u32,
        output_capacity: u32,
        payload_reference_offset: u32,
    ) -> bool {
        match self {
            Self::WindowProc => {
                input_length >= 0x40
                    && output_capacity >= input_length
                    && (payload_reference_offset == NO_PAYLOAD_REFERENCE
                        || payload_reference_offset == 0x40)
            }
            Self::Lpk => {
                input_length >= 0x3c
                    && output_capacity >= 4
                    && payload_reference_offset == NO_PAYLOAD_REFERENCE
            }
            Self::Fixed {
                input_length: expected_input,
                result_length,
            } => {
                input_length == expected_input
                    && output_capacity >= result_length
                    && payload_reference_offset == NO_PAYLOAD_REFERENCE
            }
        }
    }

    pub const fn accepts_result(
        self,
        input_length: u32,
        result_length: u32,
        callback_status: i32,
    ) -> bool {
        if callback_status < 0 {
            return result_length == 0;
        }
        match self {
            Self::WindowProc => result_length == input_length,
            Self::Lpk => result_length == 4,
            Self::Fixed {
                result_length: expected,
                ..
            } => result_length == expected,
        }
    }

    pub const fn requires_window_binding(self) -> bool {
        matches!(self, Self::WindowProc)
    }

    pub const fn minimum_result_capacity(self, input_length: u32) -> Option<u32> {
        match self {
            Self::WindowProc if input_length >= 0x40 => Some(input_length),
            Self::WindowProc => None,
            Self::Lpk if input_length >= 0x3c => Some(4),
            Self::Lpk => None,
            Self::Fixed {
                input_length: expected_input,
                result_length,
            } if input_length == expected_input => Some(result_length),
            Self::Fixed { .. } => None,
        }
    }

    pub const fn accepts_lpk_layout(
        self,
        input_length: u32,
        string_offset: u64,
        character_count: u32,
    ) -> bool {
        if !matches!(self, Self::Lpk) || string_offset != 0x38 {
            return false;
        }
        let Some(chars_with_slack) = character_count.checked_add(2) else {
            return false;
        };
        let Some(string_bytes) = chars_with_slack.checked_mul(2) else {
            return false;
        };
        let Some(total_input_length) = 0x38u32.checked_add(string_bytes) else {
            return false;
        };
        total_input_length == input_length
    }
}

pub const NTUSER_SET_WINDOW_LONG_PTR_SSN: u64 = 0x1298;
pub const NTUSER_REGISTER_HOT_KEY_SSN: u64 = 0x126b;
pub const NTUSER_PEEK_MESSAGE_SSN: u64 = 0x1001;
pub const NTUSER_GET_MESSAGE_SSN: u64 = 0x1006;
pub const NTUSER_DISPATCH_MESSAGE_SSN: u64 = 0x1035;
/// `w32ksvc64.h`: `SVC_(UserPostMessage, 4)` — the REAL keyboard/message post path. Used both for
/// the simulated Ctrl-Alt-Del SAS and for the credential keystrokes injected into the logon dialog.
pub const NTUSER_POST_MESSAGE_SSN: u64 = 0x100e;
/// `w32ksvc64.h`: `SVC_(GdiExtTextOutW, 9)` — every single-line edit control's text render
/// (`EDIT_PaintText` → `TextOutW` → `NtGdiExtTextOutW`) carries `es->text + col` + a character
/// count, so the drawn string is the control's genuine contents read back through the GDI path.
pub const NTGDI_EXT_TEXT_OUT_W_SSN: u64 = 0x1037;
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

/// `references/reactos/dll/win32/msgina/resource.h`: the IDD_LOGON credential-dialog control ids.
pub const IDC_LOGON_USERNAME: u64 = 1201;
pub const IDC_LOGON_PASSWORD: u64 = 1202;
pub const IDC_LOGON_DOMAIN: u64 = 1203;
/// `IDOK` — the dialog's DEFPUSHBUTTON (`lang/en-US.rc`: `DEFPUSHBUTTON "OK", IDOK`).
pub const IDOK: u64 = 1;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_CHAR: u32 = 0x0102;
pub const VK_RETURN: u64 = 0x000d;
/// The credential the headless keystroke shim types into `IDC_LOGON_USERNAME`. ReactOS' own
/// default interactive account; the matching password is the empty string, so only the user name
/// needs keystrokes (`DoLogon` rejects an EMPTY user name, accepts an empty password).
pub const LOGON_USERNAME: [u16; 13] = [
    b'A' as u16,
    b'd' as u16,
    b'm' as u16,
    b'i' as u16,
    b'n' as u16,
    b'i' as u16,
    b's' as u16,
    b't' as u16,
    b'r' as u16,
    b'a' as u16,
    b't' as u16,
    b'o' as u16,
    b'r' as u16,
];
/// `winwlx.h` — the action `LogonDialogProc` returns from `EndDialog` on a successful `DoLogon`.
pub const WLX_SAS_ACTION_LOGON: i32 = 1;

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

/// The headless keystroke shim for the msgina IDD_LOGON credential dialog.
///
/// A real console types into the logon box; we have no keyboard, so — exactly as the simulated
/// Ctrl-Alt-Del is posted through the REAL `NtUserPostMessage` — the user name is typed as one
/// genuine `WM_CHAR` per character posted to the REAL `IDC_LOGON_USERNAME` edit control, followed
/// by a `WM_KEYDOWN`/`VK_RETURN`. Everything downstream is the real code: win32k's message queue
/// delivers them, `DIALOG_DoDialogBox`'s pump retrieves them, `IsDialogMessageW` classifies them
/// (`WM_CHAR` → `DLGC_WANTCHARS` → `TranslateMessage`/`DispatchMessageW` → the real edit control;
/// `VK_RETURN` → `DM_GETDEFID` → `WM_COMMAND(IDOK)` → the real `LogonDialogProc`).
///
/// This type owns only the *ordering* rules; the executive owns the mechanics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialInjectionSequence {
    username_hwnd: u64,
    posted_chars: u16,
    posted_return: bool,
    retrieved_chars: u16,
    retrieved_return: bool,
    routed_get_messages: u16,
    text_readbacks: u16,
}

impl CredentialInjectionSequence {
    pub const fn new() -> Self {
        Self {
            username_hwnd: 0,
            posted_chars: 0,
            posted_return: false,
            retrieved_chars: 0,
            retrieved_return: false,
            routed_get_messages: 0,
            text_readbacks: 0,
        }
    }

    /// Latch the REAL edit-control window handle resolved from the dialog's child window list
    /// (the `GetDlgItem` rule: the child whose `WND.IDMenu` is the control id).
    pub fn begin(&mut self, username_hwnd: u64, dialog_hwnd: u64) -> Result<(), ValidationError> {
        if username_hwnd == 0
            || dialog_hwnd == 0
            || username_hwnd == dialog_hwnd
            || self.username_hwnd != 0
        {
            return Err(ValidationError::Sequence);
        }
        self.username_hwnd = username_hwnd;
        Ok(())
    }

    /// Record one posted `WM_CHAR`. `index` must advance strictly by one and stay inside
    /// [`LOGON_USERNAME`]; the post must target the latched edit control.
    pub fn record_char_post(&mut self, hwnd: u64, index: usize) -> Result<(), ValidationError> {
        if self.username_hwnd == 0
            || hwnd != self.username_hwnd
            || self.posted_return
            || index != self.posted_chars as usize
            || index >= LOGON_USERNAME.len()
        {
            return Err(ValidationError::Sequence);
        }
        self.posted_chars += 1;
        Ok(())
    }

    /// Record the posted `WM_KEYDOWN`/`VK_RETURN` that drives the dialog to its decision. Valid
    /// only once the whole user name has been typed AND every one of those characters has come
    /// back out of the real queue — i.e. the real edit control has actually received them.
    pub fn record_return_post(&mut self, hwnd: u64) -> Result<(), ValidationError> {
        if self.username_hwnd == 0
            || hwnd != self.username_hwnd
            || self.posted_return
            || self.posted_chars as usize != LOGON_USERNAME.len()
            || self.retrieved_chars as usize != LOGON_USERNAME.len()
        {
            return Err(ValidationError::Sequence);
        }
        self.posted_return = true;
        Ok(())
    }

    /// A `MSG` the REAL `GetMessageW`/`PeekMessageW` just returned to winlogon. Counts the injected
    /// keystrokes that genuinely came back out of win32k's queue.
    pub fn observe_retrieved(&mut self, hwnd: u64, message: u32, wparam: u64) -> bool {
        if self.username_hwnd == 0 || hwnd != self.username_hwnd {
            return false;
        }
        if message == WM_CHAR && (self.retrieved_chars as usize) < LOGON_USERNAME.len() {
            self.retrieved_chars += 1;
            return true;
        }
        if message == WM_KEYDOWN && wparam == VK_RETURN {
            self.retrieved_return = true;
            return true;
        }
        false
    }

    /// The credential text read back out of the control through the real GDI render path.
    pub fn record_text_readback(&mut self) {
        self.text_readbacks = self.text_readbacks.saturating_add(1);
    }

    /// Keystrokes are injected in two phases — the typed user name, then the RETURN key — each
    /// released when the dialog's pump next reports its queue empty. A blocking `GetMessageW` may
    /// be routed into win32k exactly ONCE per phase: right after a phase is posted the queue is
    /// provably non-empty, so the call returns instead of blocking win32k (and the executive with
    /// it). Every other blocking `GetMessage` means the queue drained and MUST be parked.
    pub const fn may_route_get_message(self) -> bool {
        (self.routed_get_messages as usize) < self.posted_phases()
    }

    const fn posted_phases(self) -> usize {
        (self.posted_chars as usize == LOGON_USERNAME.len()) as usize + self.posted_return as usize
    }

    pub fn record_routed_get_message(&mut self) {
        self.routed_get_messages = self.routed_get_messages.saturating_add(1);
    }

    pub const fn username_hwnd(self) -> u64 {
        self.username_hwnd
    }

    pub const fn is_injected(self) -> bool {
        self.posted_return
    }

    pub const fn posted_chars(self) -> u16 {
        self.posted_chars
    }

    pub const fn retrieved_chars(self) -> u16 {
        self.retrieved_chars
    }

    pub const fn retrieved_return(self) -> bool {
        self.retrieved_return
    }

    pub const fn text_readbacks(self) -> u16 {
        self.text_readbacks
    }

    /// Every injected keystroke was posted AND came back out of the real queue.
    pub const fn keystrokes_delivered(self) -> bool {
        self.posted_return
            && self.retrieved_return
            && self.retrieved_chars as usize == LOGON_USERNAME.len()
    }
}

impl Default for CredentialInjectionSequence {
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
/// able to grow executive state without limit. Thirty-two alternating frames permit sixteen
/// complete dispatch/callback levels. Real explorer shell-window construction has reached a ninth
/// callback level while delivering nested create/position/window-proc messages.
pub const MAX_CONTINUATION_DEPTH: usize = 32;
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

/// Pointer-free, bounded model of the alternating continuation chains of every client thread with
/// win32k work outstanding.
///
/// Within ONE client thread the expected order is `dispatch -> callback -> nested dispatch -> …`:
/// pushing a child suspends its parent, and completing the child makes that exact parent runnable
/// again. **The chains of different client threads INTERLEAVE.** A hosted process is
/// multi-threaded, and while thread A sits redirected inside a user-mode callback, thread B can
/// issue a win32k syscall of its own — in real NT that is a *concurrent* dispatch on B's own kernel
/// stack, not a nested one on A's. So the array below holds the union of the chains, and **every
/// lookup is scoped to one [`ClientThreadIdentity`]**: a frame's parent is the innermost frame *of
/// the same client thread*, and "no frame for this identity" means "this is a fresh root dispatch",
/// not an error. Correlation is still checked before mutation, so stale `NtCallbackReturn`s cannot
/// pop another thread's continuation, and within one identity the frames remain strictly LIFO.
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

    /// Index of the INNERMOST frame belonging to `client` — the top of that client thread's own
    /// chain. `None` means the thread holds no continuation at all, which is exactly the "this is a
    /// fresh root dispatch" case (see the type's doc comment).
    fn top_index_for(&self, client: &ClientThreadIdentity) -> Option<usize> {
        (0..self.len)
            .rev()
            .find(|&index| self.frames[index].is_some_and(|frame| frame.client == *client))
    }

    /// The innermost continuation of one client thread's chain.
    pub fn top_for(&self, client: &ClientThreadIdentity) -> Option<&ContinuationFrame> {
        self.top_index_for(client)
            .and_then(|index| self.frames[index].as_ref())
    }

    /// How deep `client`'s OWN chain is (the global [`Self::len`] is the union of every chain).
    pub fn len_for(&self, client: &ClientThreadIdentity) -> usize {
        (0..self.len)
            .filter(|&index| self.frames[index].is_some_and(|frame| frame.client == *client))
            .count()
    }

    /// Does this client thread hold NO continuation? (The next dispatch it issues is a root one.)
    pub fn is_empty_for(&self, client: &ClientThreadIdentity) -> bool {
        self.top_index_for(client).is_none()
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
        // The parent is THIS client thread's innermost frame, never simply the array's top: another
        // thread's frames may sit above it. No frame for this identity => a root dispatch.
        if let Some(index) = self.top_index_for(&client) {
            let parent = self.frames[index]
                .as_mut()
                .ok_or(ContinuationError::Underflow)?;
            if parent.kind != ContinuationKind::UserCallback {
                return Err(ContinuationError::Kind);
            }
            if parent.state != ContinuationState::Running {
                return Err(ContinuationError::State);
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
        let client = ClientThreadIdentity::new(
            correlation.client_pi,
            correlation.client_tid,
            correlation.client_badge,
        );
        let index = self
            .top_index_for(&client)
            .ok_or(ContinuationError::Underflow)?;
        let parent = self.frames[index]
            .as_mut()
            .ok_or(ContinuationError::Underflow)?;
        if parent.kind != ContinuationKind::Win32kDispatch {
            return Err(ContinuationError::Kind);
        }
        if parent.state != ContinuationState::Running {
            return Err(ContinuationError::State);
        }
        if parent.dispatch_id != correlation.dispatch_id {
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
        let index = self
            .top_index_for(&client)
            .ok_or(ContinuationError::Underflow)?;
        let top = self.frames[index].ok_or(ContinuationError::Underflow)?;
        if top.kind != ContinuationKind::Win32kDispatch {
            return Err(ContinuationError::Kind);
        }
        if top.state != ContinuationState::Running {
            return Err(ContinuationError::State);
        }
        if top.dispatch_id != dispatch_id {
            return Err(ContinuationError::Correlation);
        }
        self.remove_and_resume_parent(index, &client, ContinuationKind::UserCallback)
    }

    pub fn return_callback(
        &mut self,
        correlation: CallbackCorrelation,
    ) -> Result<(), ContinuationError> {
        let client = ClientThreadIdentity::new(
            correlation.client_pi,
            correlation.client_tid,
            correlation.client_badge,
        );
        let index = self
            .top_index_for(&client)
            .ok_or(ContinuationError::Underflow)?;
        let top = self.frames[index].ok_or(ContinuationError::Underflow)?;
        if top.kind != ContinuationKind::UserCallback {
            return Err(ContinuationError::Kind);
        }
        if top.state != ContinuationState::Running {
            return Err(ContinuationError::State);
        }
        if top.dispatch_id != correlation.dispatch_id || top.callback_id != correlation.callback_id
        {
            return Err(ContinuationError::Correlation);
        }
        self.remove_and_resume_parent(index, &client, ContinuationKind::Win32kDispatch)
    }

    /// Remove one frame (the top of `client`'s chain, not necessarily the array's top) and make that
    /// chain's next-innermost frame runnable again. Closing the gap preserves the relative order of
    /// every other thread's frames, so each chain stays LIFO on its own.
    fn remove_and_resume_parent(
        &mut self,
        index: usize,
        client: &ClientThreadIdentity,
        expected_parent: ContinuationKind,
    ) -> Result<(), ContinuationError> {
        if index >= self.len {
            return Err(ContinuationError::Underflow);
        }
        let mut slot = index;
        while slot + 1 < self.len {
            self.frames[slot] = self.frames[slot + 1];
            slot += 1;
        }
        self.len = self
            .len
            .checked_sub(1)
            .ok_or(ContinuationError::Underflow)?;
        self.frames[self.len] = None;
        if let Some(parent_index) = self.top_index_for(client) {
            let parent = self.frames[parent_index]
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
pub struct ClientCallbackWindowState {
    teb_alias: u64,
    saved: [u64; 3],
}

impl ClientCallbackWindowState {
    pub const fn new(teb_alias: u64, saved: [u64; 3]) -> Self {
        Self { teb_alias, saved }
    }

    pub const fn teb_alias(&self) -> u64 {
        self.teb_alias
    }

    pub const fn saved(&self) -> &[u64; 3] {
        &self.saved
    }
}

/// The win32k dispatch a callback frame suspended: everything needed to resume + re-answer the
/// client's original syscall. Frame-owned (it used to be a glue-side array indexed in lockstep with
/// the callback stack, which only works while frames are removed strictly top-first).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchContext {
    pub dispatch_id: u64,
    pub ssn: u64,
    pub args: [u64; 4],
    pub caller_sp: u64,
}

impl DispatchContext {
    pub const EMPTY: Self = Self {
        dispatch_id: 0,
        ssn: 0,
        args: [0; 4],
        caller_sp: 0,
    };
}

pub const CLIENT_TOKEN_USER_SID_MAX: usize = 68;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveCallbackClient {
    client_tcb: u64,
    client_runtime_role: u32,
    client_process_role: u32,
    client_top_badge: u64,
    client_pid: u64,
    client_teb: u64,
    client_peb_mirror: u64,
    client_scratch_base: u64,
    client_eprocess: u64,
    client_ethread: u64,
    client_token_authentication_id: u64,
    client_token_user_sid: [u8; CLIENT_TOKEN_USER_SID_MAX],
    client_token_user_sid_len: u32,
}

impl ActiveCallbackClient {
    pub const fn empty() -> Self {
        Self {
            client_tcb: 0,
            client_runtime_role: 0,
            client_process_role: 0,
            client_top_badge: 0,
            client_pid: 0,
            client_teb: 0,
            client_peb_mirror: 0,
            client_scratch_base: 0,
            client_eprocess: 0,
            client_ethread: 0,
            client_token_authentication_id: 0,
            client_token_user_sid: [0; CLIENT_TOKEN_USER_SID_MAX],
            client_token_user_sid_len: 0,
        }
    }

    pub const fn new(
        client_tcb: u64,
        client_runtime_role: u32,
        client_process_role: u32,
        client_top_badge: u64,
    ) -> Self {
        Self {
            client_tcb,
            client_runtime_role,
            client_process_role,
            client_top_badge,
            client_pid: 0,
            client_teb: 0,
            client_peb_mirror: 0,
            client_scratch_base: 0,
            client_eprocess: 0,
            client_ethread: 0,
            client_token_authentication_id: 0,
            client_token_user_sid: [0; CLIENT_TOKEN_USER_SID_MAX],
            client_token_user_sid_len: 0,
        }
    }

    #[inline(always)]
    fn clear(&mut self) {
        self.client_tcb = 0;
        self.client_runtime_role = 0;
        self.client_process_role = 0;
        self.client_top_badge = 0;
        self.client_pid = 0;
        self.client_teb = 0;
        self.client_peb_mirror = 0;
        self.client_scratch_base = 0;
        self.client_eprocess = 0;
        self.client_ethread = 0;
        self.client_token_authentication_id = 0;
        self.client_token_user_sid.fill(0);
        self.client_token_user_sid_len = 0;
    }

    pub const fn client_tcb(&self) -> u64 {
        self.client_tcb
    }

    pub const fn client_runtime_role(&self) -> u32 {
        self.client_runtime_role
    }

    pub const fn client_process_role(&self) -> u32 {
        self.client_process_role
    }

    pub const fn client_top_badge(&self) -> u64 {
        self.client_top_badge
    }

    pub const fn client_pid(&self) -> u64 {
        self.client_pid
    }

    pub const fn client_teb(&self) -> u64 {
        self.client_teb
    }

    pub const fn client_peb_mirror(&self) -> u64 {
        self.client_peb_mirror
    }

    pub const fn client_scratch_base(&self) -> u64 {
        self.client_scratch_base
    }

    pub const fn client_eprocess(&self) -> u64 {
        self.client_eprocess
    }

    pub const fn client_ethread(&self) -> u64 {
        self.client_ethread
    }

    pub const fn client_token_authentication_id(&self) -> u64 {
        self.client_token_authentication_id
    }

    pub const fn client_token_user_sid(&self) -> &[u8; CLIENT_TOKEN_USER_SID_MAX] {
        &self.client_token_user_sid
    }

    pub const fn client_token_user_sid_len(&self) -> u32 {
        self.client_token_user_sid_len
    }

    pub fn with_process_identity(
        mut self,
        client_pid: u64,
        client_teb: u64,
        client_peb_mirror: u64,
        client_scratch_base: u64,
        client_eprocess: u64,
        client_ethread: u64,
    ) -> Self {
        self.client_pid = client_pid;
        self.client_teb = client_teb;
        self.client_peb_mirror = client_peb_mirror;
        self.client_scratch_base = client_scratch_base;
        self.client_eprocess = client_eprocess;
        self.client_ethread = client_ethread;
        self
    }

    pub fn with_token(
        mut self,
        authentication_id: u64,
        user_sid: [u8; CLIENT_TOKEN_USER_SID_MAX],
        user_sid_len: u32,
    ) -> Self {
        self.client_token_authentication_id = authentication_id;
        self.client_token_user_sid = user_sid;
        self.client_token_user_sid_len = user_sid_len.min(CLIENT_TOKEN_USER_SID_MAX as u32);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveCallbackFrame {
    request: CallbackHeader,
    client: ActiveCallbackClient,
    saved_user_context: [u64; 20],
    outer_resume_ip: u64,
    redirected: bool,
    callback_window: Option<ClientCallbackWindowState>,
    dispatch_context: DispatchContext,
    /// The executive-bridged `CLIENTINFO.CallbackWnd` triple published for THIS frame
    /// (`hWnd`, client `PWND`, `pActCtx`); `[0]  == 0` means nothing was bridged.
    bridged_window: [u64; 3],
}

impl ActiveCallbackFrame {
    const fn empty() -> Self {
        Self {
            request: CallbackHeader::idle(0, 0, 0, 0),
            client: ActiveCallbackClient::empty(),
            saved_user_context: [0; 20],
            outer_resume_ip: 0,
            redirected: false,
            callback_window: None,
            dispatch_context: DispatchContext::EMPTY,
            bridged_window: [0; 3],
        }
    }

    #[inline(always)]
    fn clear(&mut self) {
        self.request.magic = CALLBACK_MAGIC;
        self.request.version = CALLBACK_VERSION;
        self.request.kind = CALLBACK_KIND_USER_MODE;
        self.request.state = CallbackState::Idle as u32;
        self.request.api_index = 0;
        self.request.input_length = 0;
        self.request.output_capacity = 0;
        self.request.output_length = 0;
        self.request.status = 0;
        self.request.client_pi = 0;
        self.request.callback_id = 0;
        self.request.payload_reference_offset = NO_PAYLOAD_REFERENCE;
        self.request.dispatch_id = 0;
        self.request.client_tid = 0;
        self.request.client_badge = 0;
        self.client.clear();
        self.saved_user_context.fill(0);
        self.outer_resume_ip = 0;
        self.redirected = false;
        self.callback_window = None;
        self.dispatch_context.dispatch_id = 0;
        self.dispatch_context.ssn = 0;
        self.dispatch_context.args.fill(0);
        self.dispatch_context.caller_sp = 0;
        self.bridged_window.fill(0);
    }

    pub const fn request(&self) -> &CallbackHeader {
        &self.request
    }

    pub const fn client_tcb(&self) -> u64 {
        self.client.client_tcb()
    }

    pub const fn client_runtime_role(&self) -> u32 {
        self.client.client_runtime_role()
    }

    pub const fn client_process_role(&self) -> u32 {
        self.client.client_process_role()
    }

    pub const fn client_top_badge(&self) -> u64 {
        self.client.client_top_badge()
    }

    pub const fn client_pid(&self) -> u64 {
        self.client.client_pid()
    }

    pub const fn client_teb(&self) -> u64 {
        self.client.client_teb()
    }

    pub const fn client_peb_mirror(&self) -> u64 {
        self.client.client_peb_mirror()
    }

    pub const fn client_scratch_base(&self) -> u64 {
        self.client.client_scratch_base()
    }

    pub const fn client_eprocess(&self) -> u64 {
        self.client.client_eprocess()
    }

    pub const fn client_ethread(&self) -> u64 {
        self.client.client_ethread()
    }

    pub const fn client_token_authentication_id(&self) -> u64 {
        self.client.client_token_authentication_id()
    }

    pub const fn client_token_user_sid(&self) -> &[u8; CLIENT_TOKEN_USER_SID_MAX] {
        self.client.client_token_user_sid()
    }

    pub const fn client_token_user_sid_len(&self) -> u32 {
        self.client.client_token_user_sid_len()
    }

    pub const fn dispatch_context(&self) -> &DispatchContext {
        &self.dispatch_context
    }

    pub const fn bridged_window(&self) -> &[u64; 3] {
        &self.bridged_window
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

    pub const fn callback_window(&self) -> Option<&ClientCallbackWindowState> {
        self.callback_window.as_ref()
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

    /// The frame at `index` (0 = outermost), or `None` past the live depth. Lets a caller ask
    /// whether a given client owns ANY outstanding frame, not just the innermost one — the
    /// distinction a per-thread park site needs before it declares a whole process a dead callback
    /// client.
    pub const fn frame(&self, index: usize) -> Option<&ActiveCallbackFrame> {
        if index >= self.len {
            None
        } else {
            Some(&self.frames[index])
        }
    }

    /// Index of the INNERMOST frame owned by `client`. Like [`ContinuationStack`], this array holds
    /// the interleaved frames of every client thread that has a callback outstanding, so "the top"
    /// is only ever meaningful per identity.
    fn top_index_for(&self, client: &ClientThreadIdentity) -> Option<usize> {
        (0..self.len).rev().find(|&index| {
            let request = &self.frames[index].request;
            request.client_pi == client.client_pi
                && request.client_tid == client.client_tid
                && request.client_badge == client.client_badge
        })
    }

    /// The innermost callback frame of ONE client thread.
    pub fn top_for(&self, client: &ClientThreadIdentity) -> Option<&ActiveCallbackFrame> {
        self.top_index_for(client).map(|index| &self.frames[index])
    }

    /// The innermost frame owned by ANY thread of `client_pi`. Because a process' threads all share
    /// the `pi`, the innermost such frame is necessarily the top of ITS OWN thread's chain — which
    /// is what lets the dead-client unwind tear a whole process down innermost-first.
    pub fn top_for_pi(&self, client_pi: u32) -> Option<&ActiveCallbackFrame> {
        (0..self.len)
            .rev()
            .find(|&index| self.frames[index].request.client_pi == client_pi)
            .map(|index| &self.frames[index])
    }

    /// The frame a correlation names: it must BE the innermost frame of that correlation's client
    /// thread, and match the correlation exactly. Together those two conditions are strictly
    /// stronger than the old "must be the array's top", and they are what make an interleaved array
    /// safe: a stale or cross-thread correlation resolves to nothing.
    fn correlated_index(
        &self,
        correlation: &CallbackCorrelation,
    ) -> Result<usize, ValidationError> {
        let client = ClientThreadIdentity::new(
            correlation.client_pi,
            correlation.client_tid,
            correlation.client_badge,
        );
        let index = self.top_index_for(&client).ok_or(ValidationError::State)?;
        if !correlation.matches_request(&self.frames[index].request) {
            return Err(ValidationError::Correlation);
        }
        Ok(index)
    }

    /// Does this correlation name the physical top of the interleaved callback array?
    ///
    /// A callback return can be logically valid for its own client thread while another thread's
    /// callback frame sits above it. That is safe for purely model-level stack mutation, but a
    /// userspace-hosted kernel component with one reply binding can only resume the global top.
    pub fn is_global_top(&self, correlation: CallbackCorrelation) -> Result<bool, ValidationError> {
        let index = self.correlated_index(&correlation)?;
        Ok(index + 1 == self.len)
    }

    pub fn push(
        &mut self,
        request: CallbackHeader,
        client_tcb: u64,
    ) -> Result<(), ValidationError> {
        self.push_with_client_runtime_role(request, client_tcb, 0)
    }

    pub fn push_with_client_runtime_role(
        &mut self,
        request: CallbackHeader,
        client_tcb: u64,
        client_runtime_role: u32,
    ) -> Result<(), ValidationError> {
        self.push_with_client_metadata(request, client_tcb, client_runtime_role, 0, 0)
    }

    pub fn push_with_client_metadata(
        &mut self,
        request: CallbackHeader,
        client_tcb: u64,
        client_runtime_role: u32,
        client_process_role: u32,
        client_top_badge: u64,
    ) -> Result<(), ValidationError> {
        self.push_with_active_client_metadata(
            request,
            ActiveCallbackClient::new(
                client_tcb,
                client_runtime_role,
                client_process_role,
                client_top_badge,
            ),
        )
    }

    pub fn push_with_active_client_metadata(
        &mut self,
        request: CallbackHeader,
        client: ActiveCallbackClient,
    ) -> Result<(), ValidationError> {
        validate_request(&request)?;
        if client.client_tcb <= 1 {
            return Err(ValidationError::State);
        }
        if self.len == DEPTH {
            return Err(ValidationError::Length);
        }
        self.frames[self.len] = ActiveCallbackFrame {
            request,
            client,
            saved_user_context: [0; 20],
            outer_resume_ip: 0,
            redirected: false,
            callback_window: None,
            dispatch_context: DispatchContext::EMPTY,
            bridged_window: [0; 3],
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
        let index = self.correlated_index(&correlation)?;
        let frame = &mut self.frames[index];
        if frame.redirected || outer_resume_ip == 0 {
            return Err(ValidationError::State);
        }
        frame.saved_user_context = saved_user_context;
        frame.outer_resume_ip = outer_resume_ip;
        frame.redirected = true;
        Ok(())
    }

    pub fn record_callback_window(
        &mut self,
        correlation: CallbackCorrelation,
        state: ClientCallbackWindowState,
    ) -> Result<(), ValidationError> {
        let index = self.correlated_index(&correlation)?;
        let frame = &mut self.frames[index];
        if frame.redirected || frame.callback_window.is_some() || state.teb_alias == 0 {
            return Err(ValidationError::State);
        }
        frame.callback_window = Some(state);
        Ok(())
    }

    /// Attach the win32k dispatch this callback suspended. Refuses a context from a different
    /// dispatch than the one the callback was raised inside.
    pub fn record_dispatch_context(
        &mut self,
        correlation: CallbackCorrelation,
        context: DispatchContext,
    ) -> Result<(), ValidationError> {
        let index = self.correlated_index(&correlation)?;
        if context.dispatch_id == 0 || context.dispatch_id != correlation.dispatch_id {
            return Err(ValidationError::Correlation);
        }
        self.frames[index].dispatch_context = context;
        Ok(())
    }

    /// Record the `CLIENTINFO.CallbackWnd` triple the executive bridged for this frame.
    pub fn record_bridged_window(
        &mut self,
        correlation: CallbackCorrelation,
        bridged: [u64; 3],
    ) -> Result<(), ValidationError> {
        let index = self.correlated_index(&correlation)?;
        self.frames[index].bridged_window = bridged;
        Ok(())
    }

    pub fn pop(
        &mut self,
        correlation: CallbackCorrelation,
    ) -> Result<ActiveCallbackFrame, ValidationError> {
        let index = self.correlated_index(&correlation)?;
        if !self.frames[index].redirected {
            return Err(ValidationError::State);
        }
        Ok(self.remove(index))
    }

    pub fn cancel_pending(
        &mut self,
        correlation: CallbackCorrelation,
    ) -> Result<ActiveCallbackFrame, ValidationError> {
        let index = self.correlated_index(&correlation)?;
        if self.frames[index].redirected {
            return Err(ValidationError::State);
        }
        Ok(self.remove(index))
    }

    /// Remove one frame and close the gap, preserving every other thread's relative frame order.
    fn remove(&mut self, index: usize) -> ActiveCallbackFrame {
        let frame = self.frames[index];
        let mut slot = index;
        while slot + 1 < self.len {
            self.frames[slot] = self.frames[slot + 1];
            slot += 1;
        }
        self.len -= 1;
        self.frames[self.len].clear();
        frame
    }

    pub fn discard_top(&mut self) -> Option<ActiveCallbackFrame> {
        let index = self.len.checked_sub(1)?;
        let frame = self.frames[index];
        self.frames[index].clear();
        self.len = index;
        Some(frame)
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
pub const USER_CONTEXT_RBX: usize = 4;
pub const USER_CONTEXT_RCX: usize = 5;
pub const USER_CONTEXT_RDX: usize = 6;
pub const USER_CONTEXT_RSI: usize = 7;
pub const USER_CONTEXT_RDI: usize = 8;
pub const USER_CONTEXT_RBP: usize = 9;
pub const USER_CONTEXT_R8: usize = 10;
pub const USER_CONTEXT_R9: usize = 11;
pub const USER_CONTEXT_R10: usize = 12;
pub const USER_CONTEXT_R11: usize = 13;
pub const USER_CONTEXT_R12: usize = 14;
pub const USER_CONTEXT_R13: usize = 15;
pub const USER_CONTEXT_R14: usize = 16;
pub const USER_CONTEXT_R15: usize = 17;
pub const USER_CONTEXT_FS_BASE: usize = 18;
pub const USER_CONTEXT_GS_BASE: usize = 19;

/// Build the context which starts `KiUserCallbackDispatcher` through the kernel's normal sysret
/// path. The dispatcher takes its arguments from the `UCALLOUT_FRAME` on RSP, so the kernel-facing
/// entry registers are scrubbed like ReactOS `KiUserCallbackExit`: stale interrupted syscall
/// registers must not leak into user32 or a client WndProc while the original outer syscall context
/// remains untouched in the caller's saved copy.
pub const fn callback_redirect_context(
    saved: &[u64; 20],
    dispatcher: u64,
    callback_sp: u64,
) -> [u64; 20] {
    let mut redirected = *saved;
    redirected[USER_CONTEXT_RIP] = dispatcher;
    redirected[USER_CONTEXT_RSP] = callback_sp;
    redirected[USER_CONTEXT_RAX] = 0;
    redirected[USER_CONTEXT_RBX] = 0;
    redirected[USER_CONTEXT_RCX] = dispatcher;
    redirected[USER_CONTEXT_RDX] = 0;
    redirected[USER_CONTEXT_RSI] = 0;
    redirected[USER_CONTEXT_RDI] = 0;
    redirected[USER_CONTEXT_RBP] = 0;
    redirected[USER_CONTEXT_R8] = 0;
    redirected[USER_CONTEXT_R9] = 0;
    redirected[USER_CONTEXT_R10] = 0;
    redirected[USER_CONTEXT_R11] = redirected[USER_CONTEXT_RFLAGS];
    redirected[USER_CONTEXT_R12] = 0;
    redirected[USER_CONTEXT_R13] = 0;
    redirected[USER_CONTEXT_R14] = 0;
    redirected[USER_CONTEXT_R15] = 0;
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

/// The post-syscall instruction pointer captured in a user context.
///
/// On x64 `syscall` saves the user return address in `RCX`. Some synthetic/test contexts only carry
/// `RIP`, so fall back to that when `RCX` is absent.
pub const fn syscall_resume_ip_from_context(saved: &[u64; 20]) -> u64 {
    let rcx = saved[USER_CONTEXT_RCX];
    if rcx == 0 {
        saved[USER_CONTEXT_RIP]
    } else {
        rcx
    }
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

// ═══ gdi32's DEFERRED GDI BATCH (`TEB.GdiTebBatch`) ═════════════════════════════════════════════
//
// `gdi32!GdiAllocBatchCommand` (`win32ss/gdi/gdi32/include/gdi32p.h:406`) appends each deferred GDI
// command to `TEB.GdiTebBatch.Buffer` at `Offset` and bumps `Offset` / `TEB.GdiBatchCount`. The
// KERNEL is what empties it: `KiSystemCallHandler` (`ntoskrnl/ke/amd64/traphandler.c:180`) calls
// `KeGdiFlushUserBatch` before dispatching ANY win32k system call whenever `GdiBatchCount != 0`, and
// `NtGdiFlushUserBatch` (`win32ss/gdi/ntgdi/gdibatch.c:487`) walks the records and then resets
// `Offset`/`GdiBatchCount`/`HDC`. A host that omits that step lets `Offset` grow past
// [`GDI_BATCH_BUF_SIZE`] and `GdiAllocBatchCommand` then writes GDI records straight through the
// rest of the caller's TEB.
//
// The layout constants and the record WALK live here — pure, host-tested — so the executive's
// `ke_gdi_flush_user_batch` is a thin reader over the client's TEB alias.

/// `GDIBATCHBUFSIZE` — `sizeof(GDI_TEB_BATCH.Buffer)` (310 `ULONG`s).
pub const GDI_BATCH_BUF_SIZE: u32 = 0x4D8;
/// `TEB.GdiTebBatch` (x64 TEB offset): `Offset` @ +0x00, `HDC` @ +0x08, `Buffer` @ +0x10.
pub const TEB_GDI_TEB_BATCH_OFFSET: u64 = 0x2F0;
/// `TEB.GdiTebBatch.HDC`.
pub const TEB_GDI_TEB_BATCH_HDC: u64 = 0x2F8;
/// `TEB.GdiTebBatch.Buffer` — where the records themselves start.
pub const TEB_GDI_TEB_BATCH_BUFFER: u64 = 0x300;
/// `TEB.GdiBatchCount` (x64).
pub const TEB_GDI_BATCH_COUNT: u64 = 0x1740;
/// `GDIBATCHCMD::GdiBCTextOut` (`win32ss/include/ntgdityp.h:88`) — a batched `TextOutW`.
pub const GDI_BC_TEXT_OUT: u16 = 2;
/// `sizeof(GDIBSTEXTOUT)` on x64 — the minimum size a `GdiBCTextOut` record can have.
pub const GDIBSTEXTOUT_SIZE: u32 = 0x58;
/// `GDIBSTEXTOUT.cbCount` (character count).
pub const GDIBSTEXTOUT_CBCOUNT: u32 = 0x38;
/// `GDIBSTEXTOUT.Size` — the byte count of the Dx array that PRECEDES the string.
pub const GDIBSTEXTOUT_DXSIZE: u32 = 0x3C;
/// `GDIBSTEXTOUT.String` — the inline UTF-16 text, after the Dx array (`objects/text.c:632`).
pub const GDIBSTEXTOUT_STRING: u32 = 0x54;

/// One record found by [`walk_gdi_batch`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GdiBatchRecord {
    /// Byte offset of the record within `GdiTebBatch.Buffer`.
    pub offset: u32,
    /// `GDIBATCHHDR.Size` — the record's total byte size (how the walk advances).
    pub size: u32,
    /// `GDIBATCHHDR.Cmd`.
    pub command: u16,
    /// For [`GDI_BC_TEXT_OUT`]: the character count and the buffer-relative byte offset of the
    /// inline UTF-16 string. `None` for every other command (and for a malformed text record).
    pub text: Option<(u32, u32)>,
}

/// Walk the `count` records `gdi32` appended to `buffer` (the first `offset` bytes of
/// `GdiTebBatch.Buffer`), exactly as `NtGdiFlushUserBatch` does: read `GDIBATCHHDR { SHORT Size;
/// SHORT Cmd; }`, hand the record to `visit`, advance by `Size`, stop on a zero/oversized `Size`.
/// Returns how many records were walked — which is less than `count` iff the list is malformed.
///
/// Every bound is checked against BOTH the live `offset` and [`GDI_BATCH_BUF_SIZE`], because the
/// whole point of the missing kernel step is that `Offset` can be a value the buffer cannot hold.
pub fn walk_gdi_batch(
    buffer: &[u8],
    offset: u32,
    count: u32,
    mut visit: impl FnMut(GdiBatchRecord),
) -> u32 {
    let limit = offset.min(GDI_BATCH_BUF_SIZE).min(buffer.len() as u32);
    let mut cursor = 0u32;
    let mut walked = 0u32;
    while walked < count && cursor + 4 <= limit {
        let base = cursor as usize;
        let size = u16::from_le_bytes([buffer[base], buffer[base + 1]]) as u32;
        let command = u16::from_le_bytes([buffer[base + 2], buffer[base + 3]]);
        if size < 4 || cursor + size > limit {
            break;
        }
        let text = if command == GDI_BC_TEXT_OUT && size >= GDIBSTEXTOUT_SIZE {
            let read = |field: u32| -> u32 {
                let at = base + field as usize;
                u32::from_le_bytes([buffer[at], buffer[at + 1], buffer[at + 2], buffer[at + 3]])
            };
            let chars = read(GDIBSTEXTOUT_CBCOUNT);
            let dx = read(GDIBSTEXTOUT_DXSIZE);
            let start = cursor
                .checked_add(GDIBSTEXTOUT_STRING)
                .and_then(|start| start.checked_add(dx));
            match start {
                Some(start)
                    if chars
                        .checked_mul(2)
                        .and_then(|bytes| start.checked_add(bytes))
                        .is_some_and(|end| end <= limit) =>
                {
                    Some((chars, start))
                }
                _ => None,
            }
        } else {
            None
        };
        visit(GdiBatchRecord {
            offset: cursor,
            size,
            command,
            text,
        });
        cursor += size;
        walked += 1;
    }
    walked
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
        assert_eq!(sequence.complete(NTUSER_PEEK_MESSAGE_SSN, 0, None), Ok(()));
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
    fn credential_injection_types_the_user_name_then_the_return_key() {
        let mut injection = CredentialInjectionSequence::new();
        assert_eq!(injection.begin(0x2008c, 0x20088), Ok(()));
        // Re-latching, a null control and the dialog itself are all rejected.
        assert_eq!(
            injection.begin(0x2008e, 0x20088),
            Err(ValidationError::Sequence)
        );
        // The RETURN key may not be posted before the whole user name is typed.
        assert_eq!(
            injection.record_return_post(0x2008c),
            Err(ValidationError::Sequence)
        );
        for index in 0..LOGON_USERNAME.len() {
            assert_eq!(injection.record_char_post(0x2008c, index), Ok(()));
        }
        // Out-of-order / foreign-window posts are rejected.
        assert_eq!(
            injection.record_char_post(0x2008c, LOGON_USERNAME.len()),
            Err(ValidationError::Sequence)
        );
        // ...and RETURN still may not be pressed until the real queue delivered every character.
        assert_eq!(
            injection.record_return_post(0x2008c),
            Err(ValidationError::Sequence)
        );
        for _ in 0..LOGON_USERNAME.len() {
            assert!(injection.observe_retrieved(0x2008c, WM_CHAR, b'A' as u64));
        }
        assert_eq!(
            injection.record_return_post(0x20088),
            Err(ValidationError::Sequence)
        );
        assert_eq!(injection.record_return_post(0x2008c), Ok(()));
        assert!(injection.is_injected());
        assert_eq!(injection.posted_chars() as usize, LOGON_USERNAME.len());
        assert!(!injection.keystrokes_delivered());
    }

    #[test]
    fn credential_injection_counts_only_the_real_queue_retrievals() {
        let mut injection = CredentialInjectionSequence::new();
        assert_eq!(injection.begin(0x2008c, 0x20088), Ok(()));
        for index in 0..LOGON_USERNAME.len() {
            assert_eq!(injection.record_char_post(0x2008c, index), Ok(()));
        }
        // A paint for another control is not a keystroke; a WM_CHAR for another window is not ours.
        assert!(!injection.observe_retrieved(0x2008c, WM_PAINT, 0));
        assert!(!injection.observe_retrieved(0x2008e, WM_CHAR, b'A' as u64));
        for _ in 0..LOGON_USERNAME.len() {
            assert!(injection.observe_retrieved(0x2008c, WM_CHAR, b'A' as u64));
        }
        // The queue can never hand back more characters than were typed.
        assert!(!injection.observe_retrieved(0x2008c, WM_CHAR, b'A' as u64));
        assert_eq!(injection.record_return_post(0x2008c), Ok(()));
        assert!(!injection.keystrokes_delivered());
        assert!(injection.observe_retrieved(0x2008c, WM_KEYDOWN, VK_RETURN));
        assert!(injection.keystrokes_delivered());
        assert_eq!(injection.retrieved_chars() as usize, LOGON_USERNAME.len());
    }

    #[test]
    fn credential_injection_routes_one_blocking_get_message_per_phase() {
        let mut injection = CredentialInjectionSequence::new();
        assert_eq!(injection.begin(0x2008c, 0x20088), Ok(()));
        // Nothing queued yet -> routing a blocking GetMessage would block win32k.
        assert!(!injection.may_route_get_message());
        for index in 0..LOGON_USERNAME.len() - 1 {
            assert_eq!(injection.record_char_post(0x2008c, index), Ok(()));
            assert!(!injection.may_route_get_message());
        }
        assert_eq!(
            injection.record_char_post(0x2008c, LOGON_USERNAME.len() - 1),
            Ok(())
        );
        // Phase 1 (the typed user name) is queued -> exactly one blocking GetMessage may run.
        assert!(injection.may_route_get_message());
        injection.record_routed_get_message();
        assert!(!injection.may_route_get_message());
        for _ in 0..LOGON_USERNAME.len() {
            assert!(injection.observe_retrieved(0x2008c, WM_CHAR, b'A' as u64));
        }
        assert!(!injection.may_route_get_message());
        // Phase 2 (RETURN) buys exactly one more.
        assert_eq!(injection.record_return_post(0x2008c), Ok(()));
        assert!(injection.may_route_get_message());
        injection.record_routed_get_message();
        assert!(!injection.may_route_get_message());
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
    fn chained_callback_uses_current_stack_but_inherited_completion_context() {
        let mut inherited = [0u64; 20];
        inherited[USER_CONTEXT_RIP] = 0x1000_8010;
        inherited[USER_CONTEXT_RSP] = 0x1001_05c3_000;
        inherited[USER_CONTEXT_RFLAGS] = 0x202;

        let mut current = inherited;
        current[USER_CONTEXT_RIP] = 0x801e_f0c1;
        current[USER_CONTEXT_RCX] = 0x801e_f0f8;
        current[USER_CONTEXT_RSP] = 0x1001_3f4f_e58;

        let layout = UserCallbackStackLayout::below(current[USER_CONTEXT_RSP], 0x40).unwrap();
        let redirected = callback_redirect_context(&current, 0x1000_9000, layout.frame_pointer);
        assert_eq!(redirected[USER_CONTEXT_RIP], 0x1000_9000);
        assert_eq!(redirected[USER_CONTEXT_RSP], layout.frame_pointer);
        assert!(layout.frame_pointer < current[USER_CONTEXT_RSP]);
        assert!(layout.frame_pointer > inherited[USER_CONTEXT_RSP]);

        let completed = completed_outer_context(&inherited, 0x1234, inherited[USER_CONTEXT_RIP]);
        assert_eq!(completed[USER_CONTEXT_RIP], inherited[USER_CONTEXT_RIP]);
        assert_eq!(completed[USER_CONTEXT_RSP], inherited[USER_CONTEXT_RSP]);
        assert_eq!(completed[USER_CONTEXT_RAX], 0x1234);
        assert_eq!(
            syscall_resume_ip_from_context(&current),
            current[USER_CONTEXT_RCX]
        );

        current[USER_CONTEXT_RCX] = 0;
        assert_eq!(
            syscall_resume_ip_from_context(&current),
            current[USER_CONTEXT_RIP]
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
    fn active_callback_contracts_validate_exact_payload_shapes() {
        let api0 = UserCallbackContract::for_api(USER32_CALLBACK_WINDOWPROC).unwrap();
        assert!(api0.accepts_request(0x40, 0x40, NO_PAYLOAD_REFERENCE));
        assert!(api0.accepts_request(0x90, 0x90, 0x40));
        assert!(!api0.accepts_request(0x38, 0x40, NO_PAYLOAD_REFERENCE));
        assert!(api0.accepts_result(0x90, 0x90, 0));

        let api7 = UserCallbackContract::for_api(USER32_CALLBACK_CLIENTTHREADSTARTUP).unwrap();
        assert!(api7.accepts_request(0, 16, NO_PAYLOAD_REFERENCE));
        assert_eq!(api7.minimum_result_capacity(0), Some(0));
        assert!(api7.accepts_result(0, 0, 0));
        assert!(!api7.requires_window_binding());

        let api3 = UserCallbackContract::for_api(USER32_CALLBACK_LOADDEFAULTCURSORS).unwrap();
        assert!(api3.accepts_request(4, 16, NO_PAYLOAD_REFERENCE));
        assert!(api3.accepts_result(4, 8, 0));
        assert!(!api3.accepts_result(4, 16, 0));

        let api11 = UserCallbackContract::for_api(USER32_CALLBACK_SETWNDICONS).unwrap();
        assert!(api11.accepts_request(0x38, 0x40, NO_PAYLOAD_REFERENCE));
        assert!(api11.accepts_result(0x38, 0x38, 0));

        let api15 = UserCallbackContract::for_api(USER32_CALLBACK_SETOBM).unwrap();
        assert!(api15.accepts_request(0x5d0, 0x5d0, NO_PAYLOAD_REFERENCE));
        assert!(api15.accepts_result(0x5d0, 0x5d0, 0));
        assert!(api15.accepts_result(0x5d0, 0, 0xc000_0001u32 as i32));
        let api16 = UserCallbackContract::for_api(USER32_CALLBACK_LPK).unwrap();
        assert!(api16.accepts_request(0x48, 0x50, NO_PAYLOAD_REFERENCE));
        assert!(api16.accepts_lpk_layout(0x48, 0x38, 6));
        assert!(!api16.accepts_lpk_layout(0x48, 0x40, 6));
        assert!(!api16.accepts_lpk_layout(0x48, 0x38, 7));
        assert_eq!(api16.minimum_result_capacity(0x48), Some(4));
        assert!(api16.accepts_result(0x48, 4, 0));
        assert_eq!(UserCallbackContract::for_api(4), None);
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
    fn continuation_stack_models_nine_nested_callback_levels() {
        let client = ClientThreadIdentity::new(2, 44, 4);
        let mut stack = ContinuationStack::<MAX_CONTINUATION_DEPTH>::new();
        let mut callbacks = [CallbackCorrelation {
            dispatch_id: 0,
            callback_id: 1,
            client_pi: 2,
            client_tid: 44,
            client_badge: 4,
        }; 9];

        for (depth, callback) in callbacks.iter_mut().enumerate() {
            callback.dispatch_id = 7 + depth as u64;
            stack.push_dispatch(client, callback.dispatch_id).unwrap();
            stack.push_callback(*callback).unwrap();
        }
        assert_eq!(stack.len(), 18);

        for callback in callbacks.iter().rev() {
            stack.return_callback(*callback).unwrap();
            stack
                .complete_dispatch(client, callback.dispatch_id)
                .unwrap();
        }
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

        // A return from a DIFFERENT client thread resolves against that thread's OWN chain, which is
        // empty — so it is rejected as `Underflow` (it cannot even see, let alone pop, this thread's
        // frames). Same guarantee as before the chains were split per thread: nothing is mutated.
        let mut wrong_thread = correlation;
        wrong_thread.client_tid += 1;
        assert_eq!(
            stack.return_callback(wrong_thread),
            Err(ContinuationError::Underflow)
        );
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.return_callback(correlation), Ok(()));
    }

    /// ★ THE WALL-B INVARIANT. Two threads of ONE process each run their own dispatch/callback
    /// chain, interleaved in the single array. A dispatch from thread B while thread A sits inside a
    /// callback is a CONCURRENT ROOT dispatch — it must neither be refused nor suspend A's callback,
    /// and each thread must still unwind its own chain in LIFO order whichever order they finish in.
    #[test]
    fn continuation_chains_of_two_threads_of_one_process_interleave() {
        let a = ClientThreadIdentity::new(2, 6, 4);
        let b = ClientThreadIdentity::new(2, 21, 13);
        let a_callback = CallbackCorrelation {
            dispatch_id: 10,
            callback_id: 1,
            client_pi: 2,
            client_tid: 6,
            client_badge: 4,
        };
        let b_callback = CallbackCorrelation {
            dispatch_id: 20,
            callback_id: 2,
            client_pi: 2,
            client_tid: 21,
            client_badge: 13,
        };
        let mut stack = ContinuationStack::<8>::new();
        // A: root dispatch -> callback (A is now redirected into user mode).
        stack.push_dispatch(a, a_callback.dispatch_id).unwrap();
        stack.push_callback(a_callback).unwrap();
        // B's win32k call arrives. It is B's ROOT dispatch, not a nested one on A.
        stack.push_dispatch(b, b_callback.dispatch_id).unwrap();
        assert_eq!(stack.len_for(&a), 2);
        assert_eq!(stack.len_for(&b), 1);
        // A's callback is STILL RUNNING — B's dispatch must not have suspended it.
        assert_eq!(stack.top_for(&a).unwrap().state, ContinuationState::Running);
        // A nested syscall from A, on top of A's own callback, still nests correctly.
        stack.push_dispatch(a, 11).unwrap();
        assert_eq!(
            stack.top_for(&a).unwrap().kind,
            ContinuationKind::Win32kDispatch
        );
        assert_eq!(stack.complete_dispatch(a, 11), Ok(()));
        assert_eq!(stack.top_for(&a).unwrap().state, ContinuationState::Running);
        // B raises a callback of its own, returns it, and completes — OUT of global LIFO order.
        stack.push_callback(b_callback).unwrap();
        assert_eq!(stack.return_callback(b_callback), Ok(()));
        assert_eq!(stack.complete_dispatch(b, b_callback.dispatch_id), Ok(()));
        assert!(stack.is_empty_for(&b));
        // A's chain survived intact and unwinds normally.
        assert_eq!(stack.len_for(&a), 2);
        assert_eq!(stack.return_callback(a_callback), Ok(()));
        assert_eq!(stack.complete_dispatch(a, a_callback.dispatch_id), Ok(()));
        assert!(stack.is_empty());
    }

    /// The interleaved ACTIVE stack: two threads redirected at once, each `NtCallbackReturn`
    /// resolving to its OWN frame and carrying its OWN suspended dispatch.
    #[test]
    fn active_callback_frames_of_two_threads_pop_by_identity() {
        let mut stack = ActiveCallbackStack::<4>::new();
        let mut a = CallbackHeader::idle(10, 2, 6, 4);
        a.state = CallbackState::Request as u32;
        a.callback_id = 1;
        a.api_index = USER32_CALLBACK_WINDOWPROC;
        a.output_capacity = 0x40;
        let mut b = a;
        b.dispatch_id = 20;
        b.callback_id = 2;
        b.client_tid = 21;
        b.client_badge = 13;
        stack
            .push_with_active_client_metadata(
                a,
                ActiveCallbackClient::new(0xaaa0, 0x11, 0x31, 0x41)
                    .with_process_identity(0x51, 0x61, 0x71, 0x81, 0x91, 0xa1)
                    .with_token(0xb1, [0xaa; CLIENT_TOKEN_USER_SID_MAX], 0x12),
            )
            .unwrap();
        stack
            .push_with_active_client_metadata(
                b,
                ActiveCallbackClient::new(0xbbb0, 0x22, 0x32, 0x42)
                    .with_process_identity(0x52, 0x62, 0x72, 0x82, 0x92, 0xa2)
                    .with_token(0xb2, [0xbb; CLIENT_TOKEN_USER_SID_MAX], 0x13),
            )
            .unwrap();
        let ca = CallbackCorrelation::from_request(&a);
        let cb = CallbackCorrelation::from_request(&b);
        stack
            .record_dispatch_context(
                ca,
                DispatchContext {
                    dispatch_id: 10,
                    ssn: 0x1050,
                    args: [1, 2, 3, 4],
                    caller_sp: 0x1000,
                },
            )
            .unwrap();
        stack
            .record_dispatch_context(
                cb,
                DispatchContext {
                    dispatch_id: 20,
                    ssn: 0x1076,
                    args: [5, 6, 7, 8],
                    caller_sp: 0x2000,
                },
            )
            .unwrap();
        stack.record_redirect(ca, [7; 20], 0xdead).unwrap();
        stack.record_redirect(cb, [9; 20], 0xbeef).unwrap();
        assert_eq!(stack.is_global_top(ca), Ok(false));
        assert_eq!(stack.is_global_top(cb), Ok(true));
        // A returns FIRST, from underneath B's frame.
        let popped_a = stack.pop(ca).unwrap();
        assert_eq!(popped_a.client_tcb(), 0xaaa0);
        assert_eq!(popped_a.client_runtime_role(), 0x11);
        assert_eq!(popped_a.client_process_role(), 0x31);
        assert_eq!(popped_a.client_top_badge(), 0x41);
        assert_eq!(popped_a.client_pid(), 0x51);
        assert_eq!(popped_a.client_teb(), 0x61);
        assert_eq!(popped_a.client_peb_mirror(), 0x71);
        assert_eq!(popped_a.client_scratch_base(), 0x81);
        assert_eq!(popped_a.client_eprocess(), 0x91);
        assert_eq!(popped_a.client_ethread(), 0xa1);
        assert_eq!(popped_a.client_token_authentication_id(), 0xb1);
        assert_eq!(popped_a.client_token_user_sid()[0], 0xaa);
        assert_eq!(popped_a.client_token_user_sid_len(), 0x12);
        assert_eq!(popped_a.dispatch_context().ssn, 0x1050);
        assert_eq!(popped_a.outer_resume_ip(), 0xdead);
        assert_eq!(stack.len(), 1);
        // B's frame survived the middle-removal with its own context intact.
        let identity_b = ClientThreadIdentity::new(2, 21, 13);
        assert_eq!(
            stack.top_for(&identity_b).unwrap().dispatch_context().ssn,
            0x1076
        );
        let popped_b = stack.pop(cb).unwrap();
        assert_eq!(popped_b.client_tcb(), 0xbbb0);
        assert_eq!(popped_b.client_runtime_role(), 0x22);
        assert_eq!(popped_b.client_process_role(), 0x32);
        assert_eq!(popped_b.client_top_badge(), 0x42);
        assert_eq!(popped_b.client_pid(), 0x52);
        assert_eq!(popped_b.client_teb(), 0x62);
        assert_eq!(popped_b.client_peb_mirror(), 0x72);
        assert_eq!(popped_b.client_scratch_base(), 0x82);
        assert_eq!(popped_b.client_eprocess(), 0x92);
        assert_eq!(popped_b.client_ethread(), 0xa2);
        assert_eq!(popped_b.client_token_authentication_id(), 0xb2);
        assert_eq!(popped_b.client_token_user_sid()[0], 0xbb);
        assert_eq!(popped_b.client_token_user_sid_len(), 0x13);
        assert_eq!(popped_b.dispatch_context().caller_sp, 0x2000);
        assert!(stack.is_empty());
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
        outer
            .begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40)
            .unwrap();
        let mut inner = CallbackHeader::idle(8, 2, 44, 4);
        inner
            .begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40)
            .unwrap();
        let outer_correlation = CallbackCorrelation::from_request(&outer);
        let inner_correlation = CallbackCorrelation::from_request(&inner);
        let mut stack = ActiveCallbackStack::<2>::new();

        stack.push(outer, 0xaaa0).unwrap();
        stack
            .record_callback_window(
                outer_correlation,
                ClientCallbackWindowState::new(0xaaaa, [0x11, 0x12, 0x13]),
            )
            .unwrap();
        stack
            .record_redirect(outer_correlation, [0x11; 20], 0x1111)
            .unwrap();
        stack.push(inner, 0xbbb0).unwrap();
        stack
            .record_callback_window(
                inner_correlation,
                ClientCallbackWindowState::new(0xbbbb, [0x21, 0x22, 0x23]),
            )
            .unwrap();
        stack
            .record_redirect(inner_correlation, [0x22; 20], 0x2222)
            .unwrap();

        let completed_inner = stack.pop(inner_correlation).unwrap();
        assert_eq!(completed_inner.saved_user_context(), &[0x22; 20]);
        assert_eq!(completed_inner.outer_resume_ip(), 0x2222);
        assert_eq!(
            completed_inner.callback_window(),
            Some(&ClientCallbackWindowState::new(0xbbbb, [0x21, 0x22, 0x23]))
        );
        assert_eq!(stack.top().unwrap().request(), &outer);
        let completed_outer = stack.pop(outer_correlation).unwrap();
        assert_eq!(completed_outer.saved_user_context(), &[0x11; 20]);
        assert_eq!(
            completed_outer.callback_window(),
            Some(&ClientCallbackWindowState::new(0xaaaa, [0x11, 0x12, 0x13]))
        );
        assert!(stack.is_empty());
    }

    /// `frame(index)` must see EVERY level, not just the innermost — a park site asks "does this
    /// client own ANY outstanding frame?" before deciding whether the whole process is a dead
    /// callback client, and a buried frame is exactly the case `top()` alone would miss.
    #[test]
    fn active_callback_stack_frame_index_sees_every_level() {
        let mut outer = CallbackHeader::idle(7, 2, 44, 4); // client_pi 2
        outer
            .begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40)
            .unwrap();
        let mut inner = CallbackHeader::idle(8, 3, 55, 5); // a DIFFERENT client_pi
        inner
            .begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40)
            .unwrap();
        let mut stack = ActiveCallbackStack::<2>::new();

        assert!(stack.frame(0).is_none());
        stack.push(outer, 0xaaa0).unwrap();
        stack.push(inner, 0xbbb0).unwrap();

        assert_eq!(stack.frame(0).unwrap().request().client_pi, 2);
        assert_eq!(stack.frame(1).unwrap().request().client_pi, 3);
        assert!(stack.frame(2).is_none(), "no read past the live depth");
        // The buried pi-2 frame is invisible to `top()` but must be visible to `frame()`.
        assert_eq!(stack.top().unwrap().request().client_pi, 3);
        let owned_by_two = (0..stack.len())
            .filter(|i| stack.frame(*i).unwrap().request().client_pi == 2)
            .count();
        assert_eq!(owned_by_two, 1);
    }

    #[test]
    fn active_callback_stack_rejects_stale_return_and_overflow() {
        let mut request = CallbackHeader::idle(7, 2, 44, 4);
        request
            .begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40)
            .unwrap();
        let correlation = CallbackCorrelation::from_request(&request);
        let mut missing_tcb = ActiveCallbackStack::<1>::new();
        assert_eq!(missing_tcb.push(request, 1), Err(ValidationError::State));
        let mut stack = ActiveCallbackStack::<1>::new();
        stack.push(request, 0xaaa0).unwrap();
        assert_eq!(stack.push(request, 0xbbb0), Err(ValidationError::Length));
        let mut stale = correlation;
        stale.callback_id += 1;
        let callback_window = ClientCallbackWindowState::new(0xaaaa, [1, 2, 3]);
        assert_eq!(
            stack.record_callback_window(stale, callback_window),
            Err(ValidationError::Correlation)
        );
        assert_eq!(stack.top().unwrap().callback_window(), None);
        stack
            .record_callback_window(correlation, callback_window)
            .unwrap();
        assert_eq!(
            stack.record_redirect(stale, [0; 20], 0x1000),
            Err(ValidationError::Correlation)
        );
        stack.record_redirect(correlation, [0; 20], 0x1000).unwrap();
        assert_eq!(stack.pop(stale), Err(ValidationError::Correlation));
        assert_eq!(stack.len(), 1);
        assert_eq!(
            stack.top().unwrap().callback_window(),
            Some(&callback_window)
        );
    }

    #[test]
    fn active_callback_cancel_returns_callback_window_state() {
        let mut request = CallbackHeader::idle(7, 2, 44, 4);
        request
            .begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40)
            .unwrap();
        let correlation = CallbackCorrelation::from_request(&request);
        let callback_window = ClientCallbackWindowState::new(0xaaaa, [1, 2, 3]);
        let mut stack = ActiveCallbackStack::<1>::new();
        stack.push(request, 0xaaa0).unwrap();
        stack
            .record_callback_window(correlation, callback_window)
            .unwrap();

        let cancelled = stack.cancel_pending(correlation).unwrap();
        assert_eq!(cancelled.callback_window(), Some(&callback_window));
        assert!(stack.is_empty());
    }

    #[test]
    fn active_callback_abort_discards_window_state_lifo() {
        let mut outer = CallbackHeader::idle(7, 2, 44, 4);
        outer
            .begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40)
            .unwrap();
        let mut inner = CallbackHeader::idle(8, 2, 44, 4);
        inner
            .begin_request(USER32_CALLBACK_WINDOWPROC, 0x40, 0x40)
            .unwrap();
        let outer_correlation = CallbackCorrelation::from_request(&outer);
        let inner_correlation = CallbackCorrelation::from_request(&inner);
        let outer_window = ClientCallbackWindowState::new(0xaaaa, [1, 2, 3]);
        let inner_window = ClientCallbackWindowState::new(0xbbbb, [4, 5, 6]);
        let mut stack = ActiveCallbackStack::<2>::new();
        stack.push(outer, 0xaaa0).unwrap();
        stack
            .record_callback_window(outer_correlation, outer_window)
            .unwrap();
        stack.push(inner, 0xbbb0).unwrap();
        stack
            .record_callback_window(inner_correlation, inner_window)
            .unwrap();

        assert_eq!(
            stack.discard_top().unwrap().callback_window(),
            Some(&inner_window)
        );
        assert_eq!(
            stack.discard_top().unwrap().callback_window(),
            Some(&outer_window)
        );
        assert_eq!(stack.discard_top(), None);
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
    fn callback_redirect_context_uses_scrubbed_dispatcher_entry() {
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
        for index in [
            USER_CONTEXT_RBX,
            USER_CONTEXT_RDX,
            USER_CONTEXT_RSI,
            USER_CONTEXT_RDI,
            USER_CONTEXT_RBP,
            USER_CONTEXT_R8,
            USER_CONTEXT_R9,
            USER_CONTEXT_R12,
            USER_CONTEXT_R13,
            USER_CONTEXT_R14,
            USER_CONTEXT_R15,
        ] {
            assert_eq!(redirected[index], 0, "register index {index}");
        }
        assert_eq!(redirected[USER_CONTEXT_RFLAGS], saved[USER_CONTEXT_RFLAGS]);
        assert_eq!(
            redirected[USER_CONTEXT_FS_BASE],
            saved[USER_CONTEXT_FS_BASE]
        );
        assert_eq!(
            redirected[USER_CONTEXT_GS_BASE],
            saved[USER_CONTEXT_GS_BASE]
        );
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

#[cfg(test)]
mod gdi_batch_tests {
    extern crate alloc;
    use super::*;

    /// Build one `GDIBSTEXTOUT` record carrying `text`, with an optional Dx array before the string.
    fn text_out_record(text: &[u16], dx_bytes: u32) -> alloc::vec::Vec<u8> {
        let size = GDIBSTEXTOUT_STRING + dx_bytes + (text.len() as u32 * 2);
        let size = (size + 7) & !7; // gdi32 keeps records 8-aligned
        let mut record = alloc::vec![0u8; size as usize];
        record[0..2].copy_from_slice(&(size as u16).to_le_bytes());
        record[2..4].copy_from_slice(&GDI_BC_TEXT_OUT.to_le_bytes());
        let at = GDIBSTEXTOUT_CBCOUNT as usize;
        record[at..at + 4].copy_from_slice(&(text.len() as u32).to_le_bytes());
        let at = GDIBSTEXTOUT_DXSIZE as usize;
        record[at..at + 4].copy_from_slice(&dx_bytes.to_le_bytes());
        let mut at = (GDIBSTEXTOUT_STRING + dx_bytes) as usize;
        for unit in text {
            record[at..at + 2].copy_from_slice(&unit.to_le_bytes());
            at += 2;
        }
        record
    }

    fn buffer_of(records: &[alloc::vec::Vec<u8>]) -> (alloc::vec::Vec<u8>, u32) {
        let mut buffer = alloc::vec![0u8; GDI_BATCH_BUF_SIZE as usize];
        let mut offset = 0usize;
        for record in records {
            buffer[offset..offset + record.len()].copy_from_slice(record);
            offset += record.len();
        }
        (buffer, offset as u32)
    }

    fn read_text(buffer: &[u8], start: u32, chars: u32) -> alloc::vec::Vec<u16> {
        (0..chars as usize)
            .map(|index| {
                let at = start as usize + index * 2;
                u16::from_le_bytes([buffer[at], buffer[at + 1]])
            })
            .collect()
    }

    #[test]
    fn walk_finds_every_record_and_locates_the_inline_string() {
        let first: alloc::vec::Vec<u16> = "Administrator".encode_utf16().collect();
        let second: alloc::vec::Vec<u16> = "ok".encode_utf16().collect();
        let (buffer, offset) = buffer_of(&[
            text_out_record(&first, 0),
            text_out_record(&second, 8), // a Dx array shifts the string
        ]);
        let mut seen = alloc::vec::Vec::new();
        let walked = walk_gdi_batch(&buffer, offset, 2, |record| {
            let (chars, start) = record.text.expect("both records are GdiBCTextOut");
            seen.push(read_text(&buffer, start, chars));
        });
        assert_eq!(walked, 2);
        assert_eq!(seen, alloc::vec![first, second]);
    }

    #[test]
    fn walk_reports_non_text_commands_without_a_string() {
        let mut record = alloc::vec![0u8; 0x20];
        record[0..2].copy_from_slice(&0x20u16.to_le_bytes());
        record[2..4].copy_from_slice(&7u16.to_le_bytes()); // GdiBCDelObj
        let (buffer, offset) = buffer_of(&[record]);
        let mut commands = alloc::vec::Vec::new();
        assert_eq!(
            walk_gdi_batch(&buffer, offset, 1, |r| {
                assert!(r.text.is_none());
                commands.push(r.command);
            }),
            1
        );
        assert_eq!(commands, alloc::vec![7u16]);
    }

    #[test]
    fn walk_stops_on_a_zero_or_oversized_size_instead_of_running_away() {
        let (mut buffer, _) = buffer_of(&[text_out_record(&[b'A' as u16], 0)]);
        // A second "record" whose Size is 0 must terminate the walk, not spin.
        let offset = GDIBSTEXTOUT_STRING + 8;
        assert_eq!(walk_gdi_batch(&buffer, offset, 8, |_| {}), 1);
        // A Size that runs past the live Offset is refused outright.
        buffer[0..2].copy_from_slice(&(GDI_BATCH_BUF_SIZE as u16 + 8).to_le_bytes());
        assert_eq!(walk_gdi_batch(&buffer, offset, 8, |_| {}), 0);
    }

    #[test]
    fn walk_is_bounded_by_the_buffer_even_when_offset_ran_away() {
        // ★ THE BUG this exists for: without the kernel flush, `GdiTebBatch.Offset` grows PAST the
        // buffer (it is what marched GDI records through the rest of the TEB). The walk must clamp
        // to GDIBATCHBUFSIZE and to the slice, never to the caller's Offset.
        let (buffer, _) = buffer_of(&[text_out_record(&[b'Z' as u16], 0)]);
        let walked = walk_gdi_batch(&buffer, 0x1398, 64, |record| {
            assert!(record.offset + record.size <= GDI_BATCH_BUF_SIZE);
        });
        assert_eq!(walked, 1); // the one real record, then the zeroed tail stops it
    }

    #[test]
    fn a_text_record_whose_string_would_leave_the_buffer_reports_no_text() {
        let mut record = text_out_record(&[b'A' as u16; 4], 0);
        // Claim far more characters than the record holds.
        let at = GDIBSTEXTOUT_CBCOUNT as usize;
        record[at..at + 4].copy_from_slice(&4096u32.to_le_bytes());
        let (buffer, offset) = buffer_of(&[record]);
        let mut records = 0;
        walk_gdi_batch(&buffer, offset, 1, |r| {
            assert!(r.text.is_none());
            records += 1;
        });
        assert_eq!(records, 1);
    }
}
