//! `NtGdiGetTextMetricsW` as ReactOS win32k implements it (`win32ss/gdi/ntgdi/text.c`):
//!
//! ```c
//! W32KAPI BOOL APIENTRY NtGdiGetTextMetricsW(HDC hDC, PTMW_INTERNAL pUnsafeTmwi, ULONG cj);
//! ```
//!
//! win32k accepts `cj <= sizeof(TMW_INTERNAL)`, fills a private `TMW_INTERNAL` and copies
//! exactly `cj` bytes to the caller only when it returns TRUE. The executive stages the output
//! in provider memory and returns it through `win32k_staged_output` on every completion path:
//! gdi32 returns the caller's `TEXTMETRICW` from that buffer whenever the call returns TRUE.

/// The pinned LiberNT win32k's service number (`win32ss/w32ksvc64.h`).
pub const GET_TEXT_METRICS_W_SSN: u64 = 0x1076;
/// `sizeof(TMW_INTERNAL)`: `TEXTMETRICW` (60 bytes) followed by `TMDIFF` (8 bytes).
pub const TMW_INTERNAL_BYTES: usize = 68;
const TM_HEIGHT_OFFSET: usize = 0;
const TM_EXTERNAL_LEADING_OFFSET: usize = 16;
const TM_AVE_CHAR_WIDTH_OFFSET: usize = 20;
const TM_MAX_CHAR_WIDTH_OFFSET: usize = 24;

/// The caller's arguments, each at its declared width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextMetricsCall {
    pub output: u64,
    pub bytes: usize,
}

/// A call win32k refuses before touching the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextMetricsCallError {
    /// `cj` exceeds `sizeof(TMW_INTERNAL)`.
    TooLarge,
    /// A non-empty copy to a NULL buffer, which win32k's probe rejects.
    NullOutput,
}

impl TextMetricsCall {
    /// `args` are the caller's registers `hdc, pUnsafeTmwi, cj, -`.
    pub fn capture(args: [u64; 4]) -> Result<Self, TextMetricsCallError> {
        let bytes = args[2] as u32 as usize;
        if bytes > TMW_INTERNAL_BYTES {
            return Err(TextMetricsCallError::TooLarge);
        }
        if bytes != 0 && args[1] == 0 {
            return Err(TextMetricsCallError::NullOutput);
        }
        Ok(Self { output: args[1], bytes })
    }

    /// How many staged bytes go back to the caller for the provider's `result`: the full
    /// request when win32k returned TRUE, nothing otherwise.
    pub fn copy_back_bytes(&self, result: u64) -> usize {
        if result as u32 != 0 { self.bytes } else { 0 }
    }
}

/// The metrics a console or text layout divides by, read from a returned `TEXTMETRICW`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextMetricsSummary {
    pub height: i32,
    pub external_leading: i32,
    pub ave_char_width: i32,
    pub max_char_width: i32,
}

impl TextMetricsSummary {
    /// `None` when fewer bytes than the metrics' fields were returned.
    pub fn read(tmw: &[u8]) -> Option<Self> {
        let at = |offset: usize| {
            tmw.get(offset..offset + 4)
                .map(|bytes| i32::from_le_bytes(bytes.try_into().unwrap()))
        };
        Some(Self {
            height: at(TM_HEIGHT_OFFSET)?,
            external_leading: at(TM_EXTERNAL_LEADING_OFFSET)?,
            ave_char_width: at(TM_AVE_CHAR_WIDTH_OFFSET)?,
            max_char_width: at(TM_MAX_CHAR_WIDTH_OFFSET)?,
        })
    }

    /// ReactOS FillTM never reports a zero cell on success; zero means the output was lost.
    pub fn has_zero_cell(&self) -> bool {
        self.height == 0 || self.ave_char_width == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdi32_requests_the_whole_tmw_internal() {
        let call = TextMetricsCall::capture([0x0101_0042, 0x7_0000_8f00, 68, 0]).unwrap();
        assert_eq!(call, TextMetricsCall { output: 0x7_0000_8f00, bytes: 68 });
        // cj is a ULONG: only the low half of the register is defined.
        let call = TextMetricsCall::capture([0, 0x7_0000_8f00, 0xdead_0000_0044, 0]).unwrap();
        assert_eq!(call.bytes, 68);
    }

    #[test]
    fn win32k_refuses_oversized_or_null_requests() {
        assert_eq!(TextMetricsCall::capture([0, 0x1000, 69, 0]), Err(TextMetricsCallError::TooLarge));
        assert_eq!(TextMetricsCall::capture([0, 0, 68, 0]), Err(TextMetricsCallError::NullOutput));
        assert_eq!(TextMetricsCall::capture([0, 0, 0, 0]), Ok(TextMetricsCall { output: 0, bytes: 0 }));
    }

    #[test]
    fn only_a_true_result_returns_the_metrics() {
        let call = TextMetricsCall::capture([0, 0x1000, 68, 0]).unwrap();
        assert_eq!(call.copy_back_bytes(1), 68);
        assert_eq!(call.copy_back_bytes(0), 0);
        // BOOL: the upper half of the return register is undefined.
        assert_eq!(call.copy_back_bytes(0xffff_ffff_0000_0000), 0);
    }

    #[test]
    fn the_summary_reads_textmetricw_offsets() {
        let mut tmw = [0u8; TMW_INTERNAL_BYTES];
        tmw[0..4].copy_from_slice(&16i32.to_le_bytes());
        tmw[16..20].copy_from_slice(&1i32.to_le_bytes());
        tmw[20..24].copy_from_slice(&8i32.to_le_bytes());
        tmw[24..28].copy_from_slice(&9i32.to_le_bytes());
        let summary = TextMetricsSummary::read(&tmw).unwrap();
        assert_eq!(
            summary,
            TextMetricsSummary { height: 16, external_leading: 1, ave_char_width: 8, max_char_width: 9 }
        );
        assert!(!summary.has_zero_cell());
        assert!(TextMetricsSummary::read(&[0u8; TMW_INTERNAL_BYTES]).unwrap().has_zero_cell());
        assert_eq!(TextMetricsSummary::read(&tmw[..27]), None);
    }
}
