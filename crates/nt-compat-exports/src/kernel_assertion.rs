//! Bounded, allocation-free capture of the four native `RtlAssert` inputs.

const FIELD_CAPACITY: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundedField {
    bytes: [u8; FIELD_CAPACITY],
    len: usize,
}

impl BoundedField {
    fn capture(input: &[u8]) -> Self {
        let len = input
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(input.len())
            .min(FIELD_CAPACITY);
        let mut bytes = [0; FIELD_CAPACITY];
        bytes[..len].copy_from_slice(&input[..len]);
        Self { bytes, len }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Owned diagnostic fields for an assertion that must not return to its caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertionRecord {
    assertion: BoundedField,
    file: BoundedField,
    line: u32,
    message: Option<BoundedField>,
}

impl AssertionRecord {
    pub fn assertion(&self) -> &[u8] {
        self.assertion.as_bytes()
    }

    pub fn file(&self) -> &[u8] {
        self.file.as_bytes()
    }

    pub fn line(&self) -> u32 {
        self.line
    }

    pub fn message(&self) -> Option<&[u8]> {
        self.message.as_ref().map(BoundedField::as_bytes)
    }
}

/// Copies at most 128 bytes of each C-string field, stopping at its first NUL.
pub fn capture_bounded(
    assertion: &[u8],
    file: &[u8],
    line: u32,
    message: Option<&[u8]>,
) -> AssertionRecord {
    AssertionRecord {
        assertion: BoundedField::capture(assertion),
        file: BoundedField::capture(file),
        line,
        message: message.map(BoundedField::capture),
    }
}
