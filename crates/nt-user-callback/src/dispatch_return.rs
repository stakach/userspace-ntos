//! Operation provenance carried by an already authenticated physical dispatch completion.
//! Correlation is not capability authority; native adapters must retain their existing lane owner.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchReturn {
    Refused(u32),
    HandlerReturned(u64),
}

impl DispatchReturn {
    pub const fn handler_value(self) -> Option<u64> {
        match self {
            Self::HandlerReturned(value) => Some(value),
            Self::Refused(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchReturnError {
    Incomplete,
    Correlation,
    InvalidDisposition,
    ResultMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct DispatchReturnReceipt {
    words: [u64; 4],
}

impl DispatchReturnReceipt {
    pub const fn from_words(words: [u64; 4]) -> Self {
        Self { words }
    }
    pub const fn words(self) -> [u64; 4] {
        self.words
    }
    pub const fn refused(dispatch_id: u64, ssn: u64, status: u32) -> Self {
        Self::from_words([dispatch_id, ssn, 1, status as u64])
    }
    pub const fn handler_returned(dispatch_id: u64, ssn: u64, value: u64) -> Self {
        Self::from_words([dispatch_id, ssn, 2, value])
    }
    pub fn authenticate(
        self,
        dispatch_id: u64,
        ssn: u64,
        result: u64,
        completed: bool,
    ) -> Result<DispatchReturn, DispatchReturnError> {
        if !completed {
            return Err(DispatchReturnError::Incomplete);
        }
        if dispatch_id == 0 || self.words[0] != dispatch_id || self.words[1] != ssn {
            return Err(DispatchReturnError::Correlation);
        }
        if self.words[3] != result {
            return Err(DispatchReturnError::ResultMismatch);
        }
        match self.words[2] {
            1 if self.words[3] <= u32::MAX as u64 => {
                Ok(DispatchReturn::Refused(self.words[3] as u32))
            }
            2 => Ok(DispatchReturn::HandlerReturned(self.words[3])),
            _ => Err(DispatchReturnError::InvalidDisposition),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_transport_refusal_is_not_a_handler_return() {
        let receipt = DispatchReturnReceipt::refused(7, 0x1077, 0xc000009a);
        let returned = receipt.authenticate(7, 0x1077, 0xc000009a, true).unwrap();
        assert_eq!(returned, DispatchReturn::Refused(0xc000009a));
        assert_eq!(returned.handler_value(), None);
    }

    #[test]
    fn negative_draw_and_pointer_width_returns_remain_exact() {
        for value in [(-3i64) as u64, 0xffff_ffff, 0x1000_1234_5678, 0] {
            let receipt = DispatchReturnReceipt::handler_returned(7, 0x1137, value);
            assert_eq!(
                receipt
                    .authenticate(7, 0x1137, value, true)
                    .unwrap()
                    .handler_value(),
                Some(value)
            );
        }
    }

    #[test]
    fn nested_or_unfinished_response_cannot_satisfy_outer_operation() {
        let receipt = DispatchReturnReceipt::handler_returned(8, 0x1298, 42);
        for (id, ssn, result, completed) in [
            (7, 0x1298, 42, true),
            (8, 0x105b, 42, true),
            (8, 0x1298, 41, true),
            (8, 0x1298, 42, false),
            (0, 0x1298, 42, true),
        ] {
            assert!(receipt.authenticate(id, ssn, result, completed).is_err());
        }
        assert_eq!(
            DispatchReturnReceipt::from_words([8, 0x1298, 0, 42]).authenticate(8, 0x1298, 42, true),
            Err(DispatchReturnError::InvalidDisposition)
        );
    }
}
