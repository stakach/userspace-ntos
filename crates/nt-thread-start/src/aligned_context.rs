//! Storage for an AMD64 CONTEXT passed across the native thread boundary.

use crate::AMD64_CONTEXT_SIZE;

#[repr(C, align(16))]
pub struct AlignedAmd64Context([u8; AMD64_CONTEXT_SIZE]);

impl AlignedAmd64Context {
    pub const fn zeroed() -> Self {
        Self([0; AMD64_CONTEXT_SIZE])
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; AMD64_CONTEXT_SIZE] {
        &mut self.0
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialized_context_is_aligned_and_capturable() {
        let mut context = AlignedAmd64Context::zeroed();
        assert!(crate::initialize_amd64_user_context(
            context.as_bytes_mut(),
            0x1000,
            0x2000,
            0x10000,
        ));
        let address = context.as_ptr() as u64;
        assert_eq!(address % crate::AMD64_CONTEXT_ALIGNMENT, 0);
        let bytes = *context.as_bytes_mut();
        let captured = crate::amd64_context::CapturedAmd64Context::capture(
            |source, output| {
                assert_eq!(source, address);
                output.copy_from_slice(&bytes[..output.len()]);
                Ok(())
            },
            address,
        );
        assert!(captured.is_ok());
    }
}
