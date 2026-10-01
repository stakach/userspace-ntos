//! Native publication transaction for `IoAttachDeviceToDeviceStackSafe`.
//!
//! The backend must admit output memory before any attach effect. Output stores must be exact:
//! on error they have not published the requested pointer. An uncertain attach/detach result is
//! not a status error; the native broker must fail-stop before returning to this adapter.

pub(crate) const STATUS_NO_SUCH_DEVICE: i32 = 0xC000_000Eu32 as i32;
pub(crate) const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
pub(crate) const STATUS_SUCCESS: i32 = 0;

pub(crate) trait SafeAttachBackend {
    fn publish_output(&mut self, output: u64, device: u64) -> Result<(), i32>;
    fn attach_projection(&mut self, source: u64, target: u64) -> Option<u64>;
    fn detach_projection(&mut self, lower: u64);
    fn attach_canonical(&mut self, source: u64, target: u64, lower: u64) -> i32;
    fn detach_canonical(&mut self, lower: u64, source: u64) -> i32;
}

pub(crate) fn attach_device_to_device_stack_safe(
    backend: &mut impl SafeAttachBackend,
    source: u64,
    target: u64,
    output: u64,
) -> i32 {
    if source == 0 || target == 0 || output == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if let Err(status) = backend.publish_output(output, 0) {
        return status;
    }
    let Some(lower) = backend.attach_projection(source, target) else {
        return STATUS_NO_SUCH_DEVICE;
    };
    let status = backend.attach_canonical(source, target, lower);
    if status != STATUS_SUCCESS {
        backend.detach_projection(lower);
        return status;
    }
    if let Err(status) = backend.publish_output(output, lower) {
        let rollback = backend.detach_canonical(lower, source);
        assert_eq!(
            rollback, STATUS_SUCCESS,
            "safe attach canonical rollback failed"
        );
        backend.detach_projection(lower);
        return status;
    }
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Backend {
        output: u64,
        attached: bool,
        projection: bool,
        output_fails_on_lower: bool,
        canonical_status: i32,
    }

    impl SafeAttachBackend for Backend {
        fn publish_output(&mut self, _output: u64, device: u64) -> Result<(), i32> {
            if device != 0 && self.output_fails_on_lower {
                return Err(-1);
            }
            self.output = device;
            Ok(())
        }
        fn attach_projection(&mut self, _source: u64, _target: u64) -> Option<u64> {
            self.projection = true;
            Some(3)
        }
        fn detach_projection(&mut self, lower: u64) {
            assert_eq!(lower, 3);
            self.projection = false;
        }
        fn attach_canonical(&mut self, _source: u64, _target: u64, lower: u64) -> i32 {
            assert_eq!(lower, 3);
            if self.canonical_status == STATUS_SUCCESS {
                self.attached = true;
            }
            self.canonical_status
        }
        fn detach_canonical(&mut self, lower: u64, source: u64) -> i32 {
            assert_eq!((lower, source), (3, 1));
            self.attached = false;
            STATUS_SUCCESS
        }
    }

    #[test]
    fn publishes_lower_only_after_both_attachments() {
        let mut backend = Backend {
            output: 99,
            attached: false,
            projection: false,
            output_fails_on_lower: false,
            canonical_status: STATUS_SUCCESS,
        };
        assert_eq!(
            attach_device_to_device_stack_safe(&mut backend, 1, 2, 4),
            STATUS_SUCCESS
        );
        assert_eq!(backend.output, 3);
        assert!(backend.attached && backend.projection);
    }

    #[test]
    fn failed_publication_rolls_back_both_attachments() {
        let mut backend = Backend {
            output: 99,
            attached: false,
            projection: false,
            output_fails_on_lower: true,
            canonical_status: STATUS_SUCCESS,
        };
        assert_eq!(
            attach_device_to_device_stack_safe(&mut backend, 1, 2, 4),
            -1
        );
        assert_eq!(backend.output, 0);
        assert!(!backend.attached && !backend.projection);
    }

    #[test]
    fn rejected_canonical_attach_restores_local_projection() {
        let mut backend = Backend {
            output: 99,
            attached: false,
            projection: false,
            output_fails_on_lower: false,
            canonical_status: STATUS_NO_SUCH_DEVICE,
        };
        assert_eq!(
            attach_device_to_device_stack_safe(&mut backend, 1, 2, 4),
            STATUS_NO_SUCH_DEVICE
        );
        assert_eq!(backend.output, 0);
        assert!(!backend.attached && !backend.projection);
    }
}
