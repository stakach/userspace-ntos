//! Classify the terminal result of `IRP_MN_FILTER_RESOURCE_REQUIREMENTS` before touching
//! `IoStatus.Information`. A driver may leave that field pointing at the caller's input list.

use nt_status::NtStatus;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterRequirementsReturnAction {
    /// The driver left the requirements unchanged; use the caller's owned copy.
    UseOriginal,
    /// The driver returned a provider allocation that must be copied and released by its owner.
    CopyProviderOutput { information: u64 },
    Barrier(NtStatus),
}

pub fn filter_requirements_return_action(
    status: NtStatus,
    information: u64,
) -> FilterRequirementsReturnAction {
    // ReactOS's ACPI PDO leaves both IoStatus fields unchanged for this optional IRP. The
    // initial Information is the input-list pointer, whose physical allocation remains owned
    // by the source IRP graph. A nonzero value alone cannot transfer that ownership.
    if status == NtStatus::NOT_SUPPORTED {
        FilterRequirementsReturnAction::UseOriginal
    } else if !status.is_success() {
        FilterRequirementsReturnAction::Barrier(status)
    } else if information != 0 {
        FilterRequirementsReturnAction::CopyProviderOutput { information }
    } else {
        FilterRequirementsReturnAction::UseOriginal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_filter_with_borrowed_input_pointer_never_copies_provider_output() {
        let borrowed_input_pointer = 0x1234_5000;
        assert_eq!(
            filter_requirements_return_action(NtStatus::NOT_SUPPORTED, borrowed_input_pointer),
            FilterRequirementsReturnAction::UseOriginal
        );
    }

    #[test]
    fn successful_filter_with_new_output_requires_provider_copy() {
        assert_eq!(
            filter_requirements_return_action(NtStatus::SUCCESS, 0x5678_9000),
            FilterRequirementsReturnAction::CopyProviderOutput {
                information: 0x5678_9000,
            }
        );
        assert_eq!(
            filter_requirements_return_action(NtStatus::SUCCESS, 0),
            FilterRequirementsReturnAction::UseOriginal
        );
    }

    #[test]
    fn failed_filter_cannot_confer_output_ownership() {
        assert_eq!(
            filter_requirements_return_action(NtStatus::INVALID_DEVICE_REQUEST, 0x1234_5000),
            FilterRequirementsReturnAction::Barrier(NtStatus::INVALID_DEVICE_REQUEST)
        );
    }
}
