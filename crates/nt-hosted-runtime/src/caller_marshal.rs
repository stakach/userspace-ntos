//! Caller-domain arguments of a provider function reached through a cross-domain route.
//!
//! A caller in another domain passes pointers into its own memory. The route stages each pointed-to
//! range in the provider's marshal window and passes the window address instead. This module
//! decides, from the marshal policy alone, which arguments are such ranges and how many bytes each
//! one covers. Mapping and copying belong to the executive.

use crate::{
    export_policy_with_effect_and_result, HostedProviderArgumentMarshal,
    HostedProviderExportMarshalPolicy, HostedProviderExportResultSemantics,
    HostedProviderExportSideEffect, HOSTED_PROVIDER_EXPORT_ARG_CAP,
};

/// `BOOLEAN SendIoctl(ULONG Code, PVOID In, ULONG InLen, PVOID Out, ULONG OutLen,
/// NTSTATUS *Status, ULONG_PTR *Info)`: the WDDM bridge slot at offset 0x268, as the pinned
/// LiberNT win32k `WddmBridgeSendIoctl` (VMA 0x164fe0) calls it.
///
/// dxgkrnl (VMA 0xb8060) returns FALSE having written nothing, or reads `In[InLen]`, writes at
/// most `OutLen` bytes of `Out`, and then writes `*Status` and `*Info`. `Out`, `Status` and `Info`
/// are therefore copied in as well as out: every byte the provider leaves alone keeps the
/// caller's value, as it would after a direct call.
pub fn hosted_wddm_bridge_send_ioctl_marshal_policy() -> HostedProviderExportMarshalPolicy {
    use HostedProviderArgumentMarshal::*;
    export_policy_with_effect_and_result(
        &[
            Scalar,
            CallerInBuffer { length_arg: 2 },
            Scalar,
            CallerInOutBuffer { length_arg: 4 },
            Scalar,
            CallerInOutFixed { bytes: 4 },
            CallerInOutFixed { bytes: 8 },
        ],
        HostedProviderExportSideEffect::None,
        HostedProviderExportResultSemantics::Boolean,
    )
    .expect("seven SendIoctl arguments fit the provider call frame")
}

/// One argument of a cross-domain call, classified by its marshal policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedCallerArgument {
    /// Passed to the provider unchanged.
    Scalar(u64),
    /// A NULL pointer reaches the provider as NULL; what NULL means is the provider's decision.
    Null,
    /// `bytes` of caller memory at `address`, staged in the provider's window. `copy_in` stages the
    /// caller's bytes before the call; `copy_out` writes the staged bytes back after a completed
    /// call. A zero-length range is still a non-NULL pointer.
    Buffer { address: u64, bytes: u64, copy_in: bool, copy_out: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedCallerMarshalError {
    ArgumentCount,
    /// A length index names a missing argument or another pointer.
    LengthArgument,
    /// The policy names a shape that needs provider-specific projection.
    Unsupported,
}

/// Classify every argument of `policy`. Arguments past `argument_count` are scalar zero.
pub fn classify_hosted_caller_arguments(
    policy: HostedProviderExportMarshalPolicy,
    args: &[u64; HOSTED_PROVIDER_EXPORT_ARG_CAP],
) -> Result<[HostedCallerArgument; HOSTED_PROVIDER_EXPORT_ARG_CAP], HostedCallerMarshalError> {
    use HostedProviderArgumentMarshal::*;
    let count = policy.argument_count as usize;
    if count > HOSTED_PROVIDER_EXPORT_ARG_CAP {
        return Err(HostedCallerMarshalError::ArgumentCount);
    }
    // Win64 passes a ULONG length in the low half of its slot; the high half is not contractual.
    let length = |index: u8| -> Result<u64, HostedCallerMarshalError> {
        let index = index as usize;
        if index >= count || policy.args[index] != Scalar {
            return Err(HostedCallerMarshalError::LengthArgument);
        }
        Ok(args[index] & u32::MAX as u64)
    };
    let mut classified = [HostedCallerArgument::Scalar(0); HOSTED_PROVIDER_EXPORT_ARG_CAP];
    for index in 0..count {
        let address = args[index];
        let (bytes, copy_in, copy_out) = match policy.args[index] {
            Scalar => {
                classified[index] = HostedCallerArgument::Scalar(address);
                continue;
            }
            CallerInBuffer { length_arg } => (length(length_arg)?, true, false),
            CallerInOutBuffer { length_arg } => (length(length_arg)?, true, true),
            CallerInOutFixed { bytes } => (bytes as u64, true, true),
            _ => return Err(HostedCallerMarshalError::Unsupported),
        };
        classified[index] = if address == 0 {
            HostedCallerArgument::Null
        } else {
            HostedCallerArgument::Buffer { address, bytes, copy_in, copy_out }
        };
    }
    Ok(classified)
}
