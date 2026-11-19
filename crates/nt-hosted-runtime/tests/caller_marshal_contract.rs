//! Caller-domain arguments of a provider function reached through a cross-domain route.
//!
//! The pinned LiberNT win32k `WddmBridgeSendIoctl` (win32k VMA 0x164fe0) calls the WDDM bridge
//! `SendIoctl` slot as `BOOLEAN (ULONG Code, PVOID In, ULONG InLen, PVOID Out, ULONG OutLen,
//! NTSTATUS *Status, ULONG_PTR *Info)`. dxgkrnl (VMA 0xb8060) reads `In[InLen]`, writes at most
//! `OutLen` bytes of `Out` and then `*Status` and `*Info`, or returns FALSE having written nothing.

use nt_hosted_runtime::{
    classify_hosted_caller_arguments, hosted_wddm_bridge_send_ioctl_marshal_policy,
    HostedCallerArgument, HostedCallerMarshalError, HostedProviderArgumentMarshal,
    HostedProviderExportResultSemantics, HostedProviderExportSideEffect,
    HOSTED_PROVIDER_EXPORT_ARG_CAP,
};

fn args(values: &[u64]) -> [u64; HOSTED_PROVIDER_EXPORT_ARG_CAP] {
    let mut all = [0; HOSTED_PROVIDER_EXPORT_ARG_CAP];
    all[..values.len()].copy_from_slice(values);
    all
}

#[test]
fn send_ioctl_policy_matches_the_win32k_call_site() {
    use HostedProviderArgumentMarshal::*;
    let policy = hosted_wddm_bridge_send_ioctl_marshal_policy();
    assert_eq!(policy.argument_count, 7);
    assert_eq!(policy.stack_qwords, 3, "OutLen, Status and Info are stack arguments");
    assert_eq!(
        &policy.args[..7],
        &[
            Scalar,
            CallerInBuffer { length_arg: 2 },
            Scalar,
            CallerInOutBuffer { length_arg: 4 },
            Scalar,
            CallerInOutFixed { bytes: 4 },
            CallerInOutFixed { bytes: 8 },
        ]
    );
    assert_eq!(policy.side_effect, HostedProviderExportSideEffect::None);
    assert_eq!(policy.result_semantics, HostedProviderExportResultSemantics::Boolean);
}

#[test]
fn send_ioctl_buffers_are_staged_with_their_typed_lengths() {
    let policy = hosted_wddm_bridge_send_ioctl_marshal_policy();
    // Win64 stack slots carry a ULONG in their low half; the high half is not contractual.
    let classified = classify_hosted_caller_arguments(policy, &args(&[
        0x23049c, 0x7000, 0xdead_beef_0000_0010, 0x8000, 0xffff_0000_0000_0020, 0x9000, 0x9008,
    ]))
    .unwrap();
    assert_eq!(classified[0], HostedCallerArgument::Scalar(0x23049c));
    assert_eq!(
        classified[1],
        HostedCallerArgument::Buffer { address: 0x7000, bytes: 0x10, copy_in: true, copy_out: false }
    );
    assert_eq!(classified[2], HostedCallerArgument::Scalar(0xdead_beef_0000_0010));
    // Out is copied in as well as out: bytes the provider leaves alone keep their caller value.
    assert_eq!(
        classified[3],
        HostedCallerArgument::Buffer { address: 0x8000, bytes: 0x20, copy_in: true, copy_out: true }
    );
    assert_eq!(
        classified[5],
        HostedCallerArgument::Buffer { address: 0x9000, bytes: 4, copy_in: true, copy_out: true }
    );
    assert_eq!(
        classified[6],
        HostedCallerArgument::Buffer { address: 0x9008, bytes: 8, copy_in: true, copy_out: true }
    );
    assert!(classified[7..].iter().all(|arg| *arg == HostedCallerArgument::Scalar(0)));
}

#[test]
fn null_and_empty_pointers_keep_their_meaning() {
    let policy = hosted_wddm_bridge_send_ioctl_marshal_policy();
    // The brightness call (win32k VMA 0x16fb20) passes a 16-byte In and no Out. dxgkrnl
    // rejects NULL with a non-zero length itself, so NULL must reach it as NULL.
    let classified =
        classify_hosted_caller_arguments(policy, &args(&[0x23049c, 0, 0x10, 0, 0, 0x9000, 0]))
            .unwrap();
    assert_eq!(classified[1], HostedCallerArgument::Null);
    assert_eq!(classified[3], HostedCallerArgument::Null);
    assert_eq!(classified[6], HostedCallerArgument::Null);
    let classified =
        classify_hosted_caller_arguments(policy, &args(&[1, 0x7000, 0, 0x8000, 0, 0x9000, 0x9008]))
            .unwrap();
    assert_eq!(
        classified[1],
        HostedCallerArgument::Buffer { address: 0x7000, bytes: 0, copy_in: true, copy_out: false }
    );
    assert_eq!(
        classified[3],
        HostedCallerArgument::Buffer { address: 0x8000, bytes: 0, copy_in: true, copy_out: true }
    );
}

#[test]
fn only_caller_buffer_shapes_with_scalar_lengths_are_admitted() {
    use HostedProviderArgumentMarshal::*;
    let mut policy = hosted_wddm_bridge_send_ioctl_marshal_policy();
    policy.args[1] = CallerInBuffer { length_arg: 7 };
    assert_eq!(
        classify_hosted_caller_arguments(policy, &args(&[0; 7])),
        Err(HostedCallerMarshalError::LengthArgument)
    );
    let mut policy = hosted_wddm_bridge_send_ioctl_marshal_policy();
    policy.args[1] = CallerInBuffer { length_arg: 3 };
    assert_eq!(
        classify_hosted_caller_arguments(policy, &args(&[0; 7])),
        Err(HostedCallerMarshalError::LengthArgument),
        "a pointer argument is not a length"
    );
    let mut policy = hosted_wddm_bridge_send_ioctl_marshal_policy();
    policy.args[1] = CallerInUnicodeString;
    assert_eq!(
        classify_hosted_caller_arguments(policy, &args(&[0; 7])),
        Err(HostedCallerMarshalError::Unsupported)
    );
    let mut policy = hosted_wddm_bridge_send_ioctl_marshal_policy();
    policy.argument_count = HOSTED_PROVIDER_EXPORT_ARG_CAP as u8 + 1;
    assert_eq!(
        classify_hosted_caller_arguments(policy, &args(&[0; 7])),
        Err(HostedCallerMarshalError::ArgumentCount)
    );
}
