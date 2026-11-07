//! Behavioral contract for the owned bank bytes behind a hosted IRP receive.

#[path = "../../../components/ntos-executive/src/hosted_irp_banks.rs"]
mod hosted_irp_banks;

use hosted_irp_banks::HostedIrpBanks;

#[test]
fn banks_remain_valid_after_original_dispatch_buffers_leave_scope() {
    let mut banks = {
        let input = vec![0x11, 0x22, 0x33, 0x44];
        let output = vec![0x55, 0x66, 0x77, 0x88];
        HostedIrpBanks::new(&input, &output).expect("bank admission")
    };

    assert_eq!(banks.input(), &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(banks.output(), &[0x55, 0x66, 0x77, 0x88]);
    banks.output_mut()[1..3].copy_from_slice(&[0xa1, 0xb2]);

    let mut caller_output = vec![0; 4];
    banks.copy_output_to(&mut caller_output);
    assert_eq!(caller_output, [0x55, 0xa1, 0xb2, 0x88]);
}

#[test]
fn empty_banks_have_an_exact_empty_copyback() {
    let banks = HostedIrpBanks::new(&[], &[]).expect("empty bank admission");
    assert!(banks.input().is_empty());
    assert!(banks.output().is_empty());
    let mut caller_output = [];
    banks.copy_output_to(&mut caller_output);
}
