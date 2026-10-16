//! Pinned LiberNT `win32k.sys` (SHA-256 cce42491d4093ba391c25ae2612bbd714ce28f95aa6a56a127e9f55736be187f).
//! The old ReactOS helper RVA is code in this image; CR8 reads occur at several instruction sites.

use nt_kernel_exec::x86_cr8::{decode_cr8_read, project_cr8_read, Cr8ActivationIdentity, Cr8Read, PublishedCr8Irql};

#[test]
fn pinned_libernt_image_rejects_old_fixed_rva_patch_but_exposes_cr8_reads() {
    // At RVA 0x305c0 in the pinned image, these are the exact first 5 bytes.
    let old_rva = [0xc6, 0x48, 0x85, 0xff, 0x74];
    assert_ne!(old_rva, [0x44, 0x0f, 0x20, 0xc0, 0xc3]);

    // RVA 0x212c0 is one actual helper; RVA 0xfc136 reads CR8 into RDX inline.
    assert_eq!(decode_cr8_read(&[0x44, 0x0f, 0x20, 0xc0, 0xc3]), Some(Cr8Read { register: 0, len: 4 }));
    assert_eq!(decode_cr8_read(&[0x44, 0x0f, 0x20, 0xc2, 0xb8]), Some(Cr8Read { register: 2, len: 4 }));
}

#[test]
fn stale_activation_cannot_supply_another_dispatch_or_reused_lane() {
    let activation = Cr8ActivationIdentity {
        lane_id: 2, lane_generation: 4, dispatch_id: 79, activation_generation: 11,
    };
    let publication = PublishedCr8Irql { activation, irql: 2 };
    assert_eq!(publication.for_activation(activation), Some(2));
    assert_eq!(publication.for_fault(2, 79), Some(2));
    assert_eq!(publication.for_fault(2, 80), None); // reused lane, old dispatch
    assert_eq!(publication.for_fault(3, 79), None); // another physical lane
    for stale in [
        Cr8ActivationIdentity { lane_id: 3, ..activation },
        Cr8ActivationIdentity { lane_generation: 5, ..activation },
        Cr8ActivationIdentity { dispatch_id: 80, ..activation },
        Cr8ActivationIdentity { activation_generation: 12, ..activation },
    ] {
        assert_eq!(publication.for_activation(stale), None);
    }
}

#[test]
fn driver_entry_kernel_activation_can_service_cr8_before_gui_assert_capability() {
    // DriverEntry's root-owned kernel activation uses its physical dispatch epoch as dispatch ID.
    // Its pump has no GUI assert-skip capability; CR8 handling is a general #GP path.
    let epoch = 31;
    let activation = Cr8ActivationIdentity {
        lane_id: 1, lane_generation: 1, dispatch_id: epoch, activation_generation: 1,
    };
    let receipt = PublishedCr8Irql { activation, irql: 0 };
    let mut registers = [0u64; 20];
    registers[0] = 0x1000_0000 + 0x212c0;
    let irql = receipt.for_fault(1, epoch).unwrap();
    let mask = project_cr8_read(&mut registers, decode_cr8_read(&[0x44, 0x0f, 0x20, 0xc0]).unwrap(), irql).unwrap();
    assert_eq!(registers[0], 0x1000_0000 + 0x212c4);
    assert_eq!(registers[3], 0);
    assert_eq!(mask, (1 << 0) | (1 << 3));
    assert_eq!(receipt.for_fault(1, epoch + 1), None);
}

#[test]
fn cr8_fault_projects_activation_irql_into_exact_destination_and_advances_rip() {
    let mut regs = [0xfeed_u64; 20];
    regs[0] = 0x1000_0000 + 0xfc136;
    let original = regs;
    let instruction = decode_cr8_read(&[0x44, 0x0f, 0x20, 0xc2]).unwrap();
    let mask = project_cr8_read(&mut regs, instruction, 2).unwrap();
    assert_eq!(regs[0], original[0] + 4);
    assert_eq!(regs[6], 2); // seL4 register word 6 is RDX.
    assert_eq!(mask, (1 << 0) | (1 << 6));
    for index in 1..20 {
        if index != 6 { assert_eq!(regs[index], original[index]); }
    }

    let mut rax = original;
    rax[0] = 0x1000_0000 + 0x212c0;
    let mask = project_cr8_read(&mut rax, decode_cr8_read(&[0x44, 0x0f, 0x20, 0xc0]).unwrap(), 0).unwrap();
    assert_eq!(rax[3], 0);
    assert_eq!(mask, (1 << 0) | (1 << 3));
}

#[test]
fn cr8_decoder_and_projection_reject_unrelated_or_unsafe_faults() {
    for bytes in [
        &[][..], &[0x44, 0x0f, 0x20][..], &[0x44, 0x0f, 0x22, 0xc0][..],
        &[0x0f, 0x20, 0xc0][..], &[0x44, 0x0f, 0x20, 0x00][..],
        &[0xf0, 0x44, 0x0f, 0x20, 0xc0][..],
    ] {
        assert_eq!(decode_cr8_read(bytes), None, "unexpected CR8 decode: {bytes:x?}");
    }
    let mut regs = [7u64; 20];
    regs[0] = u64::MAX - 2;
    let before = regs;
    assert_eq!(project_cr8_read(&mut regs, Cr8Read { register: 0, len: 4 }, 2), None);
    assert_eq!(regs, before);
}
