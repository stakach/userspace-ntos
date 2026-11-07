use super::*;
use crate::kernel_job_body::{JobBodyReceipt, KernelJobBodyOwner};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Receipt(u64);

impl JobBodyReceipt for Receipt {
    fn address(self) -> u64 { self.0 }
}

#[test]
fn kernel_job_body_owner_retains_exact_receipt_through_destruction() {
    let mut pm = ProcessManager::new();
    let first = pm.create_job(0).unwrap();
    let second = pm.create_job(0).unwrap();
    let mut owner = KernelJobBodyOwner::<Receipt>::new();

    assert_eq!(owner.publish(&mut pm, first, Receipt(0)), Err(Receipt(0)));
    assert_eq!(owner.publish(&mut pm, first, Receipt(0x3000)), Ok(()));
    assert_eq!(pm.job_kernel_object(first), Some(0x3000));
    assert_eq!(owner.receipt_for(first), Some(Receipt(0x3000)));
    assert_eq!(owner.publish(&mut pm, second, Receipt(0x3000)), Err(Receipt(0x3000)));
    assert_eq!(owner.publish(&mut pm, first, Receipt(0x4000)), Err(Receipt(0x4000)));
    assert_eq!(pm.job_kernel_object(second), None);

    assert!(pm.discard_unreferenced_job(first));
    let destruction = pm.take_job_destruction().unwrap();
    assert_eq!(destruction.kernel_job_object, Some(0x3000));
    assert_eq!(owner.retirement_receipt(destruction), Some(Receipt(0x3000)));
    assert_eq!(owner.receipt_for(first), Some(Receipt(0x3000)));
    assert!(owner.acknowledge_retirement(destruction));
    assert_eq!(owner.receipt_for(first), None);
    assert_eq!(owner.retirement_receipt(destruction), None);

    assert_eq!(owner.publish(&mut pm, second, Receipt(0x5000)), Ok(()));
    let wrong = job::JobDestruction {
        id: second,
        kernel_job_object: Some(0x5008),
        security_limits: 0,
        released_completion_port: None,
    };
    assert_eq!(owner.retirement_receipt(wrong), None);
    assert!(!owner.acknowledge_retirement(wrong));
    assert_eq!(owner.receipt_for(second), Some(Receipt(0x5000)));

    assert!(owner.quarantine_retirement(wrong.id, 0x5000));
    let exact = job::JobDestruction { kernel_job_object: Some(0x5000), ..wrong };
    assert_eq!(owner.retirement_receipt(exact), None);
    assert!(!owner.acknowledge_retirement(exact));
    assert_eq!(owner.receipt_for(second), Some(Receipt(0x5000)));
}
