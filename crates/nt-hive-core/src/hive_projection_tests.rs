use super::*;
use crate::encoded_image_len;
use alloc::vec;

#[test]
fn transaction_projection_reconciles_with_serializer_after_each_commit() {
    let mut hive = Hive::new(HiveKind::System);
    let parent = hive.create_key("ControlSet001\\Services");
    let initial = hive.create_key("ControlSet001\\Services\\Old");
    assert!(hive.set_value(initial, "Data", RegistryValueType::Binary, vec![1, 2, 3]));
    let mut baseline = encoded_image_len(&hive).unwrap();

    let mut apply = |edit: &dyn Fn(&mut HiveTransaction<'_>)| {
        let mut transaction = hive.begin_transaction();
        edit(&mut transaction);
        let projected = transaction.projected_encoded_image_len(baseline).unwrap();
        assert_eq!(projected, encoded_image_len(transaction.hive()).unwrap());
        transaction.commit();
        assert_eq!(projected, encoded_image_len(&hive).unwrap());
        baseline = projected;
    };

    apply(&|tx| {
        let child = tx.create_key("ControlSet001\\Services\\New");
        assert!(tx.set_value(child, "Data", RegistryValueType::Binary, vec![9; 2048]));
        assert!(tx.set_key_class(child, Some("class with UTF-16: Ω")));
        assert!(tx.set_key_security_descriptor(child, &[1, 2, 3, 4]));
    });
    apply(&|tx| {
        let child = tx.open_key("ControlSet001\\Services\\New").unwrap();
        assert!(tx.set_value(child, "Data", RegistryValueType::Binary, vec![8; 5]));
        assert!(tx.set_value(child, "Extra", RegistryValueType::Dword, vec![0; 4]));
        assert!(tx.set_key_class(child, None));
    });
    apply(&|tx| {
        let child = tx.open_key("ControlSet001\\Services\\New").unwrap();
        assert!(tx.delete_value(child, "Data"));
        assert!(tx.delete_value(child, "Extra"));
        assert_eq!(tx.delete_key(child), Ok(()));
        let old = tx.open_key("ControlSet001\\Services\\Old").unwrap();
        assert_eq!(tx.delete_key(old), Ok(()));
        assert_eq!(tx.open_key("ControlSet001\\Services"), Some(parent));
    });
}

#[test]
fn volatile_mutation_has_no_durable_length_delta_and_rollback_preserves_baseline() {
    let mut hive = Hive::new(HiveKind::System);
    let baseline = encoded_image_len(&hive).unwrap();
    {
        let mut tx = hive.begin_transaction();
        let root = tx.hive().root();
        let volatile_root = tx.try_create_child_with_options(
            root, "Volatile".into(), None, vec![1], true,
        ).unwrap();
        assert_eq!(tx.projected_encoded_image_len(baseline), Ok(baseline));
        tx.commit();
        assert!(hive.is_volatile(volatile_root));
    }
    {
        let mut tx = hive.begin_transaction();
        let child = tx.create_key("Volatile\\Child");
        assert!(tx.set_value(child, "Data", RegistryValueType::Binary, vec![1; 1000]));
        assert_eq!(tx.projected_encoded_image_len(baseline), Ok(baseline));
        assert_eq!(encoded_image_len(tx.hive()), Ok(baseline));
    }
    assert_eq!(encoded_image_len(&hive), Ok(baseline));
}
