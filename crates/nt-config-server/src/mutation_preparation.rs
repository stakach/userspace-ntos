//! Normalize trusted path creation into retained, descriptor-bearing child publications.

use super::{
    apply_system_hive_mutation, child_creation, system_hive_relative_path, CmServer,
    CurrentControlSet, HiveMutation, HiveTransaction, String, Vec,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, SYSTEM_HIVE_PATH,
};
use crate::mutation::ChildParentAuthority;

fn string(value: &str) -> Result<String, i32> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    copy.push_str(value);
    Ok(copy)
}

fn bytes(value: &[u8]) -> Result<Vec<u8>, i32> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(value.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    copy.extend_from_slice(value);
    Ok(copy)
}

fn copy_mutation(mutation: &HiveMutation) -> Result<HiveMutation, i32> {
    Ok(match mutation {
        HiveMutation::CreateKey { .. } => return Err(STATUS_INVALID_PARAMETER),
        HiveMutation::CreateChild { authority, parent, name, class_name, descriptor, volatile } =>
            HiveMutation::CreateChild {
                authority: authority.clone(), parent: string(parent)?, name: string(name)?,
                class_name: class_name.as_deref().map(string).transpose()?,
                descriptor: bytes(descriptor)?, volatile: *volatile,
            },
        HiveMutation::SetValue { path, name, value_type, data } => HiveMutation::SetValue {
            path: string(path)?, name: string(name)?, value_type: *value_type, data: bytes(data)?,
        },
        HiveMutation::DeleteValue { path, name } => HiveMutation::DeleteValue {
            path: string(path)?, name: string(name)?,
        },
        HiveMutation::DeleteKey { path } => HiveMutation::DeleteKey { path: string(path)? },
        HiveMutation::SetKeyClass { path, class_name } => HiveMutation::SetKeyClass {
            path: string(path)?, class_name: class_name.as_deref().map(string).transpose()?,
        },
        HiveMutation::SetKeySecurity { path, descriptor } => HiveMutation::SetKeySecurity {
            path: string(path)?, descriptor: bytes(descriptor)?,
        },
        HiveMutation::PublishDeviceAction { kind, instance_id } => HiveMutation::PublishDeviceAction {
            kind: *kind, instance_id: string(instance_id)?,
        },
    })
}

fn append(
    tx: &mut HiveTransaction<'_>,
    control_set: &CurrentControlSet,
    mutation: HiveMutation,
    normalized: &mut Vec<HiveMutation>,
    journal: &mut Vec<u8>,
) -> Result<(), i32> {
    normalized.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let previous = tx.hive().sequence;
    apply_system_hive_mutation(tx, control_set, &mutation)?;
    if tx.hive().sequence != previous {
        let record = CmServer::encode_system_hive_mutation_log_record(
            &mutation, control_set, tx.hive().sequence,
        )?;
        journal.try_reserve_exact(record.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        journal.extend_from_slice(&record);
    }
    normalized.push(mutation);
    Ok(())
}

pub(super) fn apply(
    tx: &mut HiveTransaction<'_>,
    control_set: &CurrentControlSet,
    mutation: &HiveMutation,
    normalized: &mut Vec<HiveMutation>,
    journal: &mut Vec<u8>,
) -> Result<(), i32> {
    let HiveMutation::CreateKey { path } = mutation else {
        return append(tx, control_set, copy_mutation(mutation)?, normalized, journal);
    };
    let relative = system_hive_relative_path(path, control_set).ok_or(STATUS_INVALID_PARAMETER)?;
    let mut parent = tx.hive().root();
    let mut parent_path = string(SYSTEM_HIVE_PATH)?;
    for name in relative.split('\\').filter(|part| !part.is_empty()) {
        child_creation::validate_path(&parent_path, name)?;
        if let Some(child) = tx.hive().open_subkey(parent, name) {
            parent = child;
        } else {
            if tx.hive().is_volatile(parent) {
                return Err(0xc000_0181u32 as i32);
            }
            let parent_descriptor = tx.hive().key_security_descriptor(parent)
                .ok_or(0xc000_0079u32 as i32)?;
            nt_config_manager::validate_generated_key_security(parent_descriptor)
                .map_err(|status| status as i32)?;
            let descriptor = nt_config_manager::inherit_generated_key_security(parent_descriptor)
                .map_err(|status| status as i32)?;
            let child = HiveMutation::CreateChild {
                authority: ChildParentAuthority::Path,
                parent: string(&parent_path)?, name: string(name)?, class_name: None,
                descriptor, volatile: false,
            };
            append(tx, control_set, child, normalized, journal)?;
            parent = tx.hive().open_subkey(parent, name).ok_or(STATUS_INVALID_PARAMETER)?;
        }
        let growth = name.len().checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        parent_path.try_reserve(growth).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        parent_path.push('\\');
        parent_path.push_str(name);
    }
    Ok(())
}
