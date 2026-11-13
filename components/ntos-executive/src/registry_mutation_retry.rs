//! Authority checks for retrying an acknowledged, no-effect hosted SYSTEM BEGIN.
//!
//! The retained caller, Reply, and mutation journal live in the parent work row. A newer
//! generation alone cannot authorize replay: the same CM mount and exact retained Key
//! must still resolve to the physical path captured before the original BEGIN.

use super::*;

const INVALID_KEY: i32 = 0xC000_0008u32 as i32;

fn retained_target_matches(key: KeyRef, expected: &CmSystemKeyTarget) -> Result<(), i32> {
    let current = registry_key_targets::system(key).ok_or(INVALID_KEY)?;
    if current.lease != expected.lease
        || nt_hive_core::canon_path(&current.physical_path)
            != nt_hive_core::canon_path(&expected.physical_path)
    {
        return Err(INVALID_KEY);
    }
    Ok(())
}

pub(super) unsafe fn revalidate_hosted_revision(
    caller: &HostedCaller,
    mount: SystemHiveMount,
    durable_generation: u64,
) -> Result<(), i32> {
    let (lease, physical_path, retained_key) = match &caller.completion {
        HostedCompletion::Create { parent, parent_target, .. } =>
            (parent_target.lease, parent_target.physical_path.as_str(), Some((*parent, parent_target))),
        HostedCompletion::Existing { key, target, .. } =>
            (target.lease, target.physical_path.as_str(), Some((*key, target))),
        HostedCompletion::SystemLocale { lease, physical_path, .. } =>
            (*lease, physical_path.as_str(), None),
    };
    // A hidden PM handle keeps the Key alive. Check its target again because a numeric
    // KeyRef alone is not authority across a concurrent publication or retirement.
    if let Some((key, expected)) = retained_key {
        retained_target_matches(key, expected)?;
    }
    let information = CONFIG_CLIENT_PTR.as_mut()
        .ok_or(0xC000_00A3u32 as i32)?
        .query_leased_system_hive_key_at_durable_mount(lease, mount, durable_generation)?;
    if nt_hive_core::canon_path(&information.path) != nt_hive_core::canon_path(physical_path) {
        return Err(INVALID_KEY);
    }
    // The CM exchange can reenter the executive. Reject retirement/reuse observed during it.
    if let Some((key, expected)) = retained_key {
        retained_target_matches(key, expected)?;
    }
    Ok(())
}
