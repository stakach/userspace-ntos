//! x64 processor-group projection for one NT processor group.

/// This host currently admits at most one 64-processor NT group.
pub const fn active_processor_count(count: u64) -> u32 {
    if count == 0 { 1 } else if count > 64 { 64 } else { count as u32 }
}

pub const fn active_processor_mask(count: u64) -> u64 {
    let count = active_processor_count(count);
    if count == 64 { u64::MAX } else { (1u64 << count) - 1 }
}

/// `ALL_PROCESSOR_GROUPS` is 0xffff. A nonzero concrete group does not exist.
pub const fn active_processor_count_for_group(count: u64, group: u16) -> u32 {
    if group == 0 || group == u16::MAX { active_processor_count(count) } else { 0 }
}

/// Map a hosted callback to the boot node only while its observed physical APIC identity
/// still matches the node on which the executive captured that identity. A migrated callback
/// needs an independently discovered APIC-to-node map and cannot borrow the boot node's index.
pub const fn local_processor_index(
    count: u64,
    boot_node: u64,
    boot_apic_id: u32,
    current_apic_id: u32,
) -> Option<u32> {
    if count == 0
        || boot_node >= active_processor_count(count) as u64
        || current_apic_id != boot_apic_id
    {
        None
    } else {
        Some(boot_node as u32)
    }
}

/// Encode a group-zero `PROCESSOR_NUMBER` for a real boot processor index.
pub const fn processor_number_for_index(count: u64, index: u32) -> Option<u32> {
    if count == 0 || index >= active_processor_count(count) {
        None
    } else {
        Some(index << 16)
    }
}

/// x64 `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` with one `GROUP_RELATIONSHIP`
/// and one `PROCESSOR_GROUP_INFO`. The offsets come from the WDK structures:
/// 8-byte record header, 24-byte group header, and 48-byte group info.
pub const RELATION_GROUP_RECORD_BYTES: usize = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationGroupError {
    /// The boot topology cannot be represented by the one-group host contract.
    InvalidTopology,
    /// The caller must provide this many bytes. No output was written.
    BufferTooSmall { required: usize },
}

/// Serialize `KeQueryLogicalProcessorRelationship(..., RelationGroup, ...)`
/// without handling guest pointers or NTSTATUS conversion. `None` is a size
/// probe. The executive owns validation of the native `Length` and output
/// pointers before passing a slice here.
pub fn write_relation_group(
    boot_processor_count: u64,
    output: Option<&mut [u8]>,
) -> Result<usize, RelationGroupError> {
    if !(1..=64).contains(&boot_processor_count) {
        return Err(RelationGroupError::InvalidTopology);
    }
    let Some(output) = output.filter(|bytes| bytes.len() >= RELATION_GROUP_RECORD_BYTES) else {
        return Err(RelationGroupError::BufferTooSmall {
            required: RELATION_GROUP_RECORD_BYTES,
        });
    };

    let mut record = [0u8; RELATION_GROUP_RECORD_BYTES];
    // SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX: Relationship and Size.
    record[0..4].copy_from_slice(&4u32.to_le_bytes()); // RelationGroup
    record[4..8].copy_from_slice(&(RELATION_GROUP_RECORD_BYTES as u32).to_le_bytes());
    // GROUP_RELATIONSHIP: MaximumGroupCount, ActiveGroupCount, Reserved[20].
    record[8..10].copy_from_slice(&1u16.to_le_bytes());
    record[10..12].copy_from_slice(&1u16.to_le_bytes());
    // PROCESSOR_GROUP_INFO: MaximumProcessorCount, ActiveProcessorCount,
    // Reserved[38], ActiveProcessorMask. No processor hotplug is advertised.
    record[32] = boot_processor_count as u8;
    record[33] = boot_processor_count as u8;
    record[72..80].copy_from_slice(&active_processor_mask(boot_processor_count).to_le_bytes());
    output[..RELATION_GROUP_RECORD_BYTES].copy_from_slice(&record);
    Ok(RELATION_GROUP_RECORD_BYTES)
}
