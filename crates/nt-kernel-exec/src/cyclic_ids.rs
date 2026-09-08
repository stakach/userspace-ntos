//! Allocation-free fair selection from an unordered set of eligible identities.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CyclicIdSelection {
    pub count: usize,
    pub next_cursor: u64,
}

/// Select the lowest eligible IDs at or above `cursor`, then wrap to lower IDs.
///
/// Only `output[..count]` is written. Duplicate input IDs are ignored. The cursor
/// advances past the last selected ID, wrapping after `u64::MAX`; an empty
/// selection preserves it. Input order does not affect the selection.
///
/// Uses no allocation and at most `output.len()` retained IDs. Sorted insertion
/// costs O(input length * output capacity), suitable for bounded drain batches.
pub fn select_cyclic_ids(
    ids: impl IntoIterator<Item = u64>,
    cursor: u64,
    output: &mut [u64],
) -> CyclicIdSelection {
    let mut count = 0;
    if !output.is_empty() {
        for id in ids {
            let key = (id < cursor, id);
            let position = match output[..count]
                .binary_search_by_key(&key, |selected| (*selected < cursor, *selected))
            {
                Ok(_) => continue,
                Err(position) => position,
            };
            if position == output.len() {
                continue;
            }
            let next_count = (count + 1).min(output.len());
            output.copy_within(position..next_count - 1, position + 1);
            output[position] = id;
            count = next_count;
        }
    }
    CyclicIdSelection {
        count,
        next_cursor: if count == 0 {
            cursor
        } else {
            output[count - 1].wrapping_add(1)
        },
    }
}

#[cfg(test)]
mod tests;
