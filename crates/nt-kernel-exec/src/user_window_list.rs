//! Caller arguments of `NtUserBuildHwndList` as the executive stages them for isolated win32k.

/// The caller values the executive rewrites before dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildHwndListCall {
    pub thread_id: u64,
    pub capacity: u64,
    pub list: u64,
    pub needed: u64,
    pub shape: u64,
}

impl BuildHwndListCall {
    /// Select the call shape from the fourth register argument and the caller's stack tail.
    pub fn capture(a3: u64, tail: [Option<u64>; 4]) -> Option<Self> {
        let [Some(tail0), Some(tail1), Some(tail2), tail3] = tail else {
            return None;
        };
        let eight_arg_shape = tail3.is_some_and(|needed| {
            a3 <= 1
                && tail1 != 0
                && tail1 <= 0x0001_0000
                && tail2 >= 0x0001_0000
                && needed >= 0x0001_0000
        });
        Some(if eight_arg_shape {
            Self {
                thread_id: tail0,
                capacity: tail1,
                list: tail2,
                needed: tail3.unwrap_or(0),
                shape: 8,
            }
        } else {
            Self {
                thread_id: a3,
                capacity: tail0,
                list: tail1,
                needed: tail2,
                shape: 7,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fill_call_reads_thread_capacity_list_and_needed_from_the_stack_tail() {
        let call = BuildHwndListCall::capture(
            1,
            [Some(0), Some(12), Some(0x100_302d_7d40), Some(0x100_302d_7da0)],
        )
        .unwrap();
        assert_eq!(
            (call.thread_id, call.capacity, call.list, call.needed),
            (0, 12, 0x100_302d_7d40, 0x100_302d_7da0)
        );
    }
}
