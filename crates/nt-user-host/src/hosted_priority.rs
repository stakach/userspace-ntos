//! Physical seL4 TCB priority projection for hosted NT user threads.

const NT_PRIORITY_MAX: u8 = 31;
// The ordinary NT base priority 13 must compete with provider threads at seL4 priority 100.
// Preserve every NT priority step on either side of that anchor.
const SEL4_USER_PRIORITY_OFFSET: u8 = 87;

/// Map an NT scheduler priority to the hosted TCB priority.
///
/// This projection is shared by first TCB publication and later checked priority effects.
/// NT quantum is represented in the process manager, not in the seL4 SC budget.
pub fn hosted_tcb_priority(nt_priority: i32) -> Result<u8, u32> {
    let priority = u8::try_from(nt_priority).map_err(|_| nt_process::STATUS_INVALID_PARAMETER)?;
    if priority > NT_PRIORITY_MAX {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    Ok(SEL4_USER_PRIORITY_OFFSET + priority)
}
