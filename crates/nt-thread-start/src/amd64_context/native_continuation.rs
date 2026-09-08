use super::{CapturedAmd64Context, CodecError, LegacyContextRestore};

impl CapturedAmd64Context {
    /// Prepare NtContinue against an already admitted native application continuation.
    ///
    /// Unlike fault entry, native IPC has overwritten the target's volatile registers. Every
    /// unrequested GPR must therefore come from the captured application, not the parked TCB.
    /// These words are execution data only; the caller still owns thread/reply authorization.
    pub fn prepare_native_continue(
        &self,
        application: &[u64; 18],
        highest_user_address: u64,
        test_alert: bool,
    ) -> Result<LegacyContextRestore, CodecError> {
        let plan = self.prepare_continue(
            application[0],
            application[1],
            application[2],
            highest_user_address,
            test_alert,
        )?;
        Ok(complete_application_registers(plan, application))
    }

    /// Self SET returns STATUS_SUCCESS in RAX while preserving unrequested application GPRs.
    /// The consumer must atomically install/restart instead of returning through the IPC stub.
    pub fn prepare_native_self_set(
        &self,
        application: &[u64; 18],
        highest_user_address: u64,
    ) -> Result<LegacyContextRestore, CodecError> {
        let plan = self.prepare_self_set(
            application[0],
            application[1],
            application[2],
            highest_user_address,
        )?;
        Ok(complete_application_registers(plan, application))
    }
}

fn complete_application_registers(
    mut plan: LegacyContextRestore,
    application: &[u64; 18],
) -> LegacyContextRestore {
    for (index, value) in application.iter().copied().enumerate() {
        if plan.register_mask & (1 << index) == 0 {
            plan.registers[index] = value;
        }
    }
    plan.register_mask = (1 << 18) - 1;
    plan
}

#[cfg(test)]
mod tests;
