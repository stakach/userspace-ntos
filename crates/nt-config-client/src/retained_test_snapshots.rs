//! Fixture helper using explicit production snapshot ownership and acknowledgment.

use super::*;

pub(crate) fn query<B: Backend>(client: &mut ConfigClient<B>, manager: &mut CmSnapshotAttempts,
    path: &str, expected_generation: u64) -> Result<ActiveDriverServiceBinding, i32>
{
    let mut attempt = manager.reserve_active_driver_service(path)?;
    while !attempt.is_acknowledged() {
        let operation = if attempt.server_nonce().is_none() { CmSnapshotOperation::Query }
            else if attempt.outcome_status().is_none() { CmSnapshotOperation::Begin }
            else if !attempt.is_complete() { CmSnapshotOperation::Pull }
            else { CmSnapshotOperation::Acknowledge };
        let mut exchange = manager.begin_exchange(&mut attempt, operation).unwrap();
        let response = client.exchange_retained_snapshot(&exchange);
        manager.complete_exchange(&mut attempt, &mut exchange, response).unwrap();
    }
    let result = manager.take_active_driver_service(&mut attempt, expected_generation);
    manager.release(&mut attempt).unwrap();
    result
}
