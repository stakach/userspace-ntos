//! Test fixtures acquire and release leases through the production retained protocols.

use super::*;

pub(crate) fn open<B: Backend>(client: &mut ConfigClient<B>, path: &str) -> OpenedSystemHiveKey {
    let mut manager = SystemHiveKeyOpenAttempts::new();
    let mut attempt = manager.reserve(path).unwrap();
    for operation in [SystemHiveKeyOpenOperation::Query, SystemHiveKeyOpenOperation::Begin, SystemHiveKeyOpenOperation::Acknowledge] {
        let mut exchange = manager.begin_exchange(&mut attempt, operation).unwrap();
        let response = client.exchange_system_hive_key_open(&exchange);
        manager.complete_exchange(&mut attempt, &mut exchange, response).unwrap();
    }
    let generation = attempt.known_lease().unwrap().opened_generation;
    let opened = manager.take_validated(&mut attempt, generation).unwrap();
    manager.release(&mut attempt).unwrap();
    opened
}

pub(crate) fn close<B: Backend>(client: &mut ConfigClient<B>, lease: SystemHiveKeyLease) -> Result<SystemHiveKeyCloseAcknowledgement, i32> {
    let receipt = client.prepare_system_hive_key_close(lease)?;
    client.acknowledge_system_hive_key_close(receipt)
}
