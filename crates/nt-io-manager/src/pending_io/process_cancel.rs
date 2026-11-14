//! Request selection for `NtCancelIoFileEx`.

use super::{PendingFileIo, PendingFileIoOperation, PendingFileIoTable, PendingFileRoute};

impl PendingFileIoTable {
    /// The requests `NtCancelIoFileEx` may cancel: everything process `pi` issued on `route` from
    /// any of its threads, narrowed to the request that names `iosb` as its IO_STATUS_BLOCK when
    /// one is given. A CREATE has no File object yet, a request whose completion is already owned
    /// by an APC delivery is terminal, and an abandoned consumer has been cancelled already.
    pub fn process_file_requests(
        &self,
        route: PendingFileRoute,
        pi: u32,
        iosb: Option<u64>,
    ) -> impl Iterator<Item = PendingFileIo> + '_ {
        self.slots.iter().enumerate().filter_map(move |(slot, pending)| {
            let pending = pending.as_ref()?;
            (!self.apc_owned_slot(slot)
                && pending.route == route
                && pending.pi == pi
                && !pending.consumer_abandoned
                && !matches!(pending.operation, PendingFileIoOperation::Create(_))
                && iosb.is_none_or(|iosb| pending.iosb_va == iosb))
            .then_some(*pending)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn request(file: u64, irp: u64, pi: u32, tid: u64, iosb: u64) -> PendingFileIo {
        PendingFileIo {
            route: PendingFileRoute::Hosted(file),
            irp_id: irp,
            major: nt_io_abi::major::IRP_MJ_READ,
            pi,
            tid,
            output_va: 0x1000,
            output_len: 8,
            iosb_va: iosb,
            event_obj_idx: 5,
            ..PendingFileIo::default()
        }
    }

    fn selected(
        table: &PendingFileIoTable, file: u64, pi: u32, iosb: Option<u64>,
    ) -> Vec<u64> {
        let mut irps: Vec<u64> = table
            .process_file_requests(PendingFileRoute::Hosted(file), pi, iosb)
            .map(|pending| pending.irp_id)
            .collect();
        irps.sort_unstable();
        irps
    }

    #[test]
    fn selects_every_thread_of_the_process_on_the_exact_file() {
        let mut table = PendingFileIoTable::new();
        for pending in [
            request(11, 1, 8, 100, 0x2000),
            request(11, 2, 8, 101, 0x3000),
            request(11, 3, 9, 200, 0x2000),
            request(12, 4, 8, 100, 0x2000),
        ] {
            assert!(table.park(pending).is_some(), "fixture request {}", pending.irp_id);
        }
        assert_eq!(selected(&table, 11, 8, None), [1, 2]);
        assert_eq!(selected(&table, 11, 9, None), [3]);
        assert_eq!(selected(&table, 12, 8, None), [4]);
        assert!(selected(&table, 13, 8, None).is_empty());
    }

    #[test]
    fn a_named_status_block_selects_only_its_request() {
        let mut table = PendingFileIoTable::new();
        assert!(table.park(request(11, 1, 8, 100, 0x2000)).is_some());
        assert!(table.park(request(11, 2, 8, 101, 0x3000)).is_some());
        assert_eq!(selected(&table, 11, 8, Some(0x3000)), [2]);
        assert!(selected(&table, 11, 8, Some(0x4000)).is_empty());
        // The same address in another process is a different request.
        assert!(selected(&table, 11, 9, Some(0x3000)).is_empty());
    }

    #[test]
    fn create_and_abandoned_requests_are_never_selected() {
        let mut table = PendingFileIoTable::new();
        let create = PendingFileIo {
            route: PendingFileRoute::Hosted(11),
            irp_id: 1,
            major: nt_io_abi::major::IRP_MJ_CREATE,
            operation: PendingFileIoOperation::Create(super::super::PendingFileCreate {
                handle_va: 0x1000,
                desired_access: 3,
                provider_context: 4,
                lifecycle_reserved: true,
                reservation_pid: 5,
                reserved_handle: 6,
                reservation_generation: 7,
                status: nt_status::NtStatus::PENDING.raw() as u32,
                information: 0,
                handle_value: 0,
                output: super::super::PendingCreateOutput::default(),
            }),
            pi: 8,
            tid: 100,
            iosb_va: 0x2000,
            event_obj_idx: u64::MAX,
            ..PendingFileIo::default()
        };
        assert!(table.park(create).is_some());
        let slot = table.park(request(11, 2, 8, 100, 0x2000)).unwrap();
        assert!(table.abandon_transfer_exact(slot, 2).is_some());
        assert!(table.park(request(11, 3, 8, 100, 0x2000)).is_some());
        assert_eq!(selected(&table, 11, 8, None), [3]);
    }
}
