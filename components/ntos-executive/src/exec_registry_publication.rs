//! Hosted Key handles stay invisible until their output has been delivered.

use super::*;
use nt_process::RegistryKeyHandlePublication;

impl ExecNtHandler {
    fn reserve_registry_key_publication(&mut self) -> Result<RegistryKeyHandlePublication, u32> {
        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let capacity = self.pm.handle_capacity(pid);
        let publication = self.pm.reserve_registry_key_handle(pid)?;
        let reserved = self.pm.handle_capacity(pid);
        if reserved != capacity {
            PM_HANDLE_CAP_GROWTHS.fetch_add(1, Ordering::Relaxed);
            PM_HANDLE_CAP_MAX.fetch_max(reserved as u64, Ordering::Relaxed);
        }
        Ok(publication)
    }

    fn abort_registry_key_publication(&mut self, publication: &mut RegistryKeyHandlePublication) {
        // Unexpected owner loss is not permission to release a different slot or target.
        if let Some(target) = publication
            .abort(&mut self.pm)
            .expect("registry publication retains its exact PM reservation")
        {
            self.release_registry_key_target(target);
        }
    }

    unsafe fn publish_registry_key(
        &mut self,
        mut publication: RegistryKeyHandlePublication,
        target: KeyRef,
        desired: u32,
        out: u64,
    ) -> u32 {
        if let Err(status) =
            publication.bind(&mut self.pm, target, Self::registry_map_access(desired))
        {
            self.abort_registry_key_publication(&mut publication);
            self.release_registry_key_target(target);
            return status;
        }
        if !self.xas_write_u64(out, publication.value()) {
            self.abort_registry_key_publication(&mut publication);
            return STATUS_ACCESS_VIOLATION;
        }
        match publication.publish(&mut self.pm) {
            Ok(_) => {
                let pid = publication.process_id();
                self.record_process_handle_insert(pid, self.pm.handle_capacity(pid));
                0
            }
            Err(status) => {
                self.abort_registry_key_publication(&mut publication);
                status
            }
        }
    }

    pub(super) unsafe fn mint_registry_key(
        &mut self,
        target: KeyRef,
        desired: u32,
        out: u64,
    ) -> u32 {
        let _durable = allocator::enter_durable();
        let publication = match self.reserve_registry_key_publication() {
            Ok(publication) => publication,
            Err(status) => {
                self.release_registry_key_target(target);
                return status;
            }
        };
        self.publish_registry_key(publication, target, desired, out)
    }

    pub(super) unsafe fn mint_cm_system_registry_key(
        &mut self,
        full_path: &str,
        desired: u32,
        out: u64,
    ) -> u32 {
        let _durable = allocator::enter_durable();
        // Reserve before OPEN can acquire a server lease. Malformed/uncertain OPEN outcomes
        // remain in cm_key_ownership; this caller owns only its independent PM reservation.
        let mut publication = match self.reserve_registry_key_publication() {
            Ok(publication) => publication,
            Err(status) => return status,
        };
        let opened = match crate::config_manager_open_system_hive_key(full_path) {
            Ok(opened) => {
                CM_NATIVE_SYSTEM_KEY_LEASE_ACQUIRES.fetch_add(1, Ordering::Relaxed);
                opened
            }
            Err(status) => {
                self.abort_registry_key_publication(&mut publication);
                if status as u32 != STATUS_OBJECT_NAME_NOT_FOUND {
                    CM_NATIVE_SYSTEM_KEY_LEASE_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
                return status as u32;
            }
        };
        let target = match self.install_cm_system_key_target(CmSystemKeyTarget {
            lease: opened.lease,
            physical_path: nt_hive_core::canon_path(&opened.physical_path),
        }) {
            Ok(target) => target,
            Err(status) => {
                self.abort_registry_key_publication(&mut publication);
                // Retirement transfers cleanup to the journal even when the first close fails.
                if crate::config_manager_retire_system_hive_key(opened.lease).is_ok() {
                    CM_NATIVE_SYSTEM_KEY_LEASE_CLOSES.fetch_add(1, Ordering::Relaxed);
                }
                CM_NATIVE_SYSTEM_KEY_LEASE_FAILURES.fetch_add(1, Ordering::Relaxed);
                return status;
            }
        };
        let status = self.publish_registry_key(publication, target, desired, out);
        if status != 0 {
            CM_NATIVE_SYSTEM_KEY_LEASE_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        status
    }
}
