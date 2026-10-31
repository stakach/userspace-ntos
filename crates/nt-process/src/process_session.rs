//! MM session-space membership, separate from ProcessSessionInformation's numeric value.

use crate::{ProcessId, ProcessManager, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};

const STATUS_ALREADY_COMMITTED: u32 = 0xC000_0021;
const STATUS_UNABLE_TO_FREE_VM: u32 = 0xC000_001A;

impl ProcessManager {
    /// Record successful `MmSessionCreate`: the caller owns an attached session space and is
    /// designated a session leader. A pre-existing attachment cannot be replaced by a create.
    pub fn create_process_session(&mut self, pid: ProcessId, session_id: u32) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        if process.session_space.is_some() {
            return Err(STATUS_ALREADY_COMMITTED);
        }
        if session_id == u32::MAX {
            return Err(STATUS_INVALID_PARAMETER);
        }
        process.session_leader = true;
        process.session_space = Some(session_id);
        process.session_id = session_id;
        Ok(())
    }

    /// Record successful MM attachment of a process to an existing session space. This does not
    /// designate the process as the session leader, including for session zero.
    pub fn attach_process_session(&mut self, pid: ProcessId, session_id: u32) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        if process.session_space.is_some() {
            return Err(STATUS_ALREADY_COMMITTED);
        }
        if session_id == u32::MAX {
            return Err(STATUS_INVALID_PARAMETER);
        }
        process.session_space = Some(session_id);
        process.session_id = session_id;
        Ok(())
    }

    /// Record successful MM detachment. A leader retains its designation, as in EPROCESS, but
    /// its session-space pointer is cleared. Process teardown may detach an ordinary member too.
    pub fn detach_process_session(&mut self, pid: ProcessId) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        if process.session_space.take().is_none() {
            return Err(STATUS_UNABLE_TO_FREE_VM);
        }
        process.session_id = 0;
        Ok(())
    }

    /// `MmSessionDelete` only accepts the session leader and its exact attached session ID.
    pub fn delete_process_session(&mut self, pid: ProcessId, session_id: u32) -> Result<(), u32> {
        let process = self.processes.get(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        if !process.session_leader || process.session_space != Some(session_id) {
            return Err(STATUS_UNABLE_TO_FREE_VM);
        }
        self.detach_process_session(pid)
    }

    /// `MmGetSessionIdEx`/`PsGetProcessSessionIdEx` for the exact published EPROCESS body.
    /// A leader returns zero; an unattached nonleader returns MAX, even if its numeric
    /// ProcessSessionInformation value is zero. Unknown and retired body pointers are refused.
    pub fn kernel_process_session_id_ex(&self, eprocess: u64) -> Option<u32> {
        let pid = self.pid_for_kernel_process_object(eprocess)?;
        let process = self.processes.get(&pid)?;
        Some(if process.session_leader {
            0
        } else {
            process.session_space.unwrap_or(u32::MAX)
        })
    }
}
