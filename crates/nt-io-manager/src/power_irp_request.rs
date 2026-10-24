//! Frame layout for an I/O manager-owned power IRP.
//!
//! ReactOS reserves two frames above the top device stack: one for the power
//! dispatch and its completion routine, and one retaining the request arguments
//! until the completion callback has consumed them.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerIrpPlanError {
    InvalidMinor,
    InvalidStack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerIrpPlan {
    pub stack_count: u8,
    pub request_location: u8,
    pub metadata_location: u8,
    pub initial_location: u8,
    pub pre_dispatch_location: u8,
}

impl PowerIrpPlan {
    /// x64 `IO_STACK_LOCATION.Parameters.Power` uses pointer-aligned fields.
    pub const POWER_TYPE_OFFSET: u64 = nt_power_types::PARAM_POWER_TYPE_OFFSET;
    pub const POWER_STATE_OFFSET: u64 = nt_power_types::PARAM_POWER_STATE_OFFSET;

    pub fn new(top_stack_size: u8, minor: u8) -> Result<Self, PowerIrpPlanError> {
        if !matches!(minor, 0x00 | 0x02 | 0x03) {
            return Err(PowerIrpPlanError::InvalidMinor);
        }
        // Hosted IoAllocateIrp supports at most 32 frames. The current-location
        // byte also needs one terminal location above those frames.
        if !(1..=30).contains(&top_stack_size) {
            return Err(PowerIrpPlanError::InvalidStack);
        }
        let stack_count = top_stack_size + 2;
        Ok(Self {
            stack_count,
            request_location: top_stack_size,
            metadata_location: top_stack_size + 1,
            initial_location: stack_count + 1,
            pre_dispatch_location: top_stack_size + 1,
        })
    }
}

/// Pointer-free power state carried by a canonical IRP and driver-peer wire.
/// The requestor's raw state is preserved; the receiving driver decides whether
/// it supports that state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerParameters {
    minor: u8,
    system_context: u32,
    state_type: u32,
    state: u32,
    shutdown_type: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerParameterError {
    InvalidMinor,
}

impl PowerParameters {
    pub fn device(minor: u8, state: u32) -> Result<Self, PowerParameterError> {
        if !matches!(minor, nt_power_types::IRP_MN_SET_POWER | nt_power_types::IRP_MN_QUERY_POWER) {
            return Err(PowerParameterError::InvalidMinor);
        }
        Ok(Self { minor, system_context: 0,
            state_type: nt_power_types::POWER_STATE_TYPE_DEVICE, state, shutdown_type: 0 })
    }

    pub fn system(minor: u8, state: u32) -> Result<Self, PowerParameterError> {
        if !matches!(minor, nt_power_types::IRP_MN_SET_POWER | nt_power_types::IRP_MN_QUERY_POWER) {
            return Err(PowerParameterError::InvalidMinor);
        }
        Ok(Self { minor, system_context: 0,
            state_type: nt_power_types::POWER_STATE_TYPE_SYSTEM, state, shutdown_type: 0 })
    }

    pub const fn wait_wake(state: u32) -> Result<Self, PowerParameterError> {
        Ok(Self {
            minor: nt_power_types::IRP_MN_WAIT_WAKE,
            system_context: 0,
            state_type: nt_power_types::POWER_STATE_TYPE_SYSTEM,
            state,
            shutdown_type: 0,
        })
    }

    /// Preserve the raw fields of a forwarded SET/QUERY POWER stack location.
    /// PoRequestPowerIrp uses the zero values supplied by its zeroed allocation.
    pub fn with_forwarded_context(mut self, system_context: u32,
        shutdown_type: u32) -> Result<Self, PowerParameterError> {
        if !matches!(self.minor,
            nt_power_types::IRP_MN_SET_POWER | nt_power_types::IRP_MN_QUERY_POWER) {
            return Err(PowerParameterError::InvalidMinor);
        }
        self.system_context = system_context;
        self.shutdown_type = shutdown_type;
        Ok(self)
    }

    pub const fn minor(self) -> u8 { self.minor }
    pub const fn state_type(self) -> u32 { self.state_type }
    pub const fn state(self) -> u32 { self.state }
    pub const fn system_context(self) -> u32 { self.system_context }
    pub const fn shutdown_type(self) -> u32 { self.shutdown_type }
}
