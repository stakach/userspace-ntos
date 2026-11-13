//! Admission for a hosted `KeIpiGenericCall` worker.
//!
//! A local call is the complete broadcast only when boot topology contains one CPU.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpiAdmission {
    Local,
    NeedsBroadcast,
    InvalidCallback,
    InvalidTopology,
}

pub const fn admit(
    active_cpus: u64,
    callback: u64,
    image_base: u64,
    image_len: u64,
) -> IpiAdmission {
    if active_cpus == 0 || active_cpus > 64 {
        return IpiAdmission::InvalidTopology;
    }
    let Some(end) = image_base.checked_add(image_len) else {
        return IpiAdmission::InvalidCallback;
    };
    if callback == 0 || image_base == 0 || image_len == 0 || callback < image_base || callback >= end {
        return IpiAdmission::InvalidCallback;
    }
    if active_cpus == 1 { IpiAdmission::Local } else { IpiAdmission::NeedsBroadcast }
}
