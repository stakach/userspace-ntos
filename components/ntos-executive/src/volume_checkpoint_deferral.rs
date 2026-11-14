//! Service-boundary classification of one mounted-volume checkpoint attempt.

const STATUS_SUCCESS: u32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Nothing was owed, or the owed snapshot is durable.
    Settled,
    /// The attempt was refused; the service boundary reports this status.
    Failed(u32),
}

pub(crate) fn classify(status: u32) -> Outcome {
    if status == STATUS_SUCCESS {
        Outcome::Settled
    } else {
        Outcome::Failed(status)
    }
}
