//! Typed dispatcher waits made by isolated NT providers.
//!
//! The dispatcher arbiter owns object readiness, signal consumption, and wait leases. Shared
//! `nt-component-suspension` lanes own continuation ordering and authenticated caller identity.

#![no_std]

extern crate alloc;

mod abi;
mod allocation;
mod arbiter;
mod domain;
mod kernel_activation;
mod local_event;
mod local_timer;
mod stack_activation;

pub use abi::*;
pub use allocation::*;
pub use arbiter::*;
pub use domain::*;
pub use kernel_activation::*;
pub use local_event::*;
pub use local_timer::*;
pub use nt_component_suspension::{
    LaneHandle, SuspensionCaller, SuspensionHostedClient, SuspensionOwner as ProviderWaitOwner,
};
pub use stack_activation::*;
