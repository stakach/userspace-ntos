//! Wire operation numbers for the hosted driver registry broker.
//! All component callers and executive dispatch branches use this single allocation.

pub(super) const HOSTED_REGISTRY_OP_OPEN_RELATIVE_KEY: u64 = 1;
pub(super) const HOSTED_REGISTRY_OP_OPEN_DEVICE_KEY: u64 = 2;
pub(super) const HOSTED_REGISTRY_OP_CLOSE: u64 = 3;
pub(super) const HOSTED_REGISTRY_OP_ENUMERATE_KEY: u64 = 4;
pub(super) const HOSTED_REGISTRY_OP_QUERY_HANDLE_VALUE: u64 = 5;
pub(super) const HOSTED_REGISTRY_OP_QUERY_PATH_VALUE: u64 = 6;
pub(super) const HOSTED_REGISTRY_OP_SET_HANDLE_VALUE: u64 = 7;
pub(super) const HOSTED_REGISTRY_OP_CREATE_RELATIVE_KEY: u64 = 8;
pub(super) const HOSTED_REGISTRY_OP_BEGIN_SET_HANDLE_VALUE: u64 = 9;
pub(super) const HOSTED_REGISTRY_OP_APPEND_SET_HANDLE_VALUE: u64 = 10;
pub(super) const HOSTED_REGISTRY_OP_COMMIT_SET_HANDLE_VALUE: u64 = 11;
pub(super) const HOSTED_REGISTRY_OP_ABORT_SET_HANDLE_VALUE: u64 = 12;
pub(super) const HOSTED_REGISTRY_OP_DELETE_HANDLE_VALUE: u64 = 13;
pub(super) const HOSTED_REGISTRY_OP_PUBLISH_HANDLE: u64 = 14;
pub(super) const HOSTED_REGISTRY_OP_ABORT_PUBLICATION: u64 = 15;
pub(super) const HOSTED_REGISTRY_OP_OPEN_INTERFACE_KEY: u64 = 16;
pub(super) const HOSTED_REGISTRY_OP_REGISTER_INTERFACE: u64 = 17;
pub(super) const HOSTED_REGISTRY_OP_ENUMERATE_VALUE: u64 = 18;
pub(super) const HOSTED_REGISTRY_OP_QUERY_KEY: u64 = 19;
