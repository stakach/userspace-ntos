//! Order the effects of retiring one exact hosted DMA adapter lease.
//!
//! Preflight shared records before touching either physical graph. A canonical adapter is
//! shared by exact sibling leases and is put only when its final lease retires.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LeaseIdentity<Owner> {
    pub lease_id: u64,
    pub adapter_id: u64,
    pub owner: Owner,
}

/// The caller authenticates `target` and supplies the current lease inventory. A callback owns
/// each physical or logical effect, so this function does not infer authority from a raw address.
pub(crate) fn retire_lease<Owner: Copy + Eq, E>(
    target: LeaseIdentity<Owner>,
    inventory: impl IntoIterator<Item = LeaseIdentity<Owner>>,
    published: bool,
    preflight_shared_records: impl FnOnce() -> Result<(), E>,
    retire_private_graph: impl FnOnce() -> Result<(), E>,
    retire_pair: impl FnOnce(bool) -> Result<(), E>,
    put_unpublished_adapter: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    let has_sibling = inventory.into_iter().any(|lease| {
        lease.lease_id != target.lease_id
            && lease.owner == target.owner
            && lease.adapter_id == target.adapter_id
    });
    preflight_shared_records()?;
    if published {
        retire_private_graph()?;
        retire_pair(!has_sibling)?;
    } else if !has_sibling {
        put_unpublished_adapter()?;
    }
    Ok(())
}
