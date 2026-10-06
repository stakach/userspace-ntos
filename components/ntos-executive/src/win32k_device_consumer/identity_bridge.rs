//! Compare the existing consumer binding with independently authenticated physical identities.

pub(crate) fn retained_domain<C: Copy + Eq, P: Copy + Eq, D: Copy + Eq>(
    retained: (C, P, u64, D),
    physical: (C, P, u64),
    canonical_domain: Option<D>,
) -> Option<D> {
    let (catalog, provider, pml4, domain) = retained;
    if pml4 == 0 || physical != (catalog, provider, pml4) || canonical_domain != Some(domain) {
        return None;
    }
    Some(domain)
}
