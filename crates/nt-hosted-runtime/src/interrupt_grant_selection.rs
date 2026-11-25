//! Select one retained interrupt grant for a hosted driver call.
//!
//! Callers pass only grants whose canonical device binding, PnP lease, physical claim and
//! resource-manager assignment were validated at the native boundary. A mutable lane bank
//! supplies neither a device identity nor authority for a sibling connection.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptGrantScope {
    pub driver_id: u64,
    pub instance: usize,
    pub projection_instance: usize,
    pub domain_id: u64,
    pub domain_cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptGrant {
    pub scope: InterruptGrantScope,
    pub device_id: u64,
    pub pdo_object: u64,
    pub vector: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptGrantRequest {
    pub scope: InterruptGrantScope,
    /// Zero means the traditional `IoConnectInterrupt` call, which has no PDO argument.
    pub pdo_object: u64,
    /// Zero is permitted only with an explicit PDO, as in line-based `IoConnectInterruptEx`.
    pub vector: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptGrantSelectionError {
    InvalidRequest,
    Missing,
    Ambiguous,
}

pub fn select_interrupt_grant(
    request: InterruptGrantRequest,
    grants: impl IntoIterator<Item = InterruptGrant>,
) -> Result<u64, InterruptGrantSelectionError> {
    if request.scope.driver_id == 0
        || request.scope.domain_id == 0
        || request.scope.domain_cookie == 0
        || request.vector == 0 && request.pdo_object == 0
    {
        return Err(InterruptGrantSelectionError::InvalidRequest);
    }
    let mut selected = None;
    for grant in grants {
        if grant.device_id == 0
            || grant.pdo_object == 0
            || grant.vector == 0
            || grant.scope != request.scope
            || request.pdo_object != 0 && grant.pdo_object != request.pdo_object
            || request.vector != 0 && grant.vector != request.vector
        {
            continue;
        }
        if selected.replace(grant.device_id).is_some() {
            return Err(InterruptGrantSelectionError::Ambiguous);
        }
    }
    selected.ok_or(InterruptGrantSelectionError::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPE: InterruptGrantScope = InterruptGrantScope {
        driver_id: 7, instance: 4, projection_instance: 4, domain_id: 21, domain_cookie: 9,
    };
    const KEYBOARD: InterruptGrant = InterruptGrant {
        scope: SCOPE, device_id: 12, pdo_object: 0x300, vector: 12,
    };
    const MOUSE: InterruptGrant = InterruptGrant {
        scope: SCOPE, device_id: 11, pdo_object: 0x301, vector: 11,
    };

    #[test]
    fn selects_both_siblings_without_relying_on_published_order() {
        let grants = [MOUSE, KEYBOARD];
        for vector in [11, 12] {
            let expected = if vector == 11 { MOUSE.device_id } else { KEYBOARD.device_id };
            assert_eq!(select_interrupt_grant(InterruptGrantRequest {
                scope: SCOPE, pdo_object: 0, vector,
            }, grants), Ok(expected));
        }
        assert_eq!(select_interrupt_grant(InterruptGrantRequest {
            scope: SCOPE, pdo_object: MOUSE.pdo_object, vector: 0,
        }, grants), Ok(MOUSE.device_id));
    }

    #[test]
    fn refuses_foreign_generation_scope_unknown_vector_and_ambiguity() {
        let foreign = InterruptGrant { scope: InterruptGrantScope {
            domain_cookie: 10, ..SCOPE
        }, ..MOUSE };
        let req = InterruptGrantRequest { scope: SCOPE, pdo_object: 0, vector: 11 };
        assert_eq!(select_interrupt_grant(req, [foreign]), Err(InterruptGrantSelectionError::Missing));
        assert_eq!(select_interrupt_grant(req, [KEYBOARD]), Err(InterruptGrantSelectionError::Missing));
        assert_eq!(select_interrupt_grant(req, [MOUSE, MOUSE]), Err(InterruptGrantSelectionError::Ambiguous));
        assert_eq!(select_interrupt_grant(InterruptGrantRequest {
            scope: SCOPE, pdo_object: 0, vector: 0,
        }, [MOUSE]), Err(InterruptGrantSelectionError::InvalidRequest));
    }
}
