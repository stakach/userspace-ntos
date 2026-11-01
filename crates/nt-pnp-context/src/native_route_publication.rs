//! Publication authority for the exact mounted native storage route.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRoutePublication<R> {
    Absent,
    Initial { route: R },
    Published { route: R },
    Refreshing { route: R },
}

impl<R: Copy + Eq> NativeRoutePublication<R> {
    pub const fn published(self) -> Option<R> {
        match self { Self::Published { route } => Some(route), _ => None }
    }

    pub const fn retained_recheck_route(self) -> Option<R> {
        match self {
            Self::Initial { route } | Self::Refreshing { route } => Some(route),
            _ => None,
        }
    }

    pub fn publish_initial(self, route: R) -> Result<Self, Self> {
        match self { Self::Absent => Ok(Self::Initial { route }), _ => Err(self) }
    }

    pub fn complete_initial(self, route: R) -> Result<Self, Self> {
        match self {
            Self::Initial { route: current } if current == route => Ok(Self::Published { route }),
            _ => Err(self),
        }
    }

    pub fn begin_refresh(self, route: R) -> Result<Self, Self> {
        match self {
            Self::Published { route: current } if current == route => Ok(Self::Refreshing { route }),
            _ => Err(self),
        }
    }

    pub fn abort_refresh(self, route: R) -> Option<Self> {
        match self {
            Self::Refreshing { route: current } if current == route => Some(Self::Published { route }),
            _ => None,
        }
    }

    pub fn commit_refresh(self, previous: R, next: R) -> Option<Self> {
        match self {
            Self::Refreshing { route } if route == previous => Some(Self::Published { route: next }),
            _ => None,
        }
    }
}

/// Retained work in the active relation publication. The owner survives a callback and may
/// advance only while the matching physical route is withheld from ordinary mounted I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationStorageWork {
    HeaderRecheck { id: u64 },
    Wal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelationWalClaim<I, Q> {
    pub owner: I,
    pub request: Q,
}

impl RelationStorageWork {
    pub const fn needs_pump(self) -> bool { true }
    pub const fn header_recheck(self) -> Option<u64> {
        match self { Self::HeaderRecheck { id } if id != 0 => Some(id), _ => None }
    }
    pub const fn wal(self) -> bool { matches!(self, Self::Wal) }
}

impl<I: Eq, Q: Eq> RelationWalClaim<I, Q> {
    pub fn matches(&self, owner: I, request: Q) -> bool {
        self.owner == owner && self.request == request
    }
}

#[cfg(test)]
mod tests {
    use super::{NativeRoutePublication as Publication, RelationStorageWork, RelationWalClaim};

    #[test]
    fn retained_relation_work_stays_pumpable_through_wal_and_abort() {
        let header = RelationStorageWork::HeaderRecheck { id: 9 };
        assert!(header.needs_pump());
        assert_eq!(header.header_recheck(), Some(9));
        assert!(!header.wal());
        let wal = RelationStorageWork::Wal;
        assert!(wal.needs_pump());
        assert!(wal.wal());
        assert_eq!(wal.header_recheck(), None);

        let claimed = RelationWalClaim { owner: 41u64, request: 7u64 };
        assert!(claimed.matches(41, 7));
        assert!(!claimed.matches(42, 7));
        assert!(!claimed.matches(41, 8));
    }

    #[test]
    fn only_relation_owned_mount_can_service_its_header_recheck_before_publication() {
        let absent = Publication::<u64>::Absent;
        assert_eq!(absent.published(), None);
        assert_eq!(absent.retained_recheck_route(), None);

        let initial = absent.publish_initial(41).unwrap();
        assert_eq!(initial.published(), None);
        assert_eq!(initial.retained_recheck_route(), Some(41));
        assert!(initial.publish_initial(42).is_err());
        assert!(initial.begin_refresh(41).is_err());

        let published = initial.complete_initial(41).unwrap();
        assert_eq!(published.published(), Some(41));
        assert_eq!(published.retained_recheck_route(), None);
        assert!(published.complete_initial(41).is_err());

        let refreshing = published.begin_refresh(41).unwrap();
        assert_eq!(refreshing.published(), None);
        assert_eq!(refreshing.retained_recheck_route(), Some(41));
        assert!(refreshing.begin_refresh(41).is_err());
        assert!(refreshing.complete_initial(41).is_err());
        assert_eq!(refreshing.abort_refresh(42), None);
        assert_eq!(refreshing.abort_refresh(41), Some(published));
        assert_eq!(refreshing.commit_refresh(41, 42), Some(Publication::Published { route: 42 }));
        assert_eq!(refreshing.commit_refresh(42, 43), None);
    }
}
