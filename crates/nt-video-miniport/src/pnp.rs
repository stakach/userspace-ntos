//! PnP requests owned by VideoPort rather than by a display miniport.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoPortRelationOwner {
    DriverStack,
    TargetRelation,
    BusRelations,
}

/// The VideoPort FDO handles both relation types. The miniport registers child
/// callbacks with VideoPort; it does not provide an IRP_MJ_PNP handler.
pub const fn video_port_relation_owner(
    video_port_initialized: bool,
    minor: u8,
    relation_type: Option<u32>,
) -> VideoPortRelationOwner {
    if !video_port_initialized || minor != nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS {
        return VideoPortRelationOwner::DriverStack;
    }
    match relation_type {
        Some(nt_pnp_abi::TARGET_DEVICE_RELATION) => VideoPortRelationOwner::TargetRelation,
        Some(nt_pnp_abi::BUS_RELATIONS) => VideoPortRelationOwner::BusRelations,
        _ => VideoPortRelationOwner::DriverStack,
    }
}

/// ReactOS VideoPort refuses BusRelations child enumeration before the video
/// device has been opened. An opened device must run the miniport child callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoPortBusRelationsAction {
    Complete { status: u32 },
    EnumerateChildren,
}

pub const fn video_port_bus_relations_action(device_opened: bool) -> VideoPortBusRelationsAction {
    if device_opened {
        VideoPortBusRelationsAction::EnumerateChildren
    } else {
        VideoPortBusRelationsAction::Complete {
            status: 0xC000_009A, // STATUS_INSUFFICIENT_RESOURCES
        }
    }
}

/// Compatibility predicate for the existing TargetDeviceRelation dispatch.
pub fn owns_target_device_relation(
    video_port_initialized: bool,
    minor: u8,
    relation_type: Option<u32>,
) -> bool {
    video_port_relation_owner(video_port_initialized, minor, relation_type)
        == VideoPortRelationOwner::TargetRelation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_relation_predicate_excludes_other_video_port_requests() {
        assert!(owns_target_device_relation(
            true,
            nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
            Some(nt_pnp_abi::TARGET_DEVICE_RELATION),
        ));
        assert!(!owns_target_device_relation(
            false,
            nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
            Some(nt_pnp_abi::TARGET_DEVICE_RELATION),
        ));
        assert!(!owns_target_device_relation(
            true,
            nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
            Some(nt_pnp_abi::BUS_RELATIONS),
        ));
        assert!(!owns_target_device_relation(
            true,
            nt_pnp_abi::IRP_MN_START_DEVICE,
            Some(nt_pnp_abi::TARGET_DEVICE_RELATION),
        ));
    }

    #[test]
    fn initialized_video_port_fdo_owns_bus_relations() {
        assert_eq!(
            video_port_relation_owner(
                true,
                nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
                Some(nt_pnp_abi::BUS_RELATIONS),
            ),
            VideoPortRelationOwner::BusRelations
        );
        assert_eq!(
            video_port_relation_owner(
                false,
                nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
                Some(nt_pnp_abi::BUS_RELATIONS),
            ),
            VideoPortRelationOwner::DriverStack
        );
    }

    #[test]
    fn unopened_video_device_completes_bus_relations_with_insufficient_resources() {
        assert_eq!(
            video_port_bus_relations_action(false),
            VideoPortBusRelationsAction::Complete {
                status: 0xC000_009A,
            }
        );
        assert_eq!(
            video_port_bus_relations_action(true),
            VideoPortBusRelationsAction::EnumerateChildren
        );
    }
}
