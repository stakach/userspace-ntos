//! Non-nesting allocation retirement on an exact admitted IRQ arena service.

use super::{
    HostedIrqGrantIdentity, HostedIrqLaneIdentity, HostedIrqServiceCommand, HostedIrqServiceKind,
};

impl HostedIrqServiceCommand {
    /// `current_irql` must come from the admitted arena transaction, never the wire request.
    pub fn pool_retirement_arguments(
        self,
        identity: HostedIrqLaneIdentity,
        grant: HostedIrqGrantIdentity,
        service_id: u64,
        current_irql: u8,
    ) -> Option<(u64, u64)> {
        (self.kind == HostedIrqServiceKind::PoolRetirement
            && self.valid()
            && self.service_id == service_id
            && self.target_domain_id == identity.domain_id
            && self.target_domain_cookie == identity.domain_cookie
            && self.grant == grant
            && current_irql <= 2)
            .then_some((self.arguments[0], self.arguments[1]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(op: u64) -> (HostedIrqServiceCommand, HostedIrqLaneIdentity) {
        let identity = HostedIrqLaneIdentity::new(11, 13, 17).unwrap();
        let grant = HostedIrqGrantIdentity::new(11, 13, 19, 23).unwrap();
        let mut arguments = [0; super::super::HOSTED_IRQ_ARENA_ARGUMENT_CAP];
        arguments[..2].copy_from_slice(&[op, 0x1000]);
        (
            HostedIrqServiceCommand {
                kind: HostedIrqServiceKind::PoolRetirement,
                service_id: 29,
                target_domain_id: 11,
                target_domain_cookie: 13,
                authority_cookie: 0,
                grant,
                argument_count: 2,
                arguments,
            },
            identity,
        )
    }

    #[test]
    fn only_irp_and_pool_retirement_are_non_nesting_and_dispatch_level_safe() {
        for op in 0..9 {
            let (command, identity) = command(op);
            for irql in 0..=31 {
                assert_eq!(
                    command.pool_retirement_arguments(identity, command.grant, 29, irql),
                    if matches!(op, 2 | 3) && irql <= 2 {
                        Some((op, 0x1000))
                    } else {
                        None
                    }
                );
            }
        }
        assert!(!HostedIrqServiceKind::PoolRetirement.may_request_nested_dispatch());
    }

    #[test]
    fn malformed_fields_and_wrong_authority_refuse_before_retirement() {
        let (command, identity) = command(3);
        let denied = |bad: HostedIrqServiceCommand| {
            assert_eq!(
                bad.pool_retirement_arguments(identity, command.grant, 29, 2),
                None
            );
        };
        denied(HostedIrqServiceCommand {
            authority_cookie: 1,
            ..command
        });
        denied(HostedIrqServiceCommand {
            argument_count: 1,
            ..command
        });
        denied(HostedIrqServiceCommand {
            argument_count: 3,
            ..command
        });
        denied(HostedIrqServiceCommand {
            target_domain_id: 12,
            ..command
        });
        denied(HostedIrqServiceCommand {
            target_domain_cookie: 14,
            ..command
        });
        denied(HostedIrqServiceCommand {
            service_id: 30,
            ..command
        });
        denied(HostedIrqServiceCommand {
            grant: HostedIrqGrantIdentity::new(11, 13, 19, 24).unwrap(),
            ..command
        });
        for index in 1..command.arguments.len() {
            let mut bad = command;
            bad.arguments[index] = if index == 1 { 0 } else { 1 };
            denied(bad);
        }
    }

    #[test]
    fn arena_retains_pending_until_exact_ack_and_rejects_stale_service_tokens() {
        use super::super::{
            HostedIrqArenaConfig, HostedIrqArenaControl, HostedIrqArenaResult,
            HostedIrqDispatchCommand, HostedIrqDispatchKind, HostedIrqDispatchPage,
            HostedIrqLaneDirection, HostedIrqServicePage, HostedIrqTransactionClass,
            HOSTED_IRQ_ARENA_ARGUMENT_CAP, HOSTED_IRQ_ARENA_RESULT_CAP,
        };

        let (command, identity) = command(3);
        let control = HostedIrqArenaControl::new(HostedIrqArenaConfig {
            identity,
            component_kpcr_va: 0x4000,
            stack_low: 0x8000,
            stack_high: 0x28_000,
            high_irql: 31,
        })
        .unwrap();
        control.worker_mark_ready(identity).unwrap();
        control.root_activate(identity).unwrap();
        let transaction = control
            .root_begin_transaction(identity, HostedIrqTransactionClass::Dpc)
            .unwrap();
        let dispatch = HostedIrqDispatchPage::new(identity);
        let dispatch_token = dispatch
            .root_publish(
                &control,
                identity,
                transaction,
                0,
                HostedIrqDispatchCommand {
                    kind: HostedIrqDispatchKind::DeferredProcedure,
                    work_id: 29,
                    routine: 0x1000,
                    object: 0x2000,
                    context: 0x3000,
                    entry_irql: 2,
                    synchronize_irql: 2,
                    grant: command.grant,
                    argument_count: 0,
                    arguments: [0; HOSTED_IRQ_ARENA_ARGUMENT_CAP],
                },
            )
            .unwrap();
        dispatch
            .worker_begin(&control, identity, dispatch_token)
            .unwrap();
        let page = HostedIrqServicePage::new(identity);
        let token = page
            .worker_publish(&control, identity, transaction, 0, command)
            .unwrap();
        for bad in [
            super::super::HostedIrqArenaToken {
                lane_generation: token.lane_generation + 1,
                ..token
            },
            super::super::HostedIrqArenaToken {
                transaction: token.transaction + 1,
                ..token
            },
            super::super::HostedIrqArenaToken {
                sequence: token.sequence + 1,
                ..token
            },
            super::super::HostedIrqArenaToken { depth: 1, ..token },
            super::super::HostedIrqArenaToken {
                direction: HostedIrqLaneDirection::Dispatch,
                ..token
            },
        ] {
            assert!(page.root_begin(&control, identity, bad).is_err());
        }
        assert_eq!(page.root_begin(&control, identity, token).unwrap(), command);
        let pending = HostedIrqArenaResult {
            status: 0x103,
            faulted: false,
            value_count: 0,
            values: [0; HOSTED_IRQ_ARENA_RESULT_CAP],
        };
        page.root_complete(&control, identity, token, pending)
            .unwrap();
        assert_eq!(page.worker_completion(identity, token).unwrap(), pending);
        assert!(page
            .worker_publish(&control, identity, transaction, 0, command)
            .is_err());
        let wrong_sequence = super::super::HostedIrqArenaToken {
            sequence: token.sequence + 1,
            ..token
        };
        assert!(page
            .worker_acknowledge(&control, identity, wrong_sequence)
            .is_err());
        assert_eq!(page.worker_completion(identity, token).unwrap(), pending);
        page.worker_acknowledge(&control, identity, token).unwrap();
        assert!(page.worker_completion(identity, token).is_err());

        let next = page
            .worker_publish(&control, identity, transaction, 0, command)
            .unwrap();
        assert_ne!(next.sequence, token.sequence);
        assert!(page.root_begin(&control, identity, token).is_err());
        assert_eq!(page.root_begin(&control, identity, next).unwrap(), command);
        assert!(page
            .root_complete(&control, identity, token, pending)
            .is_err());
        page.root_complete(&control, identity, next, pending)
            .unwrap();
        assert!(page.worker_acknowledge(&control, identity, token).is_err());
        assert_eq!(page.worker_completion(identity, next).unwrap(), pending);
        page.worker_acknowledge(&control, identity, next).unwrap();
        dispatch
            .worker_complete(
                &control,
                identity,
                dispatch_token,
                HostedIrqArenaResult {
                    status: 0,
                    ..pending
                },
            )
            .unwrap();
        dispatch
            .root_acknowledge(&control, identity, dispatch_token)
            .unwrap();
        control
            .root_finish_transaction(identity, transaction)
            .unwrap();
    }
}
