//! Exact Event selection across wait families, before any native reply is redriven.

use super::*;
use nt_kernel_exec::{
    DispatcherWaitSource, EventLeaseKind, EventObjectId, EventSignalMode, EventSignalSelector,
};

struct Selector<'a> {
    handler: &'a mut ExecNtHandler,
    index: usize,
    event: Option<EventObjectId>,
    deferred_selected: u64,
}

impl EventSignalSelector for Selector<'_> {
    fn oldest_ready(&self, source: DispatcherWaitSource) -> Option<u64> {
        match source {
            DispatcherWaitSource::Native => {
                object_waiter_oldest_event_consumer_sequence(self.handler, self.index)
            }
            DispatcherWaitSource::Gui => unsafe {
                service_sec_image::gui_message_wait_oldest_event_consumer_sequence(
                    self.handler,
                    self.event?,
                )
            },
            DispatcherWaitSource::Provider => {
                service_sec_image::provider_wait_oldest_event_consumer_sequence(
                    self.handler,
                    self.event?,
                )
            }
        }
    }

    fn select(&mut self, source: DispatcherWaitSource, sequence: u64) {
        let selected = unsafe {
            match source {
                DispatcherWaitSource::Native => {
                    object_waiter_select_event_consumer(self.handler, self.index, sequence)
                }
                DispatcherWaitSource::Gui => {
                    service_sec_image::gui_message_wait_select_event_consumer(
                        self.handler,
                        self.event
                            .expect("GUI selection requires a canonical Event"),
                        sequence,
                    )
                }
                DispatcherWaitSource::Provider => {
                    service_sec_image::provider_wait_select_event_consumer(
                        self.handler,
                        self.event
                            .expect("provider selection requires a canonical Event"),
                        sequence,
                    )
                }
            }
        };
        assert!(
            selected,
            "exact Event consumer changed during local selection"
        );
        if !matches!(source, DispatcherWaitSource::Native) {
            self.deferred_selected = self.deferred_selected.saturating_add(1);
        }
    }

    fn clear(&mut self) {
        self.handler
            .events
            .reset_existing(self.index as u64)
            .expect("pulse lost its retained Event backing");
    }
}

pub(super) unsafe fn wake(index: usize, handler: &mut ExecNtHandler, mode: EventSignalMode) -> u64 {
    let event = handler.event_id_for_index(index);
    let operation = event.map(|id| {
        handler
            .event_objects
            .acquire_wait(id, EventLeaseKind::Operation)
            .expect("Event arbitration could not retain operation ownership")
    });
    let deferred_selected = {
        let mut selector = Selector {
            handler,
            index,
            event,
            deferred_selected: 0,
        };
        nt_kernel_exec::select_event_signal(&mut selector, mode);
        selector.deferred_selected
    };
    // Selection and pulse clearing are complete before reply delivery can run any hosted caller.
    let woken = object_wait_reply::redrive(handler);
    if let Some(operation) = operation {
        if let Some(retired) = handler
            .event_objects
            .release_wait(operation, EventLeaseKind::Operation)
            .expect("Event arbitration lost its operation ownership")
        {
            handler.finalize_retired_event_object(retired);
        }
    }
    woken.saturating_add(deferred_selected)
}
