//! Owned callback preparation and installation for retained component terminal results.

use crate::win32k_glue::{self, CallbackTransferBinding, Win32kClientContext};
use alloc::vec::Vec;

const INVALID: u32 = 0xC000_000D;
const UNSUCCESSFUL: u32 = 0xC000_0001;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransferPhase {
    Reserved,
    Captured,
    Preparing,
    Prepared,
    Installing,
    Installed,
    Publishing,
    Published,
    Failed(u32),
}

struct PreparedCallback {
    layout: nt_user_callback::UserCallbackStackLayout,
    callout: nt_user_callback::UserCalloutFrame,
    redirected: [u64; 20],
}

/// Owns one callback's immutable input and canonical parent through separately acknowledged
/// preparation, private context installation, and callback-stack publication. The terminal
/// coordinator retains the native reply and the stage ticket; this value never sends a Reply.
pub(super) struct CallbackTransfer {
    input: Vec<u8>,
    binding: Option<CallbackTransferBinding>,
    parent: Option<[u64; 20]>,
    prepared: Option<PreparedCallback>,
    phase: TransferPhase,
}

impl CallbackTransfer {
    /// Reserve and initialize all payload storage before the provider is resumed.
    pub(super) fn reserve() -> Result<Self, u32> {
        let _durable = crate::allocator::enter_durable();
        let mut input = Vec::new();
        input
            .try_reserve_exact(nt_user_callback::CALLBACK_PAYLOAD_MAX)
            .map_err(|_| 0xC000_009Au32)?;
        input.resize(nt_user_callback::CALLBACK_PAYLOAD_MAX, 0);
        Ok(Self {
            input,
            binding: None,
            parent: None,
            prepared: None,
            phase: TransferPhase::Reserved,
        })
    }

    pub(super) const fn phase(&self) -> TransferPhase {
        self.phase
    }

    /// Capture while the provider still owns the shared-bank execution token. Later preparation
    /// reads only this owned input, never whichever request another lane published most recently.
    pub(super) unsafe fn capture(
        &mut self,
        client: Win32kClientContext,
        lane: nt_component_suspension::LaneHandle,
        dispatch_id: u64,
    ) -> Result<u64, u32> {
        if self.phase != TransferPhase::Reserved {
            return Err(INVALID);
        }
        match win32k_glue::capture_callback_transfer(client, lane, dispatch_id, &mut self.input) {
            Ok(binding) => {
                let token = u64::from(binding.request().callback_id);
                self.binding = Some(binding);
                self.phase = TransferPhase::Captured;
                Ok(token)
            }
            Err(status) => {
                self.phase = TransferPhase::Failed(status);
                Err(status)
            }
        }
    }

    pub(super) unsafe fn prepare(&mut self) -> Result<(), u32> {
        if self.phase != TransferPhase::Captured {
            return Err(INVALID);
        }
        self.phase = TransferPhase::Preparing;
        let outcome = self.prepare_inner();
        self.phase = match outcome {
            Ok(()) => TransferPhase::Prepared,
            Err(status) => TransferPhase::Failed(status),
        };
        outcome
    }

    unsafe fn prepare_inner(&mut self) -> Result<(), u32> {
        let binding = self.binding.ok_or(INVALID)?;
        win32k_glue::validate_callback_transfer_binding(binding)?;
        let client = binding.client();
        let request = binding.request();
        let saved = crate::thread_context::LegacyThreadContext::read(client.tcb)
            .map_err(|_| UNSUCCESSFUL)?
            .registers;
        // Retain the one canonical parent before further validation or client-memory effects.
        // A failed prepare never recaptures it or rewrites a later, edited parent on retry.
        self.parent = Some(saved);
        let dispatcher = win32k_glue::validate_callback_transfer_parent(binding, &saved)?;
        let layout = nt_user_callback::UserCallbackStackLayout::below(
            saved[nt_user_callback::USER_CONTEXT_RSP],
            request.input_length as usize,
        )
        .map_err(|_| INVALID)?;
        let callout = nt_user_callback::UserCalloutFrame::callback(
            layout.input_pointer,
            request.input_length,
            request.api_index,
            saved[nt_user_callback::USER_CONTEXT_RIP],
            saved[nt_user_callback::USER_CONTEXT_RSP],
            saved[nt_user_callback::USER_CONTEXT_RFLAGS] as u32,
        );
        let redirected =
            nt_user_callback::callback_redirect_context(&saved, dispatcher, layout.frame_pointer);
        self.prepared = Some(PreparedCallback {
            layout,
            callout,
            redirected,
        });
        let reference_patch = if request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
            && request.payload_reference_offset != nt_user_callback::NO_PAYLOAD_REFERENCE
        {
            if u64::from(request.input_length) < win32k_glue::WINDOWPROC_LPARAM_OFFSET + 8 {
                return Err(INVALID);
            }
            Some(
                nt_user_callback::client_payload_reference(
                    layout.input_pointer,
                    request.input_length as usize,
                    request.payload_reference_offset,
                )
                .map_err(|_| INVALID)?,
            )
        } else {
            None
        };
        if request.input_length != 0
            && !crate::img_spawn::client_write_mapped(
                u64::from(client.pi),
                layout.input_pointer,
                &self.input[..request.input_length as usize],
                &[],
                0,
                client.scratch_base,
            )
        {
            return Err(UNSUCCESSFUL);
        }
        if let Some(reference) = reference_patch {
            if !crate::img_spawn::client_write_mapped(
                u64::from(client.pi),
                layout.input_pointer + win32k_glue::WINDOWPROC_LPARAM_OFFSET,
                &reference.to_le_bytes(),
                &[],
                0,
                client.scratch_base,
            ) {
                return Err(UNSUCCESSFUL);
            }
        }
        let prepared = self.prepared.as_ref().ok_or(INVALID)?;
        let bytes = core::slice::from_raw_parts(
            core::ptr::addr_of!(prepared.callout) as *const u8,
            core::mem::size_of::<nt_user_callback::UserCalloutFrame>(),
        );
        if !crate::img_spawn::client_write_mapped(
            u64::from(client.pi),
            prepared.layout.frame_pointer,
            bytes,
            &[],
            0,
            client.scratch_base,
        ) {
            return Err(UNSUCCESSFUL);
        }
        win32k_glue::validate_callback_transfer_binding(binding)
    }

    /// Install only the already-prepared GPR/control image. Success acknowledges this private
    /// mechanism alone: callback-stack publication and the client's empty Reply remain separate.
    pub(super) unsafe fn install(&mut self) -> Result<(), u32> {
        if self.phase != TransferPhase::Prepared {
            return Err(INVALID);
        }
        self.phase = TransferPhase::Installing;
        let outcome = self.install_inner();
        self.phase = match outcome {
            Ok(()) => TransferPhase::Installed,
            Err(status) => TransferPhase::Failed(status),
        };
        outcome
    }

    unsafe fn install_inner(&self) -> Result<(), u32> {
        let binding = self.binding.ok_or(INVALID)?;
        win32k_glue::validate_callback_transfer_binding(binding)?;
        let prepared = self.prepared.as_ref().ok_or(INVALID)?;
        let update = nt_thread_start::amd64_context::LegacyContextRestore {
            registers: prepared.redirected,
            register_mask: sel4_rt::legacy_context::REGISTER_MASK,
            floating_point: None,
            debug: None,
        };
        crate::thread_context::write(binding.client().tcb, &update, false).map_err(|_| UNSUCCESSFUL)
    }

    pub(super) unsafe fn publish(&mut self) -> Result<(), u32> {
        if self.phase != TransferPhase::Installed {
            return Err(INVALID);
        }
        self.phase = TransferPhase::Publishing;
        let outcome = match (self.binding, self.parent) {
            (Some(binding), Some(parent)) => {
                win32k_glue::publish_callback_transfer(binding, parent)
            }
            _ => Err(INVALID),
        };
        self.phase = match outcome {
            Ok(()) => TransferPhase::Published,
            Err(status) => TransferPhase::Failed(status),
        };
        outcome
    }
}
