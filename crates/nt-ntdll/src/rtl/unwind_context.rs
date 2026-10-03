//! Restoration-context publication between completed AMD64 unwind frames.

use super::exception::raw_context::RawContext;

/// Publish only a successfully completed non-target frame. The target frame's own virtual
/// unwind describes its caller and must not replace the context used to enter the target body.
pub fn publish_completed_frame(restoration: &mut RawContext, unwound: &RawContext) {
    restoration.clone_from(unwound);
}

#[cfg(test)]
mod tests;
