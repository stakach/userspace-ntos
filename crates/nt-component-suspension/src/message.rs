//! Owned x86-64 seL4 receive data, independent of the live IPC buffer and reply ownership.

/// ABI extent: tag, 120 message words, user data, three cap/badge words, and receive path.
pub const IPC_BUFFER_WORDS: usize = 128;
const MESSAGE_WORDS: usize = 120;

pub struct IpcBufferSnapshot {
    words: [u64; IPC_BUFFER_WORDS],
}

impl IpcBufferSnapshot {
    /// The caller must prevent IPC or mutation of the source during this bounded copy.
    pub fn capture(mut read: impl FnMut(usize) -> u64) -> Self {
        let mut words = [0; IPC_BUFFER_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            *word = read(index);
        }
        Self { words }
    }

    pub fn restore(&self, mut write: impl FnMut(usize, u64)) {
        for (index, word) in self.words.iter().enumerate() {
            write(index, *word);
        }
    }
}

/// A receive observation, not evidence that a Call bound a Reply object. Badge/tag values alone
/// cannot distinguish a Call, Send, notification, or empty nonblocking receive. Captured cap words
/// are metadata, not ownership of transferred capabilities. This object has no Drop-side effects.
pub struct ReceivedMessage {
    badge: u64,
    info: u64,
    registers: [u64; 4],
    buffer: IpcBufferSnapshot,
}

impl ReceivedMessage {
    pub fn new(badge: u64, info: u64, registers: [u64; 4], buffer: IpcBufferSnapshot) -> Self {
        Self {
            badge,
            info,
            registers,
            buffer,
        }
    }

    pub fn badge(&self) -> u64 {
        self.badge
    }
    pub fn info(&self) -> u64 {
        self.info
    }
    pub fn registers(&self) -> [u64; 4] {
        self.registers
    }

    /// Reject malformed lengths rather than truncating or exposing stale tail words.
    pub fn message_len(&self) -> Option<usize> {
        let length = (self.info & 0x7f) as usize;
        (length <= MESSAGE_WORDS).then_some(length)
    }

    pub fn word(&self, index: usize) -> Option<u64> {
        if index >= self.message_len()? {
            return None;
        }
        Some(if index < self.registers.len() {
            self.registers[index]
        } else {
            self.buffer.words[index + 1]
        })
    }

    /// Restore the exact buffer, not a normalized message: fast MRs are authoritative registers
    /// and need not have been written into their corresponding IPC-buffer slots by the kernel.
    pub fn restore_buffer(&self, write: impl FnMut(usize, u64)) {
        self.buffer.restore(write);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_retains_received_message_across_buffer_reuse_and_handoff() {
        use crate::{ComponentIngress, ComponentSuspensionLanes, IngressObservation};
        let lanes = ComponentSuspensionLanes::<u64, u64, u64>::new(0, 1);
        let mut ingress = ComponentIngress::new(10, 20).unwrap();
        let mut attempt = lanes.begin_ingress_receive(&mut ingress).unwrap();
        let mut buffer = [91; IPC_BUFFER_WORDS];
        let message = ReceivedMessage::new(
            0,
            5,
            [1, 2, 3, 4],
            IpcBufferSnapshot::capture(|index| buffer[index]),
        );
        assert!(ingress
            .observe_receive(&mut attempt, IngressObservation::Call(message))
            .is_ok());
        buffer.fill(42);
        let replacement = ComponentIngress::new(10, 30).unwrap();
        let retained = lanes
            .handoff_ingress_call(&mut ingress, replacement)
            .ok()
            .unwrap();
        assert!(lanes.begin_ingress_receive(&mut ingress).is_ok());
        let message = retained.message().unwrap();
        assert_eq!(message.badge(), 0);
        assert_eq!(message.word(0), Some(1));
        assert_eq!(message.word(4), Some(91));
        assert_eq!(message.word(5), None);
        message.restore_buffer(|index, word| buffer[index] = word);
        assert_eq!(buffer, [91; IPC_BUFFER_WORDS]);
    }

    #[test]
    fn full_buffer_is_owned_and_restored_without_touching_surrounding_memory() {
        let mut source = core::array::from_fn::<_, IPC_BUFFER_WORDS, _>(|i| i as u64 + 91);
        let original = source;
        let snapshot = IpcBufferSnapshot::capture(|i| source[i]);
        source.fill(0);
        let mut destination = [u64::MAX; IPC_BUFFER_WORDS + 2];
        snapshot.restore(|i, word| destination[i + 1] = word);
        assert_eq!(&destination[1..=IPC_BUFFER_WORDS], &original);
        assert_eq!(destination[0], u64::MAX);
        assert_eq!(destination[IPC_BUFFER_WORDS + 1], u64::MAX);
    }

    #[test]
    fn registers_override_stale_buffer_only_when_reading_valid_message_words() {
        for length in 0..=127 {
            let message = ReceivedMessage::new(
                0,
                (55 << 12) | length,
                [11, 12, 13, 14],
                IpcBufferSnapshot::capture(|i| 1000 + i as u64),
            );
            assert_eq!(message.badge(), 0);
            assert_eq!(message.info() >> 12, 55);
            assert_eq!(
                message.message_len(),
                (length <= 120).then_some(length as usize)
            );
            for i in 0..=128 {
                let expected = if length > 120 || i >= length as usize {
                    None
                } else if i < 4 {
                    Some(11 + i as u64)
                } else {
                    Some(1001 + i as u64)
                };
                assert_eq!(message.word(i), expected);
            }
            let mut restored = [0; IPC_BUFFER_WORDS];
            message.restore_buffer(|i, word| restored[i] = word);
            assert_eq!(restored, core::array::from_fn(|i| 1000 + i as u64));
        }
    }
}
