//! Bounded NT `ExQueueWorkItem` admission. Callbacks execute after the queuing call returns.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExQueuedWork {
    pub item: u64,
    pub routine: u64,
    pub parameter: u64,
    pub queue_type: u32,
    sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExWorkQueueError {
    Invalid,
    AlreadyQueued,
    Full,
    SequenceExhausted,
}

pub struct ExWorkQueue<const N: usize> {
    entries: [Option<ExQueuedWork>; N],
    next_sequence: u64,
}

impl<const N: usize> ExWorkQueue<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N], next_sequence: 0 }
    }

    pub fn enqueue(&mut self, item: u64, routine: u64, parameter: u64, queue_type: u32)
        -> Result<(), ExWorkQueueError>
    {
        if item == 0 || routine == 0 || queue_type > 2 {
            return Err(ExWorkQueueError::Invalid);
        }
        if self.entries.iter().flatten().any(|entry| entry.item == item) {
            return Err(ExWorkQueueError::AlreadyQueued);
        }
        let slot = self.entries.iter_mut().find(|entry| entry.is_none())
            .ok_or(ExWorkQueueError::Full)?;
        let sequence = self.next_sequence.checked_add(1)
            .ok_or(ExWorkQueueError::SequenceExhausted)?;
        self.next_sequence = sequence;
        *slot = Some(ExQueuedWork { item, routine, parameter, queue_type, sequence });
        Ok(())
    }

    pub fn take_ready(&mut self) -> Option<ExQueuedWork> {
        let index = self.entries.iter().enumerate()
            .filter_map(|(index, entry)| entry.map(|work| (index, work.sequence)))
            .min_by_key(|(_, sequence)| *sequence)?.0;
        self.entries[index].take()
    }
}

impl<const N: usize> Default for ExWorkQueue<N> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_work_is_deferred_fifo_and_reusable_after_dequeue() {
        let mut queue = ExWorkQueue::<2>::new();
        queue.enqueue(10, 100, 1000, 0).unwrap();
        queue.enqueue(20, 200, 2000, 1).unwrap();
        assert_eq!(queue.enqueue(10, 100, 1000, 0), Err(ExWorkQueueError::AlreadyQueued));
        assert_eq!(queue.enqueue(30, 300, 3000, 2), Err(ExWorkQueueError::Full));
        assert_eq!(queue.take_ready().unwrap().item, 10);
        queue.enqueue(10, 100, 1000, 0).unwrap();
        assert_eq!(queue.take_ready().unwrap().item, 20);
        assert_eq!(queue.take_ready().unwrap().item, 10);
        assert!(queue.take_ready().is_none());
    }
}
