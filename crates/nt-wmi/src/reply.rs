//! The hosted WMI broker returns a status and one value in exactly two words.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwoWordReply {
    pub status: i32,
    pub value: u64,
}

impl TwoWordReply {
    /// Registers beyond `words` are not part of the reply and may retain input.
    pub const fn decode(words: u64, registers: [u64; 4]) -> Option<Self> {
        if words != 2 {
            return None;
        }
        Some(Self {
            status: registers[0] as u32 as i32,
            value: registers[1],
        })
    }
}
