/// Size admitted for publication after a storage host reads into a fixed buffer.
pub fn published_file_size(file_size: u32, capacity: u32, bytes_read: u32) -> Option<u32> {
    (file_size != 0 && file_size <= capacity && bytes_read == file_size).then_some(file_size)
}

#[cfg(test)]
mod tests {
    use super::published_file_size;

    #[test]
    fn truncated_file_must_not_publish_its_unread_tail() {
        assert_eq!(published_file_size(1_122_304, 262_144, 262_144), None);
        assert_eq!(published_file_size(1_961_984, 524_288, 524_288), None);
    }

    #[test]
    fn complete_nonempty_read_is_admitted() {
        assert_eq!(published_file_size(274_432, 327_680, 274_432), Some(274_432));
        assert_eq!(published_file_size(274_432, 327_680, 274_431), None);
        assert_eq!(published_file_size(0, 327_680, 0), None);
    }
}
