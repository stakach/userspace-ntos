//! One FAT32 volume-information contract for local and canonical mounted File routes.

pub(crate) unsafe fn encode_query(
    fs: &crate::Fat32,
    information_class: u32,
    output: &mut [u8],
) -> Result<nt_fs::QueryInformationResult, u32> {
    const FAT32_NAME: [u16; 5] = [b'F' as u16, b'A' as u16, b'T' as u16, b'3' as u16, b'2' as u16];

    let (serial_number, label_bytes) = crate::fs_loader::fat_volume_identity(fs);
    let mut label = [0u16; 11];
    for (index, byte) in label_bytes.iter().copied().enumerate() {
        label[index] = byte as u16;
    }
    let size = if matches!(
        information_class,
        nt_fs::FILE_FS_SIZE_INFORMATION | nt_fs::FILE_FS_FULL_SIZE_INFORMATION
    ) {
        crate::fs_loader::fat_volume_size(fs)
    } else {
        None
    };
    nt_fs::encode_query_volume_information(
        information_class,
        nt_fs::VolumeMetadata {
            creation_time: 0,
            serial_number,
            supports_objects: false,
            label: &label[..label_bytes.len()],
            device_type: nt_fs::FILE_DEVICE_DISK,
            device_characteristics: nt_fs::FILE_DEVICE_IS_MOUNTED,
            file_system_attributes: nt_fs::FILE_CASE_PRESERVED_NAMES | nt_fs::FILE_UNICODE_ON_DISK,
            maximum_component_name_length: 255,
            file_system_name: &FAT32_NAME,
            size,
            control: None,
            object_id: None,
        },
        output,
    )
}
