use nt_fs::{DiskSignature, examine_mbr, read_disk_signature};

#[test]
fn mbr_signature_comes_from_sector_zero_with_twos_complement_checksum() {
    let mut sector = [0u8; 512];
    sector[440..444].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let mut reads = Vec::new();
    let signature = read_disk_signature(512, |lba, out| {
        reads.push(lba);
        out.copy_from_slice(&sector);
        Ok::<_, ()>(())
    }).unwrap();
    let sum = sector.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_le_bytes(word.try_into().unwrap()))
    });
    assert_eq!(signature, DiskSignature::Mbr { signature: 0x1234_5678, checksum: 0u32.wrapping_sub(sum) });
    assert_eq!(reads, [0]);
}

#[test]
fn disk_manager_examination_requires_real_boot_signature_and_matching_type() {
    let mut sector = [0u8; 512];
    sector[450] = 0x54;
    assert_eq!(examine_mbr(&sector, 0x54), None);
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
    assert_eq!(examine_mbr(&sector, 0x55), None);
    assert_eq!(examine_mbr(&sector, 0x54), Some(nt_fs::MbrExamination::DiskManager { skew_sectors: 63 }));
}

#[test]
fn protective_mbr_reads_gpt_header_and_rejects_bad_crc() {
    let mut mbr = [0u8; 512];
    mbr[450] = 0xee;
    let mut header = [0u8; 512];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    header[12..16].copy_from_slice(&92u32.to_le_bytes());
    header[56..72].fill(0x42);
    let crc = nt_fs::gpt_crc32(&header[..92]);
    header[16..20].copy_from_slice(&crc.to_le_bytes());
    let mut reads = Vec::new();
    let sig = read_disk_signature(512, |lba, out| {
        reads.push(lba);
        out.copy_from_slice(if lba == 0 { &mbr } else { &header });
        Ok::<_, ()>(())
    }).unwrap();
    assert_eq!(sig, DiskSignature::Gpt { disk_id: [0x42; 16] });
    assert_eq!(reads, [0, 1]);
    header[56] ^= 1;
    assert!(read_disk_signature(512, |lba, out| {
        out.copy_from_slice(if lba == 0 { &mbr } else { &header });
        Ok::<_, ()>(())
    }).is_err());
}

#[test]
fn odd_sector_size_and_source_error_are_preserved() {
    let mut sector = [0u8; 520];
    sector[440..444].copy_from_slice(&0x99u32.to_le_bytes());
    assert!(matches!(read_disk_signature(520, |lba, out| {
        assert_eq!(lba, 0);
        assert_eq!(out.len(), 520);
        out.copy_from_slice(&sector);
        Ok::<_, u32>(())
    }), Ok(DiskSignature::Mbr { signature: 0x99, .. })));
    assert_eq!(read_disk_signature(520, |_lba, _out| Err::<(), _>(0xc000_0185u32)),
               Err(nt_fs::DiskSignatureReadError::Io(0xc000_0185u32)));
}
