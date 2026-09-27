pub fn parse_record(data: &[u8]) -> u8 {
    if data.len() < 3 || &data[..2] != b"OX" {
        return 0;
    }
    qualification_codec::checksum(data.get(3..3 + usize::from(data[2])).unwrap_or(&[]))
}
