pub fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}
