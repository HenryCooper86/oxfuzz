package frame

// ParseFrame sums a length-prefixed payload. The missing length check is
// deliberate: this fixture must panic when the declared payload is absent.
func ParseFrame(data []byte) uint32 {
	if len(data) == 0 {
		return 0
	}
	var checksum uint32
	for offset := 1; offset <= int(data[0]); offset++ {
		checksum += uint32(data[offset])
	}
	return checksum
}
