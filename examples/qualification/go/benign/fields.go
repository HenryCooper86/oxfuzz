package benign

// CountFields counts fields separated by ASCII whitespace without allocating.
func CountFields(text string) int {
	count := 0
	inField := false
	for _, ch := range text {
		switch ch {
		case ' ', '\t', '\r', '\n':
			inField = false
		default:
			if !inField {
				count++
				inField = true
			}
		}
	}
	return count
}
