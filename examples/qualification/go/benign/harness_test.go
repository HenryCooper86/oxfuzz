package benign

import "testing"

func FuzzCountFields(f *testing.F) {
	f.Add("")
	f.Add("one")
	f.Add("one two")
	f.Add(" \t\n")
	f.Fuzz(func(t *testing.T, text string) {
		count := CountFields(text)
		if count < 0 || count > len(text) {
			t.Fatalf("invalid field count: %d for %d input bytes", count, len(text))
		}
	})
}
