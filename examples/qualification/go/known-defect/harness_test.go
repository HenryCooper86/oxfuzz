package frame

import "testing"

func FuzzParseFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1, 'A'})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = ParseFrame(data)
	})
}

func TestParseFramePanicsWithSpareCapacity(t *testing.T) {
	backing := []byte{2, 'A', 'B'}
	input := backing[:2]
	defer func() {
		if recover() == nil {
			t.Fatal("truncated payload must panic even when the backing array has spare capacity")
		}
	}()
	_ = ParseFrame(input)
}
