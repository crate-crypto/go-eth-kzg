package erasure_code

import "testing"

// The recovery algorithm relies on the blocks tiling the data word exactly. Parameters
// that break that must be rejected at construction rather than silently recovering the
// wrong polynomial: every derived domain is still a power of two, so nothing else fails.
func TestNewDataRecoveryRejectsNonTilingParameters(t *testing.T) {
	for _, tc := range []struct {
		name                                              string
		blockErasureSize, numScalarsInDataWord, expansion int
	}{
		{"block size does not divide the data word", 7, 16, 2},
		{"block size larger than the data word", 32, 16, 2},
		{"zero block size", 0, 16, 2},
		{"negative block size", -4, 16, 2},
		{"zero expansion factor", 4, 16, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected a panic for (%d, %d, %d)",
						tc.blockErasureSize, tc.numScalarsInDataWord, tc.expansion)
				}
			}()
			NewDataRecovery(tc.blockErasureSize, tc.numScalarsInDataWord, tc.expansion)
		})
	}
}

func TestNewDataRecoveryAcceptsTilingParameters(t *testing.T) {
	for _, tc := range [][3]int{{64, 4096, 2}, {4, 16, 2}, {4, 16, 4}, {1, 8, 2}, {16, 16, 2}} {
		if dr := NewDataRecovery(tc[0], tc[1], tc[2]); dr == nil {
			t.Fatalf("expected %v to be accepted", tc)
		}
	}
}
