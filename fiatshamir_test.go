package gokzg4844

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

// This is both an interop test and a regression check
// If the way computeChallenge is computed is updated
// then this test will fail
func TestComputeChallengeInterop(t *testing.T) {
	blob := &Blob{}
	commitment := SerializeG1Point(bls12381.G1Affine{})
	challenge := computeChallenge(blob, KZGCommitment(commitment))
	expected := []byte{
		0x04, 0xb7, 0xb2, 0x2a, 0xf6, 0x3d, 0x2b, 0x2f,
		0x1c, 0xed, 0x8d, 0x55, 0x05, 0x60, 0xe5, 0xd1,
		0xe4, 0xb0, 0x1e, 0x35, 0x59, 0x03, 0xde, 0xe2,
		0x27, 0x81, 0xe8, 0x78, 0x26, 0x85, 0x60, 0x96,
	}
	got := SerializeScalar(challenge)
	require.Equal(t, expected, got[:])
}

func TestTo16Bytes(t *testing.T) {
	number := uint64(4096)
	// Generated using the following python snippet:
	// FIELD_ELEMENTS_PER_BLOB = 4096
	// degree_poly = int.to_bytes(FIELD_ELEMENTS_PER_BLOB, 16, 'big')
	// " ".join(format(x, "d") for x in degree_poly)
	expected := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0}
	got := u64ToByteArray16(number)
	require.Equal(t, expected, got)
}

func BenchmarkComputeChallenge(b *testing.B) {
	var (
		blob       = &Blob{}
		commitment = SerializeG1Point(bls12381.G1Affine{})
		challenge  fr.Element
		want       = []byte{
			0x04, 0xb7, 0xb2, 0x2a, 0xf6, 0x3d, 0x2b, 0x2f,
			0x1c, 0xed, 0x8d, 0x55, 0x05, 0x60, 0xe5, 0xd1,
			0xe4, 0xb0, 0x1e, 0x35, 0x59, 0x03, 0xde, 0xe2,
			0x27, 0x81, 0xe8, 0x78, 0x26, 0x85, 0x60, 0x96,
		}
	)
	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		challenge = computeChallenge(blob, KZGCommitment(commitment))
	}
	have := SerializeScalar(challenge)
	require.Equal(b, want, have[:])
}
