package api

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
	"github.com/stretchr/testify/require"
)

var ctx, _ = NewContext4096Insecure1337()

func GetRandFieldElement(seed int64) [32]byte {
	rand.Seed(seed)
	bytes := make([]byte, 31)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to get random field element")
	}

	var fieldElementBytes [32]byte
	copy(fieldElementBytes[:], bytes)
	return fieldElementBytes
}

func GetRandBlob(seed int64) serialisation.Blob {
	var blob serialisation.Blob
	bytesPerBlob := serialisation.SCALARS_PER_BLOB * serialisation.SERIALISED_SCALAR_SIZE
	for i := 0; i < bytesPerBlob; i += serialisation.SERIALISED_SCALAR_SIZE {
		fieldElementBytes := GetRandFieldElement(seed + int64(i))
		copy(blob[i:i+serialisation.SERIALISED_SCALAR_SIZE], fieldElementBytes[:])
	}
	return blob
}

func Benchmark(b *testing.B) {
	const length = 64
	blobs := make([]serialisation.Blob, length)
	for i := 0; i < length; i++ {
		blobs[i] = GetRandBlob(int64(i))
	}

	commitments, err := ctx.BlobsToCommitments(blobs)
	require.NoError(b, err)

	z := [32]byte{1, 2, 3}
	y := [32]byte{4, 5, 6}
	// change to uppercase KZG
	proof, _, err := ctx.ComputeAggregateKZGProof(blobs[:1])
	require.NoError(b, err)

	blob := []serialisation.Blob{blobs[0]}

	b.Run("BlobToKZGCommitment", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := ctx.BlobsToCommitments(blob)
			require.NoError(b, err)
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, _, err := ctx.ComputeKZGProof(blobs[0], z)
			require.NoError(b, err)
		}
	})

	b.Run("VerifyKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			// TODO: ordering may differ from specs -- check c-kzg and spec
			_ = ctx.VerifyKZGProof(commitments[0], proof, z, y)
			// require.NoError(b, err)
		}
	})

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("ComputeAggregateKZGProof(blobs=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, _, err := ctx.ComputeAggregateKZGProof(blobs[:i])
				require.NoError(b, err)
			}
		})
	}

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyAggregateKZGProof(blobs=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_ = ctx.VerifyAggregateKZGProof(blobs[:i], proof, commitments[:i])
				// require.NoError(b, C_KZG_OK, ret)
			}
		})
	}
}

func TestModulus(t *testing.T) {
	expected_modulus := fr.Modulus()
	if !bytes.Equal(expected_modulus.Bytes(), MODULUS[:]) {
		t.Error("expected modulus does not match the modulus of the scalar field")
	}
}

// func GeneratePolys(numPolys int, degree int) [][]fr.Element {
// 	polys := make([]kzg.Polynomial, numPolys)
// 	for i := 0; i < numPolys; i++ {
// 		polys[i] = randPoly(degree)
// 	}
// 	return polys
// }

// func randPoly(polyDegree int) []fr.Element {
// 	poly := make([]fr.Element, polyDegree)
// 	for i := 0; i < polyDegree; i++ {
// 		var eval fr.Element
// 		_, err := eval.SetRandom()
// 		if err != nil {
// 			panic("err is not nil")
// 		}
// 		poly[i] = eval
// 	}
// 	return poly
// }
