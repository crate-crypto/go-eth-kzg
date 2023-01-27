package api

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

var ctx = NewContextInsecure(1337)

func GetRandFieldElement(seed int64) [32]byte {
	rand.Seed(seed)
	fieldElementBytes := make([]byte, 31)
	_, err := rand.Read(fieldElementBytes)
	if err != nil {
		panic("failed to get random field element")
	}

	var ret [32]byte
	copy(ret[:], fieldElementBytes)
	return ret
}

func GetRandBlob(seed int64) Blob {
	var blob Blob
	var BytesPerBlob = SCALARS_PER_BLOB * SERIALISED_SCALAR_SIZE

	for i := 0; i < BytesPerBlob; i += SERIALISED_SCALAR_SIZE {
		fieldElementBytes := GetRandFieldElement(seed + int64(i))
		copy(blob[i:i+SERIALISED_SCALAR_SIZE], fieldElementBytes[:])
	}
	return blob
}

func Benchmark(b *testing.B) {
	const length = 64
	blobs := make([]Blob, length)
	for i := 0; i < length; i++ {
		blobs[i] = GetRandBlob(int64(i))
	}

	commitments, err := ctx.BlobsToCommitments(blobs)
	require.NoError(b, err)

	z := GetRandFieldElement(0)
	y := GetRandFieldElement(10)
	// change to uppercase KZG
	proof, _, err := ctx.ComputeAggregateKZGProof(blobs[:1])
	require.NoError(b, err)

	blob := []Blob{blobs[0]}

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
