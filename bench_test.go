package gokzg4844_test

import (
	"fmt"
	// We do not require crypto/rand in tests
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/stretchr/testify/require"
)

// / Returns a serialized random field element in big-endian
func GetRandFieldElement(seed int64) [32]byte {
	rand.Seed(seed)

	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to get random field element")
	}

	var r fr.Element
	r.SetBytes(bytes)

	return gokzg4844.SerializeScalar(r)
}

func GetRandBlob(seed int64) gokzg4844.Blob {
	var blob gokzg4844.Blob
	bytesPerBlob := gokzg4844.ScalarsPerBlob * gokzg4844.SerializedScalarSize
	for i := 0; i < bytesPerBlob; i += gokzg4844.SerializedScalarSize {
		fieldElementBytes := GetRandFieldElement(seed + int64(i))
		copy(blob[i:i+gokzg4844.SerializedScalarSize], fieldElementBytes[:])
	}
	return blob
}

func Benchmark(b *testing.B) {
	const length = 64
	blobs := make([]gokzg4844.Blob, length)
	commitments := make([]gokzg4844.KZGCommitment, length)
	proofs := make([]gokzg4844.KZGProof, length)
	fields := make([]gokzg4844.Scalar, length)

	for i := 0; i < length; i++ {
		blob := GetRandBlob(int64(i))
		commitment, err := ctx.BlobToKZGCommitment(blob, NumGoRoutines)
		require.NoError(b, err)
		proof, err := ctx.ComputeBlobKZGProof(blob, commitment, NumGoRoutines)
		require.NoError(b, err)

		blobs[i] = blob
		commitments[i] = commitment
		proofs[i] = proof
		fields[i] = GetRandFieldElement(int64(i))
	}

	///////////////////////////////////////////////////////////////////////////
	// Public functions
	///////////////////////////////////////////////////////////////////////////

	b.Run("BlobToKZGCommitment", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _ = ctx.BlobToKZGCommitment(blobs[0], NumGoRoutines)
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, _ = ctx.ComputeKZGProof(blobs[0], fields[0], NumGoRoutines)
		}
	})

	b.Run("ComputeBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _ = ctx.ComputeBlobKZGProof(blobs[0], commitments[0], NumGoRoutines)
		}
	})

	b.Run("VerifyKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_ = ctx.VerifyKZGProof(commitments[0], fields[0], fields[1], proofs[0])
		}
	})

	b.Run("VerifyBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_ = ctx.VerifyBlobKZGProof(blobs[0], commitments[0], proofs[0])
		}
	})

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyBlobKZGProofBatch(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_ = ctx.VerifyBlobKZGProofBatch(blobs[:i], commitments[:i], proofs[:i])
			}
		})
	}

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyBlobKZGProofBatchPar(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_ = ctx.VerifyBlobKZGProofBatchPar(blobs[:i], commitments[:i], proofs[:i])
			}
		})
	}
}
