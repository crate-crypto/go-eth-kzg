package api_test

import (
	"fmt"
	// We do not require crypto/rand in tests
	"math/rand"
	"testing"

	"github.com/crate-crypto/go-proto-danksharding-crypto/api"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

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

func GetRandBlob(seed int64) serialization.Blob {
	var blob serialization.Blob
	bytesPerBlob := serialization.ScalarsPerBlob * serialization.SerializedScalarSize
	for i := 0; i < bytesPerBlob; i += serialization.SerializedScalarSize {
		fieldElementBytes := GetRandFieldElement(seed + int64(i))
		copy(blob[i:i+serialization.SerializedScalarSize], fieldElementBytes[:])
	}
	return blob
}

var ctxG *api.Context

func BenchmarkSetup(b *testing.B) {
	ctx, err := api.NewContext4096Insecure1337()
	if err != nil {
		panic(err)
	}
	ctxG = ctx
}

func Benchmark(b *testing.B) {
	const length = 64
	blobs := make([]serialization.Blob, length)
	commitments := make([]serialization.KZGCommitment, length)
	proofs := make([]serialization.KZGProof, length)
	fields := make([]serialization.Scalar, length)

	for i := 0; i < length; i++ {
		blob := GetRandBlob(int64(i))
		commitment, err := ctx.BlobToKZGCommitment(blob)
		requireNoError(err)
		proof, err := ctx.ComputeBlobKZGProof(blob, commitment)
		requireNoError(err)

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
			_, _ = ctx.BlobToKZGCommitment(blobs[0])
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _, _ = ctx.ComputeKZGProof(blobs[0], fields[0])
		}
	})

	b.Run("ComputeBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _ = ctx.ComputeBlobKZGProof(blobs[0], commitments[0])
		}
	})

	b.Run("VerifyKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_ = ctx.VerifyKZGProof(serialization.KZGCommitment(commitments[0]), fields[0], fields[1], proofs[0])
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

func requireNoError(err error) {
	if err != nil {
		panic(err)
	}
}
