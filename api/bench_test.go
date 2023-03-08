package api

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
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

func GetRandBlob(seed int64) serialization.Blob {
	var blob serialization.Blob
	bytesPerBlob := serialization.SCALARS_PER_BLOB * serialization.SERIALIZED_SCALAR_SIZE
	for i := 0; i < bytesPerBlob; i += serialization.SERIALIZED_SCALAR_SIZE {
		fieldElementBytes := GetRandFieldElement(seed + int64(i))
		copy(blob[i:i+serialization.SERIALIZED_SCALAR_SIZE], fieldElementBytes[:])
	}
	return blob
}

func Benchmark(b *testing.B) {
	const length = 64
	blobs := make([]serialization.Blob, length)
	commitments := make([]serialization.Commitment, length)
	proofs := make([]serialization.G1Point, length)
	fields := make([]serialization.Scalar, length)

	for i := 0; i < length; i++ {
		blob := GetRandBlob(int64(i))
		commitment, err := ctx.BlobToCommitment(blob)
		requireNoError(err)
		proof, _, err := ctx.ComputeBlobKZGProof(blob, commitment)
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
			ctx.BlobToCommitment(blobs[0])
		}
	})

	b.Run("ComputeKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ctx.ComputeKZGProof(blobs[0], fields[0])
		}
	})

	b.Run("ComputeBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ctx.ComputeBlobKZGProof(blobs[0], commitments[0])
		}
	})

	b.Run("VerifyKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ctx.VerifyKZGProof(commitments[0], proofs[0], fields[0], fields[1])
		}
	})

	b.Run("VerifyBlobKZGProof", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ctx.VerifyBlobKZGProof(blobs[0], commitments[0], proofs[0])
		}
	})

	for i := 1; i <= len(blobs); i *= 2 {
		b.Run(fmt.Sprintf("VerifyBlobKZGProofBatch(count=%v)", i), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				ctx.VerifyBlobKZGProofBatch(blobs[:i], commitments[:i], proofs[:i])
			}
		})
	}

}

func requireNoError(err error) {
	if err != nil {
		panic(err)
	}
}
