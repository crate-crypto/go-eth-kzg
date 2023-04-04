package api_test

import (
	"testing"

	"github.com/crate-crypto/go-proto-danksharding-crypto/api"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

// Globally initialize a ctx for tests.
var ctx, _ = api.NewContext4096Insecure1337()

func TestBlobProveVerifyRandomPointIntegration(t *testing.T) {
	blob := GetRandBlob(123)

	commitment, err := ctx.BlobToKZGCommitment(blob)
	if err != nil {
		t.Error(err)
	}
	proof, err := ctx.ComputeBlobKZGProof(blob, commitment)
	if err != nil {
		t.Error(err)
	}
	err = ctx.VerifyBlobKZGProof(blob, commitment, proof)
	if err != nil {
		t.Error(err)
	}
}
func TestBlobProveVerifySpecifiedPointIntegration(t *testing.T) {
	blob := GetRandBlob(123)

	commitment, err := ctx.BlobToKZGCommitment(blob)
	if err != nil {
		t.Error(err)
	}
	inputPoint := GetRandFieldElement(123)
	proof, claimedValue, err := ctx.ComputeKZGProof(blob, inputPoint)
	if err != nil {
		t.Error(err)
	}
	err = ctx.VerifyKZGProof(commitment, inputPoint, claimedValue, proof)
	if err != nil {
		t.Error(err)
	}
}
func TestBlobProveVerifyBatchIntegration(t *testing.T) {

	batchSize := 5

	blobs := make([]serialization.Blob, batchSize)
	commitments := make([]serialization.KZGCommitment, batchSize)
	proofs := make([]serialization.KZGProof, batchSize)

	for i := 0; i < batchSize; i++ {
		blobs[i] = GetRandBlob(int64(i))
		commitment_i, err := ctx.BlobToKZGCommitment(blobs[i])
		if err != nil {
			t.Error(err)
		}
		commitments[i] = commitment_i
		proof_i, err := ctx.ComputeBlobKZGProof(blobs[i], commitments[i])
		if err != nil {
			t.Error(err)
		}
		proofs[i] = proof_i
	}
	err := ctx.VerifyBlobKZGProofBatch(blobs, commitments, proofs)
	if err != nil {
		t.Error(err)
	}
}
