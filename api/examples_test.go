package api_test

import (
	"testing"

	"github.com/crate-crypto/go-proto-danksharding-crypto/api"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
	"github.com/stretchr/testify/require"
)

// Globally initialize a ctx for tests.
var ctx, _ = api.NewContext4096Insecure1337()

func TestBlobProveVerifyRandomPointIntegration(t *testing.T) {
	blob := GetRandBlob(123)
	commitment, err := ctx.BlobToKZGCommitment(blob)
	require.NoError(t, err)
	proof, err := ctx.ComputeBlobKZGProof(blob, commitment)
	require.NoError(t, err)
	err = ctx.VerifyBlobKZGProof(blob, commitment, proof)
	require.NoError(t, err)
}

func TestBlobProveVerifySpecifiedPointIntegration(t *testing.T) {
	blob := GetRandBlob(123)
	commitment, err := ctx.BlobToKZGCommitment(blob)
	require.NoError(t, err)
	inputPoint := GetRandFieldElement(123)
	require.NoError(t, err)
	proof, claimedValue, err := ctx.ComputeKZGProof(blob, inputPoint)
	require.NoError(t, err)
	err = ctx.VerifyKZGProof(commitment, inputPoint, claimedValue, proof)
	require.NoError(t, err)
}

func TestBlobProveVerifyBatchIntegration(t *testing.T) {
	batchSize := 5
	blobs := make([]serialization.Blob, batchSize)
	commitments := make([]serialization.KZGCommitment, batchSize)
	proofs := make([]serialization.KZGProof, batchSize)

	for i := 0; i < batchSize; i++ {
		blob := GetRandBlob(int64(i))
		commitment, err := ctx.BlobToKZGCommitment(blob)
		require.NoError(t, err)
		proof, err := ctx.ComputeBlobKZGProof(blob, commitment)
		require.NoError(t, err)

		blobs[i] = blob
		commitments[i] = commitment
		proofs[i] = proof
	}
	err := ctx.VerifyBlobKZGProofBatch(blobs, commitments, proofs)
	require.NoError(t, err)
}
