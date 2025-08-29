package goethkzg_test

import (
	"testing"

	goethkzg "github.com/crate-crypto/go-eth-kzg"
	"github.com/stretchr/testify/require"
)

// Globally initialize a ctx for tests.
var ctx, _ = goethkzg.NewContext4096Secure()

func TestBlobProveVerifyRandomPointIntegration(t *testing.T) {
	blob := GetRandBlob(123)
	commitment, err := ctx.BlobToKZGCommitment(blob, NumGoRoutines)
	require.NoError(t, err)
	proof, err := ctx.ComputeBlobKZGProof(blob, commitment, NumGoRoutines)
	require.NoError(t, err)
	err = ctx.VerifyBlobKZGProof(blob, commitment, proof)
	require.NoError(t, err)
}

func TestBlobProveVerifySpecifiedPointIntegration(t *testing.T) {
	blob := GetRandBlob(123)
	commitment, err := ctx.BlobToKZGCommitment(blob, NumGoRoutines)
	require.NoError(t, err)
	inputPoint := GetRandFieldElement(123)
	proof, claimedValue, err := ctx.ComputeKZGProof(blob, inputPoint, NumGoRoutines)
	require.NoError(t, err)
	err = ctx.VerifyKZGProof(commitment, inputPoint, claimedValue, proof)
	require.NoError(t, err)
}

func TestBlobProveVerifyBatchIntegration(t *testing.T) {
	batchSize := 5
	blobs := make([]*goethkzg.Blob, batchSize)
	commitments := make([]goethkzg.KZGCommitment, batchSize)
	proofs := make([]goethkzg.KZGProof, batchSize)

	for i := 0; i < batchSize; i++ {
		blob := GetRandBlob(int64(i))
		commitment, err := ctx.BlobToKZGCommitment(blob, NumGoRoutines)
		require.NoError(t, err)
		proof, err := ctx.ComputeBlobKZGProof(blob, commitment, NumGoRoutines)
		require.NoError(t, err)

		blobs[i] = blob
		commitments[i] = commitment
		proofs[i] = proof
	}
	err := ctx.VerifyBlobKZGProofBatch(blobs, commitments, proofs)
	require.NoError(t, err)
}
