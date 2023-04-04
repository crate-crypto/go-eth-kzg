package api

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
	"golang.org/x/sync/errgroup"
)

// [verify_kzg_proof](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#verify_kzg_proof)
func (c *Context) VerifyKZGProof(blobCommitment serialization.KZGCommitment, inputPointBytes, claimedValueBytes serialization.Scalar, kzgProof serialization.KZGProof) error {
	// 1. Deserialization
	//
	claimedValue, err := serialization.DeserializeScalar(claimedValueBytes)
	if err != nil {
		return err
	}

	inputPoint, err := serialization.DeserializeScalar(inputPointBytes)
	if err != nil {
		return err
	}

	polynomialCommitment, err := serialization.DeserializeG1Point(blobCommitment)
	if err != nil {
		return err
	}

	quotientCommitment, err := serialization.DeserializeG1Point(kzgProof)
	if err != nil {
		return err
	}

	// 2. Verify opening proof
	proof := kzg.OpeningProof{
		QuotientCommitment: quotientCommitment,
		InputPoint:         inputPoint,
		ClaimedValue:       claimedValue,
	}

	return kzg.Verify(&polynomialCommitment, &proof, c.openKey)
}

// [verify_blob_kzg_proof](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof)
func (c *Context) VerifyBlobKZGProof(blob serialization.Blob, blobCommitment serialization.KZGCommitment, kzgProof serialization.KZGProof) error {
	// 1. Deserialize
	//
	polynomial, err := serialization.DeserializeBlob(blob)
	if err != nil {
		return err
	}

	polynomialCommitment, err := serialization.DeserializeG1Point(blobCommitment)
	if err != nil {
		return err
	}

	quotientCommitment, err := serialization.DeserializeG1Point(kzgProof)
	if err != nil {
		return err
	}

	// 2. Compute the evaluation challenge
	evaluationChallenge := computeChallenge(blob, blobCommitment)

	// 3. Compute output point/ claimed value
	outputPoint, err := c.domain.EvaluateLagrangePolynomial(polynomial, evaluationChallenge)
	if err != nil {
		return err
	}

	// 4. Verify opening proof
	openingProof := kzg.OpeningProof{
		QuotientCommitment: quotientCommitment,
		InputPoint:         evaluationChallenge,
		ClaimedValue:       *outputPoint,
	}

	return kzg.Verify(&polynomialCommitment, &openingProof, c.openKey)
}

// [verify_blob_kzg_proof_batch](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof_batch)
func (c *Context) VerifyBlobKZGProofBatch(blobs []serialization.Blob, polynomialCommitments []serialization.KZGCommitment, kzgProofs []serialization.KZGProof) error {
	// 1. Check that all components in the batch have the same size
	//
	blobsLen := len(blobs)
	lengthsAreEqual := blobsLen == len(polynomialCommitments) && blobsLen == len(kzgProofs)
	if !lengthsAreEqual {
		return ErrBatchLengthCheck
	}
	batchSize := blobsLen

	// 2. Collect opening proofs
	//
	openingProofs := make([]kzg.OpeningProof, batchSize)
	commitments := make([]bls12381.G1Affine, batchSize)
	for i := 0; i < batchSize; i++ {
		// 2a. Deserialize
		//
		serComm := polynomialCommitments[i]
		polynomialCommitment, err := serialization.DeserializeG1Point(serComm)
		if err != nil {
			return err
		}

		kzgProof := kzgProofs[i]
		quotientCommitment, err := serialization.DeserializeG1Point(kzgProof)
		if err != nil {
			return err
		}

		blob := blobs[i]
		polynomial, err := serialization.DeserializeBlob(blob)
		if err != nil {
			return err
		}

		// 2b. Compute the evaluation challenge
		evaluationChallenge := computeChallenge(blob, serComm)

		// 2c. Compute output point/ claimed value
		outputPoint, err := c.domain.EvaluateLagrangePolynomial(polynomial, evaluationChallenge)
		if err != nil {
			return err
		}

		// 2d. Append opening proof to list
		openingProof := kzg.OpeningProof{
			QuotientCommitment: quotientCommitment,
			InputPoint:         evaluationChallenge,
			ClaimedValue:       *outputPoint,
		}
		openingProofs[i] = openingProof
		commitments[i] = polynomialCommitment
	}

	// 3. Verify opening proofs
	return kzg.BatchVerifyMultiPoints(commitments, openingProofs, c.openKey)
}

// This is the same as `VerifyBlobKZGProofBatch` however we use go-routines to process each batch.
//
// If you are worried about resource starvation on large batches, then it is advised to
// schedule your own go-routines in a more intricate way than done below for large batches.
//
// [verify_blob_kzg_proof_batch](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof_batch)
func (c *Context) VerifyBlobKZGProofBatchPar(blobs []serialization.Blob, polynomialCommitments []serialization.KZGCommitment, kzgProofs []serialization.KZGProof) error {
	// 1. Check that all components in the batch have the same size
	//
	blobsLen := len(blobs)
	lengthsAreEqual := blobsLen == len(polynomialCommitments) && blobsLen == len(kzgProofs)
	if !lengthsAreEqual {
		return ErrBatchLengthCheck
	}
	batchSize := blobsLen

	var errG errgroup.Group

	// 2. Verify each opening proof using green threads
	for i := 0; i < batchSize; i++ {
		_i := i
		errG.Go(func() error {
			err := c.VerifyBlobKZGProof(blobs[_i], polynomialCommitments[_i], kzgProofs[_i])
			if err != nil {
				return err
			}
			return nil
		})
	}

	// 3. Wait for all go routines to complete and check if any returned an error
	return errG.Wait()
}
