package api

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

// [verify_kzg_proof](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#verify_kzg_proof)
func (c *Context) VerifyKZGProof(polynomialComm serialization.KZGCommitment, kzgProof serialization.KZGProof, inputPointBytes, claimedValueBytes serialization.Scalar) error {
	claimedValue, err := serialization.DeserializeScalar(claimedValueBytes)
	if err != nil {
		return err
	}
	inputPoint, err := serialization.DeserializeScalar(inputPointBytes)
	if err != nil {
		return err
	}

	polyComm, err := serialization.DeserializeG1Point(polynomialComm)
	if err != nil {
		return err
	}

	quotientComm, err := serialization.DeserializeG1Point(kzgProof)
	if err != nil {
		return err
	}

	proof := kzg.OpeningProof{
		QuotientComm: quotientComm,
		InputPoint:   inputPoint,
		ClaimedValue: claimedValue,
	}

	return kzg.Verify(&polyComm, &proof, c.openKey)
}

// [verify_blob_kzg_proof](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof)
func (c *Context) VerifyBlobKZGProof(blob serialization.Blob, serComm serialization.Commitment, serProof serialization.KZGProof) error {
	return c.VerifyBlobKZGProofBatch([]serialization.Blob{blob}, serialization.Commitments{serComm}, []serialization.KZGProof{serProof})
}

// [verify_blob_kzg_proof_batch](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof_batch)
func (c *Context) VerifyBlobKZGProofBatch(blobs []serialization.Blob, serComms serialization.Commitments, serProof []serialization.KZGProof) error {
	// 1. Length checks
	//
	blobsLen := len(blobs)
	commsLen := len(serComms)
	proofsLen := len(serProof)
	lengthsAreEqual := blobsLen == commsLen && blobsLen == proofsLen
	if !lengthsAreEqual {
		return ErrBatchLengthCheck
	}

	// 2. Create Opening Proof
	//
	openingProofs := make([]kzg.OpeningProof, blobsLen)
	commitments := make([]bls12381.G1Affine, blobsLen)
	for i := 0; i < blobsLen; i++ {
		// Deserialize commitment
		serComm := serComms[i]
		polyCommitment, err := serialization.DeserializeG1Point(serComm)
		if err != nil {
			return err
		}
		// Deserialize quotient commitment
		serQuotientComm := serProof[i]
		quotientCommitment, err := serialization.DeserializeG1Point(serQuotientComm)
		if err != nil {
			return err
		}
		// Deserialize blob
		blob := blobs[i]
		polynomial, err := serialization.DeserializeBlob(blob)
		if err != nil {
			return err
		}

		// Compute the evaluation challenge
		evaluationChallenge := computeChallenge(blob, serComm)
		// Compute output point
		outputPoint, err := c.domain.EvaluateLagrangePolynomial(polynomial, evaluationChallenge)
		if err != nil {
			return err
		}

		openingProof := kzg.OpeningProof{
			QuotientComm: quotientCommitment,
			InputPoint:   evaluationChallenge,
			ClaimedValue: *outputPoint,
		}
		openingProofs[i] = openingProof
		commitments[i] = polyCommitment
	}

	return kzg.BatchVerifyMultiPoints(commitments, openingProofs, c.openKey)
}
