package api

import (
	"errors"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/fiatshamir"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
)

// Needed for precompile
func (c *Context) VerifyKZGProof(polynomialComm serialisation.KZGCommitment, kzgProof serialisation.KZGProof, inputPointBytes, claimedValueBytes serialisation.Scalar) error {

	claimedValue, err := serialisation.DeserialiseScalar(claimedValueBytes)
	if err != nil {
		return err
	}
	inputPoint, err := serialisation.DeserialiseScalar(inputPointBytes)
	if err != nil {
		return err
	}

	polyComm, err := serialisation.DeserialiseG1Point(polynomialComm)
	if err != nil {
		return err
	}

	quotientComm, err := serialisation.DeserialiseG1Point(kzgProof)
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

// TODO: change naming convention to use `ser` prefix instead of Bytes postfix
// TODO impl a version of this that just does it in parallel
func (c *Context) VerifyKZGProofBatch(serPolynomialComms []serialisation.KZGCommitment, serProofs []serialisation.KZGProof, serInputPoints, serClaimedValues []serialisation.Scalar) error {
	// 1. Check that lengths are all equal
	//
	polyCommsLen := len(serPolynomialComms)
	proofsLen := len(serProofs)
	inputPointsLen := len(serInputPoints)
	claimedValuesLen := len(serClaimedValues)
	lengthsAreEqual := polyCommsLen == proofsLen && polyCommsLen == inputPointsLen && polyCommsLen == claimedValuesLen
	if !lengthsAreEqual {
		return errors.New("the number of polynomials, proofs, input values and claimed values must be the same")
	}

	// 2. Deserialisation
	//
	commitments, err := serialisation.DeserialiseG1Points(serPolynomialComms)
	if err != nil {
		return err
	}
	proofs, err := serialisation.DeserialiseG1Points(serProofs)
	if err != nil {
		return err
	}
	inputPoints, err := serialisation.DeserialiseScalars(serInputPoints)
	if err != nil {
		return err
	}
	claimedValues, err := serialisation.DeserialiseScalars(serClaimedValues)
	if err != nil {
		return err
	}
	// This is probably a less efficient way as we
	// could deserialise each quotient commitment
	// and then create the openingProof struct.
	// Instead of allocating above
	// TODO: benchmark
	openingProofs := make([]kzg.OpeningProof, polyCommsLen)
	for i := 0; i < polyCommsLen; i++ {
		openingProof := kzg.OpeningProof{
			QuotientComm: proofs[i],
			InputPoint:   inputPoints[i],
			ClaimedValue: claimedValues[i],
		}
		openingProofs[i] = openingProof
	}

	return kzg.BatchVerifyMultiPoints(commitments, openingProofs, c.openKey)
}

func (c *Context) VerifyBlobKZGProof(blob serialisation.Blob, serComm serialisation.Commitment, serProof serialisation.KZGProof) error {
	return c.VerifyBlobKZGProofBatch([]serialisation.Blob{blob}, serialisation.Commitments{serComm}, []serialisation.KZGProof{serProof})
}
func (c *Context) VerifyBlobKZGProofBatch(blobs []serialisation.Blob, serComms serialisation.Commitments, serProof []serialisation.KZGProof) error {
	// 1. Length checks
	//
	blobsLen := len(blobs)
	commsLen := len(serComms)
	proofsLen := len(serProof)
	lengthsAreEqual := blobsLen == commsLen && blobsLen == proofsLen
	if !lengthsAreEqual {
		return errors.New("the number of blobs, commitments, and proofs must be the same")
	}

	// 2. Create Opening Proof
	// TODO: benchmark if we can speed these up by calling the analogous
	// deserialisation methods which take in []T instead of T.
	// Eg DeserialiseBlobs instead of DeserialiseBlob
	openingProofs := make([]kzg.OpeningProof, blobsLen)
	commitments := make([]bls12381.G1Affine, blobsLen)
	for i := 0; i < blobsLen; i++ {
		// Deserialise commitment
		serComm := serComms[i]
		polyCommitment, err := serialisation.DeserialiseG1Point(serComm)
		if err != nil {
			return err
		}
		// Deserialise quotient commitment
		serQuotientComm := serProof[i]
		quotientCommitment, err := serialisation.DeserialiseG1Point(serQuotientComm)
		if err != nil {
			return err
		}
		// Deserialise blob
		blob := blobs[i]
		polynomial, err := serialisation.DeserialiseBlob(blob)
		if err != nil {
			return err
		}

		// Compute the evaluation challenge
		evaluationChallenge := fiatshamir.ComputeChallenge(serialisation.SCALARS_PER_BLOB, blob[:], serComm[:])
		// Compute output point
		outputPoint, err := kzg.EvaluateLagrangePolynomial(c.domain, polynomial, evaluationChallenge)
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
