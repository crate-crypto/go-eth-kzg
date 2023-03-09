package api

import (
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

func (c *Context) BlobToKZGCommitment(blob serialization.Blob) (serialization.Commitment, error) {
	// Deserialization
	//
	// 1. Deserialize the Blobs into polynomial objects
	poly, err := serialization.DeserializeBlob(blob)
	if err != nil {
		return serialization.Commitment{}, err
	}

	// 2. Commit to polynomial
	commitment, err := kzg.Commit(poly, c.commitKey)
	if err != nil {
		return serialization.Commitment{}, err
	}

	// Serialization
	//
	// 3. Serialize commitment
	serComm := serialization.SerializeG1Point(*commitment)

	return serComm, nil
}

// Note: This method does not check that the commitment corresponds
// to the `blob`.
// The method does still check that the commitment is a valid commitment.
// One should check this externally or call `BlobToCommitment`
func (c *Context) ComputeBlobKZGProof(blob serialization.Blob, serializedComm serialization.Commitment) (serialization.KZGProof, error) {
	// Deserialization
	//
	// 1. Deserialize the `Blob`  into a polynomial
	//
	poly, err := serialization.DeserializeBlob(blob)
	if err != nil {
		return serialization.KZGProof{}, err
	}
	// Deserialize the commitment -- we only do this to check
	// if it is in the correct subgroup
	_, err = serialization.DeserializeG1Point(serializedComm)
	if err != nil {
		return serialization.KZGProof{}, err
	}

	// 2. Compute Fiat-Shamir challenge
	evaluationChallenge := computeChallenge(blob, serializedComm)

	// 3. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, evaluationChallenge, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, err
	}

	// Serialization
	//
	// 4. Serialize values
	//
	// Polynomial commitment
	//
	// Quotient commitment
	serProof := serialization.SerializeG1Point(openingProof.QuotientComm)

	return serProof, nil
}

func (c *Context) ComputeKZGProof(blob serialization.Blob, inputPointBytes serialization.Scalar) (serialization.KZGProof, serialization.Scalar, error) {
	// Deserialization
	//
	// 1. Deserialize the `Blob` into a polynomial
	//
	poly, err := serialization.DeserializeBlob(blob)
	if err != nil {
		return serialization.KZGProof{}, [32]byte{}, err
	}

	// 2. Deserialize input point
	inputPoint, err := serialization.DeserializeScalar(inputPointBytes)
	if err != nil {
		return serialization.KZGProof{}, [32]byte{}, err
	}

	// 3. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, inputPoint, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, [32]byte{}, err
	}

	// Serialization
	//
	// 4. Serialize values
	//

	//
	// Quotient commitment
	serProof := serialization.SerializeG1Point(openingProof.QuotientComm)
	//
	// Claimed value
	claimedValueBytes := serialization.SerializeScalar(openingProof.ClaimedValue)

	return serProof, claimedValueBytes, nil
}
