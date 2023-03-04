package api

import (
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

func (c *Context) ComputeBlobKZGProof(blob serialization.Blob) (serialization.KZGProof, serialization.G1Point, serialization.Scalar, error) {
	// Deserialisation
	//
	// 1. Deserialise the `Blob` into a polynomial
	//
	poly, err := serialization.DeserialiseBlob(blob)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// 2. Commit to polynomial
	comms, err := kzg.CommitToPolynomials([]kzg.Polynomial{poly}, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// 3. Compute Fiat-Shamir challenge
	serialisedComm := serialization.SerialiseG1Point(comms[0])
	evaluationChallenge := computeChallenge(blob, serialisedComm)

	//4. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, evaluationChallenge, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// Serialisation
	//
	// 5. Serialise values
	//
	// Polynomial commitment
	commitment := comms[0]

	serComm := serialization.SerialiseG1Point(commitment)
	//
	// Quotient commitment
	serProof := serialization.SerialiseG1Point(openingProof.QuotientComm)
	//
	// Claimed value -- Reverse it to use little endian
	claimedValueBytes := serialization.SerialiseScalar(openingProof.ClaimedValue)

	return serProof, serComm, claimedValueBytes, nil
}

func (c *Context) ComputeKZGProof(blob serialization.Blob, inputPointBytes serialization.Scalar) (serialization.KZGProof, serialization.G1Point, serialization.Scalar, error) {
	// Deserialisation
	//
	// 1. Deserialise the `Blob` into a polynomial
	//
	poly, err := serialization.DeserialiseBlob(blob)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// 2. Deserialise input point
	inputPoint, err := serialization.DeserialiseScalar(inputPointBytes)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// 3. Commit to polynomial
	comms, err := kzg.CommitToPolynomials([]kzg.Polynomial{poly}, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	//4. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, inputPoint, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// Serialisation
	//
	// 5. Serialise values
	//
	// Polynomial commitment
	commitment := comms[0]

	serComm := serialization.SerialiseG1Point(commitment)
	//
	// Quotient commitment
	serProof := serialization.SerialiseG1Point(openingProof.QuotientComm)
	//
	// Claimed value -- Reverse it to use little endian
	claimedValueBytes := serialization.SerialiseScalar(openingProof.ClaimedValue)

	return serProof, serComm, claimedValueBytes, nil
}
