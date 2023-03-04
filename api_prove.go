package api

import (
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

func (c *Context) ComputeBlobKZGProof(blob serialization.Blob) (serialization.KZGProof, serialization.G1Point, serialization.Scalar, error) {
	// Deserialization
	//
	// 1. Deserialize the `Blob` into a polynomial
	//
	poly, err := serialization.DeserializeBlob(blob)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// 2. Commit to polynomial
	comms, err := kzg.CommitToPolynomials([]kzg.Polynomial{poly}, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// 3. Compute Fiat-Shamir challenge
	serializedComm := serialization.SerializeG1Point(comms[0])
	evaluationChallenge := computeChallenge(blob, serializedComm)

	//4. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, evaluationChallenge, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// Serialisation
	//
	// 5. Serialize values
	//
	// Polynomial commitment
	commitment := comms[0]

	serComm := serialization.SerializeG1Point(commitment)
	//
	// Quotient commitment
	serProof := serialization.SerializeG1Point(openingProof.QuotientComm)
	//
	// Claimed value -- Reverse it to use little endian
	claimedValueBytes := serialization.SerializeScalar(openingProof.ClaimedValue)

	return serProof, serComm, claimedValueBytes, nil
}

func (c *Context) ComputeKZGProof(blob serialization.Blob, inputPointBytes serialization.Scalar) (serialization.KZGProof, serialization.G1Point, serialization.Scalar, error) {
	// Deserialisation
	//
	// 1. Deserialize the `Blob` into a polynomial
	//
	poly, err := serialization.DeserializeBlob(blob)
	if err != nil {
		return serialization.KZGProof{}, serialization.G1Point{}, [32]byte{}, err
	}

	// 2. Deserialize input point
	inputPoint, err := serialization.DeserializeScalar(inputPointBytes)
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
	// 5. Serialize values
	//
	// Polynomial commitment
	commitment := comms[0]

	serComm := serialization.SerializeG1Point(commitment)
	//
	// Quotient commitment
	serProof := serialization.SerializeG1Point(openingProof.QuotientComm)
	//
	// Claimed value -- Reverse it to use little endian
	claimedValueBytes := serialization.SerializeScalar(openingProof.ClaimedValue)

	return serProof, serComm, claimedValueBytes, nil
}
