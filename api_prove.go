package api

import (
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
)

func (c *Context) ComputeBlobKZGProof(blob serialisation.Blob) (serialisation.KZGProof, serialisation.G1Point, serialisation.Scalar, error) {
	// Deserialisation
	//
	// 1. Deserialise the `Blob` into a polynomial
	//
	poly, err := serialisation.DeserialiseBlob(blob)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	// 2. Commit to polynomial
	comms, err := kzg.CommitToPolynomials([]kzg.Polynomial{poly}, c.commitKey)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	// 3. Compute Fiat-Shamir challenge
	serialisedComm := serialisation.SerialiseG1Point(comms[0])
	evaluationChallenge := computeChallenge(serialisation.SCALARS_PER_BLOB, blob, serialisedComm)

	//4. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, evaluationChallenge, c.commitKey)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	// Serialisation
	//
	// 5. Serialise values
	//
	// Polynomial commitment
	commitment := comms[0]

	serComm := serialisation.SerialiseG1Point(commitment)
	//
	// Quotient commitment
	serProof := serialisation.SerialiseG1Point(openingProof.QuotientComm)
	//
	// Claimed value -- Reverse it to use little endian
	claimedValueBytes := serialisation.SerialiseScalar(openingProof.ClaimedValue)

	return serProof, serComm, claimedValueBytes, nil
}

func (c *Context) ComputeKZGProof(blob serialisation.Blob, inputPointBytes serialisation.Scalar) (serialisation.KZGProof, serialisation.G1Point, serialisation.Scalar, error) {
	// Deserialisation
	//
	// 1. Deserialise the `Blob` into a polynomial
	//
	poly, err := serialisation.DeserialiseBlob(blob)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	// 2. Deserialise input point
	inputPoint, err := serialisation.DeserialiseScalar(inputPointBytes)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	// 3. Commit to polynomial
	comms, err := kzg.CommitToPolynomials([]kzg.Polynomial{poly}, c.commitKey)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	//4. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, inputPoint, c.commitKey)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	// Serialisation
	//
	// 5. Serialise values
	//
	// Polynomial commitment
	commitment := comms[0]

	serComm := serialisation.SerialiseG1Point(commitment)
	//
	// Quotient commitment
	serProof := serialisation.SerialiseG1Point(openingProof.QuotientComm)
	//
	// Claimed value -- Reverse it to use little endian
	claimedValueBytes := serialisation.SerialiseScalar(openingProof.ClaimedValue)

	return serProof, serComm, claimedValueBytes, nil
}
