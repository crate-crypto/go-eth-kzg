package api

import (
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

// BlobToKZGCommitment implements [blob_to_kzg_commitment].
//
// [blob_to_kzg_commitment]: https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#blob_to_kzg_commitment
func (c *Context) BlobToKZGCommitment(blob serialization.Blob) (serialization.KZGCommitment, error) {
	// 1. Deserialization
	//
	// Deserialize blob into polynomial
	polynomial, err := serialization.DeserializeBlob(blob)
	if err != nil {
		return serialization.KZGCommitment{}, err
	}

	// 2. Commit to polynomial
	commitment, err := kzg.Commit(polynomial, c.commitKey)
	if err != nil {
		return serialization.KZGCommitment{}, err
	}

	// 3. Serialization
	//
	// Serialize commitment
	serComm := serialization.SerializeG1Point(*commitment)

	return serialization.KZGCommitment(serComm), nil
}

// ComputeBlobKZGProof implements [compute_blob_kzg_proof]. It takes a blob and returns the KZG proof that is used to
// verify it against the given KZG commitment at a random point.
//
// Note: This method does not check that the commitment corresponds to the `blob`. The method does still check that the
// commitment is a valid commitment. One should check this externally or call [Context.BlobToKZGCommitment].
//
// [compute_blob_kzg_proof]: https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#compute_blob_kzg_proof
func (c *Context) ComputeBlobKZGProof(blob serialization.Blob, blobCommitment serialization.KZGCommitment) (serialization.KZGProof, error) {
	// 1. Deserialization
	//
	polynomial, err := serialization.DeserializeBlob(blob)
	if err != nil {
		return serialization.KZGProof{}, err
	}

	// Deserialize commitment
	//
	// We only do this to check if it is in the correct subgroup
	_, err = serialization.DeserializeG1Point(serialization.G1Point(blobCommitment))
	if err != nil {
		return serialization.KZGProof{}, err
	}

	// 2. Compute Fiat-Shamir challenge
	evaluationChallenge := computeChallenge(blob, blobCommitment)

	// 3. Create opening proof
	openingProof, err := kzg.Open(c.domain, polynomial, evaluationChallenge, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, err
	}

	// 4. Serialization
	//
	// Quotient commitment
	kzgProof := serialization.SerializeG1Point(openingProof.QuotientCommitment)

	return serialization.KZGProof(kzgProof), nil
}

// ComputeKZGProof implements [compute_kzg_proof].
//
// [compute_kzg_proof]: https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#compute_kzg_proof
func (c *Context) ComputeKZGProof(blob serialization.Blob, inputPointBytes serialization.Scalar) (serialization.KZGProof, serialization.Scalar, error) {
	// 1. Deserialization
	//
	polynomial, err := serialization.DeserializeBlob(blob)
	if err != nil {
		return serialization.KZGProof{}, [32]byte{}, err
	}

	inputPoint, err := serialization.DeserializeScalar(inputPointBytes)
	if err != nil {
		return serialization.KZGProof{}, [32]byte{}, err
	}

	// 2. Create opening proof
	openingProof, err := kzg.Open(c.domain, polynomial, inputPoint, c.commitKey)
	if err != nil {
		return serialization.KZGProof{}, [32]byte{}, err
	}

	// 3. Serialization
	//
	kzgProof := serialization.SerializeG1Point(openingProof.QuotientCommitment)

	claimedValueBytes := serialization.SerializeScalar(openingProof.ClaimedValue)

	return serialization.KZGProof(kzgProof), claimedValueBytes, nil
}
