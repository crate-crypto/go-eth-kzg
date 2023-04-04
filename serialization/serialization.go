package serialization

import (
	"errors"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

// ScalarsPerBlob is the number of 32 byte slices a blob can contain.
// We use the nomenclature `FIELD_ELEMENTS_PER_BLOB` because
// each field element when serialized is 32 bytes
//
// These 32 byte slices may not be _valid_, to which an error
// will be returned on deserialization.
//
// This constant is set at the 4844 protocol level and is not
// related to any cryptographic assumptions.
const ScalarsPerBlob = 4096

// This is the number of bytes needed to represent a
// group element in G1 when compressed.
const CompressedG1Size = 48

// This is the number of bytes needed to represent a
// group element in G2 when compressed.
const CompressedG2Size = 96

// This is the number of bytes needed to represent a field
// element corresponding to the order of the G1 group.
const SerializedScalarSize = 32

type (
	Scalar  [SerializedScalarSize]byte
	G1Point = [CompressedG1Size]byte
	G2Point = [CompressedG2Size]byte
)

// A blob is a flattened representation for a serialized polynomial
type Blob [ScalarsPerBlob * SerializedScalarSize]byte

// KZGProof is a serialized commitment to the quotient polynomial
type KZGProof G1Point

// KZGCommitment is a serialized commitment to a polynomial.
// that one wants to make proofs about.
type KZGCommitment G1Point

func SerializeG1Point(affine bls12381.G1Affine) G1Point {
	return affine.Bytes()
}

// This method will return an error if the point is not on the group
// or if the point is not in the correct subgroup.
//
// [validate_kzg_g1](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#validate_kzg_g1)
// [bytes_to_kzg_commitment](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#bytes_to_kzg_commitment)
// [bytes_to_kzg_proof](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#bytes_to_kzg_proof)
func DeserializeG1Point(serPoint G1Point) (bls12381.G1Affine, error) {
	var point bls12381.G1Affine

	_, err := point.SetBytes(serPoint[:])
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	return point, nil
}

func DeserializeG1Points(serCommitments []KZGCommitment) ([]bls12381.G1Affine, error) {
	commitments := make([]bls12381.G1Affine, len(serCommitments))
	for i := 0; i < len(serCommitments); i++ {
		// This will do subgroup checks and is relatively expensive (bench)
		comm, err := DeserializeG1Point(serCommitments[i])
		if err != nil {
			return nil, err
		}
		commitments[i] = comm
	}

	return commitments, nil
}

func SerializeG1Points(commitments []bls12381.G1Affine) []KZGCommitment {
	serCommitments := make([]KZGCommitment, len(commitments))
	for i := 0; i < len(commitments); i++ {
		comm := SerializeG1Point(commitments[i])
		serCommitments[i] = comm
	}

	return serCommitments
}

func DeserializeBlobs(blobs []Blob) ([]kzg.Polynomial, error) {
	numPolynomials := len(blobs)
	polys := make([]kzg.Polynomial, numPolynomials)

	for i, serPoly := range blobs {
		poly, err := DeserializeBlob(serPoly)
		if err != nil {
			return nil, err
		}
		polys[i] = poly
	}

	return polys, nil
}

// [blob_to_polynomial](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#blob_to_polynomial)
func DeserializeBlob(blob Blob) (kzg.Polynomial, error) {
	numEvaluations := ScalarsPerBlob
	poly := make(kzg.Polynomial, numEvaluations)

	if len(blob)%SerializedScalarSize != 0 {
		return kzg.Polynomial{}, errors.New("serialized polynomial size should be a multiple of `SERIALIZED_SCALAR_SIZE`")
	}

	for i, j := 0, 0; i < len(blob); i, j = i+SerializedScalarSize, j+1 {
		// Move pointer to select the next serialized scalar
		end := i + SerializedScalarSize

		chunk := blob[i:end]
		// Convert slice to array
		serializedScalar := (*[SerializedScalarSize]byte)(chunk)

		scalar, err := DeserializeScalar(*serializedScalar)
		if err != nil {
			return nil, err
		}
		poly[j] = scalar
	}

	return poly, nil
}

// Deserializes a 32 byte slice into a scalar.
// Returns an error if the 32 byte slice when interpreted
// as a big integer in little-endian format is not in the range
// [0, p-1] (inclusive) where `p` is the prime associated with
// the scalar field.
//
// [bytes_to_bls_field](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#bytes_to_bls_field)
func DeserializeScalar(serScalar Scalar) (fr.Element, error) {
	// gnark uses big-endian but the format according to the specs is little-endian
	// so we reverse the scalar
	utils.Reverse(serScalar[:])
	scalar, err := utils.ReduceCanonical(serScalar[:])
	if err != nil {
		return fr.Element{}, ErrNonCanonicalScalar
	}

	return scalar, nil
}

func DeserializeScalars(serScalars []Scalar) ([]fr.Element, error) {
	scalars := make([]fr.Element, len(serScalars))
	for i := 0; i < len(scalars); i++ {
		scalar, err := DeserializeScalar(serScalars[i])
		if err != nil {
			return nil, err
		}
		scalars[i] = scalar
	}

	return scalars, nil
}

func SerializeScalar(element fr.Element) Scalar {
	byts := element.Bytes()
	utils.Reverse(byts[:])

	return byts
}

// This method is never used in the API because we always expect a byte array
// and will never receive deserialized field elements.
//
// We include it so that upstream fuzzers do not need to reimplement it
func SerializePoly(poly kzg.Polynomial) Blob {
	var blob Blob
	for i, j := 0, 0; j < len(poly); i, j = i+SerializedScalarSize, j+1 {
		end := i + SerializedScalarSize
		serializedScalar := SerializeScalar(poly[j])
		copy(blob[i:end], serializedScalar[:])
	}

	return blob
}

// This method and its deserialization counterpart is never used in the
// API because we never need to serialize G2 points
// when creating/verifying proofs.
// We do however need it for processing the trusted setup.
func SerializeG2Point(point bls12381.G2Affine) G2Point {
	return point.Bytes()
}

func DeserializeG2Point(serPoint G2Point) (bls12381.G2Affine, error) {
	var point bls12381.G2Affine

	_, err := point.SetBytes(serPoint[:])
	if err != nil {
		return bls12381.G2Affine{}, err
	}

	return point, nil
}
