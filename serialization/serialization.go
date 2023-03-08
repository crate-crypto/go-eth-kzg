package serialization

import (
	"errors"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

// This is the number of 32 byte slices a blob can contain.
// We use the nomenclature `FIELD_ELEMENTS_PER_BLOB` because
// each field element when serialized is 32 bytes
//
// These 32 byte slices may not be _valid_, to which an error
// will be returned on deserialization.
//
// This constant is set at the 4844 protocol level and is not
// related to any cryptographic assumptions.
const SCALARS_PER_BLOB = 4096

// This is the number of bytes needed to represent a
// group element in G1 when compressed.
const COMPRESSED_G1_SIZE = 48

// This is the number of bytes needed to represent a field
// element corresponding to the order of the G1 group.
const SERIALIZED_SCALAR_SIZE = 32

type Scalar = [SERIALIZED_SCALAR_SIZE]byte
type G1Point = [COMPRESSED_G1_SIZE]byte

// A blob is a flattened representation for a serialized polynomial
type Blob = [SCALARS_PER_BLOB * SERIALIZED_SCALAR_SIZE]byte

// This is a misnomer, its KZGWitness
type KZGProof = G1Point
type KZGCommitment = G1Point

type Commitment = G1Point
type Commitments = []Commitment

func SerializeG1Point(affine bls12381.G1Affine) G1Point {
	return affine.Bytes()
}
func DeserializeG1Point(serPoint G1Point) (bls12381.G1Affine, error) {
	var point bls12381.G1Affine

	_, err := point.SetBytes(serPoint[:])
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	return point, nil
}

func DeserializeG1Points(serComms Commitments) ([]bls12381.G1Affine, error) {

	comms := make([]bls12381.G1Affine, len(serComms))
	for i := 0; i < len(serComms); i++ {
		// This will do subgroup checks and is relatively expensive (bench)
		// TODO: We _could_ do these on multiple threads that are warmed up, if bench shows them to be relatively slow
		comm, err := DeserializeG1Point(serComms[i])
		if err != nil {
			return nil, err
		}
		comms[i] = comm
	}

	return comms, nil
}
func SerializeG1Points(comms []bls12381.G1Affine) Commitments {
	serComms := make(Commitments, len(comms))
	for i := 0; i < len(comms); i++ {
		comm := SerializeG1Point(comms[i])
		serComms[i] = comm
	}
	return serComms
}

func DeserializeBlobs(blobs []Blob) ([]kzg.Polynomial, error) {

	num_polynomials := len(blobs)
	polys := make([]kzg.Polynomial, 0, num_polynomials)

	for _, serPoly := range blobs {
		poly, err := DeserializeBlob(serPoly)
		if err != nil {
			return nil, err
		}
		polys = append(polys, poly)
	}
	return polys, nil
}

func DeserializeBlob(blob Blob) (kzg.Polynomial, error) {
	numCoeffs := SCALARS_PER_BLOB
	poly := make(kzg.Polynomial, numCoeffs)

	if len(blob)%SERIALIZED_SCALAR_SIZE != 0 {
		return kzg.Polynomial{}, errors.New("serialized polynomial size should be a multiple of `SERIALIZED_SCALAR_SIZE`")
	}

	for i, j := 0, 0; i < len(blob); i, j = i+SERIALIZED_SCALAR_SIZE, j+1 {
		// Move pointer to select the next serialized scalar
		end := i + SERIALIZED_SCALAR_SIZE

		chunk := blob[i:end]
		// Convert slice to array
		serializedScalar := (*[SERIALIZED_SCALAR_SIZE]byte)(chunk)

		scalar, err := DeserializeScalar(*serializedScalar)
		if err != nil {
			return nil, err
		}
		poly[j] = scalar
	}
	return poly, nil
}

func DeserializeScalar(serScalar Scalar) (fr.Element, error) {
	// gnark uses big-endian but the format according to the specs is little-endian
	// so we reverse the scalar
	utils.Reverse(serScalar[:])
	scalar, err := utils.ReduceCanonical(serScalar[:])
	if err != nil {
		return fr.Element{}, errors.New("scalar is not in canonical format")
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
	for i, j := 0, 0; j < len(poly); i, j = i+SERIALIZED_SCALAR_SIZE, j+1 {
		end := i + SERIALIZED_SCALAR_SIZE
		serializedScalar := SerializeScalar(poly[j])
		copy(blob[i:end], serializedScalar[:])
	}
	return blob
}

// This method and its deserialization counterpart is never used in the
// API because we never need to serialize G2 points
// when creating/verifying proofs
func SerializeG2Point(point bls12381.G2Affine) [96]byte {
	return point.Bytes()
}
func DeserializeG2Point(serPoint [96]byte) (bls12381.G2Affine, error) {
	var point bls12381.G2Affine

	_, err := point.SetBytes(serPoint[:])
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	return point, nil
}
