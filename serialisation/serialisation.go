package serialisation

import (
	"errors"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

// This is the number of 32 byte slices a blob can contain.
// We use the nomenclature `FIELD_ELEMENTS_PER_BLOB` because
// each field element when serialised is 32 bytes
//
// These 32 byte slices may not be _valid_, to which an error
// will be returned on deserialisation.
//
// This constant is set at the 4844 protocol level and is not
// related to any cryptographic assumptions.
const SCALARS_PER_BLOB = 4096

// This is the number of bytes needed to represent a
// group element in G1 when compressed.
const COMPRESSED_G1_SIZE = 48

// This is the number of bytes needed to represent a field
// element corresponding to the order of the G1 group.
const SERIALISED_SCALAR_SIZE = 32

type Scalar = [SERIALISED_SCALAR_SIZE]byte
type G1Point = [COMPRESSED_G1_SIZE]byte

// A blob is a flattened representation for a serialised polynomial
type Blob = [SCALARS_PER_BLOB * SERIALISED_SCALAR_SIZE]byte

// This is a misnomer, its KZGWitness
type KZGProof = G1Point
type KZGCommitment = G1Point

type Commitment = G1Point
type Commitments = []Commitment

func SerialiseG1Point(affine curve.G1Affine) G1Point {
	return affine.Bytes()
}
func DeserialiseG1Point(serPoint G1Point) (curve.G1Affine, error) {
	var point curve.G1Affine

	_, err := point.SetBytes(serPoint[:])
	if err != nil {
		return curve.G1Affine{}, err
	}
	return point, nil
}

func DeserialiseG1Points(serComms Commitments) ([]curve.G1Affine, error) {

	comms := make([]curve.G1Affine, len(serComms))
	for i := 0; i < len(serComms); i++ {
		// This will do subgroup checks and is relatively expensive (bench)
		// TODO: We _could_ do these on multiple threads that are warmed up, if bench shows them to be relatively slow
		comm, err := DeserialiseG1Point(serComms[i])
		if err != nil {
			return nil, err
		}
		comms[i] = comm
	}

	return comms, nil
}
func SerialiseG1Points(comms []curve.G1Affine) Commitments {
	serComms := make(Commitments, len(comms))
	for i := 0; i < len(comms); i++ {
		comm := SerialiseG1Point(comms[i])
		serComms[i] = comm
	}
	return serComms
}

func DeserialiseBlobs(blobs []Blob) ([]kzg.Polynomial, error) {

	num_polynomials := len(blobs)
	polys := make([]kzg.Polynomial, 0, num_polynomials)

	for _, serPoly := range blobs {
		poly, err := DeserialiseBlob(serPoly)
		if err != nil {
			return nil, err
		}
		polys = append(polys, poly)
	}
	return polys, nil
}

func DeserialiseBlob(blob Blob) (kzg.Polynomial, error) {
	num_coeffs := SCALARS_PER_BLOB
	poly := make(kzg.Polynomial, num_coeffs)

	if len(blob)%SERIALISED_SCALAR_SIZE != 0 {
		return kzg.Polynomial{}, errors.New("serialised polynomial size should be a multiple of `SERIALISED_SCALAR_SIZE`")
	}

	for i, j := 0, 0; i < len(blob); i, j = i+SERIALISED_SCALAR_SIZE, j+1 {
		// Move pointer to select the next serialised scalar
		end := i + SERIALISED_SCALAR_SIZE

		chunk := blob[i:end]
		// Convert slice to array
		serialisedScalar := (*[SERIALISED_SCALAR_SIZE]byte)(chunk)

		scalar, err := DeserialiseScalar(*serialisedScalar)
		if err != nil {
			return nil, err
		}
		poly[j] = scalar
	}
	return poly, nil
}

func DeserialiseScalar(serScalar Scalar) (fr.Element, error) {
	// gnark uses big-endian but the format according to the specs is little-endian
	// so we reverse the scalar
	utils.ReverseArray(&serScalar)
	scalar, isCanon := utils.ReduceCanonical(serScalar[:])
	if !isCanon {
		return fr.Element{}, errors.New("scalar is not in canonical format")
	}
	return scalar, nil
}

func SerialiseScalar(element fr.Element) Scalar {
	byts := element.Bytes()
	utils.ReverseArray(&byts)
	return byts
}

// This method is never used in the API because we always expect a byte array
// and will never receive deserialised field elements.
//
// We include it so that upstream fuzzers do not need to reimplement it
func SerialisePoly(poly kzg.Polynomial) Blob {
	var blob Blob
	for i, j := 0, 0; j < len(poly); i, j = i+SERIALISED_SCALAR_SIZE, j+1 {
		end := i + SERIALISED_SCALAR_SIZE
		serialisedScalar := SerialiseScalar(poly[j])
		copy(blob[i:end], serialisedScalar[:])
	}
	return blob
}

// This method and its deserialisation counterpart is never used in the
// API because we never need to serialise G2 points
// when creating/verifying proofs
func SerialiseG2Point(point curve.G2Affine) [96]byte {
	return point.Bytes()
}
func DeserialiseG2Point(serPoint [96]byte) (curve.G2Affine, error) {
	var point curve.G2Affine

	_, err := point.SetBytes(serPoint[:])
	if err != nil {
		return curve.G2Affine{}, err
	}
	return point, nil
}
