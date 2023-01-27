package api

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

type SerialisedScalar = [SERIALISED_SCALAR_SIZE]byte
type SerialisedG1Point = [COMPRESSED_G1_SIZE]byte
type SerialisedPoly = [SCALARS_PER_BLOB]SerialisedScalar

type FlattenedPoly = [SCALARS_PER_BLOB * SERIALISED_SCALAR_SIZE]byte

// A blob is a representation for a serialised polynomial
type Blob = FlattenedPoly

// This is a misnomer, its KZGWitness
type KZGProof = SerialisedG1Point
type KZGCommitment = SerialisedG1Point

type SerialisedCommitment = SerialisedG1Point
type SerialisedCommitments = []SerialisedCommitment

func deserialiseComms(serComms SerialisedCommitments) ([]curve.G1Affine, error) {

	comms := make([]curve.G1Affine, len(serComms))
	for i := 0; i < len(serComms); i++ {
		// This will do subgroup checks and is relatively expensive (bench)
		// TODO: We _could_ do these on multiple threads that are warmed up, if bench shows them to be relatively slow
		comm, err := deserialiseG1Point(serComms[i])
		if err != nil {
			return nil, err
		}
		comms[i] = comm
	}

	return comms, nil
}

func serialiseCommitments(comms []curve.G1Affine) SerialisedCommitments {
	serComms := make(SerialisedCommitments, len(comms))
	for i := 0; i < len(comms); i++ {
		comm := serialiseG1Point(comms[i])
		serComms[i] = comm
	}
	return serComms
}

func serialiseG1Point(affine curve.G1Affine) SerialisedG1Point {
	return affine.Bytes()
}
func deserialiseG1Point(serPoint SerialisedG1Point) (curve.G1Affine, error) {
	var point curve.G1Affine

	_, err := point.SetBytes(serPoint[:])
	if err != nil {
		return curve.G1Affine{}, err
	}
	return point, nil
}

func deserialisePolys(serPolys []FlattenedPoly) ([]kzg.Polynomial, error) {

	num_polynomials := len(serPolys)
	polys := make([]kzg.Polynomial, 0, num_polynomials)

	for _, serPoly := range serPolys {
		poly, err := deserialiseFlattenedPoly(serPoly)
		if err != nil {
			return nil, err
		}
		polys = append(polys, poly)
	}
	return polys, nil
}

func deserialisePoly(serPoly SerialisedPoly) (kzg.Polynomial, error) {
	num_coeffs := len(serPoly)
	poly := make(kzg.Polynomial, num_coeffs)
	for i := 0; i < num_coeffs; i++ {
		scalar, err := deserialiseScalar(serPoly[i])
		if err != nil {
			return nil, err
		}
		poly[i] = scalar
	}
	return poly, nil
}

func deserialiseFlattenedPoly(serFlattenedPoly FlattenedPoly) (kzg.Polynomial, error) {
	num_coeffs := SCALARS_PER_BLOB
	poly := make(kzg.Polynomial, num_coeffs)

	if len(serFlattenedPoly)%SERIALISED_SCALAR_SIZE != 0 {
		return kzg.Polynomial{}, errors.New("serialised polynomial size should be a multiple of `SERIALISED_SCALAR_SIZE`")
	}

	for i, j := 0, 0; i < len(serFlattenedPoly); i, j = i+SERIALISED_SCALAR_SIZE, j+1 {
		// Move pointer to select the next serialised scalar
		end := i + SERIALISED_SCALAR_SIZE

		chunk := serFlattenedPoly[i:end]
		// Convert slice to array
		serialisedScalar := (*[SERIALISED_SCALAR_SIZE]byte)(chunk)

		scalar, err := deserialiseScalar(*serialisedScalar)
		if err != nil {
			return nil, err
		}
		poly[j] = scalar
	}
	return poly, nil
}

func deserialiseScalar(serScalar SerialisedScalar) (fr.Element, error) {
	// gnark uses big-endian but the format according to the specs is little-endian
	// so we reverse the scalar
	utils.ReverseArray(&serScalar)
	scalar, isCanon := utils.ReduceCanonical(serScalar[:])
	if !isCanon {
		return fr.Element{}, errors.New("scalar is not in canonical format")
	}
	return scalar, nil
}
