package context

import (
	"errors"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

func deserialiseComms(serComms SerialisedCommitments) ([]curve.G1Affine, error) {

	comms := make([]curve.G1Affine, len(serComms))
	for i := 0; i < len(serComms); i++ {
		// This will do subgroup checks and is relatively expensive (bench)
		// TODO: We _could_ do these on multiple threads, if bench shows them to be relatively slow
		comm, err := deserialiseG1Point(serComms[i])
		if err != nil {
			return nil, err
		}
		comms[i] = comm
	}

	return comms, nil
}

func deserialiseG1Point(serPoint SerialisedG1Point) (curve.G1Affine, error) {
	var point curve.G1Affine

	_, err := point.SetBytes(serPoint[:])
	if err != nil {
		return curve.G1Affine{}, err
	}
	return point, nil
}

func deserialisePolys(serPolys []SerialisedPoly) ([]kzg.Polynomial, error) {

	num_polynomials := len(serPolys)
	polys := make([]kzg.Polynomial, 0, num_polynomials)

	for _, serPoly := range serPolys {
		poly, err := deserialisePoly(serPoly)
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

func serialiseCommitments(comms []curve.G1Affine) SerialisedCommitments {
	serComms := make(SerialisedCommitments, len(comms))
	for i := 0; i < len(comms); i++ {
		comm := comms[i].Bytes()
		serComms[i] = comm
	}
	return serComms
}
