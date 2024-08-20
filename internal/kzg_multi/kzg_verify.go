package kzgmulti

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/poly"
)

// vanishingPolyCoeff returns the polynomial that has roots at the given points
func vanishingPolyCoeff(xs []fr.Element) poly.PolynomialCoeff {
	result := []fr.Element{fr.One()}

	for _, x := range xs {
		// This is to silence: G601: Implicit memory aliasing in for loop.
		x := x

		negX := fr.Element{}
		negX.Neg(&x)
		result = poly.PolyMul(result, []fr.Element{negX, fr.One()})
	}

	return result
}

func VerifyMultiPointKZGProof(commitment, proof bls12381.G1Affine, outputPoints, inputPoints []fr.Element, openKey *kzg.OpeningKey) error {
	// Compute the following pairing check:
	// e([Q(X)]_1, [Z(X)]_2) == e([f(X)]_1 - [I(X)]_1, [1]_2)

	zeroPoly := vanishingPolyCoeff(inputPoints)
	zeroPolyComm, err := kzg.CommitG2(zeroPoly, openKey)
	if err != nil {
		return err
	}

	interpolatedPoly := poly.LagrangeInterpolate(inputPoints, outputPoints)
	interpolatedPolyComm, err := kzg.CommitG1(interpolatedPoly, openKey)
	if err != nil {
		return err
	}

	// [f(X)]_1 - [I(X)]_1,
	var fMinusIx bls12381.G1Affine
	fMinusIx.Neg(interpolatedPolyComm)
	fMinusIx.Add(&fMinusIx, &commitment)

	var negG2Gen bls12381.G2Affine
	negG2Gen.Neg(&openKey.GenG2)

	check, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{proof, fMinusIx},
		[]bls12381.G2Affine{*zeroPolyComm, negG2Gen},
	)
	if err != nil {
		return err
	}
	if !check {
		return kzg.ErrVerifyOpeningProof
	}

	return nil
}
