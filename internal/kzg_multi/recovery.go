package kzgmulti

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
)

const CellsPerExtBlob = 128

const ScalarsPerExtBlob = 8192

const ScalarsPerCell = 64

// Note: These cell indices should not be in bit reversed order
func constructVanishingPolyOnIndices(missingCellIndices []uint64) []fr.Element {
	rootsOfUnityReduced := kzg.NewDomain(uint64(CellsPerExtBlob))

	missingCellIndexRoot := make([]fr.Element, len(missingCellIndices))
	for i, index := range missingCellIndices {
		missingCellIndexRoot[i] = rootsOfUnityReduced.Roots[index]
	}

	shortZeroPoly := vanishingPolyCoeff(missingCellIndexRoot)

	zeroPolyCoeff := make([]fr.Element, ScalarsPerExtBlob)
	for i, coeff := range shortZeroPoly {
		zeroPolyCoeff[i*ScalarsPerCell] = coeff
	}

	return zeroPolyCoeff
}

func RecoverPolynomialCoefficients(data []fr.Element, domainExtended *kzg.Domain, missingIndices []uint64) ([]fr.Element, error) {
	zX := constructVanishingPolyOnIndices(missingIndices)

	zXEval := domainExtended.FftFr(zX)

	if len(zXEval) != len(data) {
		return nil, errors.New("length of data and zXEval should be equal")
	}

	eZEval := make([]fr.Element, len(data))
	for i := 0; i < len(data); i++ {
		eZEval[i].Mul(&data[i], &zXEval[i])
	}

	dzPoly := domainExtended.IfftFr(eZEval)

	cosetZxEval := domainExtended.CosetFFtFr(zX)
	cosetDzEVal := domainExtended.CosetFFtFr(dzPoly)

	cosetQuotientEval := make([]fr.Element, len(cosetZxEval))
	cosetZxEval = fr.BatchInvert(cosetZxEval)

	for i := 0; i < len(cosetZxEval); i++ {
		cosetQuotientEval[i].Mul(&cosetDzEVal[i], &cosetZxEval[i])
	}

	polyCoeff := domainExtended.CosetIFFtFr(cosetQuotientEval)

	// We have a expansion factor of two, so this polynomial being returned
	// should have its latter half as zeros
	polyCoeff = polyCoeff[:len(polyCoeff)/2]
	return polyCoeff, nil
}
