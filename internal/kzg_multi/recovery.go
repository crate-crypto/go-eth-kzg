package kzgmulti

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
)

type DataRecovery struct {
	rootsOfUnityReduced *kzg.Domain
	domainExtended      *kzg.Domain
	scalarsPerCell      int
	scalarsPerExtBlob   int
	cellsPerExtBlob     int
}

func NewDataRecovery(scalarsPerCell, scalarsPerExtBlob, cellsPerExtBlob int) *DataRecovery {
	rootsOfUnityReduced := kzg.NewDomain(uint64(cellsPerExtBlob))
	domainExtended := kzg.NewDomain(uint64(scalarsPerExtBlob))

	return &DataRecovery{
		rootsOfUnityReduced: rootsOfUnityReduced,
		domainExtended:      domainExtended,
		scalarsPerCell:      scalarsPerCell,
		scalarsPerExtBlob:   scalarsPerExtBlob,
		cellsPerExtBlob:     cellsPerExtBlob,
	}
}

// Note: These cell indices should not be in bit reversed order
func (dr *DataRecovery) constructVanishingPolyOnIndices(missingCellIndices []uint64) []fr.Element {
	rootsOfUnityReduced := kzg.NewDomain(uint64(dr.cellsPerExtBlob))

	missingCellIndexRoot := make([]fr.Element, len(missingCellIndices))
	for i, index := range missingCellIndices {
		missingCellIndexRoot[i] = rootsOfUnityReduced.Roots[index]
	}

	shortZeroPoly := vanishingPolyCoeff(missingCellIndexRoot)

	zeroPolyCoeff := make([]fr.Element, dr.scalarsPerExtBlob)
	for i, coeff := range shortZeroPoly {
		zeroPolyCoeff[i*dr.scalarsPerCell] = coeff
	}

	return zeroPolyCoeff
}

func (dr *DataRecovery) RecoverPolynomialCoefficients(data []fr.Element, missingIndices []uint64) ([]fr.Element, error) {
	zX := dr.constructVanishingPolyOnIndices(missingIndices)

	zXEval := dr.domainExtended.FftFr(zX)

	if len(zXEval) != len(data) {
		return nil, errors.New("length of data and zXEval should be equal")
	}

	eZEval := make([]fr.Element, len(data))
	for i := 0; i < len(data); i++ {
		eZEval[i].Mul(&data[i], &zXEval[i])
	}

	dzPoly := dr.domainExtended.IfftFr(eZEval)

	cosetZxEval := dr.domainExtended.CosetFFtFr(zX)
	cosetDzEVal := dr.domainExtended.CosetFFtFr(dzPoly)

	cosetQuotientEval := make([]fr.Element, len(cosetZxEval))
	cosetZxEval = fr.BatchInvert(cosetZxEval)

	for i := 0; i < len(cosetZxEval); i++ {
		cosetQuotientEval[i].Mul(&cosetDzEVal[i], &cosetZxEval[i])
	}

	polyCoeff := dr.domainExtended.CosetIFFtFr(cosetQuotientEval)

	// We have a expansion factor of two, so this polynomial being returned
	// should have its latter half as zeros
	polyCoeff = polyCoeff[:len(polyCoeff)/2]
	return polyCoeff, nil
}
