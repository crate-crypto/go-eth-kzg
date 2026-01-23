package fk20

import (
	"math/big"
	"slices"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
)

func TestCirculantMatrixG1(t *testing.T) {
	row := []fr.Element{fr.NewElement(1), fr.NewElement(2), fr.NewElement(3), fr.NewElement(4)}
	col := []fr.Element{fr.NewElement(1), fr.NewElement(5), fr.NewElement(6), fr.NewElement(7)}

	toeplitz := newToeplitz(row, col)

	one := fr.NewElement(1)
	oneBigInt := one.BigInt(new(big.Int))
	two := fr.NewElement(2)
	twoBigInt := two.BigInt(new(big.Int))
	three := fr.NewElement(3)
	threeBigInt := three.BigInt(new(big.Int))
	four := fr.NewElement(4)
	fourBigInt := four.BigInt(new(big.Int))

	vector := []bls12381.G1Affine{
		*new(bls12381.G1Affine).ScalarMultiplicationBase(oneBigInt),
		*new(bls12381.G1Affine).ScalarMultiplicationBase(twoBigInt),
		*new(bls12381.G1Affine).ScalarMultiplicationBase(threeBigInt),
		*new(bls12381.G1Affine).ScalarMultiplicationBase(fourBigInt),
	}

	expected := toeplitz.mulVectorG1(vector)

	circulant := toeplitz.embedCirculant()

	result := circulant.mulVectorG1(vector)

	if len(result) != len(expected) {
		t.Fatalf("computed vector has the wrong size")
	}

	for i := 0; i < len(expected); i++ {
		if !expected[i].Equal(&result[i]) {
			t.Fatalf("computed vector is incorrect")
		}
	}
}

func (t *toeplitzMatrix) mulVectorG1(vector []bls12381.G1Affine) []bls12381.G1Affine {
	if len(vector) != len(t.row) {
		panic("Vector length must match the number of columns in the Toeplitz matrix")
	}

	n := len(t.col)
	m := len(t.row)
	result := make([]bls12381.G1Affine, n)

	for i := 0; i < n; i++ {
		var sum bls12381.G1Jac

		for j := 0; j < m; j++ {
			var term bls12381.G1Affine
			var matrixElement fr.Element

			if i-j >= 0 {
				matrixElement.Set(&t.col[i-j])
			} else {
				matrixElement.Set(&t.row[j-i])
			}

			term.ScalarMultiplication(&vector[j], matrixElement.BigInt(new(big.Int)))
			sum.AddMixed(&term)
		}

		result[i].FromJacobian(&sum)
	}

	return result
}

func (cm *circulantMatrix) mulVectorG1(vector []bls12381.G1Affine) []bls12381.G1Affine {
	vector = slices.Clone(vector)
	row := slices.Clone(cm.row)

	originalVectorLen := len(vector)

	n := len(vector) * 2
	circulantDomain := domain.NewDomain(uint64(n))

	for i := len(vector); i < n; i++ {
		vector = append(vector, bls12381.G1Affine{})
	}
	for i := len(row); i < n; i++ {
		row = append(row, fr.Element{})
	}

	circulantDomain.FftG1(vector)
	mFFT := vector
	circulantDomain.FftFr(row)
	colFFT := row

	result := make([]bls12381.G1Affine, len(mFFT))
	for i := 0; i < len(mFFT); i++ {
		result[i].ScalarMultiplication(&mFFT[i], colFFT[i].BigInt(new(big.Int)))
	}

	circulantDomain.IfftG1(result)

	return result[:originalVectorLen]
}
