package kzg

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/multiexp"
)

// Key used to verify opening proofs
type OpeningKey struct {
	// This is the degree-0 G_1 element in the trusted setup.
	// In the specs, this is denoted as `KZG_SETUP_G1[0]`
	GenG1 bls12381.G1Affine
	// This is the degree-0 G_1 element in the trusted setup.
	// In the specs, this is denoted as `KZG_SETUP_G2[0]`
	GenG2 bls12381.G2Affine
	// This is the degree-1 G_2 element in the trusted setup.
	// In the specs, this is denoted as `KZG_SETUP_G2[1]`
	AlphaG2 bls12381.G2Affine
}

// Key used to commit to polynomials and by proxy make open proofs
type CommitKey struct {
	// These are the G1 elements from the trusted setup.
	// In the specs this is denoted as `KZG_SETUP_G1` before
	// we processed it with `ifftG1`. Once we compute `ifftG1`
	// then this list is denoted as `KZG_SETUP_LAGRANGE` in the specs.
	G1 []bls12381.G1Affine
}

// Applies the bit reversal permutation
// to the G1 points.
func (c CommitKey) ReversePoints() {
	bitReverse(c.G1)
}

// Structured reference string (SRS) for making
// and verifying KZG proofs
//
// This codebase is only concerned with polynomials in Lagrange
// form, so we only expose methods to create the SRS in lagrange form
//
// The monomial SRS methods are solely used for testing.
type SRS struct {
	CommitKey  CommitKey
	OpeningKey OpeningKey
}

// Creates a new SRS object with the secret `bAlpha`
//
// This method should not be used in production because the trusted setup
// is not secure, if one person knows what `bAlpha`is.
func NewLagrangeSRSInsecure(domain Domain, bAlpha *big.Int) (*SRS, error) {
	return newSRS(domain, bAlpha, true)
}

func newSRS(domain Domain, bAlpha *big.Int, convertToLagrange bool) (*SRS, error) {
	srs, err := newMonomialSRS(domain.Cardinality, bAlpha)
	if err != nil {
		return nil, err
	}

	if convertToLagrange {
		// Convert SRS from monomial form to lagrange form
		lagrangeG1 := domain.IfftG1(srs.CommitKey.G1)
		srs.CommitKey.G1 = lagrangeG1
	}

	return srs, nil
}

// SRS in monomial basis. This is only used for testing.
// Note that since we provide the secret scalar as input.
// This method should also never be used in production.
//
// Copied from [gnark-crypto](https://github.com/ConsenSys/gnark-crypto/blob/8f7ca09273c24ed9465043566906cbecf5dcee91/ecc/bls12-381/fr/kzg/kzg.go#L65)
func newMonomialSRS(size uint64, bAlpha *big.Int) (*SRS, error) {
	if size < 2 {
		return nil, ErrMinSRSSize
	}

	var commitKey CommitKey
	var openKey OpeningKey
	commitKey.G1 = make([]bls12381.G1Affine, size)

	var alpha fr.Element
	alpha.SetBigInt(bAlpha)

	_, _, gen1Aff, gen2Aff := bls12381.Generators()
	commitKey.G1[0] = gen1Aff
	openKey.GenG1 = gen1Aff
	openKey.GenG2 = gen2Aff
	openKey.AlphaG2.ScalarMultiplication(&gen2Aff, bAlpha)

	alphas := make([]fr.Element, size-1)
	alphas[0] = alpha
	for i := 1; i < len(alphas); i++ {
		alphas[i].Mul(&alphas[i-1], &alpha)
	}
	g1s := bls12381.BatchScalarMultiplicationG1(&gen1Aff, alphas)
	copy(commitKey.G1[1:], g1s)

	return &SRS{
		CommitKey:  commitKey,
		OpeningKey: openKey,
	}, nil
}

// Commit commits to a polynomial using a multi exponentiation with the
// Commitment key.
func Commit(p []fr.Element, ck *CommitKey) (*Commitment, error) {
	if len(p) == 0 || len(p) > len(ck.G1) {
		return nil, ErrInvalidPolynomialSize
	}

	res, err := multiexp.MultiExp(p, ck.G1[:len(p)])
	if err != nil {
		return nil, err
	}

	return res, nil
}
