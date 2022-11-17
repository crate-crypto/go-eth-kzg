package kzg

import (
	"errors"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/multiexp"
	"github.com/crate-crypto/go-proto-danksharding-crypto/utils"
)

var ErrMinSRSSize = errors.New("minimum srs size is 2")
var ErrSRSPow2 = errors.New("srs size must be a power of 2")

// Key used to verify opening proofs
type OpeningKey struct {
	GenG1   curve.G1Affine
	GenG2   curve.G2Affine
	AlphaG2 curve.G2Affine
}

// Key used to make opening proofs
type CommitKey struct {
	G1 []curve.G1Affine
}

func (c CommitKey) ReversePoints() {
	utils.BitReversePoints(c.G1)
}

// Structured reference string (SRS) for making
// and verifying KZG proofs
type SRS struct {
	CommitKey  CommitKey
	OpeningKey OpeningKey
}

// Creates an SRS in lagrange form.
// DO NOT USE THIS METHOD IN PRODUCTION
func NewSRSInsecure(domain Domain, bAlpha *big.Int) (*SRS, error) {

	size := domain.Cardinality
	if !utils.IsPowerOfTwo(size) {
		return nil, ErrSRSPow2
	}

	if size < 2 {
		return nil, ErrMinSRSSize
	}

	var openKey OpeningKey
	var commitKey CommitKey
	commitKey.G1 = make([]curve.G1Affine, size)

	var alpha fr.Element
	alpha.SetBigInt(bAlpha)

	_, _, gen1Aff, gen2Aff := curve.Generators()

	openKey.GenG1 = gen1Aff
	openKey.GenG2 = gen2Aff
	openKey.AlphaG2.ScalarMultiplication(&gen2Aff, bAlpha)

	alphas := evaluateAllLagrangeCoefficients(domain, alpha)
	for i := 0; i < len(alphas); i++ {
		alphas[i].FromMont()
	}

	g1s := curve.BatchScalarMultiplicationG1(&gen1Aff, alphas)
	copy(commitKey.G1[:], g1s[:])

	return &SRS{
		CommitKey:  commitKey,
		OpeningKey: openKey,
	}, nil
}

// SRS in monomial basis. This is only used for testing.
// Note that since we provide the secret scalar as input.
// This method should also never be used in production.
func newSRS(size uint64, bAlpha *big.Int) (*SRS, error) {

	if size < 2 {
		return nil, ErrMinSRSSize
	}

	var commitKey CommitKey
	var openKey OpeningKey
	commitKey.G1 = make([]curve.G1Affine, size)

	var alpha fr.Element
	alpha.SetBigInt(bAlpha)

	_, _, gen1Aff, gen2Aff := curve.Generators()
	commitKey.G1[0] = gen1Aff
	openKey.GenG1 = gen1Aff
	openKey.GenG2 = gen2Aff
	openKey.AlphaG2.ScalarMultiplication(&gen2Aff, bAlpha)

	alphas := make([]fr.Element, size-1)
	alphas[0] = alpha
	for i := 1; i < len(alphas); i++ {
		alphas[i].Mul(&alphas[i-1], &alpha)
	}
	for i := 0; i < len(alphas); i++ {
		alphas[i].FromMont()
	}
	g1s := curve.BatchScalarMultiplicationG1(&gen1Aff, alphas)
	copy(commitKey.G1[1:], g1s)

	return &SRS{
		CommitKey:  commitKey,
		OpeningKey: openKey,
	}, nil
}

// Commit commits to a polynomial using a multi exponentiation with the SRS.
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
