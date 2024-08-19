package kzg

import (
	"errors"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/multiexp"
)

// OpeningKey is the key used to verify opening proofs
type OpeningKey struct {
	// This is the degree-0 G_1 element in the trusted setup.
	// In the specs, this is denoted as `KZG_SETUP_G1[0]`
	GenG1 bls12381.G1Affine
	// This is the degree-0 G_2 element in the trusted setup.
	// In the specs, this is denoted as `KZG_SETUP_G2[0]`
	GenG2 bls12381.G2Affine
	// This is the degree-1 G_2 element in the trusted setup.
	// In the specs, this is denoted as `KZG_SETUP_G2[1]`
	AlphaG2 bls12381.G2Affine
	// These are the G1 elements in monomial form from the trusted setup
	G1 []bls12381.G1Affine
	// These are the G2 elements in monomial form from the trusted setup
	// Note: the length of this list is the same as the length of the G1 list
	G2 []bls12381.G2Affine
}

// CommitKey holds the data needed to commit to polynomials and by proxy make opening proofs
// TODO: We currently use this for both monomial and lagrange form points.
// TODO:  consider using two types
type CommitKey struct {
	// These are the G1 elements from the trusted setup.
	// In the specs this is denoted as `KZG_SETUP_G1` before
	// we processed it with `ifftG1`. Once we compute `ifftG1`
	// then this list is denoted as `KZG_SETUP_LAGRANGE` in the specs.
	G1 []bls12381.G1Affine
}

// ReversePoints applies the bit reversal permutation
// to the G1 points stored inside the CommitKey c.
func (c *CommitKey) ReversePoints() {
	domain.BitReverse(c.G1)
}

// SRS holds the structured reference string (SRS) for making
// and verifying KZG proofs
//
// This codebase is only concerned with polynomials in Lagrange
// form, so we only expose methods to create the SRS in Lagrange form
//
// The monomial SRS methods are solely used for testing.
type SRS struct {
	CommitKey  CommitKey
	OpeningKey OpeningKey
}

// Commit commits to a polynomial using a multi exponentiation with the
// Commitment key.
//
// numGoRoutines is used to configure the amount of concurrency needed. Setting this
// value to a negative number or 0 will make it default to the number of CPUs.
// TODO: Move this to a method on CommitKey
func Commit(p Polynomial, ck *CommitKey, numGoRoutines int) (*Commitment, error) {
	if len(p) == 0 || len(p) > len(ck.G1) {
		return nil, ErrInvalidPolynomialSize
	}

	return multiexp.MultiExpG1(p, ck.G1[:len(p)], numGoRoutines)
}

// TODO: Move this to a method on OpeningKey
func CommitG1(scalars []fr.Element, ok *OpeningKey) (*bls12381.G1Affine, error) {
	if len(scalars) == 0 || len(scalars) > len(ok.G1) {
		return nil, errors.New("invalid vector size for G1 commitment")
	}

	return multiexp.MultiExpG1(scalars, ok.G1[:len(scalars)], 0)
}

// TODO: Move this to a method on OpeningKey
func CommitG2(scalars []fr.Element, ok *OpeningKey) (*bls12381.G2Affine, error) {
	if len(scalars) == 0 || len(scalars) > len(ok.G2) {
		return nil, errors.New("invalid vector size for G2 commitment")
	}

	return multiexp.MultiExpG2(scalars, ok.G2[:len(scalars)], 0)
}
