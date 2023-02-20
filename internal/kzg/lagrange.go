package kzg

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

func EvaluateLagrangePolynomial(domain *Domain, poly Polynomial, eval_point fr.Element) (*fr.Element, error) {
	outputPoint, _, err := evaluateLagrangePolynomial(domain, poly, eval_point)
	return outputPoint, err
}

// Evaluates polynomial and returns the index iff the evaluation point
// was in the domain, -1 otherwise
// TODO: benchmark how long it takes to check if an element is in the domain
// TODO if its not a lot, we don't need to return the index here and just recompute
// TODO when we need it.
func evaluateLagrangePolynomial(domain *Domain, poly Polynomial, eval_point fr.Element) (*fr.Element, int, error) {
	indexInDomain := -1

	if domain.Cardinality != uint64(len(poly)) {
		return nil, indexInDomain, errors.New("domain size does not equal the number of evaluations in the polynomial")
	}

	// If the evaluation point is in the domain
	// then evaluation of the polynomial in lagrange form
	// is the same as indexing it with the position
	// that the evaluation point is in, in the domain
	indexInDomain = domain.findRootIndex(eval_point)
	if indexInDomain != -1 {
		index := domain.findRootIndex(eval_point)
		return &poly[index], indexInDomain, nil
	}

	denom := make([]fr.Element, domain.Cardinality)
	for i := range denom {
		denom[i].Sub(&eval_point, &domain.Roots[i])
	}
	invDenom := fr.BatchInvert(denom)

	var result fr.Element
	for i := 0; i < int(domain.Cardinality); i++ {
		var num fr.Element
		num.Mul(&poly[i], &domain.Roots[i])

		var div fr.Element
		div.Mul(&num, &invDenom[i])

		result.Add(&result, &div)
	}

	// result * (x^width - 1) * 1/width
	tmp := utils.Pow2(eval_point, domain.Cardinality)
	one := fr.One()
	tmp.Sub(tmp, &one)
	tmp.Mul(tmp, &domain.CardinalityInv)
	result.Mul(tmp, &result)

	return &result, indexInDomain, nil
}

// This function assumes that one has checked that the index
// is in the domain.
// If this is not the case, then the function will return the wrong result
// or panic
func polyAtIndex(poly Polynomial, indexInDomain fr.Element) *fr.Element {
	evalPointU64 := frToIndex(indexInDomain)
	polyValue := poly[evalPointU64]
	return &polyValue
}

// This method should only be called after one has checked that
// index is in the domain.
// TODO Maybe we should guard this function such that it can only be
// TODO called by checking if element is in the domain, then returning
// TODO a element not in domain error if so. Caller can then check for this error
func frToIndex(indexInDomain fr.Element) uint64 {
	// A reasonable assumption to make is that the domain size
	// can fit within a u64.
	// Given that our polynomial is not in sparse form
	// then we would run out of memory when we try to allocate
	// a polynomial with u64::MAX elements
	if !indexInDomain.IsUint64() {
		// We panic because, given that the index is in the domain
		// and the polynomial is represented in sparse form
		// then we simply cannot index the polynomial as we are doing below.
		// It would be a map and not a slice
		indexBigInt := &big.Int{}
		indexInDomain.BigInt(indexBigInt)
		panic(fmt.Errorf("Domain size does not fit within a uint64, size is %d", indexBigInt))
	}

	return indexInDomain.Uint64()
}
