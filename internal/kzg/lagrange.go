package kzg

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

func EvaluateLagrangePolynomial(domain *Domain, poly Polynomial, eval_point fr.Element) (*fr.Element, error) {
	outputPoint, _, err := evaluateLagrangePolynomial(domain, poly, eval_point)
	return outputPoint, err
}

// TODO: possibly put this as a method on the domain instead
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
		return &poly[indexInDomain], indexInDomain, nil
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
