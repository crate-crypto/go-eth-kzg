package kzg

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/utils"
)

func EvaluateLagrangePolynomial(domain *Domain, poly Polynomial, eval_point fr.Element) (*fr.Element, error) {
	if domain.Cardinality != uint64(len(poly)) {
		return nil, errors.New("domain size does not equal the number of evaluations in the polynomial")
	}

	// TODO: should we check here instead that eval_point is not in the domain
	// TODO We should do it in a using channels, so that it doesn't block the rest of the code

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

	return &result, nil
}
