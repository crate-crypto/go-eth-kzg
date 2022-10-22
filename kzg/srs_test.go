package kzg

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestLagrangeSRSSmoke(t *testing.T) {
	domain := NewDomain(4)
	srs_lagrange, _ := NewSRSInsecure(*domain, big.NewInt(100))
	srs_monomial, _ := newSRS(4, big.NewInt(100))

	// 1 + x + x^2
	poly_monomial := []fr.Element{fr.One(), fr.One(), fr.One()}
	f_x := func(x fr.Element) fr.Element {
		one := fr.One()
		var tmp fr.Element
		tmp.Square(&x)
		tmp.Add(&tmp, &x)
		tmp.Add(&tmp, &one)

		return tmp
	}
	poly_lagrange := []fr.Element{f_x(domain.Roots[0]), f_x(domain.Roots[1]), f_x(domain.Roots[2]), f_x(domain.Roots[3])}

	c_l, _ := Commit(poly_lagrange, &srs_lagrange.CommitKey)
	c_m, _ := Commit(poly_monomial, &srs_monomial.CommitKey)
	if !c_l.Equal(&c_m) {
		t.Error("commitment mismatch between monomial srs and lagrange srs")
	}

}
