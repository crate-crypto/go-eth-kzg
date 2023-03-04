package kzg

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestRootsSmoke(t *testing.T) {
	domain := NewDomain(4)

	roots_0 := domain.Roots[0]
	roots_1 := domain.Roots[1]
	roots_2 := domain.Roots[2]
	roots_3 := domain.Roots[3]

	// First root should be 1 : omega^0
	if !roots_0.IsOne() {
		t.Error("the first root should be one")
	}

	// Second root should have an order of 4 : omega^1
	var res fr.Element
	res.Exp(roots_1, big.NewInt(4))
	if !res.IsOne() {
		t.Error("root does not have an order of 4")
	}

	// Third root should have an order of 2 : omega^2
	res.Exp(roots_2, big.NewInt(2))
	if !res.IsOne() {
		t.Error("root does not have an order of 2")
	}

	// Fourth root when multiplied by first root should give 1 : omega^3
	res.Mul(&roots_3, &roots_1)
	if !res.IsOne() {
		t.Error("root does not have an order of 2")
	}
}

func TestEvalPolynomialSmoke(t *testing.T) {
	// The polynomial in question is: f(x) =  x^2 + x
	f_x := func(x fr.Element) fr.Element {
		var tmp fr.Element
		tmp.Square(&x)
		tmp.Add(&tmp, &x)
		return tmp
	}

	// You need at least 3 evaluations to determine a degree 2 polynomial
	num_evaluations := 3
	domain := NewDomain(uint64(num_evaluations))

	// Elements are the evaluations of the polynomial over
	// `domain`
	poly := make([]fr.Element, domain.Cardinality)

	for i := 0; i < int(domain.Cardinality); i++ {
		var x = domain.Roots[i]
		poly[i] = f_x(x)
	}

	point := samplePointOutsideDomain(*domain)

	got, indexInDomain, err := domain.evaluateLagrangePolynomial(poly, *point)
	if err != nil {
		t.Fail()
	}
	if indexInDomain != -1 {
		t.Fatalf("point was sampled to be outside of the domain")
	}

	// Now we evaluate the polynomial in monomial form
	// on the point outside of the domain
	expected := f_x(*point)

	if !expected.Equal(got) {
		t.Error("unexpected evaluation of polynomial")
	}

}

func samplePointOutsideDomain(domain Domain) *fr.Element {
	var rand_element fr.Element

	for {
		rand_element.SetUint64(randUint64())
		if !domain.isInDomain(rand_element) {
			break
		}
	}

	return &rand_element
}

func randUint64() uint64 {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		panic("could not generate random number")
	}
	return binary.LittleEndian.Uint64(buf)
}
