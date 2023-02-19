package kzg

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

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

	got, isInDomain, err := EvaluateLagrangePolynomial(domain, poly, *point)
	if err != nil {
		t.Fail()
	}
	if isInDomain {
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
