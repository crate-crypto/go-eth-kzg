package poly

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestPolyAdd(t *testing.T) {
	a := []fr.Element{fr.One(), fr.One(), fr.One()}
	b := []fr.Element{fr.One(), fr.One(), fr.One()}
	expected := []fr.Element{fr.NewElement(2), fr.NewElement(2), fr.NewElement(2)}
	got := PolyAdd(a, b)
	if !equalPoly(got, expected) {
		t.Errorf("expected %v, got %v", expected, got)
	}
}

func TestPolyMul(t *testing.T) {
	a := []fr.Element{fr.NewElement(0), fr.NewElement(0), fr.One()}                                    // x^2
	b := []fr.Element{fr.One(), fr.NewElement(0), fr.One()}                                            // 1+x^2
	expected := []fr.Element{fr.NewElement(0), fr.NewElement(0), fr.One(), fr.NewElement(0), fr.One()} // x^4 + x^2
	got := PolyMul(a, b)
	if !equalPoly(got, expected) {
		t.Errorf("expected %v, got %v", expected, got)
	}
}

func TestPolyInterpolate(t *testing.T) {
	points := []fr.Element{fr.NewElement(1), fr.NewElement(2), fr.NewElement(3), fr.NewElement(4)}
	values := []fr.Element{fr.NewElement(1), fr.NewElement(2), fr.NewElement(3), fr.NewElement(4)}
	poly := LagrangeInterpolate(points, values)
	for i, point := range points {
		eval := PolyEval(poly, point)
		if !eval.Equal(&values[i]) {
			t.Fatalf("expected evaluation at the interpolated polynomial to be the value")
		}
	}
}

func TestPolyEval(t *testing.T) {
	// f(x) = 1 + 2x + 3x^2 + 4x^3
	poly := []fr.Element{fr.One(), fr.NewElement(2), fr.NewElement(3), fr.NewElement(4)}

	// f(0) = 1
	point := fr.NewElement(0)
	expectedEval := fr.NewElement(1)

	eval := PolyEval(poly, point)
	if !eval.Equal(&expectedEval) {
		t.Fatalf("computation of f(0) is incorrect")
	}

	// f(1) = 1 + 2 + 3 + 4 = 10
	point = fr.NewElement(1)
	expectedEval = fr.NewElement(10)

	eval = PolyEval(poly, point)
	if !eval.Equal(&expectedEval) {
		t.Fatalf("computation of f(1) is incorrect")
	}

	// f(10) = 10 + 20 + 300 + 4000
	point = fr.NewElement(10)
	expectedEval = fr.NewElement(4321)

	eval = PolyEval(poly, point)
	if !eval.Equal(&expectedEval) {
		t.Fatalf("computation of f(10) is incorrect")
	}
}

func TestPolyDivXMinusA(t *testing.T) {
	// f(x) = (x-1)(x-2)(x-3) = x^3 - 6x^2 + 11x - 6
	minusSix := fr.NewElement(6)
	minusSix.Neg(&minusSix)
	poly := []fr.Element{minusSix, fr.NewElement(11), minusSix, fr.One()}

	// g(x) = f(x) / (x - 1) = (x-2)(x-3) = x^2 - 5x + 6
	minusFive := fr.NewElement(5)
	minusFive.Neg(&minusFive)

	quotient := DividePolyByXminusA(poly, fr.NewElement(1))
	expectedQuotient := []fr.Element{fr.NewElement(6), minusFive, fr.One()}

	for i := 0; i < len(quotient); i++ {
		if !quotient[i].Equal(&expectedQuotient[i]) {
			t.Fatalf("computation of f(x) / (x - 1) is incorrect")
		}
	}

	// h(x) = g(x) / (x-2) = x-3
	minusThree := fr.NewElement(3)
	minusThree.Neg(&minusThree)
	quotient = DividePolyByXminusA(quotient, fr.NewElement(2))
	expectedQuotient = []fr.Element{minusThree, fr.One()}
	for i := 0; i < len(quotient); i++ {
		if !quotient[i].Equal(&expectedQuotient[i]) {
			t.Fatalf("computation of f(x) / (x - 2) is incorrect")
		}
	}

	// h(x) / (x - 3) = 1
	quotient = DividePolyByXminusA(quotient, fr.NewElement(3))
	expectedQuotient = []fr.Element{fr.One()}
	for i := 0; i < len(quotient); i++ {
		if !quotient[i].Equal(&expectedQuotient[i]) {
			t.Fatalf("computation of f(x) / (x - 3) is incorrect")
		}
	}
}
