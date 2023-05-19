package kzg

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
	"math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-kzg-4844/internal/utils"
)

func TestRootsSmoke(t *testing.T) {
	domain := NewDomain(4)

	roots0 := domain.Roots[0]
	roots1 := domain.Roots[1]
	roots2 := domain.Roots[2]
	roots3 := domain.Roots[3]

	// First root should be 1 : omega^0
	if !roots0.IsOne() {
		t.Error("the first root should be one")
	}

	// Second root should have an order of 4 : omega^1
	var res fr.Element
	res.Exp(roots1, big.NewInt(4))
	if !res.IsOne() {
		t.Error("root does not have an order of 4")
	}

	// Third root should have an order of 2 : omega^2
	res.Exp(roots2, big.NewInt(2))
	if !res.IsOne() {
		t.Error("root does not have an order of 2")
	}

	// Fourth root when multiplied by first root should give 1 : omega^3
	res.Mul(&roots3, &roots1)
	if !res.IsOne() {
		t.Error("root is not last element in subgroup")
	}
}

func TestBitReversal(t *testing.T) {
	powInt := func(x, y int) int {
		return int(math.Pow(float64(x), float64(y)))
	}

	// We only go up to 20 because we don't want a long running test
	for i := 0; i < 20; i++ {
		size := powInt(2, i)

		scalars := testScalars(size)
		reversed := bitReversalPermutation(scalars)

		bitReverse(scalars)

		for i := 0; i < size; i++ {
			if !reversed[i].Equal(&scalars[i]) {
				t.Error("bit reversal methods are not consistent")
			}
		}
	}
}

// This is simply another way to do the bit reversal,
// if these were incorrect then integration tests would
// fail.
func bitReversalPermutation(l []fr.Element) []fr.Element {
	size := uint64(len(l))
	if !utils.IsPowerOfTwo(size) {
		panic("size of slice must be a power of two")
	}

	out := make([]fr.Element, size)

	for i := range l {
		j := bits.Reverse64(uint64(i)) >> (65 - bits.Len64(size))
		out[i] = l[j]
	}

	return out
}

func TestEvalPolynomialSmoke(t *testing.T) {
	// The polynomial in question is: f(x) =  x^2 + x
	f := func(x fr.Element) fr.Element {
		var tmp fr.Element
		tmp.Square(&x)
		tmp.Add(&tmp, &x)
		return tmp
	}

	// You need at least 3 evaluations to determine a degree 2 polynomial
	// Due to restriction of the library, we use 4 points.
	numEvaluations := 4
	domain := NewDomain(uint64(numEvaluations))

	// lagrangePoly are the evaluations of the coefficient polynomial over
	// `domain`
	lagrangePoly := make(Polynomial, domain.Cardinality)
	for i := 0; i < int(domain.Cardinality); i++ {
		x := domain.Roots[i]
		lagrangePoly[i] = f(x)
	}

	// Evaluate the lagrange polynomial at all points in the domain
	//
	for i := int64(0); i < int64(domain.Cardinality); i++ {
		inputPoint := domain.Roots[i]

		gotOutputPoint, indexInDomain, err := domain.evaluateLagrangePolynomial(lagrangePoly, inputPoint)
		if err != nil {
			t.Error(err)
		}

		expectedOutputPoint := lagrangePoly[i]

		if !expectedOutputPoint.Equal(gotOutputPoint) {
			t.Fatalf("incorrect output point computed from evaluateLagrangePolynomial")
		}

		if indexInDomain != i {
			t.Fatalf("Expected %d as the index of the point being evaluated in the domain. Got %d", i, indexInDomain)
		}
	}

	// Evaluate polynomial at points outside of the domain
	//
	numPointsToEval := 10

	for i := 0; i < numPointsToEval; i++ {
		// Sample some random point
		inputPoint := samplePointOutsideDomain(*domain)

		gotOutputPoint, indexInDomain, err := domain.evaluateLagrangePolynomial(lagrangePoly, *inputPoint)
		if err != nil {
			t.Errorf(err.Error(), inputPoint.Bytes())
		}

		// Now we evaluate the polynomial in monomial form
		// on the point outside of the domain
		expectedPoint := f(*inputPoint)

		if !expectedPoint.Equal(gotOutputPoint) {
			t.Fatalf("unexpected evaluation of polynomial at point %v", inputPoint.Bytes())
		}

		if indexInDomain != -1 {
			t.Fatalf("point was sampled to be outside of the domain, but returned index is %d", indexInDomain)
		}
	}
}

func samplePointOutsideDomain(domain Domain) *fr.Element {
	var randElement fr.Element

	for {
		randElement.SetUint64(randUint64())
		if domain.findRootIndex(randElement) == -1 {
			break
		}
	}

	return &randElement
}

func randUint64() uint64 {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		panic("could not generate random number")
	}
	return binary.BigEndian.Uint64(buf)
}

func testScalars(size int) []fr.Element {
	res := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		res[i] = fr.NewElement(uint64(i))
	}
	return res
}
