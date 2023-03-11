package kzg

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

type Domain struct {
	// Size of the domain as a uint64
	Cardinality uint64
	// Inverse of the size of the domain as
	// a field element. This is useful for
	// inverse FFTs.
	CardinalityInv fr.Element
	// Generator for the multiplicative subgroup
	// Not the primitive generator for the field
	//
	// This generator will have order equal to the
	// cardinality of the domain.
	Generator fr.Element
	// Inverse of the Generator. This is precomputed
	// and useful for inverse FFTs.
	GeneratorInv fr.Element

	// Roots of unity for the multiplicative subgroup
	Roots []fr.Element

	// Precomputed inverses of the domain which
	// we will use to speed up the computation
	// f(x)/g(x) where g(x) is a linear polynomial
	// which vanishes on a point on the domain
	PreComputedInverses []fr.Element
}

// Copied and modified from fft.NewDomain
func NewDomain(m uint64) *Domain {
	domain := &Domain{}
	x := ecc.NextPowerOfTwo(m)
	domain.Cardinality = uint64(x)

	// generator of the largest 2-adic subgroup
	var rootOfUnity fr.Element

	rootOfUnity.SetString("10238227357739495823651030575849232062558860180284477541189508159991286009131")
	const maxOrderRoot uint64 = 32

	// find generator for Z/2^(log(m))Z
	logx := uint64(bits.TrailingZeros64(x))
	if logx > maxOrderRoot {
		panic(fmt.Sprintf("m (%d) is too big: the required root of unity does not exist", m))
	}

	// Generator = FinerGenerator^2 has order x
	expo := uint64(1 << (maxOrderRoot - logx))
	domain.Generator.Exp(rootOfUnity, big.NewInt(int64(expo))) // order x
	domain.GeneratorInv.Inverse(&domain.Generator)
	domain.CardinalityInv.SetUint64(uint64(x)).Inverse(&domain.CardinalityInv)

	// Compute the roots of unity for the multiplicative subgroup
	domain.Roots = make([]fr.Element, x)
	current := fr.One()
	for i := uint64(0); i < x; i++ {
		domain.Roots[i] = current
		current.Mul(&current, &domain.Generator)
	}

	// Compute precomputed inverses: 1 / w^i
	domain.PreComputedInverses = make([]fr.Element, x)

	for i := uint64(0); i < x; i++ {
		domain.PreComputedInverses[i].Inverse(&domain.Roots[i])
	}

	return domain
}

// BitReverse applies the bit-reversal permutation to `list`.
// `len(list)` must be a power of 2
// Taken and modified from gnark-crypto (insert link to where I copied it from)
//
// [bit_reverse](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#reverse_bits)
func bitReverse[K interface{}](list []K) {
	n := uint64(len(list))
	if !utils.IsPowerOfTwo(n) {
		panic("size of list must be a power of two")
	}

	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			list[i], list[irev] = list[irev], list[i]
		}
	}
}

// Bit reverses the elements in the domain
// and their inverses
//
// [bit_reversal_permutation](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#bit_reversal_permutation)
func (domain *Domain) ReverseRoots() {
	bitReverse(domain.Roots)
	bitReverse(domain.PreComputedInverses)
}

// Returns the index of the element in the domain or -1 if it
// is not an element in the domain
func (domain Domain) findRootIndex(point fr.Element) int {
	for i := 0; i < int(domain.Cardinality); i++ {
		if point.Equal(&domain.Roots[i]) {
			return i
		}
	}

	return -1
}

// Evaluates a lagrange polynomial and returns an error if the
// number of evaluations in the polynomial is different to the size
// of the domain
//
// [evaluate_polynomial_in_evaluation_form](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#evaluate_polynomial_in_evaluation_form)
func (domain *Domain) EvaluateLagrangePolynomial(poly Polynomial, evalPoint fr.Element) (*fr.Element, error) {
	outputPoint, _, err := domain.evaluateLagrangePolynomial(poly, evalPoint)

	return outputPoint, err
}

// Evaluates polynomial and returns the index of the evaluation point
// in the domain, if it is a point in the domain and -1 otherwise
// This semantics was copied from the go library, see: https://cs.opensource.google/go/x/exp/+/522b1b58:slices/slices.go;l=117
func (domain *Domain) evaluateLagrangePolynomial(poly Polynomial, evalPoint fr.Element) (*fr.Element, int, error) {
	indexInDomain := -1

	if domain.Cardinality != uint64(len(poly)) {
		return nil, indexInDomain, ErrPolynomialMismatchedSizeDomain
	}

	// If the evaluation point is in the domain
	// then evaluation of the polynomial in lagrange form
	// is the same as indexing it with the position
	// that the evaluation point is in, in the domain
	indexInDomain = domain.findRootIndex(evalPoint)
	if indexInDomain != -1 {
		return &poly[indexInDomain], indexInDomain, nil
	}

	denom := make([]fr.Element, domain.Cardinality)
	for i := range denom {
		denom[i].Sub(&evalPoint, &domain.Roots[i])
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
	var tmp fr.Element
	tmp.Exp(evalPoint, big.NewInt(int64(domain.Cardinality)))
	one := fr.One()
	tmp.Sub(&tmp, &one)
	tmp.Mul(&tmp, &domain.CardinalityInv)
	result.Mul(&tmp, &result)

	return &result, indexInDomain, nil
}
