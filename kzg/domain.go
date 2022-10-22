package kzg

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/utils"
)

type Domain struct {
	Cardinality    uint64
	CardinalityInv fr.Element
	// Generator for the multiplicative subgroup
	// Not the primitive generator for the field
	Generator    fr.Element
	GeneratorInv fr.Element

	// Roots of unity for the multiplicative subgroup
	Roots []fr.Element
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

	return domain
}

func (d *Domain) ReverseRoots() {
	BitReverse(d.Roots)
}

// Checks if a point is in the domain. Used for tests
func (d Domain) isInDomain(point fr.Element) bool {
	for i := 0; i < int(d.Cardinality); i++ {
		if point.Equal(&d.Roots[i]) {
			return true
		}
	}
	return false
}

// BitReverse applies the bit-reversal permutation to a.
// len(a) must be a power of 2
// Taken and modified from gnark-crypto
func BitReverse(a []fr.Element) {
	n := uint64(len(a))
	if !utils.IsPowerOfTwo(n) {
		panic("size of slice must be a power of two")
	}

	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}

// Copied from prysm code
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

func evaluateAllLagrangeCoefficients(domain Domain, tau fr.Element) []fr.Element {
	size := domain.Cardinality

	var t_size fr.Element
	t_size.Exp(tau, big.NewInt(int64(size)))

	one := fr.One()

	if t_size.IsOne() {
		u := make([]fr.Element, size)
		omega_i := one
		for i := uint64(0); i < size; i++ {
			if omega_i.Equal(&tau) {
				u[i] = one
			}
			omega_i.Mul(&omega_i, &domain.Generator)
		}
		return u
	} else {

		var l fr.Element
		l.Sub(&t_size, &one)
		l.Mul(&l, &domain.CardinalityInv)

		r := fr.One()
		u := make([]fr.Element, size)
		ls := make([]fr.Element, size)
		for i := uint64(0); i < size; i++ {
			u[i].Sub(&tau, &r)
			ls[i] = l
			l.Mul(&l, &domain.Generator)
			r.Mul(&r, &domain.Generator)
		}

		u = fr.BatchInvert(u)

		for i := uint64(0); i < size; i++ {
			u[i].Mul(&u[i], &ls[i])
		}
		return u
	}
}
