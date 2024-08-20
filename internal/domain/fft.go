package domain

import (
	"math/big"
	"math/bits"
	"slices"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// In this file we implement a simple version of the fft algorithm
// without any optimizations. This is sufficient as the fft algorithm is
// not on the hot path; we only need it to compute the lagrange version
// of the SRS, this can be done once at startup. Even if not cached,
// this process takes two to three seconds.
//
// See: https://faculty.sites.iastate.edu/jia/files/inline-files/polymultiply.pdf
// for a reference.

// Computes an FFT (Fast Fourier Transform) of the G1 elements.
//
// The elements are returned in order as opposed to being returned in
// bit-reversed order.
func (domain *Domain) FftG1(values []bls12381.G1Affine) []bls12381.G1Affine {
	fftVals := slices.Clone(values)
	fftG1(fftVals, domain.Generator)
	return fftVals
}

// Computes an IFFT(Inverse Fast Fourier Transform) of the G1 elements.
//
// The elements are returned in order as opposed to being returned in
// bit-reversed order.
func (domain *Domain) IfftG1(values []bls12381.G1Affine) []bls12381.G1Affine {
	var invDomainBI big.Int
	domain.CardinalityInv.BigInt(&invDomainBI)

	inverseFFT := slices.Clone(values)
	fftG1(inverseFFT, domain.GeneratorInv)

	// scale by the inverse of the domain size
	for i := 0; i < len(inverseFFT); i++ {
		inverseFFT[i].ScalarMultiplication(&inverseFFT[i], &invDomainBI)
	}

	return inverseFFT
}

// fftG1 computes an FFT (Fast Fourier Transform) of the G1 elements.
//
// This is the actual implementation of [FftG1] with the same convention.
// That is, the returned slice is in "normal", rather than bit-reversed order.
// We assert that values is a slice of length n==2^i and nthRootOfUnity is a primitive n'th root of unity.
// func fftG1(values []bls12381.G1Affine, nthRootOfUnity fr.Element) []bls12381.G1Affine {
// 	n := len(values)
// 	if n == 1 {
// 		return values
// 	}

// 	var generatorSquared fr.Element
// 	generatorSquared.Square(&nthRootOfUnity) // generator with order n/2

// 	// split the input slice into a (copy of) the values at even resp. odd indices.
// 	even, odd := takeEvenOdd(values)

// 	// perform FFT recursively on those parts.
// 	fftEven := fftG1(even, generatorSquared)
// 	fftOdd := fftG1(odd, generatorSquared)

// 	// combine them to get the result
// 	// - evaluations[k] = fftEven[k] + w^k * fftOdd[k]
// 	// - evaluations[k] = fftEven[k] - w^k * fftOdd[k]
// 	// where w is a n'th primitive root of unity.
// 	inputPoint := fr.One()
// 	evaluations := make([]bls12381.G1Affine, n)
// 	for k := 0; k < n/2; k++ {
// 		var tmp bls12381.G1Affine

// 		var inputPointBI big.Int
// 		inputPoint.BigInt(&inputPointBI)

// 		if inputPoint.IsOne() {
// 			tmp.Set(&fftOdd[k])
// 		} else {
// 			tmp.ScalarMultiplication(&fftOdd[k], &inputPointBI)
// 		}

// 		evaluations[k].Add(&fftEven[k], &tmp)
// 		evaluations[k+n/2].Sub(&fftEven[k], &tmp)

// 		// we could take this from precomputed values in Domain (as domain.roots[n*k]), but then we would need to pass the domain.
// 		// At any rate, we don't really need to optimize here.
// 		inputPoint.Mul(&inputPoint, &nthRootOfUnity)
// 	}

// 	return evaluations
// }

func fftG1(a []bls12381.G1Affine, omega fr.Element) {
	n := uint(len(a))
	logN := log2PowerOf2(uint64(n))

	if n != 1<<logN {
		panic("input size must be a power of 2")
	}

	// Bit-reversal permutation
	BitReverse(a)

	// Main FFT computation
	for s := uint(1); s <= logN; s++ {
		m := uint(1) << s
		halfM := m >> 1
		wm := new(fr.Element).Exp(omega, new(big.Int).SetUint64(uint64(n/m)))

		for k := uint(0); k < n; k += m {
			w := new(fr.Element).SetOne()
			for j := uint(0); j < halfM; j++ {
				var t bls12381.G1Affine
				var bi big.Int

				t.ScalarMultiplication(&a[k+j+halfM], w.BigInt(&bi))
				u := a[k+j]
				a[k+j].Add(&u, &t)
				a[k+j+halfM].Sub(&u, &t)
				w.Mul(w, wm)
			}
		}
	}
}

func (d *Domain) FftFr(values []fr.Element) []fr.Element {
	fftVals := slices.Clone(values)
	fftFr(fftVals, d.Generator)
	return fftVals
}

func (d *Domain) IfftFr(values []fr.Element) []fr.Element {
	var invDomain fr.Element
	invDomain.SetInt64(int64(len(values)))
	invDomain.Inverse(&invDomain)

	inverseFFT := slices.Clone(values)
	fftFr(inverseFFT, d.GeneratorInv)

	// scale by the inverse of the domain size
	for i := 0; i < len(inverseFFT); i++ {
		inverseFFT[i].Mul(&inverseFFT[i], &invDomain)
	}
	return inverseFFT
}

func log2PowerOf2(n uint64) uint {
	if n == 0 || (n&(n-1)) != 0 {
		panic("Input must be a power of 2 and not zero")
	}

	return uint(bits.TrailingZeros64(n))
}

func fftFr(a []fr.Element, omega fr.Element) {
	n := uint(len(a))
	logN := log2PowerOf2(uint64(n))

	if n != 1<<logN {
		panic("input size must be a power of 2")
	}

	// Bit-reversal permutation
	BitReverse(a)

	// Main FFT computation
	for s := uint(1); s <= logN; s++ {
		m := uint(1) << s
		halfM := m >> 1
		wm := new(fr.Element).Exp(omega, new(big.Int).SetUint64(uint64(n/m)))

		for k := uint(0); k < n; k += m {
			w := new(fr.Element).SetOne()
			for j := uint(0); j < halfM; j++ {
				t := new(fr.Element).Mul(&a[k+j+halfM], w)
				u := a[k+j]
				a[k+j].Add(&u, t)
				a[k+j+halfM].Sub(&u, t)
				w.Mul(w, wm)
			}
		}
	}
}

// func fftFr(values []fr.Element, nthRootOfUnity fr.Element) []fr.Element {
// 	n := len(values)
// 	if n == 1 {
// 		return values
// 	}

// 	var generatorSquared fr.Element
// 	generatorSquared.Square(&nthRootOfUnity) // generator with order n/2

// 	even, odd := takeEvenOdd(values)

// 	fftEven := fftFr(even, generatorSquared)
// 	fftOdd := fftFr(odd, generatorSquared)

// 	inputPoint := fr.One()
// 	evaluations := make([]fr.Element, n)
// 	for k := 0; k < n/2; k++ {
// 		var tmp fr.Element
// 		tmp.Mul(&inputPoint, &fftOdd[k])

// 		evaluations[k].Add(&fftEven[k], &tmp)
// 		evaluations[k+n/2].Sub(&fftEven[k], &tmp)

// 		inputPoint.Mul(&inputPoint, &nthRootOfUnity)
// 	}
// 	return evaluations
// }

// takeEvenOdd Takes a slice and return two slices
// The first slice contains (a copy of) all of the elements
// at even indices, the second slice contains
// (a copy of) all of the elements at odd indices
//
// We assume that the length of the given values slice is even
// so the returned arrays will be the same length.
// This is the case for a radix-2 FFT
// func takeEvenOdd[T interface{}](values []T) ([]T, []T) {
// 	n := len(values)
// 	even := make([]T, 0, n/2)
// 	odd := make([]T, 0, n/2)
// 	for i := 0; i < n; i++ {
// 		if i%2 == 0 {
// 			even = append(even, values[i])
// 		} else {
// 			odd = append(odd, values[i])
// 		}
// 	}

// 	return even, odd
// }
