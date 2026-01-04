package domain

import (
	"math/big"

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
	return fftG1(values, domain.Generator)
}

// Computes an IFFT(Inverse Fast Fourier Transform) of the G1 elements.
//
// The elements are returned in order as opposed to being returned in
// bit-reversed order.
func (domain *Domain) IfftG1(values []bls12381.G1Affine) []bls12381.G1Affine {
	var invDomainBI big.Int
	domain.CardinalityInv.BigInt(&invDomainBI)

	inverseFFT := fftG1(values, domain.GeneratorInv)

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
func fftG1(values []bls12381.G1Affine, nthRootOfUnity fr.Element) []bls12381.G1Affine {
	n := len(values)
	if n == 1 {
		return values
	}

	var generatorSquared fr.Element
	generatorSquared.Square(&nthRootOfUnity) // generator with order n/2

	// split the input slice into a (copy of) the values at even resp. odd indices.
	even, odd := takeEvenOdd(values)

	// perform FFT recursively on those parts.
	fftEven := fftG1(even, generatorSquared)
	fftOdd := fftG1(odd, generatorSquared)

	// combine them to get the result
	// - evaluations[k] = fftEven[k] + w^k * fftOdd[k]
	// - evaluations[k] = fftEven[k] - w^k * fftOdd[k]
	// where w is a n'th primitive root of unity.
	inputPoint := fr.One()
	evaluations := make([]bls12381.G1Affine, n)
	for k := 0; k < n/2; k++ {
		var tmp bls12381.G1Affine

		var inputPointBI big.Int
		inputPoint.BigInt(&inputPointBI)

		if inputPoint.IsOne() {
			tmp.Set(&fftOdd[k])
		} else {
			tmp.ScalarMultiplication(&fftOdd[k], &inputPointBI)
		}

		evaluations[k].Add(&fftEven[k], &tmp)
		evaluations[k+n/2].Sub(&fftEven[k], &tmp)

		// we could take this from precomputed values in Domain (as domain.roots[n*k]), but then we would need to pass the domain.
		// At any rate, we don't really need to optimize here.
		inputPoint.Mul(&inputPoint, &nthRootOfUnity)
	}

	return evaluations
}

// FftFr performs a Fast Fourier Transform on field elements.
// Returns a newly allocated slice with the result (does not use pooling for the output).
func (d *Domain) FftFr(values []fr.Element) []fr.Element {
	n := len(values)

	// Allocate output buffer (not from pool - caller owns this)
	output := make([]fr.Element, n)
	copy(output, values)

	fftFrInPlaceSimple(output, d.Generator)
	return output
}

// FftFrInto performs FFT and writes the result into the provided output slice.
// The output slice must have the same length as values.
// This is the zero-allocation version for use in hot paths when caller manages buffers.
func (d *Domain) FftFrInto(values, output []fr.Element) {
	copy(output, values)
	fftFrInPlaceSimple(output, d.Generator)
}

// IfftFr performs an Inverse Fast Fourier Transform on field elements.
// Returns a newly allocated slice with the result (does not use pooling for the output).
func (d *Domain) IfftFr(values []fr.Element) []fr.Element {
	n := len(values)

	// Allocate output buffer (not from pool - caller owns this)
	output := make([]fr.Element, n)
	copy(output, values)

	fftFrInPlaceSimple(output, d.GeneratorInv)

	// Scale by the inverse of the domain size
	var invDomain fr.Element
	invDomain.SetInt64(int64(n))
	invDomain.Inverse(&invDomain)

	for i := 0; i < n; i++ {
		output[i].Mul(&output[i], &invDomain)
	}

	return output
}

// IfftFrInto performs IFFT and writes the result into the provided output slice.
// The output slice must have the same length as values.
// This is the zero-allocation version for use in hot paths when caller manages buffers.
func (d *Domain) IfftFrInto(values, output []fr.Element) {
	copy(output, values)
	fftFr(output, d.GeneratorInv)

	// Scale by the inverse of the domain size
	n := len(values)
	var invDomain fr.Element
	invDomain.SetInt64(int64(n))
	invDomain.Inverse(&invDomain)

	for i := 0; i < n; i++ {
		output[i].Mul(&output[i], &invDomain)
	}
}

// fftFr performs an in-place Cooley-Tukey FFT.
func fftFr(values []fr.Element, nthRootOfUnity fr.Element) {
	n := len(values)
	if n == 1 {
		return
	}

	// Decimation-in-frequency (DIF) FFT - Gentleman-Sande butterfly
	// Takes input in natural order, produces output in bit-reversed order
	for size := n; size >= 2; size /= 2 {
		halfSize := size / 2

		// Compute the twiddle factor step for this stage
		// We need w = nthRootOfUnity^(n/size) as the primitive size-th root of unity
		var wStep fr.Element
		exp := uint64(n / size)
		wStep.Set(&nthRootOfUnity)
		for i := uint64(1); i < exp; i++ {
			wStep.Mul(&wStep, &nthRootOfUnity)
		}

		for start := 0; start < n; start += size {
			w := fr.One()
			for k := 0; k < halfSize; k++ {
				topIdx := start + k
				botIdx := start + k + halfSize

				// Gentleman-Sande butterfly
				var tmp fr.Element
				tmp.Sub(&values[topIdx], &values[botIdx])
				values[topIdx].Add(&values[topIdx], &values[botIdx])
				values[botIdx].Mul(&tmp, &w)

				w.Mul(&w, &wStep)
			}
		}
	}

	// Bit-reverse permutation to get output in natural order
	bitReversePerm(values)
}

// bitReversePerm performs in-place bit-reversal permutation on the slice.
func bitReversePerm(values []fr.Element) {
	n := len(values)
	j := 0
	for i := 1; i < n; i++ {
		bit := n >> 1
		for j&bit != 0 {
			j ^= bit
			bit >>= 1
		}
		j ^= bit
		if i < j {
			values[i], values[j] = values[j], values[i]
		}
	}
}

// takeEvenOdd Takes a slice and return two slices
// The first slice contains (a copy of) all of the elements
// at even indices, the second slice contains
// (a copy of) all of the elements at odd indices
//
// We assume that the length of the given values slice is even
// so the returned arrays will be the same length.
// This is the case for a radix-2 FFT
func takeEvenOdd[T interface{}](values []T) ([]T, []T) {
	n := len(values)
	even := make([]T, 0, n/2)
	odd := make([]T, 0, n/2)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			even = append(even, values[i])
		} else {
			odd = append(odd, values[i])
		}
	}

	return even, odd
}
