package domain

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// FFTCoset represents a coset for Fast Fourier Transform operations.
// It contains the generator of the coset and its inverse.
type FFTCoset struct {
	// CosetGen is the generator element of the coset.
	// It's used to shift the domain for coset FFT operations.
	CosetGen fr.Element

	// InvCosetGen is the inverse of the coset generator.
	// It's used in inverse coset FFT operations to shift back to the original domain.
	InvCosetGen fr.Element
}

// CosetDomain represents a domain for performing FFT operations over a coset.
// It combines a standard FFT domain with coset information for efficient coset FFT computations.
type CosetDomain struct {
	// domain is the underlying FFT domain.
	domain *Domain

	// coset contains the coset generator and its inverse for this domain.
	coset FFTCoset
}

// NewCosetDomain creates a new CosetDomain with the given Domain and FFTCoset.
func NewCosetDomain(domain *Domain, fft_coset FFTCoset) *CosetDomain {
	return &CosetDomain{
		domain: domain,
		coset:  fft_coset,
	}
}

// CosetFFtFr performs a forward coset FFT on the input values.
//
// It first scales the input values by powers of the coset generator,
// then performs a standard FFT on the scaled values.
func (d *CosetDomain) CosetFFtFr(values []fr.Element) []fr.Element {
	n := len(values)
	result := make([]fr.Element, n)

	cosetScale := fr.One()
	for i := 0; i < n; i++ {
		result[i].Mul(&values[i], &cosetScale)
		cosetScale.Mul(&cosetScale, &d.coset.CosetGen)
	}

	fftFrInPlaceSimple(result, d.domain.Generator)
	return result
}

// CosetFFtFrInto performs forward coset FFT and writes the result into output.
// The output slice must have the same length as values.
// This is the zero-allocation version for use in hot paths when caller manages buffers.
func (d *CosetDomain) CosetFFtFrInto(values, output []fr.Element) {
	n := len(values)
	cosetScale := fr.One()
	for i := 0; i < n; i++ {
		output[i].Mul(&values[i], &cosetScale)
		cosetScale.Mul(&cosetScale, &d.coset.CosetGen)
	}

	fftFrInPlaceSimple(output, d.domain.Generator)
}

// CosetIFFtFr performs an inverse coset FFT on the input values.
//
// It first performs a standard inverse FFT, then scales the results
// by powers of the inverse coset generator to shift back to the original domain.
func (d *CosetDomain) CosetIFFtFr(values []fr.Element) []fr.Element {
	n := len(values)
	result := make([]fr.Element, n)
	copy(result, values)

	fftFrInPlaceSimple(result, d.domain.GeneratorInv)

	// Scale by the inverse of the domain size
	var invDomain fr.Element
	invDomain.SetInt64(int64(n))
	invDomain.Inverse(&invDomain)

	for i := 0; i < n; i++ {
		result[i].Mul(&result[i], &invDomain)
	}

	// Scale by inverse coset generator powers
	cosetScale := fr.One()
	for i := 0; i < n; i++ {
		result[i].Mul(&result[i], &cosetScale)
		cosetScale.Mul(&cosetScale, &d.coset.InvCosetGen)
	}

	return result
}

// CosetIFFtFrInto performs inverse coset FFT and writes the result into output.
// The output slice must have the same length as values.
// This is the zero-allocation version for use in hot paths when caller manages buffers.
func (d *CosetDomain) CosetIFFtFrInto(values, output []fr.Element) {
	n := len(values)
	copy(output, values)

	fftFrInPlaceSimple(output, d.domain.GeneratorInv)

	// Scale by the inverse of the domain size
	var invDomain fr.Element
	invDomain.SetInt64(int64(n))
	invDomain.Inverse(&invDomain)

	for i := 0; i < n; i++ {
		output[i].Mul(&output[i], &invDomain)
	}

	// Scale by inverse coset generator powers
	cosetScale := fr.One()
	for i := 0; i < n; i++ {
		output[i].Mul(&output[i], &cosetScale)
		cosetScale.Mul(&cosetScale, &d.coset.InvCosetGen)
	}
}
