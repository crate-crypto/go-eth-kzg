package domain

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/utils"
)

// Computes an FFT (Fast Fourier Transform) of the G1 elements in-place.
//
// The elements are returned in order as opposed to being returned in
// bit-reversed order.
func (domain *Domain) FftG1(values []bls12381.G1Affine, numGoRoutines int) {
	fftG1InPlace(values, domain.Generator, numGoRoutines)
}

// Computes an IFFT(Inverse Fast Fourier Transform) of the G1 elements in-place.
//
// The elements are returned in order as opposed to being returned in
// bit-reversed order.
func (domain *Domain) IfftG1(values []bls12381.G1Affine, numGoRoutines int) {
	fftG1InPlace(values, domain.GeneratorInv, numGoRoutines)

	// Scale by the inverse of the domain size.
	var invDomainBI big.Int
	domain.CardinalityInv.BigInt(&invDomainBI)
	parallelizeG1(len(values), numGoRoutines, func(start, end int) {
		for i := start; i < end; i++ {
			values[i].ScalarMultiplication(&values[i], &invDomainBI)
		}
	})
}

// FftFr computes the FFT of the input values in-place
func (d *Domain) FftFr(values []fr.Element) {
	fftFrInPlace(values, d.Generator)
}

// IfftFr computes the inverse FFT of the input values in-place
func (d *Domain) IfftFr(values []fr.Element) {
	// In-place DIF using inverse generator
	fftFrInPlace(values, d.GeneratorInv)
	// scale by the inverse of the domain size
	for i := 0; i < len(values); i++ {
		values[i].Mul(&values[i], &d.CardinalityInv)
	}
}

func fftFrInPlace(values []fr.Element, nthRootOfUnity fr.Element) {
	n := len(values)
	if n <= 1 {
		return
	}

	for size := n; size >= 2; size >>= 1 {
		half := size >> 1

		// Compute wStep = root^(n/size)
		var wStep fr.Element
		wStep.Set(&nthRootOfUnity)
		for i := n / size; i > 1; i-- {
			wStep.Mul(&wStep, &nthRootOfUnity)
		}

		for start := 0; start < n; start += size {
			w := fr.One()
			for k := 0; k < half; k++ {
				i0 := start + k
				i1 := i0 + half

				// Gentleman–Sande butterfly
				var tmp fr.Element
				tmp.Sub(&values[i0], &values[i1])
				values[i0].Add(&values[i0], &values[i1])
				values[i1].Mul(&tmp, &w)

				w.Mul(&w, &wStep)
			}
		}
	}

	// Bit-reverse permutation to restore natural order
	BitReverse(values)
}

// fftG1InPlace computes an in-place Gentleman-Sande FFT of the G1 elements, using the
// given powers of the root of unity as twiddles. Input and output are both in natural
// order.
//
// The length of values must be a power of two; a non-power-of-two length silently
// misbehaves.
//
// Each butterfly costs a full scalar multiplication, which dominates everything else
// here, so two things matter: the butterflies of a single stage are independent and are
// spread across cores, and the transform runs in Jacobian coordinates so that only one
// batch conversion pays for an inversion rather than every individual addition.
func fftG1InPlace(values []bls12381.G1Affine, nthRootOfUnity fr.Element, numGoRoutines int) {
	n := len(values)
	if n <= 1 {
		return
	}

	// Twiddles are derived from the generator rather than read out of Domain.Roots.
	// Roots is mutable -- ReverseRoots bit-reverses it in place -- so indexing it as
	// roots[k*step] is only correct while the table happens to be in normal order, which
	// is not a property this transform should depend on.
	twiddles := make([]fr.Element, n/2)

	jac := make([]bls12381.G1Jac, n)
	parallelizeG1(n, numGoRoutines, func(start, end int) {
		for i := start; i < end; i++ {
			jac[i].FromAffine(&values[i])
		}
	})

	numButterflies := n / 2
	for size := n; size >= 2; size >>= 1 {
		half := size >> 1

		// Powers of the root of order `size`, built once per stage. This is a serial
		// chain of `half` field multiplications, which is nothing next to the scalar
		// multiplications the butterflies below perform.
		var stageRoot fr.Element
		stageRoot.Exp(nthRootOfUnity, big.NewInt(int64(n/size)))
		stageTwiddles := twiddles[:half]
		stageTwiddles[0].SetOne()
		for k := 1; k < half; k++ {
			stageTwiddles[k].Mul(&stageTwiddles[k-1], &stageRoot)
		}

		parallelizeG1(numButterflies, numGoRoutines, func(start, end int) {
			var tmp bls12381.G1Jac
			var twiddle big.Int
			for b := start; b < end; b++ {
				block, k := b/half, b%half
				i0 := block*size + k
				i1 := i0 + half

				tmp.Set(&jac[i0])
				tmp.SubAssign(&jac[i1])
				jac[i0].AddAssign(&jac[i1])

				// The k == 0 twiddle is one, so the multiplication is skipped.
				if k == 0 {
					jac[i1].Set(&tmp)
				} else {
					stageTwiddles[k].BigInt(&twiddle)
					jac[i1].ScalarMultiplication(&tmp, &twiddle)
				}
			}
		})
	}

	copy(values, bls12381.BatchJacobianToAffineG1(jac))
	BitReverse(values)
}

// parallelizeG1 splits [0, n) across at most numGoRoutines goroutines and waits.
//
// The G1 operations these bodies perform are expensive enough that the cost of starting a
// goroutine is irrelevant above a small threshold; below it the split is skipped.
//
// Note this bounds the goroutines *this package* starts. gnark-crypto does its own
// internal fan out in places -- BatchJacobianToAffineG1 spreads the batch conversion over
// runtime.NumCPU() regardless -- so a caller passing 1 still sees brief bursts of wider
// parallelism from the dependency. GOMAXPROCS is the only hard cap.
func parallelizeG1(n, numGoRoutines int, body func(start, end int)) {
	const minWorkPerGoRoutine = 4

	utils.Parallelize(n, numGoRoutines, minWorkPerGoRoutine, body)
}
