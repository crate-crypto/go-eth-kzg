package kzg

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Create a KZG proof that a polynomial f(x) when evaluated at a point `z` is equal to `f(z)`
//
// [compute_kzg_proof_impl](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#compute_kzg_proof_impl)
func Open(domain *Domain, p Polynomial, point fr.Element, ck *CommitKey) (OpeningProof, error) {
	if len(p) == 0 || len(p) > len(ck.G1) {
		return OpeningProof{}, ErrInvalidPolynomialSize
	}

	outputPoint, indexInDomain, err := domain.evaluateLagrangePolynomial(p, point)
	if err != nil {
		return OpeningProof{}, err
	}

	// Compute the quotient polynomial
	quotientPoly, err := computeQuotientPoly(*domain, p, indexInDomain, *outputPoint, point)
	if err != nil {
		return OpeningProof{}, err
	}

	// Commit to Quotient polynomial
	quotientCommit, err := Commit(quotientPoly, ck)
	if err != nil {
		return OpeningProof{}, err
	}

	res := OpeningProof{
		InputPoint:   point,
		ClaimedValue: *outputPoint,
	}

	res.QuotientCommitment.Set(quotientCommit)

	return res, nil
}

// Computes q(X) = f(X) - f(z) / X - z in lagrange form.
//
// We refer to q(X) as the quotient polynomial.
//
// The division needs to be handled differently if `z` is an element in the domain
// as this means that one needs to divide by 0. Hence, you will observe that this function
// will follow a different code-path depending on this condition.
//
// Note: Since compute f(z) necessitates one knowing whether `z` is in the domain,
// this function accepts an `indexInDomain` value which will tell us the index of the
// element if it is in the domain, see `evaluateLagrangePolynomial` for when `indexInDomain`
// is computed.
//
// The matching code for this method is in `compute_kzg_proof_impl` where the quotient polynomial
// is computed.
func computeQuotientPoly(domain Domain, f Polynomial, indexInDomain int, fz, z fr.Element) ([]fr.Element, error) {
	if domain.Cardinality != uint64(len(f)) {
		return nil, ErrPolynomialMismatchedSizeDomain
	}

	if indexInDomain != -1 {
		// Note: the uint64 conversion is both semantically correct and safer
		// than accepting an `int``, since we know it shouldn't be negative
		// and it should cause a panic, if not checked; uint64(-1) = 2^64 -1
		return computeQuotientPolyOnDomain(domain, f, uint64(indexInDomain))
	}

	return computeQuotientPolyOutsideDomain(domain, f, fz, z)
}

// Computes q(X) = f(X) - f(z) / X - z in lagrange form where `z` is not in the domain.
//
// This function then performs division of two polynomials in evaluation form in the usual way.
func computeQuotientPolyOutsideDomain(domain Domain, f Polynomial, fz, z fr.Element) ([]fr.Element, error) {

	// Compute the lagrange form the of the numerator f(X) - f(z)
	// Since f(X) is already in lagrange form, we can compute f(X) - f(z)
	// by shifting all elements in f(X) by f(z)
	numerator := make([]fr.Element, len(f))
	for i := 0; i < len(f); i++ {
		numerator[i].Sub(&f[i], &fz)
	}

	// Compute the lagrange form of the denominator X - z
	// and invert all of the evaluations, since it is the
	// denominator, we do a batch inversion.
	denominator := make([]fr.Element, len(f))
	for i := 0; i < len(f); i++ {
		denominator[i].Sub(&domain.Roots[i], &z)
	}
	// Since `z` is not in the domain, we are sure that there
	// are no zeroes in this inversion.
	//
	// Note: even if there was a zero, the gnark-crypto library would skip
	// it and not panic.
	denominator = fr.BatchInvert(denominator)

	// Compute q(X)
	for i := 0; i < len(f); i++ {
		denominator[i].Mul(&denominator[i], &numerator[i])
	}

	return denominator, nil
}

// Computes f(X) - f(z) / X - z in lagrange form where `z` is in the domain.
//
// [compute_quotient_eval_within_domain](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#compute_quotient_eval_within_domain)
func computeQuotientPolyOnDomain(domain Domain, f Polynomial, index uint64) ([]fr.Element, error) {
	fz := f[index]
	z := domain.Roots[index]
	invZ := domain.PreComputedInverses[index]

	rootsMinusZ := make([]fr.Element, domain.Cardinality)
	for i := 0; i < int(domain.Cardinality); i++ {
		rootsMinusZ[i].Sub(&domain.Roots[i], &z)
	}
	// Since we know that `z` is in the domain, rootsMinusZ[index] will be zero.
	// We Set this value to `1` instead to compute the batch inversion.
	// Note: The underlying gnark-crypto library will not panic if
	// one of the elements is zero, but this is not common across libraries so we just set it to one.
	rootsMinusZ[index].SetOne()

	invRootsMinusZ := fr.BatchInvert(rootsMinusZ)

	quotientPoly := make([]fr.Element, domain.Cardinality)
	for j := 0; j < int(domain.Cardinality); j++ {
		// check if we are on the current root of unity
		if uint64(j) == index {
			continue
		}

		// Compute q_j = f_j / w^j - w^m
		//
		// Note: f_j is the numerator of the quotient polynomial ie f_j = f[j] - f(z)
		//
		//
		var q_j fr.Element
		q_j.Sub(&f[j], &fz)
		q_j.Mul(&q_j, &invRootsMinusZ[j])
		quotientPoly[j] = q_j

		// Compute the j'th term in q_m denoted `q_m_j`
		// q_m_j = (f_j / w^m - w^j) * (w^j/w^m) , where w^m = z
		//		 = - q_j * w^{j-m}
		//
		// We _could_ find 1 / w^{j-m} via a lookup table
		// but we want to avoid lookup tables because
		// the roots are bit-reversed which can make the
		// code less readable.
		var q_m_j fr.Element
		q_m_j.Neg(&q_j)
		q_m_j.Mul(&q_m_j, &domain.Roots[j])
		q_m_j.Mul(&q_m_j, &invZ)

		quotientPoly[index].Add(&quotientPoly[index], &q_m_j)
	}

	return quotientPoly, nil
}
