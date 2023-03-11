package kzg

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Create a KZG proof that a polynomial f(x) when evaluated at a point `a` is equal to `f(a)`
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

	res.QuotientComm.Set(quotientCommit)

	return res, nil
}

// Computes q(X) = f(X) - f(a) / X - a in lagrange form.
//
// We refer to q(X) as the quotient polynomial.
//
// The division needs to be handled differently if `a` is an element in the domain
// as this means that one needs to divide by 0. Hence, you will observe that this function
// will follow a different code-path depending on this condition.
//
// Note: Since compute f(a) necessitates one knowing whether `a` is in the domain,
// this function accepts an `indexInDomain` value which will tell us the index of the
// element if it is in the domain. See `evaluateLagrangePolynomial`
func computeQuotientPoly(domain Domain, f Polynomial, indexInDomain int, fa, a fr.Element) ([]fr.Element, error) {
	if domain.Cardinality != uint64(len(f)) {
		return nil, ErrPolynomialMismatchedSizeDomain
	}

	if indexInDomain != -1 {
		// Note: the uint64 conversion is both semantically correct and safer
		// than accepting an `int``, since we know it shouldn't be negative
		// and it should cause a panic, if not checked; uint64(-1) = 2^64 -1
		return computeQuotientPolyOnDomain(domain, f, uint64(indexInDomain))
	}

	return computeQuotientPolyOutsideDomain(domain, f, fa, a)
}

// Computes q(X) = f(X) - f(a) / X - a in lagrange form where `a` is not in the domain.
//
// This function then performs division of two polynomials in evaluation form in the usual way.
func computeQuotientPolyOutsideDomain(domain Domain, f Polynomial, fa, a fr.Element) ([]fr.Element, error) {

	// Compute the lagrange form the of the numerator f(X) - f(a)
	// Since f is already in lagrange form, we can compute f(X) - f(a)
	// by shifting all elements in f(X) by f(a)
	numerator := make([]fr.Element, len(f))
	for i := 0; i < len(f); i++ {
		numerator[i].Sub(&f[i], &fa)
	}

	// Compute the lagrange form of the denominator X - a
	// and invert all of the evaluations, since it is the
	// denominator, we do a batch inversion.
	denominator := make([]fr.Element, len(f))
	for i := 0; i < len(f); i++ {
		denominator[i].Sub(&domain.Roots[i], &a)
	}
	// Since `a` is not in the domain, we are sure that there
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

// Computes f(X) - f(a) / X - a in lagrange form where `a` is in the domain
//
// [compute_quotient_eval_within_domain](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#compute_quotient_eval_within_domain)
func computeQuotientPolyOnDomain(domain Domain, f Polynomial, index uint64) ([]fr.Element, error) {
	y := f[index]
	z := domain.Roots[index]
	invZ := domain.PreComputedInverses[index]

	rootsMinusZ := make([]fr.Element, domain.Cardinality)
	for i := 0; i < int(domain.Cardinality); i++ {
		rootsMinusZ[i].Sub(&domain.Roots[i], &z)
	}
	invRootsMinusZ := fr.BatchInvert(rootsMinusZ)

	quotientPoly := make([]fr.Element, domain.Cardinality)
	for j := 0; j < int(domain.Cardinality); j++ {
		// check if we are on the current root of unity
		if uint64(j) == index {
			continue
		}

		// Compute q_j = f_j / w^j - w^m
		//
		//
		var q_j fr.Element
		// TODO: this can be confusing since f_j = f[j] - y
		q_j.Sub(&f[j], &y)
		q_j.Mul(&q_j, &invRootsMinusZ[j])
		quotientPoly[j] = q_j

		// Compute the j'th term in q_m denoted `q_m_j``
		// q_m_j = (f_j / w^m - w^j) * (w^j/w^m) , where w^m = z
		//		 = - q_j * w^{j-m}
		//
		// We _could_ find w^{j-m} via a lookup table
		// but we want to avoid lookup tables because
		// the roots are permuted/reversed which can make the
		// code less intuitive.
		var q_m_j fr.Element
		q_m_j.Neg(&q_j)
		q_m_j.Mul(&q_m_j, &domain.Roots[j])
		q_m_j.Mul(&q_m_j, &invZ)

		quotientPoly[index].Add(&quotientPoly[index], &q_m_j)
	}

	return quotientPoly, nil
}
