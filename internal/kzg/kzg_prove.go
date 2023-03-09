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

	res := OpeningProof{
		InputPoint:   point,
		ClaimedValue: *outputPoint,
	}

	// compute the quotient polynomial
	quotientPoly, err := dividePolyByXminusA(*domain, p, indexInDomain, res.ClaimedValue, point)
	if err != nil {
		return OpeningProof{}, err
	}

	// commit to Quotient polynomial
	quotientCommit, err := Commit(quotientPoly, ck)
	if err != nil {
		return OpeningProof{}, err
	}
	res.QuotientComm.Set(quotientCommit)

	return res, nil
}

// dividePolyByXminusA computes (f-f(a))/(x-a)
// TODO rename: DividePolyByLinearOnDomain or DividePolyByLinearVanishing
func dividePolyByXminusA(domain Domain, f Polynomial, indexInDomain int, fa, a fr.Element) ([]fr.Element, error) {
	if domain.Cardinality != uint64(len(f)) {
		return nil, ErrPolynomialMismatchedSizeDomain
	}

	if indexInDomain != -1 {
		return dividePolyByXminusAOnDomain(domain, f, uint64(indexInDomain))
	}

	return dividePolyByXminusAOutsideDomain(domain, f, fa, a)
}

func dividePolyByXminusAOutsideDomain(domain Domain, f Polynomial, fa, a fr.Element) ([]fr.Element, error) {
	// first we compute f-f(a)
	numer := make([]fr.Element, len(f))
	for i := 0; i < len(f); i++ {
		numer[i].Sub(&f[i], &fa)
	}

	// Now compute 1/(roots - a)
	denom := make([]fr.Element, len(f))
	for i := 0; i < len(f); i++ {
		denom[i].Sub(&domain.Roots[i], &a)
	}
	denom = fr.BatchInvert(denom)

	for i := 0; i < len(f); i++ {
		denom[i].Mul(&denom[i], &numer[i])
	}

	return denom, nil
}

// Divides by X-w^m when w^m is in the domain.
// [compute_quotient_eval_within_domain](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#compute_quotient_eval_within_domain)
func dividePolyByXminusAOnDomain(domain Domain, f Polynomial, index uint64) ([]fr.Element, error) {
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
