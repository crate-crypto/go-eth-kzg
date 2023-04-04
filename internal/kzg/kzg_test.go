package kzg

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

func TestProofVerifySmoke(t *testing.T) {
	domain := NewDomain(4)
	srs, _ := newLagrangeSRSInsecure(*domain, big.NewInt(1234))

	// polynomial in lagrange form
	poly := []fr.Element{fr.NewElement(2), fr.NewElement(3), fr.NewElement(4), fr.NewElement(5)}

	comm, _ := Commit(poly, &srs.CommitKey)
	point := samplePointOutsideDomain(*domain)
	proof, _ := Open(domain, poly, *point, &srs.CommitKey)

	err := Verify(comm, &proof, &srs.OpeningKey)
	if err != nil {
		t.Error("proof failed to verify")
	}
}

func TestBatchVerifySmoke(t *testing.T) {
	domain := NewDomain(4)
	srs, _ := newLagrangeSRSInsecure(*domain, big.NewInt(1234))

	numProofs := 10
	commitments := make([]Commitment, 0, numProofs)
	proofs := make([]OpeningProof, 0, numProofs)
	for i := 0; i < numProofs-1; i++ {
		proof, commitment := randValidOpeningProof(t, *domain, *srs)
		commitments = append(commitments, commitment)
		proofs = append(proofs, proof)
	}

	// Check that these verify successfully.
	err := BatchVerifyMultiPoints(commitments, proofs, &srs.OpeningKey)
	require.NoError(t, err)

	// Add an invalid proof, to ensure that it fails
	proof, _ := randValidOpeningProof(t, *domain, *srs)
	commitments = append(commitments, bls12381.G1Affine{})
	proofs = append(proofs, proof)
	err = BatchVerifyMultiPoints(commitments, proofs, &srs.OpeningKey)
	require.Error(t, err, "An invalid proof was added to the list, however verification returned true")
}

func TestComputeQuotientPolySmoke(t *testing.T) {
	numEvaluations := 128
	domain := NewDomain(uint64(numEvaluations))

	polyLagrange := randPoly(t, *domain)

	polyEqual := func(lhs, rhs []fr.Element) bool {
		for i := 0; i < int(domain.Cardinality); i++ {
			if !lhs[i].Equal(&rhs[i]) {
				return false
			}
		}
		return true
	}

	// Compute quotient for all values on the domain
	for i := 0; i < int(domain.Cardinality); i++ {
		computedQuotientLagrange, err := domain.computeQuotientPolyOnDomain(polyLagrange, uint64(i))
		if err != nil {
			t.Error(err)
		}
		expectedQuotientLagrange, err := computeQuotientPolySlow(*domain, polyLagrange, domain.Roots[i])
		if err != nil {
			t.Error(err)
		}

		for i := 0; i < int(domain.Cardinality); i++ {
			if !polyEqual(computedQuotientLagrange, expectedQuotientLagrange) {
				t.Errorf("computed lagrange polynomial differs from the expected polynomial")
			}
		}
	}

	// Compute quotient polynomial for values not in the domain
	numRandomEvaluations := 10

	for i := 0; i < numRandomEvaluations; i++ {
		inputPoint := randomScalarNotInDomain(t, *domain)
		claimedValue, _ := domain.EvaluateLagrangePolynomial(polyLagrange, inputPoint)
		gotQuotientPoly, err := domain.computeQuotientPolyOutsideDomain(polyLagrange, *claimedValue, inputPoint)
		if err != nil {
			t.Error(err)
		}
		expectedQuotientPoly, err := computeQuotientPolySlow(*domain, polyLagrange, inputPoint)
		if err != nil {
			t.Error(err)
		}

		if !polyEqual(gotQuotientPoly, expectedQuotientPoly) {
			t.Errorf("computed lagrange polynomial differs from the expected polynomial")
		}
	}
}

// This is the way it is done in the consensus-specs
func computeQuotientPolySlow(domain Domain, f Polynomial, z fr.Element) ([]fr.Element, error) {
	quotient := make([]fr.Element, len(f))
	y, err := domain.EvaluateLagrangePolynomial(f, z)
	if err != nil {
		panic(err)
	}
	polyShifted := make([]fr.Element, len(f))
	for i := 0; i < len(f); i++ {
		polyShifted[i].Sub(&f[i], y)
	}

	denominatorPoly := make([]fr.Element, len(f))
	for i := 0; i < len(f); i++ {
		denominatorPoly[i].Sub(&domain.Roots[i], &z)
	}

	for i := 0; i < len(f); i++ {
		a := polyShifted[i]
		b := denominatorPoly[i]
		if b.IsZero() {
			quotient[i] = compute_quotient_eval_within_domain(domain, domain.Roots[i], f, *y)
		} else {
			quotient[i].Div(&a, &b)
		}
	}

	return quotient, nil
}

func compute_quotient_eval_within_domain(domain Domain, z fr.Element, polynomial []fr.Element, y fr.Element) fr.Element {
	var result fr.Element
	for i := 0; i < int(domain.Cardinality); i++ {
		omega_i := domain.Roots[i]
		if omega_i.Equal(&z) {
			continue
		}
		var f_i fr.Element
		f_i.Sub(&polynomial[i], &y)
		var numerator fr.Element
		numerator.Mul(&f_i, &omega_i)
		var denominator fr.Element
		denominator.Sub(&z, &omega_i)
		denominator.Mul(&denominator, &z)

		var tmp fr.Element
		tmp.Div(&numerator, &denominator)

		result.Add(&result, &tmp)
	}

	return result
}

func randValidOpeningProof(t *testing.T, domain Domain, srs SRS) (OpeningProof, Commitment) {
	poly := randPoly(t, domain)
	comm, _ := Commit(poly, &srs.CommitKey)
	point := samplePointOutsideDomain(domain)
	proof, _ := Open(&domain, poly, *point, &srs.CommitKey)
	return proof, *comm
}

func randPoly(t *testing.T, domain Domain) []fr.Element {
	var poly []fr.Element
	for i := 0; i < int(domain.Cardinality); i++ {
		randFr := randomScalarNotInDomain(t, domain)
		poly = append(poly, randFr)
	}
	return poly
}

func randomScalarNotInDomain(t *testing.T, domain Domain) fr.Element {
	var randFr fr.Element
	for {
		_, err := randFr.SetRandom()
		if err != nil {
			t.Fatalf("could not generate a random integer %s", err.Error())
		}
		if domain.findRootIndex(randFr) == -1 {
			break
		}
	}
	return randFr
}
