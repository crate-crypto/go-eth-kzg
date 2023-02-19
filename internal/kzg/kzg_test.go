package kzg

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestProofVerifySmoke(t *testing.T) {
	domain := NewDomain(4)
	srs, _ := NewSRSInsecure(*domain, big.NewInt(1234))

	// polynomial in lagrange form
	poly := []fr.Element{fr.NewElement(2), fr.NewElement(3), fr.NewElement(4), fr.NewElement(5)}

	comm, _ := Commit(poly, &srs.CommitKey)
	point := samplePointOutsideDomain(*domain)
	proof, _ := Open(domain, poly, *point, &srs.CommitKey)

	err := Verify(comm, &proof, &srs.OpeningKey)
	if err != nil {
		t.Error("proof down bad")
	}
}

func TestBatchVerifySmoke(t *testing.T) {
	domain := NewDomain(4)
	srs, _ := NewSRSInsecure(*domain, big.NewInt(1234))

	numProofs := 10

	commitments := make([]Commitment, numProofs)
	proofs := make([]OpeningProof, numProofs)
	for i := 0; i < numProofs; i++ {
		proof, comm := randValidOpeningProof(t, *domain, *srs)
		commitments = append(commitments, comm)
		proofs = append(proofs, proof)
	}
	err := BatchVerifyMultiPoints(commitments, proofs, &srs.OpeningKey)
	if err != nil {
		t.Fatalf(err.Error())
	}
	// Add an invalid proof, to ensure that it fails
	proof, _ := randValidOpeningProof(t, *domain, *srs)
	commitments = append(commitments, bls12381.G1Affine{})
	proofs = append(proofs, proof)
	err = BatchVerifyMultiPoints(commitments, proofs, &srs.OpeningKey)
	if err == nil {
		t.Fatalf("An invalid proof was added to the list, however verification returned true")
	}
}

func TestDivideOnDomainSmoke(t *testing.T) {

	// The polynomial in question is: f(x) =  x^2 + x
	f_x := func(x fr.Element) fr.Element {
		var tmp fr.Element
		tmp.Square(&x)
		tmp.Add(&tmp, &x)
		return tmp
	}

	// You need at least 3 evaluations to determine a degree 2 polynomial
	num_evaluations := 3
	domain := NewDomain(uint64(num_evaluations))

	// Elements are the evaluations of the polynomial over
	// `domain`
	polyLagrange := make([]fr.Element, domain.Cardinality)

	for i := 0; i < int(domain.Cardinality); i++ {
		var x = domain.Roots[i]
		polyLagrange[i] = f_x(x)
	}

	quotientLagrange, err := DividePolyByXminusAOnDomain(*domain, polyLagrange, 0)
	if err != nil {
		t.Error(err)
	}

	points := Points{}
	for k := 0; k < int(domain.Cardinality); k++ {
		var x = domain.Roots[k]

		point := Point{
			x: x,
			y: quotientLagrange[k],
		}
		points = append(points, point)
	}
	// TODO We can probably get rid of the interpolation and just evaluate on a
	// TODO random point outside of the domain to check for correctness
	// TODO We can additionally do it the "slow" way and test against that
	quotientCoeff := points.interpolate()

	// Lets do the same thing but in coefficient form
	// f(x) =  x^2 + x - f(w^0)
	var minusPoly0 fr.Element
	minusPoly0.Neg(&polyLagrange[0])
	poly_coeff_numerator := []fr.Element{minusPoly0, fr.NewElement(1), fr.NewElement(1)}
	// g(x) = X - w^0
	var minusRoot fr.Element
	minusRoot.Neg(&domain.Roots[0])
	poly_coeff_denominator := []fr.Element{minusRoot, fr.NewElement(1)}
	gotQuotient, gotRem, ok := pld(poly_coeff_numerator, poly_coeff_denominator)
	if !ok {
		t.Fatalf("polynomial division was not successful")
	}
	for _, x := range gotRem {
		if !x.IsZero() {
			panic("remainder should be zero")
		}
	}

	evalPoint := fr.NewElement(100)

	num := Poly(poly_coeff_numerator).evaluate(evalPoint)
	den := Poly(poly_coeff_denominator).evaluate(evalPoint)
	var eval fr.Element
	eval.Div(&num, &den)
	// evalPoint := RandomScalarNotInDomain(t, *domain)
	a := Poly(gotQuotient).evaluate(evalPoint)
	b_a := quotientCoeff.evaluate(evalPoint)
	b, _, _ := EvaluateLagrangePolynomial(domain, quotientLagrange, evalPoint)

	if !b_a.Equal(b) {
		t.Fatalf("b's are not the same")
	}
	if !a.Equal(&eval) {
		t.Fatalf("a : computed quotient polynomial is incorrect")
	}
	if !eval.Equal(b) {
		t.Fatalf("b: computed quotient polynomial is incorrect")
	}

}

func DividePolyByXminusAOnDomainSlow(domain Domain, f Polynomial, index uint64) ([]fr.Element, error) {
	quotient := make([]fr.Element, len(f))
	z := domain.Roots[index]
	y, _, err := EvaluateLagrangePolynomial(&domain, f, z)
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
	var poly []fr.Element
	for i := 0; i < int(domain.Cardinality); i++ {
		var randFr = RandomScalarNotInDomain(t, domain)
		poly = append(poly, randFr)
	}
	comm, _ := Commit(poly, &srs.CommitKey)
	point := samplePointOutsideDomain(domain)
	proof, _ := Open(&domain, poly, *point, &srs.CommitKey)
	return proof, *comm
}

func RandomScalarNotInDomain(t *testing.T, domain Domain) fr.Element {
	var randFr fr.Element
	for {
		_, err := randFr.SetRandom()
		if err != nil {
			t.Fatalf("could not generate a random integer %s", err.Error())
		}
		if !domain.isInDomain(randFr) {
			break
		}
	}
	return randFr
}

// The interpolation is only needed for tests,
// but we need to make sure it is correct.
func TestBasicInterpolate(testing *testing.T) {

	// These two points define the polynomial y = X
	// Once we interpolate the polynomial, any point
	// we evalate the polynomial at, should return the point
	point_a := Point{
		x: fr.NewElement(0),
		y: fr.NewElement(0),
	}
	point_b := Point{
		x: fr.One(),
		y: fr.One(),
	}
	points := Points{point_a, point_b}
	poly := points.interpolate()

	var rand_fr fr.Element
	_, err := rand_fr.SetRandom()
	if err != nil {
		panic("could not generate a random element")
	}
	result := poly.evaluate(rand_fr)

	if !result.Equal(&rand_fr) {
		panic("result should be rand_fr, because the polynomial should be the identity polynomial")
	}
}

// The code below is solely used to create the coefficient form
// of the polynomials, so that we can test against monomial form.

type Point struct {
	x fr.Element
	y fr.Element
}

type Points []Point

type Poly []fr.Element

func (poly Poly) evaluate(point fr.Element) fr.Element {
	powers := powersOf(point, len(poly))
	total := fr.NewElement(0)
	for i := 0; i < len(poly); i++ {
		var tmp fr.Element
		tmp.Mul(&powers[i], &poly[i])
		total.Add(&total, &tmp)
	}
	return total
}
func (points Points) interpolate() Poly {
	one := fr.One()
	zero := fr.NewElement(0)

	max_degree_plus_one := len(points)
	if max_degree_plus_one < 2 {
		panic("should interpolate for degree >= 1")
	}
	coeffs := make([]fr.Element, max_degree_plus_one)

	for k := 0; k < len(points); k++ {
		point := points[k]
		x_k := point.x
		y_k := point.y

		contribution := make([]fr.Element, max_degree_plus_one)
		denominator := fr.One()
		max_contribution_degree := 0
		for j := 0; j < len(points); j++ {
			point := points[j]
			x_j := point.x
			if j == k {
				continue
			}

			diff := x_k
			diff.Sub(&diff, &x_j)
			denominator.Mul(&denominator, &diff)
			if max_contribution_degree == 0 {

				max_contribution_degree = 1
				contribution[0].Sub(&contribution[0], &x_j)
				contribution[1].Add(&contribution[1], &one)

			} else {
				var mul_by_minus_x_j []fr.Element
				for _, el := range contribution {
					tmp := el
					tmp.Mul(&tmp, &x_j)
					tmp.Sub(&zero, &tmp)
					mul_by_minus_x_j = append(mul_by_minus_x_j, tmp)
				}
				contribution = append([]fr.Element{zero}, contribution...)
				contribution = truncate(contribution, max_degree_plus_one)
				if max_degree_plus_one != len(mul_by_minus_x_j) {
					panic("malformed mul_by_minus_x_j")
				}
				for i := 0; i < len(contribution); i++ {
					other := mul_by_minus_x_j[i]
					contribution[i].Add(&contribution[i], &other)
				}

			}

		}
		denominator.Inverse(&denominator)
		if denominator.IsZero() {
			panic("denominator should not be zero")
		}
		for i := 0; i < len(contribution); i++ {
			tmp := contribution[i]
			tmp.Mul(&tmp, &denominator)
			tmp.Mul(&tmp, &y_k)
			coeffs[i].Add(&coeffs[i], &tmp)
		}

	}
	return coeffs
}

func truncate(s []fr.Element, to int) []fr.Element {
	return s[:to]
}

func degree(p []fr.Element) int {
	for d := len(p) - 1; d >= 0; d-- {

		if !p[d].IsZero() {
			return d
		}
	}
	return -1
}

// Taken from https://rosettacode.org/wiki/Polynomial_long_division#Go
func pld(nn, dd []fr.Element) (q, r []fr.Element, ok bool) {
	if degree(dd) < 0 {
		return
	}
	nn = append(r, nn...)
	if degree(nn) >= degree(dd) {
		q = make([]fr.Element, degree(nn)-degree(dd)+1)
		for degree(nn) >= degree(dd) {
			d := make([]fr.Element, degree(nn)+1)
			copy(d[degree(nn)-degree(dd):], dd)
			var tmp fr.Element
			tmp.Div(&nn[degree(nn)], &d[degree(d)])
			q[degree(nn)-degree(dd)] = tmp
			for i := range d {
				d[i].Mul(&d[i], &q[degree(nn)-degree(dd)])
				nn[i].Sub(&nn[i], &d[i])
			}
		}
	}
	return q, nn, true
}

// Returns powers of x from 0 to degree-1
// <1, x, x^2, x^3, x^4,...,x^(degree-1)>
func powersOf(x fr.Element, degree int) []fr.Element {
	result := make([]fr.Element, degree)
	result[0] = fr.One()

	for i := 1; i < degree; i++ {
		result[i].Mul(&result[i-1], &x)
	}

	return result
}
