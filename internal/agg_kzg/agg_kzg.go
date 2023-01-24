package agg_kzg

import (
	"errors"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/fiatshamir"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/multiexp"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

// Proof to the claim that for i \in n , polynomials f_i(x) were evaluated at a point `a` and
// resulted in `f_i(a)`
type BatchOpeningProof struct {
	// H quotient polynomial \sum (f_i - f_i(a))/(x-a)
	QuotientComm curve.G1Affine

	// Commitment for each polynomial in the proof
	Commitments []kzg.Commitment
}

func CommitToPolynomials(polynomials []kzg.Polynomial, commitKey *kzg.CommitKey) ([]kzg.Commitment, error) {
	// TODO: Add a go-routine to do this in parallel
	comms := make([]kzg.Commitment, len(polynomials))
	for i := 0; i < len(polynomials); i++ {
		comm, err := kzg.Commit(polynomials[i], commitKey)
		if err != nil {
			return nil, err
		}
		comms[i] = *comm
	}
	return comms, nil
}

// Modified function from gnark
func BatchOpenSinglePoint(domain *kzg.Domain, polynomials []kzg.Polynomial, commitKey *kzg.CommitKey) (*BatchOpeningProof, error) {
	// 1. Commit to polynomials
	//
	commitments, err := CommitToPolynomials(polynomials, commitKey)
	if err != nil {
		return nil, err
	}

	// 2. Correctness checks on polynomials and commitments
	//
	err = correctnessChecks(domain, polynomials, commitments)
	if err != nil {
		return nil, err
	}

	// 3. Compute the challenges needed. This is one round protocol, so all challenges to be computed
	// are done here
	vandermondeChallenges, evaluationChallenge := computeChallenges(commitments, polynomials)

	// 4. Aggregate the polynomials using powers of the first challenge generated
	//
	// The prover does not need to compute the aggregated commitment like the verifier does
	foldedPoly, err := foldPolynomials(polynomials, vandermondeChallenges)
	if err != nil {
		return nil, err
	}

	// 5. Open the aggregated polynomial at the `evaluationChallenge` point
	// This method will implicitly evaluate the polynomial, simply because the prover/opener usually
	// has the polynomial to open. It is not usually the case that the verifier has the polynomial at hand
	// so kzg.Verify does not implicitly evaluate the polynomial.
	singlePointProof, err := kzg.Open(domain, foldedPoly, evaluationChallenge, commitKey)
	if err != nil {
		return nil, err
	}

	return &BatchOpeningProof{
		QuotientComm: singlePointProof.QuotientComm,
		Commitments:  commitments,
	}, nil
}

func VerifyBatchOpen(domain *kzg.Domain, polynomials []kzg.Polynomial, proof *BatchOpeningProof, open_key *kzg.OpeningKey) error {
	// 1. Correctness checks on polynomials and commitments
	//
	err := correctnessChecks(domain, polynomials, proof.Commitments)
	if err != nil {
		return err
	}

	// 2. Compute the challenges needed. This is one round protocol, so all challenges to be computed
	// are done here
	vandermondeChallenges, evaluationChallenge := computeChallenges(proof.Commitments, polynomials)

	// 3. Aggregate the polynomials and commitments using powers of the first challenge generated
	foldedPoly, err := foldPolynomials(polynomials, vandermondeChallenges)
	if err != nil {
		return err
	}
	foldedComm, err := foldCommitments(proof.Commitments, vandermondeChallenges)
	if err != nil {
		return err
	}

	// 4. Evaluate the aggregated polynomial at the random evaluation point
	// This is the second point generated
	outputPoint, err := kzg.EvaluateLagrangePolynomial(domain, foldedPoly, evaluationChallenge)
	if err != nil {
		return err
	}

	// 5. Verify the KZG opening proof
	openingProof := &kzg.OpeningProof{
		QuotientComm: proof.QuotientComm,
		InputPoint:   evaluationChallenge,
		ClaimedValue: *outputPoint,
	}
	return kzg.Verify(foldedComm, openingProof, open_key)
}

func computeChallenges(points []curve.G1Affine, polynomials [][]fr.Element) ([]fr.Element, fr.Element) {
	transcript := fiatshamir.NewTranscript(DOM_SEP_PROTOCOL)
	transcript.AppendPointsPolys(points, polynomials)

	// Generate two challenges:
	// 1) To aggregate multiple polynomials/points into one using a linear combination
	// 2) To open the aggregated polynomial at
	numChallengesNeeded := uint8(2)
	challenges := transcript.ChallengeScalars(numChallengesNeeded)

	linearCombinationChallenge := challenges[0]
	evaluationChallenge := challenges[1]

	numPolynomials := uint(len(polynomials))
	vandermondeChallenges := utils.ComputePowers(linearCombinationChallenge, numPolynomials)

	return vandermondeChallenges, evaluationChallenge
}

func correctnessChecks(domain *kzg.Domain, polynomials []kzg.Polynomial, digests []kzg.Commitment) error {
	numPolynomials := len(polynomials)

	// In the case, that there are no polynomials, we return an error
	if numPolynomials == 0 {
		return errors.New("cannot create a batch opening proof with no polynomials")
	}

	// Check that all polynomials have the same length
	currentPolyLength := len(polynomials[0])
	for i := 0; i < numPolynomials; i++ {
		if currentPolyLength != len(polynomials[i]) {
			return errors.New("all polynomials must be the same length")
		}
	}

	// Check that all of the polynomials are the same size as the domain
	if domain.Cardinality != uint64(currentPolyLength) {
		return errors.New("domain must be the same size as the number of evaluations in each polynomial")
	}

	// Check that each polynomial has an associated commitment
	numComms := len(digests)
	if numComms != numPolynomials {
		return kzg.ErrInvalidNbDigests
	}

	return nil
}

func foldPolynomials(polynomials []kzg.Polynomial, challenges []fr.Element) (kzg.Polynomial, error) {
	numPolynomials := len(polynomials)
	numChallenges := len(challenges)

	if numPolynomials != numChallenges {
		return nil, errors.New("number of polynomials is different to the number of challenges provided")
	}

	result := make(kzg.Polynomial, len(polynomials[0]))
	// This copy assumes that the first challenge is 1
	// TODO: can add an assert here, which may be fine because if this is changed
	// TODO: it will break tests at compile time
	copy(result, polynomials[0])

	var pj fr.Element
	for i := 1; i < numPolynomials; i++ {
		for j := 0; j < len(result); j++ {
			pj.Mul(&polynomials[i][j], &challenges[i])
			result[j].Add(&result[j], &pj)
		}
	}

	return result, nil
}

// Note: We can compute this aggregate commitment by committing to the aggregate poly
// or doing a linear combination of the individual polynomial commitments
// The first will be a MSM where the size is the length of the largest polynomial
// The second will be an MSM where the size is the number of polynomials
// The second will therefore be cheaper in all cases for the usage of this lib
func foldCommitments(commitments []kzg.Commitment, challenges []fr.Element) (*kzg.Commitment, error) {
	if len(commitments) != len(challenges) {
		return nil, errors.New("incorrect number of commitments or challenges")
	}

	foldedComm, err := multiexp.MultiExp(challenges, commitments)
	if err != nil {
		return nil, err
	}

	return foldedComm, nil
}
