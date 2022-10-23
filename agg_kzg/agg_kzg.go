package agg_kzg

import (
	"errors"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/fiatshamir"
	"github.com/crate-crypto/go-proto-danksharding-crypto/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/multiexp"
	"github.com/crate-crypto/go-proto-danksharding-crypto/utils"
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
	transcript := fiatshamir.NewTranscript(DOM_SEP_AGG_PROTOCOL)

	commitments, err := CommitToPolynomials(polynomials, commitKey)
	if err != nil {
		return nil, err
	}

	err = correctnessChecks(domain, polynomials, commitments)
	if err != nil {
		return nil, err
	}

	// Generate challenge to combine multiple polynomials into one
	transcript.AppendPolynomials(polynomials)
	transcript.AppendPoints(commitments)
	challenge := transcript.ChallengeScalar()

	num_polynomials := uint(len(polynomials))
	challenges := utils.ComputePowers(challenge, num_polynomials)

	foldedPoly, foldedComm, err := foldPolyComms(polynomials, commitments, challenges)
	if err != nil {
		return nil, err
	}

	transcript.NewProtocol(DOM_SEP_EVAL_PROTOCOL)
	transcript.AppendPolynomial(foldedPoly)
	transcript.AppendPoint(*foldedComm)
	challenge_point := transcript.ChallengeScalar()

	// Open the folded polynomial
	singlePointProof, err := kzg.Open(domain, foldedPoly, challenge_point, commitKey)
	if err != nil {
		return nil, err
	}

	return &BatchOpeningProof{
		QuotientComm: singlePointProof.QuotientComm,
		Commitments:  commitments,
	}, nil
}

func VerifyBatchOpen(domain *kzg.Domain, polynomials []kzg.Polynomial, proof *BatchOpeningProof, open_key *kzg.OpeningKey) error {
	err := correctnessChecks(domain, polynomials, proof.Commitments)
	if err != nil {
		return err
	}

	transcript := fiatshamir.NewTranscript(DOM_SEP_AGG_PROTOCOL)

	transcript.AppendPolynomials(polynomials)
	transcript.AppendPoints(proof.Commitments)
	challenge := transcript.ChallengeScalar()

	num_polynomials := uint(len(polynomials))
	challenges := utils.ComputePowers(challenge, num_polynomials)

	foldedPoly, foldedComm, err := foldPolyComms(polynomials, proof.Commitments, challenges)
	if err != nil {
		return err
	}

	transcript.NewProtocol(DOM_SEP_EVAL_PROTOCOL)
	transcript.AppendPolynomial(foldedPoly)
	transcript.AppendPoint(*foldedComm)
	challenge_point := transcript.ChallengeScalar()

	output_point, err := kzg.EvaluateLagrangePolynomial(domain, foldedPoly, challenge_point)
	if err != nil {
		return err
	}

	open_proof := &kzg.OpeningProof{
		QuotientComm: proof.QuotientComm,
		InputPoint:   challenge_point,
		ClaimedValue: *output_point,
	}
	return kzg.Verify(foldedComm, open_proof, open_key)
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

func foldPolyComms(polynomials []kzg.Polynomial, comms []kzg.Commitment, challenges []fr.Element) (kzg.Polynomial, *kzg.Commitment, error) {

	foldedPoly, err := foldPolynomials(polynomials, challenges)
	if err != nil {
		return nil, nil, err
	}
	// Note: We can compute this aggregate commitment by committing to the aggregate poly
	// or doing a linear combination of the individual polynomial commitments
	// The first will be a MSM where the size is the length of the largest polynomial
	// The second will be an MSM where the size is the number of polynomials
	// The second will therefore be cheaper in all cases for the usage of this lib
	//
	foldedComm, err := foldCommitments(comms, challenges)
	if err != nil {
		return nil, nil, err
	}
	return foldedPoly, foldedComm, nil
}

func foldPolynomials(polynomials []kzg.Polynomial, challenges []fr.Element) (kzg.Polynomial, error) {
	num_polynomials := len(polynomials)
	num_challenges := len(challenges)

	if num_polynomials != num_challenges {
		return nil, errors.New("number of polynomials is different to the number of challenges provided")
	}

	result := make(kzg.Polynomial, len(polynomials[0]))
	copy(result, polynomials[0])

	var pj fr.Element
	for i := 1; i < num_polynomials; i++ {
		acc := challenges[i]
		for j := 0; j < len(result); j++ {
			pj.Mul(&polynomials[i][j], &acc)
			result[j].Add(&result[j], &pj)
		}

	}

	return result, nil
}

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
