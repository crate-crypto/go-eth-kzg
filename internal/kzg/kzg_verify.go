package kzg

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Proof to the claim that a polynomial f(x) was evaluated at a point `a` and
// resulted in `f(a)`
type OpeningProof struct {
	// H quotient polynomial (f - f(a))/(x-a)
	QuotientComm bls12381.G1Affine

	// Point that we are evaluating the polynomial at : `a`
	InputPoint fr.Element

	// ClaimedValue purported value : `f(a)`
	ClaimedValue fr.Element
}

// Verify a KZG proof
//
// Copied from gnark-crypto with minor modifications
func Verify(commitment *Commitment, proof *OpeningProof, open_key *OpeningKey) error {

	// [f(a)]G₁
	var claimedValueG1Aff bls12381.G1Jac
	var claimedValueBigInt big.Int
	proof.ClaimedValue.BigInt(&claimedValueBigInt)
	claimedValueG1Aff.ScalarMultiplicationAffine(&open_key.GenG1, &claimedValueBigInt)

	// [f(α) - f(a)]G₁
	var fminusfaG1Jac bls12381.G1Jac
	fminusfaG1Jac.FromAffine(commitment)
	fminusfaG1Jac.SubAssign(&claimedValueG1Aff)

	// [-H(α)]G₁
	var negH bls12381.G1Affine
	negH.Neg(&proof.QuotientComm)

	// [α-a]G₂
	var alphaMinusaG2Jac, genG2Jac, alphaG2Jac bls12381.G2Jac
	var pointBigInt big.Int
	proof.InputPoint.BigInt(&pointBigInt)
	genG2Jac.FromAffine(&open_key.GenG2)
	alphaG2Jac.FromAffine(&open_key.AlphaG2)
	alphaMinusaG2Jac.ScalarMultiplication(&genG2Jac, &pointBigInt).
		Neg(&alphaMinusaG2Jac).
		AddAssign(&alphaG2Jac)

	// [α-a]G₂
	var xminusaG2Aff bls12381.G2Affine
	xminusaG2Aff.FromJacobian(&alphaMinusaG2Jac)

	// [f(α) - f(a)]G₁
	var fminusfaG1Aff bls12381.G1Affine
	fminusfaG1Aff.FromJacobian(&fminusfaG1Jac)

	// e([f(α) - f(a)]G₁, G₂).e([-H(α)]G₁, [α-a]G₂) ==? 1
	check, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{fminusfaG1Aff, negH},
		[]bls12381.G2Affine{open_key.GenG2, xminusaG2Aff},
	)
	if err != nil {
		return err
	}
	if !check {
		return ErrVerifyOpeningProof
	}
	return nil
}

// Copied from gnark-crypto
func BatchVerifyMultiPoints(commitments []Commitment, proofs []OpeningProof, open_key *OpeningKey) error {

	// check consistency nb proofs vs nb commitments
	if len(commitments) != len(proofs) {
		return ErrInvalidNbDigests
	}

	// This is a change from gnark
	//
	// If there is nothing to verify, we return nil
	// to signal that verification was true
	// TODO: upstream change to gnark repo
	if len(commitments) == 0 {
		return nil
	}

	// if only one commitment, call Verify
	if len(commitments) == 1 {
		return Verify(&commitments[0], &proofs[0], open_key)
	}

	// sample random numbers for sampling
	randomNumbers := make([]fr.Element, len(commitments))
	randomNumbers[0].SetOne()
	for i := 1; i < len(randomNumbers); i++ {
		// TODO: check the difference between this
		// TODO and computing powers.
		// TODO Also check if we can use small numbers
		_, err := randomNumbers[i].SetRandom()
		if err != nil {
			return err
		}
	}

	// combine random_i*quotient_i
	var foldedQuotients bls12381.G1Affine
	quotients := make([]bls12381.G1Affine, len(proofs))
	for i := 0; i < len(randomNumbers); i++ {
		quotients[i].Set(&proofs[i].QuotientComm)
	}
	config := ecc.MultiExpConfig{}
	_, err := foldedQuotients.MultiExp(quotients, randomNumbers, config)
	if err != nil {
		return nil
	}

	// fold commitments and evals
	evals := make([]fr.Element, len(commitments))
	for i := 0; i < len(randomNumbers); i++ {
		evals[i].Set(&proofs[i].ClaimedValue)
	}
	foldedCommitments, foldedEvals, err := fold(commitments, evals, randomNumbers)
	if err != nil {
		return err
	}

	// compute commitment to folded Eval
	var foldedEvalsCommit bls12381.G1Affine
	var foldedEvalsBigInt big.Int
	foldedEvals.BigInt(&foldedEvalsBigInt)
	foldedEvalsCommit.ScalarMultiplication(&open_key.GenG1, &foldedEvalsBigInt)

	// compute F = foldedCommitments - foldedEvalsCommit
	foldedCommitments.Sub(&foldedCommitments, &foldedEvalsCommit)

	// combine random_i*(point_i*quotient_i)
	var foldedPointsQuotients bls12381.G1Affine
	for i := 0; i < len(randomNumbers); i++ {
		randomNumbers[i].Mul(&randomNumbers[i], &proofs[i].InputPoint)
	}
	_, err = foldedPointsQuotients.MultiExp(quotients, randomNumbers, config)
	if err != nil {
		return err
	}

	// lhs first pairing
	foldedCommitments.Add(&foldedCommitments, &foldedPointsQuotients)

	// lhs second pairing
	foldedQuotients.Neg(&foldedQuotients)

	// pairing check
	check, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{foldedCommitments, foldedQuotients},
		[]bls12381.G2Affine{open_key.GenG2, open_key.AlphaG2},
	)
	if err != nil {
		return err
	}
	if !check {
		return ErrVerifyOpeningProof
	}
	return nil

}
func BatchVerifyMultiPoints2(commitments []Commitment, QuotientComms []bls12381.G1Affine, inputPoints []fr.Element, claimedValues []fr.Element, open_key *OpeningKey) error {

	// check consistency nb proofs vs nb commitments
	if len(commitments) != len(QuotientComms) {
		return ErrInvalidNbDigests
	}

	// This is a change from gnark
	//
	// If there is nothing to verify, we return nil
	// to signal that verification was true
	// TODO: upstream change to gnark repo
	if len(commitments) == 0 {
		return nil
	}

	// if only one commitment, call Verify
	if len(commitments) == 1 {

		return Verify(&commitments[0], &OpeningProof{
			QuotientComm: QuotientComms[0],
			InputPoint:   inputPoints[0],
			ClaimedValue: claimedValues[0],
		}, open_key)
	}

	// sample random numbers for sampling
	randomNumbers := make([]fr.Element, len(commitments))
	randomNumbers[0].SetOne()
	for i := 1; i < len(randomNumbers); i++ {
		// TODO: check the difference between this
		// TODO and computing powers.
		// TODO Also check if we can use small numbers
		_, err := randomNumbers[i].SetRandom()
		if err != nil {
			return err
		}
	}

	// combine random_i*quotient_i
	var foldedQuotients bls12381.G1Affine
	quotients := make([]bls12381.G1Affine, len(QuotientComms))
	for i := 0; i < len(randomNumbers); i++ {
		quotients[i].Set(&QuotientComms[i])
	}
	config := ecc.MultiExpConfig{}
	_, err := foldedQuotients.MultiExp(quotients, randomNumbers, config)
	if err != nil {
		return nil
	}

	// fold commitments and evals
	evals := make([]fr.Element, len(commitments))
	for i := 0; i < len(randomNumbers); i++ {
		evals[i].Set(&claimedValues[i])
	}
	foldedCommitments, foldedEvals, err := fold(commitments, evals, randomNumbers)
	if err != nil {
		return err
	}

	// compute commitment to folded Eval
	var foldedEvalsCommit bls12381.G1Affine
	var foldedEvalsBigInt big.Int
	foldedEvals.BigInt(&foldedEvalsBigInt)
	foldedEvalsCommit.ScalarMultiplication(&open_key.GenG1, &foldedEvalsBigInt)

	// compute F = foldedCommitments - foldedEvalsCommit
	foldedCommitments.Sub(&foldedCommitments, &foldedEvalsCommit)

	// combine random_i*(point_i*quotient_i)
	var foldedPointsQuotients bls12381.G1Affine
	for i := 0; i < len(randomNumbers); i++ {
		randomNumbers[i].Mul(&randomNumbers[i], &inputPoints[i])
	}
	_, err = foldedPointsQuotients.MultiExp(quotients, randomNumbers, config)
	if err != nil {
		return err
	}

	// lhs first pairing
	foldedCommitments.Add(&foldedCommitments, &foldedPointsQuotients)

	// lhs second pairing
	foldedQuotients.Neg(&foldedQuotients)

	// pairing check
	check, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{foldedCommitments, foldedQuotients},
		[]bls12381.G2Affine{open_key.GenG2, open_key.AlphaG2},
	)
	if err != nil {
		return err
	}
	if !check {
		return ErrVerifyOpeningProof
	}
	return nil

}

// Copied from gnark-crypto
func fold(commitments []Commitment, evaluations []fr.Element, factors []fr.Element) (Commitment, fr.Element, error) {

	// length inconsistency between commitments and evaluations should have been done before calling this function
	nbCommitments := len(commitments)

	// fold the claimed values
	var foldedEvaluations, tmp fr.Element
	for i := 0; i < nbCommitments; i++ {
		tmp.Mul(&evaluations[i], &factors[i])
		foldedEvaluations.Add(&foldedEvaluations, &tmp)
	}

	// fold the commitments
	var foldedCommitments Commitment
	_, err := foldedCommitments.MultiExp(commitments, factors, ecc.MultiExpConfig{})
	if err != nil {
		return foldedCommitments, foldedEvaluations, err
	}

	// folding done
	return foldedCommitments, foldedEvaluations, nil
}
