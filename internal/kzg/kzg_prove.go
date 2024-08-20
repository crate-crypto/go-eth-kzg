package kzg

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/poly"
)

// Open verifies that a polynomial f(x) when evaluated at a point `z` is equal to `f(z)`
//
// numGoRoutines is used to configure the amount of concurrency needed. Setting this
// value to a negative number or 0 will make it default to the number of CPUs.
func Open(domain *domain.Domain, polyCoeff []fr.Element, evaluationPoint fr.Element, ck *CommitKey, numGoRoutines int) (OpeningProof, error) {

	outputPoint := poly.PolyEval(polyCoeff, evaluationPoint)

	quotient := poly.DividePolyByXminusA(polyCoeff, evaluationPoint)

	comm, err := ck.Commit(quotient, 0)
	if err != nil {
		return OpeningProof{}, nil
	}

	return OpeningProof{
		QuotientCommitment: *comm,
		InputPoint:         evaluationPoint,
		ClaimedValue:       outputPoint,
	}, nil
}
