package context

import (
	"errors"
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/agg_kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/utils"
)

type Context struct {
	domain    *kzg.Domain
	commitKey *kzg.CommitKey
	openKey   *kzg.OpeningKey
}

type SerialisedScalar = []byte
type SerialisedG1Point = []byte
type SerialisedPoly = []SerialisedScalar

// This is a misnomer, its KZGWitness
type KZGProof = SerialisedG1Point
type KZGCommitment = SerialisedG1Point
type SerialisedCommitments = []SerialisedG1Point

// These methods are used mainly for testing purposes.
// One should not need to use the domain/commitKey/OpeningKey directly
func (c *Context) Domain() kzg.Domain {
	return *c.domain
}
func (c *Context) CommitKey() kzg.CommitKey {
	return *c.commitKey
}
func (c *Context) OpenKeyKey() kzg.OpeningKey {
	return *c.openKey
}

func NewContextInsecure(polyDegree int, trustedSetupSecret int) *Context {
	secret := big.NewInt(int64(trustedSetupSecret))
	domain := kzg.NewDomain(uint64(polyDegree))

	srs, err := kzg.NewSRSInsecure(*domain, secret)
	if err != nil {
		panic(fmt.Sprintf("could not create context %s", err))
	}

	// Reverse the roots and the domain
	srs.CommitKey.ReversePoints()
	domain.ReverseRoots()

	return &Context{
		domain:    domain,
		commitKey: &srs.CommitKey,
		openKey:   &srs.OpeningKey,
	}
}

// Spec: compute_aggregate_kzg_proof
// Note: We additionally return the commitments
func (c *Context) ComputeAggregateKzgProof(serPolys []SerialisedPoly) (KZGProof, SerialisedCommitments, error) {

	// 1. Deserialise the polynomials
	polys, err := deserialisePolys(serPolys)
	if err != nil {
		return KZGProof{}, nil, err
	}

	// 2. Create batch opening proof
	proof, err := agg_kzg.BatchOpenSinglePoint(c.domain, polys, c.commitKey)
	if err != nil {
		return KZGProof{}, nil, err
	}

	// 3. Serialise points, so caller only needs to be concerned with
	// bytes
	serComms := serialiseCommitments(proof.Commitments)
	serProof := proof.QuotientComm.Bytes()

	return serProof[:], serComms, nil
}

func (c *Context) VerifyKZGProof(polynomialKZG KZGCommitment, z, y [32]byte, kzgProof KZGProof) error {
	polyComm, err := deserialisePoint(polynomialKZG)
	if err != nil {
		return err
	}

	quotientComm, err := deserialisePoint(kzgProof)
	if err != nil {
		return err
	}

	inputPoint, err := deserialiseScalar(z[:])
	if err != nil {
		return err
	}
	claimedValue, err := deserialiseScalar(y[:])
	if err != nil {
		return err
	}
	proof := kzg.OpeningProof{
		QuotientComm: quotientComm,
		InputPoint:   inputPoint,
		ClaimedValue: claimedValue,
	}
	return kzg.Verify(&polyComm, &proof, c.openKey)
}

// Specs: blob_to_kzg_commitment
func (c *Context) PolyToCommitments(serPolys []SerialisedPoly) (SerialisedCommitments, error) {
	// 1. Deserialise the polynomials
	polys, err := deserialisePolys(serPolys)
	if err != nil {
		return nil, err
	}

	// 2. Commit to polynomials
	comms, err := agg_kzg.CommitToPolynomials(polys, c.commitKey)
	if err != nil {
		return nil, err
	}

	// 3. Serialise commitments
	serComms := serialiseCommitments(comms)

	return serComms, nil
}

// Spec: verify_aggregate_kzg_proof
func (c *Context) VerifyAggregateKzgProof(serPolys []SerialisedPoly, serProof KZGProof, serComms SerialisedCommitments) error {
	// 1. Deserialise the polynomials
	polys, err := deserialisePolys(serPolys)
	if err != nil {
		return err
	}

	// 2. Deserialise the quotient commitment
	quotientComm, err := deserialisePoint(serProof)
	if err != nil {
		return err
	}

	// 3. Deserialise the polynomial commitments
	comms, err := deserialiseComms(serComms)
	if err != nil {
		return err
	}

	agg_proof := &agg_kzg.BatchOpeningProof{
		QuotientComm: quotientComm,
		Commitments:  comms,
	}
	return agg_kzg.VerifyBatchOpen(c.domain, polys, agg_proof, c.openKey)
}

func deserialiseComms(serComms SerialisedCommitments) ([]curve.G1Affine, error) {

	comms := make([]curve.G1Affine, len(serComms))
	for i := 0; i < len(serComms); i++ {
		// This will do subgroup checks and is relatively expensive (bench)
		// TODO: We _could_ do these on multiple threads, if bench shows them to be relatively slow
		comm, err := deserialisePoint(serComms[i])
		if err != nil {
			return nil, err
		}
		comms[i] = comm
	}

	return comms, nil
}
func deserialisePoint(serPoint SerialisedG1Point) (curve.G1Affine, error) {
	var point curve.G1Affine

	_, err := point.SetBytes(serPoint[:])
	if err != nil {
		return curve.G1Affine{}, err
	}
	return point, nil
}

func deserialisePolys(serPolys []SerialisedPoly) ([]kzg.Polynomial, error) {

	num_polynomials := len(serPolys)
	polys := make([]kzg.Polynomial, 0, num_polynomials)

	for _, serPoly := range serPolys {
		poly, err := deserialisePoly(serPoly)
		if err != nil {
			return nil, err
		}
		polys = append(polys, poly)
	}
	return polys, nil
}
func deserialisePoly(serPoly SerialisedPoly) (kzg.Polynomial, error) {
	num_coeffs := len(serPoly)
	poly := make(kzg.Polynomial, num_coeffs)
	for i := 0; i < num_coeffs; i++ {
		scalar, err := deserialiseScalar(serPoly[i])
		if err != nil {
			return nil, err
		}
		poly[i] = scalar
	}
	return poly, nil
}

func deserialiseScalar(serScalar SerialisedScalar) (fr.Element, error) {
	scalar, isCanon := utils.ReduceCanonical(serScalar[:])
	if !isCanon {
		return fr.Element{}, errors.New("scalar is not in canonical format")
	}
	return scalar, nil
}

func serialiseCommitments(comms []curve.G1Affine) SerialisedCommitments {
	serComms := make(SerialisedCommitments, len(comms))
	for i := 0; i < len(comms); i++ {
		comm := comms[i].Bytes()
		serComms[i] = comm[:]
	}
	return serComms
}
