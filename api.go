package context

import (
	"errors"
	"fmt"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/agg_kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

type Context struct {
	domain    *kzg.Domain
	commitKey *kzg.CommitKey
	openKey   *kzg.OpeningKey
}

// We could make this [32]byte and [48]byte respectively, but the idea is that the
// caller should view the SerialisedPoly as an opaque collection of bytes
type SerialisedScalar = []byte
type SerialisedG1Point = []byte
type SerialisedPoly = []SerialisedScalar // TODO: fix this to use 4096

// This is a misnomer, its KZGWitness
type KZGProof = SerialisedG1Point
type KZGCommitment = SerialisedG1Point
type SerialisedCommitments = []SerialisedG1Point

// These methods are used only for testing/fuzzing purposes.
//
// The API proper does not require one to call these methods
// and these methods _should_ not modify the state of the context
// object making them safe to use.
func (c Context) Domain() kzg.Domain {
	return *c.domain
}
func (c Context) CommitKey() kzg.CommitKey {
	return *c.commitKey
}
func (c Context) OpenKeyKey() kzg.OpeningKey {
	return *c.openKey
}

// Creates a new context object which will hold all of the state needed
// for one to use the EIP-4844 methods.
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

func (c *Context) VerifyKZGProof(polynomialKZG KZGCommitment, kzgProof KZGProof, inputPointBytes, claimedValueBytes [32]byte) error {
	// gnark-library needs field element representations in big endian form
	// Usually we reverse the bytes in `deserialiseScalar` but we are using
	// big.Int, so we manually do it here
	utils.ReverseArray(&inputPointBytes)
	utils.ReverseArray(&claimedValueBytes)

	var claimedValueBigInt big.Int
	claimedValueBigInt.SetBytes(claimedValueBytes[:])
	if !utils.BytesToBigIntCanonical(&claimedValueBigInt) {
		return errors.New("claimed value is not serialised canonically")
	}

	var inputPointBigInt big.Int
	inputPointBigInt.SetBytes(inputPointBytes[:])
	if !utils.BytesToBigIntCanonical(&inputPointBigInt) {
		return errors.New("input point is not serialised canonically")
	}

	polyComm, err := deserialisePoint(polynomialKZG)
	if err != nil {
		return err
	}

	quotientComm, err := deserialisePoint(kzgProof)
	if err != nil {
		return err
	}

	proof := kzg.OpeningProofOpt{
		QuotientComm:       quotientComm,
		InputPointBigInt:   &inputPointBigInt,
		ClaimedValueBigInt: &claimedValueBigInt,
	}
	return kzg.VerifyOpt(&polyComm, &proof, c.openKey)
}

func (c *Context) ComputeKzgProof(serPoly SerialisedPoly, inputPointBytes [32]byte) (KZGProof, SerialisedG1Point, [32]byte, error) {

	// 1. Deserialise the polynomial

	poly, err := deserialisePoly(serPoly)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}

	// 2. Deserialise input point
	inputPoint, err := deserialiseScalar(inputPointBytes[:])
	if err != nil {
		return nil, nil, [32]byte{}, err
	}

	// 3. Commit to polynomial
	comms, err := agg_kzg.CommitToPolynomials([]kzg.Polynomial{poly}, c.commitKey)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}

	//4. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, inputPoint, c.commitKey)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}

	// 5. Serialise values
	//
	// Polynomial commitment
	commitment := comms[0]
	serComm := commitment.Bytes()
	//
	// Quotient commitment
	serProof := openingProof.QuotientComm.Bytes()
	//
	// Claimed value -- Reverse it to use little endian
	claimedValueBytes := openingProof.ClaimedValue.Bytes()
	utils.ReverseArray(&claimedValueBytes)

	return serProof[:], serComm[:], claimedValueBytes, nil
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
	reverseBytes(serScalar) // gnark uses big-endian but format is little-endian
	scalar, isCanon := utils.ReduceCanonical(serScalar)
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
