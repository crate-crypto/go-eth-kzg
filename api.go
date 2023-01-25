package context

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/agg_kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

type Context struct {
	domain    *kzg.Domain
	commitKey *kzg.CommitKey
	openKey   *kzg.OpeningKey
}

// This is the number of 32 byte slices a blob can contain.
// We use the nomenclature `FIELD_ELEMENTS_PER_BLOB` because
// each field element when serialised is 32 bytes
//
// These 32 byte slices may not be _valid_, to which an error
// will be returned on deserialisation.
//
// This constant is set at the protocol level and is not
// related to any cryptographic assumptions.
const FIELD_ELEMENTS_PER_BLOB = 4096

// This is the number of bytes needed to represent a
// group element in G1 when compressed.
const COMPRESSED_G1_SIZE = 48

// This is the number of bytes needed to represent a field
// element corresponding to the order of the G1 group.
const SERIALISED_SCALAR_SIZE = 32

type SerialisedScalar = [SERIALISED_SCALAR_SIZE]byte
type SerialisedG1Point = [COMPRESSED_G1_SIZE]byte
type SerialisedPoly = [FIELD_ELEMENTS_PER_BLOB]SerialisedScalar

// A blob is a representation for a serialised polynomial
type Blob = SerialisedPoly

// This is a misnomer, its KZGWitness
type KZGProof = SerialisedG1Point
type KZGCommitment = SerialisedG1Point

type SerialisedCommitment = SerialisedG1Point
type SerialisedCommitments = []SerialisedCommitment

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

	// Reverse the roots and the domain according to the specs
	srs.CommitKey.ReversePoints()
	domain.ReverseRoots()

	return &Context{
		domain:    domain,
		commitKey: &srs.CommitKey,
		openKey:   &srs.OpeningKey,
	}
}

// This method is similar to the specs
// TODO: We should expose the method that takes in one Blob
func (c *Context) BlobsToCommitments(serPolys []SerialisedPoly) (SerialisedCommitments, error) {
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

	polyComm, err := deserialiseG1Point(polynomialKZG)
	if err != nil {
		return err
	}

	quotientComm, err := deserialiseG1Point(kzgProof)
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
		return KZGProof{}, SerialisedG1Point{}, [32]byte{}, err
	}

	// 2. Deserialise input point
	inputPoint, err := deserialiseScalar(inputPointBytes)
	if err != nil {
		return KZGProof{}, SerialisedG1Point{}, [32]byte{}, err
	}

	// 3. Commit to polynomial
	comms, err := agg_kzg.CommitToPolynomials([]kzg.Polynomial{poly}, c.commitKey)
	if err != nil {
		return KZGProof{}, SerialisedG1Point{}, [32]byte{}, err
	}

	//4. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, inputPoint, c.commitKey)
	if err != nil {
		return KZGProof{}, SerialisedG1Point{}, [32]byte{}, err
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

	return serProof, serComm, claimedValueBytes, nil
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

	return serProof, serComms, nil
}

// Spec: verify_aggregate_kzg_proof
func (c *Context) VerifyAggregateKzgProof(serPolys []SerialisedPoly, serProof KZGProof, serComms SerialisedCommitments) error {
	// 1. Deserialise the polynomials
	polys, err := deserialisePolys(serPolys)
	if err != nil {
		return err
	}

	// 2. Deserialise the quotient commitment
	quotientComm, err := deserialiseG1Point(serProof)
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
