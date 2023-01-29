package api

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/agg_kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
)

// This struct holds all of the necessary configuration needed
// to create and verify proofs.
type Context struct {
	domain    *kzg.Domain
	commitKey *kzg.CommitKey
	openKey   *kzg.OpeningKey
}

// The Modulus of the scalar field of bls12-381
var MODULUS = [32]byte{115, 237, 167, 83, 41, 157, 125, 72, 51, 57, 216, 8, 9, 161, 216, 5, 83, 189, 164, 2, 255, 254, 91, 254, 255, 255, 255, 255, 0, 0, 0, 1}

// Creates a new context object which will hold all of the state needed
// for one to use the EIP-4844 methods.
// The `4096“ denotes that we will only be able to commit to polynomials
// with at most 4096 evaluations.
// The `Insecure` denotes that this method should not be used in
// production since the secret is known.
func NewContext4096Insecure(trustedSetupSecret int) (*Context, error) {

	const NUM_EVALUATIONS_IN_POLYNOMIAL = uint64(4096)

	secret := big.NewInt(int64(trustedSetupSecret))
	domain := kzg.NewDomain(NUM_EVALUATIONS_IN_POLYNOMIAL)

	srs, err := kzg.NewSRSInsecure(*domain, secret)
	if err != nil {
		return nil, fmt.Errorf("could not create context %s", err)
	}

	// Reverse the roots and the domain according to the specs
	srs.CommitKey.ReversePoints()
	domain.ReverseRoots()

	return &Context{
		domain:    domain,
		commitKey: &srs.CommitKey,
		openKey:   &srs.OpeningKey,
	}, nil
}

// Call this method once we are ready to use the trusted
// setup from the ceremony
//
// TODO: use this method to parse the "insecure" trusted setup
// TODO from the consensus specs
func NewContextFromJson(json string) (*Context, error) {
	return nil, nil
}

// spec: blob_to_kzg_commitments
// For now we call the method that calls multiple Blobs as a sub-routine
func (c *Context) BlobToCommitment(blob serialisation.Blob) (serialisation.Commitment, error) {
	commitments, err := c.BlobsToCommitments([]serialisation.Blob{blob})
	if err != nil {
		return serialisation.Commitment{}, nil
	}
	return commitments[0], nil
}
func (c *Context) BlobsToCommitments(blobs []serialisation.Blob) (serialisation.Commitments, error) {
	// Deserialisation
	//
	// 1. Deserialise the Blobs into polynomial objects
	polys, err := serialisation.DeserialiseBlobs(blobs)
	if err != nil {
		return nil, err
	}

	// 2. Commit to polynomials
	comms, err := agg_kzg.CommitToPolynomials(polys, c.commitKey)
	if err != nil {
		return nil, err
	}

	// Serialisation
	//
	// 3. Serialise commitments
	serComms := serialisation.SerialiseG1Points(comms)

	return serComms, nil
}

// TODO: check performance difference with this method and the original method
// TODO which redundantly converts from and to montgomery form
func (c *Context) VerifyKZGProof(polynomialKZG serialisation.KZGCommitment, kzgProof serialisation.KZGProof, inputPointBytes, claimedValueBytes serialisation.Scalar) error {
	// Deserialisation
	//
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

	polyComm, err := serialisation.DeserialiseG1Point(polynomialKZG)
	if err != nil {
		return err
	}

	quotientComm, err := serialisation.DeserialiseG1Point(kzgProof)
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

func (c *Context) ComputeKZGProof(blob serialisation.Blob, inputPointBytes serialisation.Scalar) (serialisation.KZGProof, serialisation.G1Point, serialisation.Scalar, error) {
	// Deserialisation
	//
	// 1. Deserialise the `Blob` into a polynomial
	//
	poly, err := serialisation.DeserialiseBlob(blob)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	// 2. Deserialise input point
	inputPoint, err := serialisation.DeserialiseScalar(inputPointBytes)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	// 3. Commit to polynomial
	comms, err := agg_kzg.CommitToPolynomials([]kzg.Polynomial{poly}, c.commitKey)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	//4. Create opening proof
	openingProof, err := kzg.Open(c.domain, poly, inputPoint, c.commitKey)
	if err != nil {
		return serialisation.KZGProof{}, serialisation.G1Point{}, [32]byte{}, err
	}

	// Serialisation
	//
	// 5. Serialise values
	//
	// Polynomial commitment
	commitment := comms[0]

	serComm := serialisation.SerialiseG1Point(commitment)
	//
	// Quotient commitment
	serProof := serialisation.SerialiseG1Point(openingProof.QuotientComm)
	//
	// Claimed value -- Reverse it to use little endian
	claimedValueBytes := serialisation.SerialiseScalar(openingProof.ClaimedValue)

	return serProof, serComm, claimedValueBytes, nil
}

// Spec: compute_aggregate_kzg_proof
// Note: We additionally return the commitments (There is a PR open to accept the commitment)
func (c *Context) ComputeAggregateKZGProof(blobs []serialisation.Blob) (serialisation.KZGProof, serialisation.Commitments, error) {
	// Deserialisation
	//
	// 1. Deserialise the polynomials
	polys, err := serialisation.DeserialiseBlobs(blobs)
	if err != nil {
		return serialisation.KZGProof{}, nil, err
	}

	// 2. Create batch opening proof
	proof, err := agg_kzg.BatchOpenSinglePoint(c.domain, polys, c.commitKey)
	if err != nil {
		return serialisation.KZGProof{}, nil, err
	}

	// Serialisation
	//
	// 3. Serialise points, so caller only needs to be concerned with
	// bytes
	serComms := serialisation.SerialiseG1Points(proof.Commitments)
	serProof := serialisation.SerialiseG1Point(proof.QuotientComm)

	return serProof, serComms, nil
}

// Spec: verify_aggregate_kzg_proof
func (c *Context) VerifyAggregateKZGProof(blobs []serialisation.Blob, serProof serialisation.KZGProof, serComms serialisation.Commitments) error {
	// Deserialisation
	//
	// 1. Deserialise the polynomials
	polys, err := serialisation.DeserialiseBlobs(blobs)
	if err != nil {
		return err
	}

	// 2. Deserialise the quotient commitment
	quotientComm, err := serialisation.DeserialiseG1Point(serProof)
	if err != nil {
		return err
	}

	// 3. Deserialise the polynomial commitments
	comms, err := serialisation.DeserialiseG1Points(serComms)
	if err != nil {
		return err
	}

	agg_proof := &agg_kzg.BatchOpeningProof{
		QuotientComm: quotientComm,
		Commitments:  comms,
	}
	return agg_kzg.VerifyBatchOpen(c.domain, polys, agg_proof, c.openKey)
}

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
