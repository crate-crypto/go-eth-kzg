package api

import (
	"fmt"
	"math/big"

	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
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
// production since the secret is known. In particular, it is `1337`
func NewContext4096Insecure1337() (*Context, error) {

	const SECRET = int64(1337)
	const NUM_EVALUATIONS_IN_POLYNOMIAL = uint64(4096)

	secret := big.NewInt(int64(SECRET))
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
func (c *Context) BlobToCommitment(blob serialization.Blob) (serialization.Commitment, error) {
	commitments, err := c.BlobsToCommitments([]serialization.Blob{blob})
	if err != nil {
		return serialization.Commitment{}, nil
	}
	return commitments[0], nil
}
func (c *Context) BlobsToCommitments(blobs []serialization.Blob) (serialization.Commitments, error) {
	// Deserialisation
	//
	// 1. Deserialise the Blobs into polynomial objects
	polys, err := serialization.DeserialiseBlobs(blobs)
	if err != nil {
		return nil, err
	}

	// 2. Commit to polynomials
	comms, err := kzg.CommitToPolynomials(polys, c.commitKey)
	if err != nil {
		return nil, err
	}

	// Serialisation
	//
	// 3. Serialise commitments
	serComms := serialization.SerialiseG1Points(comms)

	return serComms, nil
}

// These methods are used only for testing/fuzzing purposes.
// Since we use an internal package, they are not accessible
// from external package.
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
