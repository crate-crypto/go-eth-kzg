package api

import (
	"fmt"
	"math/big"

	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

// This struct holds all of the necessary configuration needed
// to create and verify proofs.
//
// TODO instead of requiring upstream to save the lagrange SRS
// TODO we can have them marshall the Context object
// TODO This requires the fields to be public which is not safer
// TODO what we can do instead is have a json file contains the lagrange
// TODO srs and other important information that will save us processing time
// TODO need to be careful here as SRS will be reversed, but a new domain will
// TODO not
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

	if serialization.SCALARS_PER_BLOB != 4096 {
		panic("this method is named `NewContext4096Insecure1337` we expect SCALARS_PER_BLOB to be 4096")
	}

	const SECRET = int64(1337)

	secret := big.NewInt(int64(SECRET))
	domain := kzg.NewDomain(serialization.SCALARS_PER_BLOB)

	srs, err := kzg.NewLagrangeSRSInsecure(*domain, secret)
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

// Creates a new context object which will hold all of the state needed
// for one to use the EIP-4844 methods.
// To initialize one must pass the parameters generated after the trusted setup.
//
// These are the parameters in monomial form -- This is the form that the trusted
// setup will be in, if no further processing is applied to it once its created.
//
// This function assumes that the G1 and G2 points are in order
// - G1points = {G, alpha * G, alpha^2 * G, ..., alpha^n * G}
// - G2points = {H, alpha * H, alpha^2 * H, ..., alpha^n * H}
// Note, for KZG we only need 2 G2 points
func NewContext(setupG1 []G1CompressedHexStr, setupG2 []G2CompressedHexStr) (*Context, error) {

	// Debug assert
	// This should not happen for the ETH protocol
	// However we add this panic, since the API does is more generic
	if len(setupG1) < 2 || len(setupG2) < 2 {
		panic("need at least two G1/G2 elements for the SRS")
	}

	// Parse the trusted setup from hex strings to G1 and G2 points
	g1Points, g2Points, err := parseTrustedSetup(setupG1, setupG2)
	if err != nil {
		return nil, err
	}

	// Get the generator points and the degree-1 element for G2 points
	// The generators are the degree-0 elements in the trusted setup
	//
	genG1 := g1Points[0]
	genG2 := g2Points[0]
	alphaGenG2 := g2Points[1]

	domain := kzg.NewDomain(serialization.SCALARS_PER_BLOB)
	// The G1 points will be in monomial form
	// Convert them to lagrange form
	// See 3.1 onwards in https://eprint.iacr.org/2017/602.pdf for further details
	lagrangeG1Points := domain.IfftG1(g1Points)

	commitKey := kzg.CommitKey{
		G1: lagrangeG1Points,
	}
	openingKey := kzg.OpeningKey{
		GenG1:   genG1,
		GenG2:   genG2,
		AlphaG2: alphaGenG2,
	}

	// Bit-Reverse the roots and the domain according to the specs
	// The bit reversal is not needed for simple KZG however it was
	// implemented to make the step for full dank-sharding easier.
	commitKey.ReversePoints()
	domain.ReverseRoots()

	return &Context{
		domain:    domain,
		commitKey: &commitKey,
		openKey:   &openingKey,
	}, nil
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
