package api

import (
	"encoding/json"

	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

// This struct holds all of the necessary configuration needed
// to create and verify proofs.
//
// Note: We could marshall this object so that clients won't need to
// process the SRS each time. The time to process is about 2-5 seconds.
type Context struct {
	domain    *kzg.Domain
	commitKey *kzg.CommitKey
	openKey   *kzg.OpeningKey
}

// BlsModulus is the bytes representation of the bls12-381 scalar field modulus:
//
//	52435875175126190479447740508185965837690552500527637822603658699938581184513
var BlsModulus = [32]byte{
	0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
	0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
	0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
}

// PointAtInfinity represents the serialized form of the point at infinity
// on the G1 group. This is defined as Bytes48(b'\xc0' + b'\x00' * 47).
var PointAtInfinity = [48]byte{0xc0}

// NewContext4096Insecure1337 creates a new context object which will hold all of the state needed
// for one to use the EIP-4844 methods.
// The `4096` denotes that we will only be able to commit to polynomials
// with at most 4096 evaluations.
// The `Insecure` denotes that this method should not be used in
// production since the secret is known. In particular, it is `1337`.
func NewContext4096Insecure1337() (*Context, error) {
	if serialization.ScalarsPerBlob != 4096 {
		// This is a library bug and so we panic.
		panic("this method is named `NewContext4096Insecure1337` we expect SCALARS_PER_BLOB to be 4096")
	}

	parsedSetup := JSONTrustedSetup{}

	err := json.Unmarshal([]byte(testKzgSetupStr), &parsedSetup)
	if err != nil {
		return nil, err
	}

	if serialization.ScalarsPerBlob != len(parsedSetup.SetupG1) {
		// This is a library method and so we panic
		panic("this method is named `NewContext4096Insecure1337` we expect the number of G1 elements in the trusted setup to be 4096")
	}
	return NewContext4096(&parsedSetup)
}

// NewContext4096 creates a new context object which will hold all of the state needed
// for one to use the EIP-4844 methods.
//
// The 4096 represents the fact that without extra changes to the code, this context will
// only handle polynomials with 4096 evaluations (degree 4095).
//
// Note: The G2 points do not have a fixed size. Technically we could specify it to be `2`
// as this is the number of G2 points that are required for KZG. However, the trusted setup
// in Ethereum has `65` since we want to use it for a future protocol; Full Danksharding.
// For this reason, we do not apply a fixed size, allowing the user to pass, say, `2 or `65`
//
// To initialize one must pass the parameters generated after the trusted setup, plus
// the lagrange version of the G1 points.
//
// This function assumes that the G1 and G2 points are in order:
//   - G1points = {G, alpha * G, alpha^2 * G, ..., alpha^n * G}
//   - G2points = {H, alpha * H, alpha^2 * H, ..., alpha^n * H} (For KZG we only need 2 G2 points)
//   - Lagrange G1Points = {L_0(alpha^0) * G, L_1(alpha) * G, L_2(alpha^2) * G, ..., L_n(alpha^n) * G}
//     L_i(X) are lagrange polynomials.
//
// See `NewContextMonomial` for how to generate the Lagrange version of the G1Points from the monomial version
func NewContext4096(trustedSetup *JSONTrustedSetup) (*Context, error) {
	// This should not happen for the ETH protocol
	// However since its a public method, we add the check.
	if len(trustedSetup.SetupG2) < 2 {
		return nil, kzg.ErrMinSRSSize
	}

	// Parse the trusted setup from hex strings to G1 and G2 points
	genG1, setupLagrangeG1Points, setupG2Points, err := parseTrustedSetup(trustedSetup)
	if err != nil {
		return nil, err
	}

	// Get the generator points and the degree-1 element for G2 points
	// The generators are the degree-0 elements in the trusted setup
	//
	// This will never panic as we checked the minimum SRS size is >= 2
	// and `serialization.ScalarsPerBlob` is 4096
	genG2 := setupG2Points[0]
	alphaGenG2 := setupG2Points[1]

	commitKey := kzg.CommitKey{
		G1: setupLagrangeG1Points,
	}
	openingKey := kzg.OpeningKey{
		GenG1:   genG1,
		GenG2:   genG2,
		AlphaG2: alphaGenG2,
	}

	domain := kzg.NewDomain(serialization.ScalarsPerBlob)
	// Bit-Reverse the roots and the trusted setup according to the specs
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
