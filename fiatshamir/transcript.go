package fiatshamir

import (
	"crypto/sha256"
	"hash"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/utils"
)

// Domain Separator to separate field elements
const DOM_SEP_FIELD_ELEMENT = ""

// Domain Separator to separate group elements
const DOM_SEP_POINT = ""

// Domain Separator to separate challenge outputs
const DOMAIN_SEP_SQUEEZE = ""

/// The transcript is used to create challenge scalars.
/// See: Fiat-Shamir
type Transcript struct {
	state hash.Hash
}

func NewTranscript(label string) *Transcript {
	digest := sha256.New()

	transcript := &Transcript{
		state: digest,
	}
	transcript.NewProtocol(label)

	return transcript
}

func (t *Transcript) domainSep(label string) {
	t.state.Write([]byte(label))
}

func (t *Transcript) appendMessage(label string, message []byte) {
	t.domainSep(label)
	t.state.Write(message)
}

// Separates a sub protocol using domain separator
func (t *Transcript) NewProtocol(_label string) {
	// This does nothing according to the specs right now
	//
	// See DOMAIN_SEPARATOR_AGGREGATE_PROTOCOL and DOMAIN_SEPARATOR_EVAL_PROTOCOL
	// referring to empty strings
}

// Appends a Polynomial to the transcript
//
// Converts each coefficient in the polynomial to 32 bytes, then appends it to
// the state
//
// TODO : If we want to optimise, we can check and introduce a read from bytes
// TODO method, so we are not deserialise, then serialising again
// TODO: (only if its slow). Check this by finding out how long it
// TODO takes to serialise polynomials
func (t *Transcript) AppendPolynomial(poly []fr.Element) {
	for _, eval := range poly {
		t.AppendScalar(eval)
	}
}
func (t *Transcript) AppendPolynomials(polys [][]fr.Element) {
	for _, poly := range polys {
		t.AppendPolynomial(poly)
	}
}

// Appends a Scalar to the transcript
//
// Converts the scalar to 32 bytes, then appends it to
// the state
func (t *Transcript) AppendScalar(scalar fr.Element) {
	tmpBytes := scalar.Bytes()
	utils.ReverseSlice(tmpBytes[:]) // Reverse bytes so that we use little-endian

	t.appendMessage(DOM_SEP_FIELD_ELEMENT, tmpBytes[:])
}

// Appends a Point to the transcript
//
// Serialises the Point into a 32 byte slice, then appends it to
// the state
func (t *Transcript) AppendPoint(point curve.G1Affine) {
	tmp_bytes := point.Bytes() // Do not reverse the bytes, use zcash encoding format
	t.appendMessage(DOM_SEP_POINT, tmp_bytes[:])
}
func (t *Transcript) AppendPoints(points []curve.G1Affine) {
	for _, point := range points {
		t.AppendPoint(point)
	}
}

// Computes a challenge based off of the state of the transcript
//
// Hash the transcript state, then reduce the hash modulo the size of the
// scalar field
//
// Note that calling the transcript twice, will yield two different challenges
// Because we always add the previous squeezed challenge back into the transcript
// This is useful because the transcript closely mimics the behaviour of a random oracle
func (t *Transcript) ChallengeScalar() fr.Element {
	t.domainSep(DOMAIN_SEP_SQUEEZE)

	// First hash the transcript state to get a byte slice
	bytes := t.state.Sum(nil)
	// Reverse the bytes, so that we use little-endian
	utils.ReverseSlice(bytes)

	// Now interpret those bytes as a field element
	var challenge fr.Element
	challenge.SetBytes(bytes)

	// Clear the state
	t.state.Reset()

	// Add the hash of the state
	// This "summarises" the previous state before we cleared it,
	// given the hash is collision resistance
	t.appendMessage("", bytes)
	// Return the new challenge
	return challenge
}
