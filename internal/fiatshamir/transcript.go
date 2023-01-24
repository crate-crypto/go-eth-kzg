package fiatshamir

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
)

// / The transcript is used to create challenge scalars.
// / See: Fiat-Shamir
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

func (t *Transcript) appendMessage(message []byte) {
	t.state.Write(message)
}

// Separates a sub protocol using domain separator
func (t *Transcript) NewProtocol(label string) {
	t.domainSep(label)
}

// Appends a Polynomial to the transcript
//
// Converts each coefficient in the polynomial to 32 bytes, then appends it to
// the state
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

	t.appendMessage(tmpBytes[:])
}

// Appends a Point to the transcript
//
// Serialises the Point into a 32 byte slice, then appends it to
// the state
func (t *Transcript) AppendPoint(point curve.G1Affine) {
	tmp_bytes := point.Bytes() // Do not reverse the bytes, use zcash encoding format
	t.appendMessage(tmp_bytes[:])
}
func (t *Transcript) AppendPoints(points []curve.G1Affine) {
	for _, point := range points {
		t.AppendPoint(point)
	}
}

func (t *Transcript) AppendPointsPolys(points []curve.G1Affine, polys [][]fr.Element) {
	numPoints := len(points)
	numPolys := len(polys)
	if numPoints != numPolys {
		panic(fmt.Sprintf("number of points %d does not equal number of polynomials %d", numPoints, numPolys))
	}

	// Note, we do not allow one to input no polynomials, because
	// there is no valid usecase for this
	if numPoints == 0 {
		panic("number of points/polynomials is zero which is not valid")
	}

	degreePoly := len(polys[0])
	t.appendMessage(u64ToByteArray(uint64(degreePoly)))
	t.appendMessage(u64ToByteArray(uint64(numPolys)))

	t.AppendPolynomials(polys)
	t.AppendPoints(points)
}

func u64ToByteArray(number uint64) []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(number))
	return bytes
}

// Hash the transcript. This is so that we can compress the inner buffer,
// the compressed inner buffer can then be cheaply copied to create many challenges
func (t *Transcript) compressState() []byte {
	hashedData := t.state.Sum(nil)
	return hashedData
}

// Computes challenges based off of the state of the transcript
//
// Hash the transcript state, then reduce the hash modulo the size of the
// scalar field, appending an integer to denote the challenge index
//
// Note that calling the transcript twice, will yield two different challenges
// Because we always add the previous squeezed challenge back into the transcript
// This is useful because the transcript closely mimics the behaviour of a random oracle
//
// Calling this function with zero challenges, will not throw an error
// This is something that will be caught quite at compile time, since
// the numbers of challenges that will be used will be known and used at compile time
func (t *Transcript) ChallengeScalars(numChallenges uint8) []fr.Element {

	// First compress the state
	compressedState := t.compressState()
	challenges := make([]fr.Element, numChallenges)
	for challengeIndex := uint8(0); challengeIndex < numChallenges; challengeIndex++ {

		// Create a new buffer to store the compressed state and one
		// extra byte for the challenge index
		hashedData := make([]byte, len(compressedState)+1)
		copy(hashedData, compressedState)
		//
		hashedData[len(hashedData)-1] = challengeIndex

		// Hash the compressed state with the challenged index
		digest := sha256.Sum256(hashedData)

		// Reverse the digest, so that we reduce the little-endian
		// representation
		utils.ReverseSlice(digest[:])

		// Now interpret those bytes as a field element
		// If gnark had a SetBytesLE method, we would not need to reverse
		// the bytes
		var challenge fr.Element
		challenge.SetBytes(digest[:])

		challenges[int(challengeIndex)] = challenge
	}

	// Clear the state
	t.state.Reset()

	// Add the compressed state to the transcript
	// This "summarises" the previous state before we cleared it,
	// given the hash is collision resistance
	//
	// This protocol does not require adding the compressed state
	// to the transcript because we only use this function once.
	// If this code is copy and pasted or extended for multiple rounds
	// then this function will work.
	t.appendMessage(compressedState)

	return challenges
}

func (t *Transcript) challengeScalar() fr.Element {
	scalars := t.ChallengeScalars(1)
	return scalars[0]
}
