package fiatshamir_test

// This file contains interopability tests that should be run
// to ensure compatibility between different implementations
// whom use the transcript abstraction.
// TODO: We can move some of these to test vectors instead
import (
	"encoding/hex"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/agg_kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/fiatshamir"
)

func TestInteropBasic1(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	expected := "3516abc057520fa76120d4fcf31725dd8a79edc48460fa8b96907ffa8c512a8c"
	testChallenge(t, transcript, expected)

}
func TestInteropBasic2(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	polyDegree := 4096
	zeroPoly := make([]fr.Element, polyDegree)

	transcript.AppendPolynomial(zeroPoly)

	expected := "31d85bd6a2003b0278f4f3bc508881b3d0e8153afd6258f0cb9b17548ed8befe"
	testChallenge(t, transcript, expected)
}

func TestInteropBasic3(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	numPolys := 10
	polyDegree := 4096
	polys := testPolys(numPolys, polyDegree)

	transcript.AppendPolynomials(polys)
	expected := "2a3353baeb57e99de1b5aaf43f22473d949ea78558720416dd765c437e35ac51"

	testChallenge(t, transcript, expected)
}

func TestInteropBasic4(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	numPoints := 123

	points := testPoints(numPoints)
	for _, point := range points {
		transcript.AppendPoint(point)
	}

	testChallenge(t, transcript, "6465b5691194f3ad50a0ef03124d458d3c78f40ebccc31b8775848401be43153")
}
func TestInteropBasic5(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	numPoints := 123
	polyDegree := 4096

	points := testPoints(numPoints)
	polys := testPolys(numPoints, polyDegree)

	transcript.AppendPointsPolys(points, polys)

	testChallenge(t, transcript, "5ddd4970fe9ffc25e39b00b338269828a21429b1fd423bed635ab7ed27c678d2")
}

// This method is a quick way to test that the output of the transcript is correct
// we simply squeeze out a challenge and check
func testChallenge(t *testing.T, transcript *fiatshamir.Transcript, expected string) {
	numChallenges := 1

	challenge := transcript.ChallengeScalars(uint8(numChallenges))[0]

	bytes := challenge.Bytes()
	got := hex.EncodeToString(bytes[:])

	if got != expected {
		t.Errorf("expected challenge is incorrect\n expected : %s\n got : %s", expected, got)
	}
}

func testPoints(size int) []curve.G1Affine {
	points := make([]curve.G1Affine, size)
	_, _, g1Gen, _ := curve.Generators()

	for i := 0; i < size; i++ {
		// gnark is missing a doubling operation for affine
		points[i] = g1Gen
		g1Gen.Add(&g1Gen, &g1Gen)
	}

	return points
}
func testPolys(numPolys int, polyDegree int) [][]fr.Element {

	polys := make([][]fr.Element, numPolys)

	for i := 0; i < numPolys; i++ {
		polys[i] = offsetPoly(i, polyDegree)
	}
	return polys
}
func offsetPoly(offset int, polyDegree int) []fr.Element {
	poly := make([]fr.Element, polyDegree)
	for i := 0; i < polyDegree; i++ {
		var eval fr.Element
		eval.SetInt64(int64(offset + i))
		poly[i] = eval
	}
	return poly
}
