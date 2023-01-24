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
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/agg_kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/fiatshamir"
)

func TestInteropBasic1(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	expected := "585f39007d35d5dd2235c9ac951750bed15c5cf8fdbc685b81df8af7069bb26b"
	testChallenge(t, transcript, expected)

}
func TestInteropBasic2(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	polyDegree := 4096
	zeroPoly := make([]fr.Element, polyDegree)

	transcript.AppendPolynomial(zeroPoly)

	expected := "655a158aa61ac277153c3aab84610b9079de88f075ee28396e89583957dcbdd4"
	testChallenge(t, transcript, expected)
}

func TestInteropBasic3(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	numPolys := 10
	polyDegree := 4096
	polys := testPolys(numPolys, polyDegree)

	transcript.AppendPolynomials(polys)
	expected := "151f8938fef5de0b713101ab1c24195a23933de54753dba0945f759e5eccd36d"

	testChallenge(t, transcript, expected)
}

func TestInteropBasic4(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	numPoints := 123

	points := testPoints(numPoints)
	for _, point := range points {
		transcript.AppendPoint(point)
	}

	testChallenge(t, transcript, "226f81ef676186ea38e0c05efcb2f923f2fdb7542de3355d4ec11511579cea91")
}
func TestInteropBasic5(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	numPoints := 123
	polyDegree := 4096

	points := testPoints(numPoints)
	polys := testPolys(numPoints, polyDegree)

	transcript.AppendPointsPolys(points, polys)

	testChallenge(t, transcript, "2f15f4e189fbe0f295e1261c940dc5363fddc7b32230092e2d7548caf012f550")
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
