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

	expected := "2c518c867e909617a9fe8120420c3a9b0d45f2aac02ed1911c2cd098d06daaa8"
	testChallenge(t, transcript, expected)

}
func TestInteropBasic2(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	polyDegree := 4096
	zeroPoly := make([]fr.Element, polyDegree)

	transcript.AppendPolynomial(zeroPoly)

	expected := "4beae6feedfe4ea5dd26253853c1a0b8de0ebfc9a36a8393353bf57daab31900"
	testChallenge(t, transcript, expected)
}

func TestInteropBasic3(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	numPolys := 10
	polyDegree := 4096
	polys := testPolys(numPolys, polyDegree)

	transcript.AppendPolynomials(polys)
	expected := "3a47d74130d9601fb3747d8abf43b830a4ded2796019c42dd67dfbbe085057c2"

	testChallenge(t, transcript, expected)
}

func TestInteropBasic4(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	numPoints := 123

	points := testPoints(numPoints)
	for _, point := range points {
		transcript.AppendPoint(point)
	}

	testChallenge(t, transcript, "32e41b934758770b5db0bb15caa0d32641ac9471ecb7ee779d02319cc8ffbb4e")
}
func TestInteropBasic5(t *testing.T) {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)

	numPoints := 123
	polyDegree := 4096

	points := testPoints(numPoints)
	polys := testPolys(numPoints, polyDegree)

	transcript.AppendPointsPolys(points, polys)

	testChallenge(t, transcript, "06d8806c8cbce6778f1923339c29936c1a55f12bdad8f553c769168dad382088")
}

func testChallenge(t *testing.T, transcript *fiatshamir.Transcript, expected string) {
	challenge := transcript.ChallengeScalar()

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
