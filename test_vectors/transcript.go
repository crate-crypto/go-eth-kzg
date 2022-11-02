package main

import (
	"encoding/hex"

	"github.com/crate-crypto/go-proto-danksharding-crypto/agg_kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/fiatshamir"
)

type TranscriptJson struct {
	NumPolys    int
	PolyDegree  int
	Polynomials string
	Commitments string
	challenge   string
}

func generate(polyDegree int) TranscriptJson {
	transcript := fiatshamir.NewTranscript(agg_kzg.DOM_SEP_PROTOCOL)
	numPolys := 12

	points := generatePoints(numPolys)
	polys := generatePolys(numPolys, polyDegree)

	transcript.AppendPointsPolys(points, polys)

	challenge := transcript.ChallengeScalar()
	bytes := challenge.Bytes()
	challengeHex := hex.EncodeToString(bytes[:])

	serPolys := flattenPolys(polys)
	serComms := flattenPoints(points)

	return TranscriptJson{
		NumPolys:    numPolys,
		PolyDegree:  polyDegree,
		Polynomials: hex.EncodeToString(serPolys),
		Commitments: hex.EncodeToString(serComms),
		challenge:   challengeHex,
	}
}
