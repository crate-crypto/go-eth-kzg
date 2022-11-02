package main

import (
	"encoding/hex"

	context "github.com/crate-crypto/go-proto-danksharding-crypto"
)

type AggProofJson struct {
	NumPolys    int
	PolyDegree  int
	Polynomials string
	Proof       string
	Commitments string
}

func agg_proof_json(c *context.Context, polyDegree int) AggProofJson {
	numPolys := 2

	polys := generatePolys(numPolys, polyDegree)
	serPolys := flattenPolys(polys)

	proof, comms, err := c.ComputeAggregateKzgProofAlt(serPolys, uint(polyDegree))
	if err != nil {
		panic(err)
	}
	flattenedComms := flattenBytes(comms)

	return AggProofJson{
		NumPolys:    numPolys,
		PolyDegree:  polyDegree,
		Polynomials: hex.EncodeToString(serPolys),
		Proof:       hex.EncodeToString(proof),
		Commitments: hex.EncodeToString(flattenedComms),
	}
}
