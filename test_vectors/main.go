package main

import (
	"encoding/json"
	"io/ioutil"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	context "github.com/crate-crypto/go-proto-danksharding-crypto"
)

func main() {
	secret := 123456789
	polyDegree := 4096

	c := context.NewContextInsecure(polyDegree, secret)

	saveAsJson(agg_proof_json(c, polyDegree), "agg_proof.json")
	saveAsJson(generate(polyDegree), "transcript.json")
}

func saveAsJson(data interface{}, fileName string) {
	file, _ := json.MarshalIndent(data, "", " ")
	_ = ioutil.WriteFile(fileName, file, 0644)
}

func generatePolys(numPolys int, degree int) [][]fr.Element {
	polys := make([][]fr.Element, numPolys)
	offset := 0
	for i := 0; i < numPolys; i++ {
		polys[i] = offsetPoly(offset, degree)
		offset += degree
	}
	return polys
}

func flattenBytes(matrix [][]byte) []byte {
	var flattenedBytes []byte
	for _, byteSlice := range matrix {
		flattenedBytes = append(flattenedBytes, byteSlice...)
	}
	return flattenedBytes
}

func flattenPolys(polys [][]fr.Element) []byte {
	var flattenedPolys []byte
	for _, poly := range polys {
		flattenedPolys = append(flattenedPolys, flattenPoly(poly)...)
	}
	return flattenedPolys
}
func flattenPoints(points []curve.G1Affine) []byte {
	var flattenedPoints []byte
	for _, point := range points {
		serPoint := point.Bytes()
		flattenedPoints = append(flattenedPoints, serPoint[:]...)
	}
	return flattenedPoints
}
func flattenPoly(poly []fr.Element) []byte {
	var flattenedPoly []byte
	for _, eval := range poly {
		bytes := eval.Bytes()
		flattenedPoly = append(flattenedPoly, bytes[:]...)
	}
	return flattenedPoly
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

func generatePoints(size int) []curve.G1Affine {
	points := make([]curve.G1Affine, size)
	_, _, g1Gen, _ := curve.Generators()

	for i := 0; i < size; i++ {
		points[i] = g1Gen
		g1Gen.Add(&g1Gen, &g1Gen)
	}

	return points
}
