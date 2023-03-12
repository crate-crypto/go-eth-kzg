package api

import (
	_ "embed"

	"encoding/hex"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Hex string for a compressed G1 point without the `0x` prefix
type G1CompressedHexStr = string

// Hex string for a compressed G2 point without the `0x` prefix
type G2CompressedHexStr = string

var (
	// This is the test trusted setup, which SHOULD NOT BE USED IN PRODUCTION.
	// The secret for this 1337.
	//
	//go:embed trusted_setup.json
	testKzgSetupStr string
)

func parseTrustedSetup(setupG1 []G1CompressedHexStr, setupLagrangeG1 []G1CompressedHexStr, setupG2 []G2CompressedHexStr) ([]bls12381.G1Affine, []bls12381.G1Affine, []bls12381.G2Affine, error) {
	setupG1Points, err := parseG1Points(setupG1)
	if err != nil {
		return nil, nil, nil, err
	}
	setupLagrangeG1Points, err := parseG1Points(setupLagrangeG1)
	if err != nil {
		return nil, nil, nil, err
	}

	g2Points, err := parseG2Points(setupG2)
	if err != nil {
		return nil, nil, nil, err
	}

	return setupG1Points, setupLagrangeG1Points, g2Points, nil
}

func parseG1Point(hexString string) (*bls12381.G1Affine, error) {
	var g1Point bls12381.G1Affine
	serializedPoint, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}
	_, err = g1Point.SetBytes(serializedPoint)
	if err != nil {
		return nil, err
	}

	return &g1Point, nil
}
func parseG2Point(hexString string) (*bls12381.G2Affine, error) {
	var g2Point bls12381.G2Affine
	serializedPoint, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}
	_, err = g2Point.SetBytes(serializedPoint)
	if err != nil {
		return nil, err
	}

	return &g2Point, nil
}

func parseG1Points(hexStrings []string) ([]bls12381.G1Affine, error) {
	numG1 := len(hexStrings)
	g1Points := make([]bls12381.G1Affine, numG1)

	for i, hexStr := range hexStrings {
		g1Point, err := parseG1Point(hexStr)
		if err != nil {
			return nil, err
		}
		g1Points[i] = *g1Point
	}

	return g1Points, nil
}
func parseG2Points(hexStrings []string) ([]bls12381.G2Affine, error) {
	numG2 := len(hexStrings)
	g2Points := make([]bls12381.G2Affine, numG2)

	for i, hexStr := range hexStrings {
		g2Point, err := parseG2Point(hexStr)
		if err != nil {
			return nil, err
		}
		g2Points[i] = *g2Point
	}

	return g2Points, nil
}
