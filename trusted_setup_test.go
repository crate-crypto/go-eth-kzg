package goethkzg

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransformTrustedSetup(t *testing.T) {
	parsedSetup := JSONTrustedSetup{}

	err := json.Unmarshal([]byte(testKzgSetupStr), &parsedSetup)
	require.NoError(t, err)
	err = CheckTrustedSetupIsWellFormed(&parsedSetup)
	require.NoError(t, err)
}

func TestCheckTrustedSetupIsWellFormed_MalformedHex(t *testing.T) {
	var g1Lagrange [ScalarsPerBlob]G1CompressedHexStr
	g1Lagrange[0] = "" // Empty string should trigger an error, not a panic
	var g1Monomial [ScalarsPerBlob]G1CompressedHexStr
	g1Monomial[0] = "x" // Short string should trigger an error, not a panic

	setup := &JSONTrustedSetup{
		SetupG1Lagrange: g1Lagrange,
		SetupG1Monomial: g1Monomial,
		SetupG2:         []G2CompressedHexStr{"0x"},
	}

	// This should return an error, not panic
	err := CheckTrustedSetupIsWellFormed(setup)
	require.Error(t, err)
	require.Contains(t, err.Error(), "hex string is not prefixed with 0x")
}
