package gokzg4844

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransformTrustedSetup(t *testing.T) {
	parsedSetup := JSONTrustedSetup{}

	// Mainnet trusted setup
	err := json.Unmarshal([]byte(testMainnetKzgSetupStr), &parsedSetup)
	require.NoError(t, err)
	err = CheckTrustedSetupIsWellFormed(&parsedSetup)
	require.NoError(t, err)

	// Minimal trusted setup
	err = json.Unmarshal([]byte(testMinimalKzgSetupStr), &parsedSetup)
	require.NoError(t, err)
	err = CheckTrustedSetupIsWellFormed(&parsedSetup)
	require.NoError(t, err)
}
