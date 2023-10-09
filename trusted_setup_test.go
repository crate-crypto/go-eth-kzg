package gokzg4844

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
