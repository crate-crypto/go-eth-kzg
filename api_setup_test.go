package goethkzg

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func embeddedSetup(t *testing.T) *JSONTrustedSetup {
	t.Helper()
	setup := &JSONTrustedSetup{}
	require.NoError(t, json.Unmarshal([]byte(testKzgSetupStr), setup))
	return setup
}

// Regression test: a trusted setup with exactly `scalarsPerCell` G2 points used
// to be accepted by NewContext4096. The first EIP-7594 verification then indexed
// `G2[scalarsPerCell]` (see kzg_multi.VerifyMultiPointKZGProofBatch) and panicked
// with "index out of range". It must be rejected with a clear error instead.
func TestNewContext4096RejectsInsufficientG2Points(t *testing.T) {
	setup := embeddedSetup(t)
	require.GreaterOrEqual(t, len(setup.SetupG2), scalarsPerCell+1)

	setup.SetupG2 = setup.SetupG2[:scalarsPerCell]
	ctx, err := NewContext4096(setup)
	require.ErrorIs(t, err, ErrInvalidG2Count)
	require.Nil(t, ctx)
}

// `scalarsPerCell + 1` G2 points is the minimum a usable context needs, so it
// must be accepted.
func TestNewContext4096AcceptsMinimumG2Points(t *testing.T) {
	setup := embeddedSetup(t)
	setup.SetupG2 = setup.SetupG2[:scalarsPerCell+1]
	ctx, err := NewContext4096(setup)
	require.NoError(t, err)
	require.NotNil(t, ctx)
}

// A trusted setup with more G2 points than G1 points used to panic with a slice
// bounds error at `setupMonomialG1Points[:len(setupG2Points)]`. It must be
// rejected with an error instead.
func TestNewContext4096RejectsExcessiveG2Points(t *testing.T) {
	setup := embeddedSetup(t)
	require.NotEmpty(t, setup.SetupG2)

	excess := make([]G2CompressedHexStr, ScalarsPerBlob+1)
	for i := range excess {
		excess[i] = setup.SetupG2[0]
	}
	setup.SetupG2 = excess

	ctx, err := NewContext4096(setup)
	require.ErrorIs(t, err, ErrInvalidG2Count)
	require.Nil(t, ctx)
}
