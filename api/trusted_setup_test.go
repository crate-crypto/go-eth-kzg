package api

import (
	"encoding/json"
	"testing"
)

func TestTransformTrustedSetup(t *testing.T) {
	parsedSetup := JSONTrustedSetup{}

	err := json.Unmarshal([]byte(testKzgSetupStr), &parsedSetup)
	if err != nil {
		t.Fatal(err)
	}
	err = CheckTrustedSetupIsWellFormed(&parsedSetup)
	if err != nil {
		t.Fatal(err)
	}
}
