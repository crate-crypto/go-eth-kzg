package fiatshamir

import (
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestTranscriptSmoke(t *testing.T) {
	tr := NewTranscript("my_protocol")
	challenge_1 := tr.ChallengeScalar()
	challenge_2 := tr.ChallengeScalar()

	if challenge_1 == challenge_2 {
		panic("calling ChallengeScalar twice should yield two different challenges")
	}
}

func TestTwoProtocolSmoke(t *testing.T) {

	message_a := fr.NewElement(12)
	message_b := curve.G1Affine{}
	message_c := fr.NewElement(20)

	// Provers View
	prover_tr := NewTranscript("protocol_1")

	// Add things according to this protocol
	prover_tr.AppendScalar(message_a)
	prover_tr.AppendPoint(message_b)

	prover_tr.NewProtocol("protocol_2")
	prover_tr.AppendScalar(message_c)

	prover_challenge := prover_tr.ChallengeScalar()

	// Verifiers View
	verifier_tr := NewTranscript("protocol_1")

	// Add things according to this protocol
	verifier_tr.AppendScalar(message_a)
	verifier_tr.AppendPoint(message_b)

	verifier_tr.NewProtocol("protocol_2")
	verifier_tr.AppendScalar(message_c)

	verifier_challenge := verifier_tr.ChallengeScalar()

	if !prover_challenge.Equal(&verifier_challenge) {
		t.Error("challenges do not match for the verifier and prover")
	}
}

func TestSameMessage(t *testing.T) {
	// Another property to note; adding the same message multiple times
	// should result in different challenges outputted

	tr := NewTranscript("my_protocol")
	tr.AppendScalar(fr.NewElement(0))
	challenge_1 := tr.ChallengeScalar()

	tr.AppendScalar(fr.NewElement(0))
	challenge_2 := tr.ChallengeScalar()

	if challenge_1 == challenge_2 {
		t.Error("expected different challenges, even though we added the same message")
	}
}
