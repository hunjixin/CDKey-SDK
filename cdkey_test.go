package cdkeysdk

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestBatchGenerateCDKey(t *testing.T) {
	priv, err := GeneratePrivKey()
	if err != nil {
		t.Error(err)
	}
	rand.Seed(time.Now().Unix())
	id := uint64(rand.Int63())

	cdkeys, err := BatchGenerateCDKey(priv, id, 1000)
	if err != nil {
		t.Error(err)
	}

	for _, cdkey := range cdkeys {
		fmt.Println(cdkey)
		success, vId, err := VerifyCDKey(priv, cdkey)
		if err != nil {
			t.Error(err)
		}
		if !success {
			t.Errorf("expect verify success but failed")
		}

		if vId != id {
			t.Errorf("expected %d but got %d", id, vId)
		}
	}
}

func TestGenerateCDKey(t *testing.T) {
	priv, err := GeneratePrivKey()
	if err != nil {
		t.Error(err)
	}
	rand.Seed(time.Now().Unix())
	id := uint64(rand.Int63())

	cdkey, err := GenerateCDKey(priv, id)
	if err != nil {
		t.Error(err)
	}

	success, vId, err := VerifyCDKey(priv, cdkey)
	if err != nil {
		t.Error(err)
	}
	if !success {
		t.Errorf("expect verify success but failed")
	}

	if vId != id {
		t.Errorf("expected %d but got %d", id, vId)
	}
}

func TestPadUid(t *testing.T) {
	rand.Seed(time.Now().Unix())
	for i := 0; i < 1000; i++ {
		id := uint64(rand.Int63())
		padBytes := PadUid(id)
		_, unPadId, err := UnPadUid(padBytes)
		if err != nil {
			t.Error(err)
		}
		if unPadId != id {
			t.Errorf("expected %d but got %d", id, unPadId)
		}
	}

}
