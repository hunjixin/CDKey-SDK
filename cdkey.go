package cdkeysdk

import (
	"crypto/ecdsa"
	"encoding/base32"
	"errors"
	"github.com/ethereum/go-ethereum/crypto"
	rand2 "math/rand"
	"time"
)

func GeneratePrivKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func PadUid(mid uint64) []byte {
	padId := make([]byte, 32)
	offset := rand2.Intn(2)
	padId[0] = byte(offset)
	//i+3*0 +0
	//i+3*1 +0
	secretByteIndex := uint64(7)
	for i := 1; i < 32; i++ {
		if secretByteIndex >= 0 && (i+3-offset)%3 == 1 {
			//secret byte
			padId[i] = byte(mid >> (secretByteIndex * 8))
			secretByteIndex--
		} else {
			padId[i] = byte(rand2.Intn(255))
		}
	}

	return padId
}

func UnPadUid(padId []byte) ([]byte, uint64, error) {
	if len(padId) != 32 {
		return nil, 0, errors.New("not enough length")
	}

	offset := int(padId[0])
	//i+3*0 +0
	//i+3*1 +0
	randBytes := []byte{}
	mid := uint64(0)
	secretByteIndex := uint64(7)
	for i := 1; i < 32; i++ {
		if secretByteIndex >= 0 && (i+3-offset)%3 == 1 {
			//secret byte
			mid = mid | (uint64(padId[i]) << (secretByteIndex * 8))
			secretByteIndex--
		} else {
			randBytes = append(randBytes, byte(padId[i]))
		}
	}
	return randBytes, mid, nil
}

func BatchGenerateCDKey(priv *ecdsa.PrivateKey, mid uint64, number int) ([]string, error) {
	var results []string
	rand2.Seed(time.Now().Unix())
	for i := 0; i < number; i++ {
		padMid := PadUid(mid)
		sig, err := crypto.Sign(padMid, priv)
		if err != nil {
			return nil, err
		}
		key := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(append(sig, padMid...))
		results = append(results, key)
	}

	return results, nil
}

func GenerateCDKey(priv *ecdsa.PrivateKey, mid uint64) (string, error) {
	padMid := PadUid(mid)
	sig, err := crypto.Sign(padMid, priv)
	if err != nil {
		return "", err
	}
	key := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(append(sig, padMid...))
	return key, nil
}

func VerifyCDKey(priv *ecdsa.PrivateKey, cdKey string) (bool, uint64, error) {
	keyBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cdKey)
	if err != nil {
		return false, 0, err
	}
	if len(keyBytes) < 32 {
		return false, 0, errors.New("invalidate msg")
	}

	_, mid, err := UnPadUid(keyBytes[len(keyBytes)-32:])
	if err != nil {
		return false, 0, err
	}

	sig := keyBytes[:len(keyBytes)-32]
	pk, err := crypto.SigToPub(keyBytes[len(keyBytes)-32:], sig)
	if err != nil {
		return false, 0, err
	}
	if pk.Equal(priv.Public()) {
		return true, mid, nil
	} else {
		return false, 0, errors.New("not pubkey expected")
	}
}
