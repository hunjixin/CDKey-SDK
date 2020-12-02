package cdkeysdk

import (
	"crypto/ecdsa"
	"encoding/base32"
	"errors"
	"github.com/ethereum/go-ethereum/crypto"
)

func GeneratePrivKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func PadUid(mid uint64) []byte {
	padId := make([]byte, 32)
	padId[24] = byte(mid >> 56)
	padId[25] = byte(mid >> 48)
	padId[26] = byte(mid >> 40)
	padId[27] = byte(mid >> 32)
	padId[28] = byte(mid >> 24)
	padId[29] = byte(mid >> 16)
	padId[30] = byte(mid >> 8)
	padId[31] = byte(mid)
	return padId
}

func UnPadUid(padId []byte)(uint64, error) {
	if len(padId) != 32 {
		return 0, errors.New("not enough length")
	}
	return uint64(padId[31]) | uint64(padId[30])<<8 | uint64(padId[29])<<16 | uint64(padId[28])<<24 |
		uint64(padId[27])<<32 | uint64(padId[26])<<40 | uint64(padId[25])<<48 | uint64(padId[24])<<56, nil
}

func GenerateCDKey(priv *ecdsa.PrivateKey, mid uint64)(string, error)  {
	padMid := PadUid(mid)
	sig, err := crypto.Sign(padMid, priv)
	if err != nil {
		return "", err
	}
	key := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(append(sig,padMid[24:]...))
	return key, nil
}

func VerifyCDKey(priv *ecdsa.PrivateKey, cdKey string) (bool,uint64, error) {
	keyBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cdKey)
	if err != nil {
		return false,0, err
	}
	if len(keyBytes) <32 {
		return false,0, errors.New("invalidate msg")
	}
	mIdTailBytes := keyBytes[len(keyBytes)-8:]
	midBytes := make([]byte, 32)
	copy(midBytes[24:], mIdTailBytes)

	mid, err := UnPadUid(midBytes)
	if err != nil {
		return false,0, err
	}

	sig := keyBytes[:len(keyBytes)-8]
	pk, err := crypto.SigToPub(midBytes, sig)
	if err != nil {
		return false,0, err
	}
	if pk.Equal(priv.Public()) {
		return true, mid, nil
	}else{
		return false,0, errors.New("not pubkey expected")
	}
}