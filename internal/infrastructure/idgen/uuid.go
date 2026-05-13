package idgen

import (
	"crypto/rand"
	"encoding/hex"
)

type RandomID struct{}

func (RandomID) New() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
