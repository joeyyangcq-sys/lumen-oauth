package password

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	algorithm  = "pbkdf2-sha256"
	iterations = 210_000
	keyLen     = 32
	saltLen    = 16
)

var ErrInvalidHash = errors.New("invalid password hash")

type PBKDF2SHA256 struct{}

func (PBKDF2SHA256) Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, iterations, keyLen)
	return fmt.Sprintf(
		"%s$%d$%s$%s",
		algorithm,
		iterations,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	), nil
}

func (PBKDF2SHA256) Verify(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 || parts[0] != algorithm {
		return false, ErrInvalidHash
	}
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters <= 0 {
		return false, ErrInvalidHash
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return false, ErrInvalidHash
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false, ErrInvalidHash
	}
	got := pbkdf2SHA256([]byte(password), salt, iters, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hashLen := sha256.Size
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
