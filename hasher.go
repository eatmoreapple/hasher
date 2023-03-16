package hasher

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"math"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// randomStringChars is a string of characters that can be used to generate a random string.
const randomStringChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Hasher is an interface for hashing passwords.
type Hasher interface {
	// Encode encodes a password using the given salt.
	Encode(password, salt string) (string, error)
	// Verify verifies a password against an encoded string.
	Verify(password, encoded string) (bool, error)
	// Salt generates a random salt.
	Salt() (string, error)
}

// hasher is a Hasher implementation.
type hasher struct {
	algorithm  string
	iterations int
	digest     func() hash.Hash
}

// Encode encodes a password using the given salt.
func (h *hasher) Encode(password, salt string) (string, error) {
	key := pbkdf2.Key([]byte(password), []byte(salt), h.iterations, 32, h.digest)
	text := base64.StdEncoding.EncodeToString(key)
	parts := []string{h.algorithm, strconv.Itoa(h.iterations), salt, text}
	return strings.Join(parts, "$"), nil
}

// Verify verifies a password against an encoded string.
func (h *hasher) Verify(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 {
		return false, nil
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, err
	}
	salt := parts[2]
	text := parts[3]
	key := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, h.digest)
	other := base64.StdEncoding.EncodeToString(key)
	return text == other, nil
}

// Salt generates a random salt.
func (h *hasher) Salt() (string, error) {
	charCount := int(math.Ceil(float64(32) / math.Log2(float64(len(randomStringChars)))))
	bytes := make([]byte, charCount)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = randomStringChars[int(b)%len(randomStringChars)]
	}
	return string(bytes), nil
}

var (
	// PBKDF2PasswordHasher is a Hasher implementation using PBKDF2 with SHA256.
	PBKDF2PasswordHasher = &hasher{
		algorithm:  "pbkdf2_sha256",
		iterations: 260000,
		digest:     sha256.New,
	}
	// PBKDF2SHA1PasswordHasher is a Hasher implementation using PBKDF2 with SHA1.
	PBKDF2SHA1PasswordHasher = &hasher{
		algorithm:  "pbkdf2_sha1",
		iterations: 260000,
		digest:     sha1.New,
	}
)
