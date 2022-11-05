package hashing

// The purpose of this package is only to have a central place to store
// selected hashing algoritm settings and some helper functions since
// both the server code and etcd3 config storage backend needs to hash
// stuff in a matching way.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// https://datatracker.ietf.org/doc/rfc9106/
// ===
// If much less memory is available, a uniformly safe option is
// Argon2id with t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of
// RAM), 128-bit salt, and 256-bit tag size.  This is the SECOND
// RECOMMENDED option.
// [...]
// The Argon2id variant with t=1 and 2 GiB memory is the FIRST
// RECOMMENDED option and is suggested as a default setting for
// all environments.  This setting is secure against
// side-channel attacks and maximizes adversarial costs on
// dedicated brute-force hardware. The Argon2id variant with t=3
// and 64 MiB memory is the SECOND RECOMMENDED option and is
// suggested as a default setting for memory- constrained
// environments.
// ===
//
// Use the "SECOND RECOMMENDED" settings because we are
// probably running in a memory constrained container:
// t=3 iterations
const ArgonTime = uint32(3)

// p=4 lanes
const ArgonThreads = uint8(4)

// m=2^(16) (64 MiB of RAM)
const ArgonMemory = uint32(64 * 1024)

// 128-bit salt (== 16 bytes == 32 hexadecimal chararacters)
func SaltFromHex(hexString string) ([]byte, error) {
	if len(hexString) != 32 {
		return nil, fmt.Errorf("SaltFromHex: hex string must be 32 hex characters long")
	}
	salt, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("SaltFromHex: cannot decode salt hex")
	}
	return salt, nil
}

// 256-bit tag size (== 32 bytes)
const ArgonHashSize = uint32(32)

func GetHashedPassword(password string, salt []byte, argonTime uint32, argonMemory uint32, argonThreads uint8, argonHashSize uint32) HashedPassword {
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonHashSize)

	return HashedPassword{
		Hash:          key,
		Salt:          salt,
		ArgonTime:     ArgonTime,
		ArgonMemory:   ArgonMemory,
		ArgonThreads:  ArgonThreads,
		ArgonHashSize: argonHashSize,
	}
}

func GetRandSalt(saltLen int) ([]byte, error) {
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("GetRandSalt: %w", err)
	}
	return salt, nil
}

func HashPermissionPasswords(perms map[string]string) (map[string]HashedPassword, error) {
	hashedPerms := map[string]HashedPassword{}
	for id, password := range perms {
		// Generate 16 byte (128 bit) salt as
		// recommended for argon2 in RFC 9106
		salt, err := GetRandSalt(16)
		if err != nil {
			return nil, fmt.Errorf("newFlcStorage: %w", err)
		}

		hashedPerms[id] = GetHashedPassword(password, salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonHashSize)
	}

	return hashedPerms, nil
}

type HashedPassword struct {
	Hash          []byte `json:"hash"`
	Salt          []byte `json:"salt"`
	ArgonTime     uint32 `json:"argon_time"`
	ArgonMemory   uint32 `json:"argon_memory"`
	ArgonThreads  uint8  `json:"argon_threads"`
	ArgonHashSize uint32 `json:"argon_hash_size"`
}
