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

type ArgonSettings struct {
	ArgonTime     uint32 `json:"argon_time"`
	ArgonMemory   uint32 `json:"argon_memory"`
	ArgonThreads  uint8  `json:"argon_threads"`
	ArgonHashSize uint32 `json:"argon_hash_size"`
}

func NewArgonSettings(argonTime uint32, argonMemory uint32, argonThreads uint8, argonHashSize uint32) ArgonSettings {
	return ArgonSettings{
		ArgonTime:     argonTime,
		ArgonMemory:   argonMemory,
		ArgonThreads:  argonThreads,
		ArgonHashSize: argonHashSize,
	}
}

func NewArgonDefaultSettings() ArgonSettings {
	argonSettings := ArgonSettings{}
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
	argonSettings.ArgonTime = uint32(3)

	// p=4 lanes
	// const ArgonThreads = uint8(4)
	argonSettings.ArgonThreads = uint8(4)

	// m=2^(16) (64 MiB of RAM)
	argonSettings.ArgonMemory = uint32(64 * 1024)

	// 256-bit tag size (== 32 bytes)
	argonSettings.ArgonHashSize = uint32(32)

	return argonSettings
}

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

func GetHashedPassword(password string, salt []byte, argonSettings ArgonSettings) HashedPassword {
	key := argon2.IDKey([]byte(password), salt, argonSettings.ArgonTime, argonSettings.ArgonMemory, argonSettings.ArgonThreads, argonSettings.ArgonHashSize)

	return HashedPassword{
		Hash: key,
		Salt: salt,
		ArgonSettings: ArgonSettings{
			ArgonTime:     argonSettings.ArgonTime,
			ArgonMemory:   argonSettings.ArgonMemory,
			ArgonThreads:  argonSettings.ArgonThreads,
			ArgonHashSize: argonSettings.ArgonHashSize,
		},
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

func HashPermissionPasswords(perms map[string]string, argonSettings ArgonSettings) (map[string]HashedPassword, error) {
	hashedPerms := map[string]HashedPassword{}
	for id, password := range perms {
		// Generate 16 byte (128 bit) salt as
		// recommended for argon2 in RFC 9106
		salt, err := GetRandSalt(16)
		if err != nil {
			return nil, fmt.Errorf("newFlcStorage: %w", err)
		}

		hashedPerms[id] = GetHashedPassword(password, salt, argonSettings)
	}

	return hashedPerms, nil
}

type HashedPassword struct {
	Hash []byte `json:"hash"`
	Salt []byte `json:"salt"`
	ArgonSettings
}
