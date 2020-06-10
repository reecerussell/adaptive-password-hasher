package hasher

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// Common errors.
var (
	ErrInvalidIterationCount = errors.New("iteration count must be at least 1")
	ErrInvalidSaltSize       = errors.New("salt size must be positive and divisible by 8")
	ErrInvalidKeySize        = errors.New("key size must be positive and divisinle by 8")
)

const (
	// HashSHA256 is the has key used to tell a hasher
	// to use the SHA256 hashing algorithm.
	HashSHA256 = 1

	// HashSHA512 is the has key used to tell a hasher
	// to use the SHA512 hashing algorithm.
	HashSHA512 = 2

	// DefaultIterationCount is the default number of times a
	// password will be hashed.
	DefaultIterationCount = 1000

	// DefaultSaltSize is the default size of password salts.
	DefaultSaltSize = 128

	// DefaultKeySize is the default size of password sub-keys.
	DefaultKeySize = 256

	// DefaultHashKey is the default hash key.
	DefaultHashKey = HashSHA256
)

// Hasher is a high-level interface used to hash and verify passwords using
// the pbkdf2 key derivation algorithm. Using an adaptive format, passwords
// can be hashed using different hash algorithms and key sizes.
type Hasher interface {
	Hash(pwd []byte) []byte
	Verify(pwd, hash []byte) bool
}

func init() {
	// init the default hasher.
	defaultHasher, _ = New(
		DefaultIterationCount,
		DefaultSaltSize,
		DefaultKeySize,
		DefaultHashKey,
	)
}

var defaultHasher Hasher

// Hash hases the given password using the default hasher.
func Hash(pwd []byte) []byte {
	return defaultHasher.Hash(pwd)
}

// Verify attempts to verifiy the password using the default hasher.
func Verify(pwd, hash []byte) bool {
	return defaultHasher.Verify(pwd, hash)
}

type hasher struct {
	iterCnt  int
	saltSize int
	keySize  int
	hashKey  int
}

// New returns a new Hasher, configured with the given values.
//
// Both saltSize and keySize are recognised as number of bits. So,
// the given values must be divisible by 8, for the number of bytes.
//
// A non-nil error will be returned if any of the values are invalid.
func New(iterCtn, saltSize, keySize, hashKey int) (Hasher, error) {
	if iterCtn < 1 {
		return nil, ErrInvalidIterationCount
	}

	if saltSize%8 != 0 || saltSize/8 < 1 {
		return nil, ErrInvalidSaltSize
	}

	if keySize%8 != 0 || keySize/8 < 1 {
		return nil, ErrInvalidKeySize
	}

	return &hasher{
		iterCnt:  iterCtn,
		saltSize: saltSize / 8,
		keySize:  keySize / 8,
		hashKey:  hashKey,
	}, nil
}

// formatMarker is used to indicate the start of the hash.
const formatMarker = 0x01

// Hash hashes the given password data using the pbkdf2, key derivation
// algorithm. The output will contain, hash information alongside the salt
// and sub-key data.
func (h *hasher) Hash(pwd []byte) []byte {
	salt := make([]byte, h.saltSize)
	rand.Read(salt)
	subKey := pbkdf2.Key(pwd, salt, h.iterCnt, h.keySize, alg(h.hashKey))

	out := make([]byte, 13+h.saltSize+h.keySize)
	out[0] = formatMarker // format marker

	// write header hasher info
	writeHeaderValue(out, 1, uint(h.hashKey))
	writeHeaderValue(out, 5, uint(h.iterCnt))
	writeHeaderValue(out, 9, uint(len(salt)))

	// copy data to output
	copy(out[13:], salt)
	copy(out[13+len(salt):], subKey)

	return out
}

// writes header data using the given offset and value.
func writeHeaderValue(buf []byte, offset int, value uint) {
	buf[offset+0] = byte(value >> 24)
	buf[offset+1] = byte(value >> 16)
	buf[offset+2] = byte(value >> 8)
	buf[offset+3] = byte(value >> 0)
}

// Verify hashed the given password and compares it to the given hash data,
// returning a flag which determines whether or not the password matches the hash.
//
// Will return false if either:
//     - the hash salt size is less than the hasher's salt size,
//     - the hash key size is less than the hasher's key size,
//     - or if the hash is in an invalid format.
func (h *hasher) Verify(pwd, hash []byte) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			// this should never occur, unless the given hash was not
			// originally hashed using the Hash() function, i.e. invalid format
			// from another third-party hashing function.
			ok = false
		}
	}()

	if hash[0] != formatMarker {
		return false
	}

	hashFunc, iterCnt, saltLen := scanHeader(hash)
	fmt.Printf("%d < %d\n", saltLen, h.saltSize)
	if saltLen < h.saltSize {
		// saltLen must be >= to the hasher's salt size.
		return false
	}

	salt := make([]byte, saltLen)
	copy(salt[:], hash[13:13+saltLen])

	subKeyLen := len(hash) - 13 - saltLen
	if subKeyLen < h.keySize {
		// subKeyLen must be >= to the hasher's key size.
		return false
	}

	expected := make([]byte, subKeyLen)
	copy(expected[:], hash[13+saltLen:13+saltLen+subKeyLen])
	actual := pbkdf2.Key(pwd, salt, iterCnt, subKeyLen, hashFunc)

	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// scans a hash for the header information, such as version, algorithm, iteration count and salt size.
func scanHeader(buf []byte) (hashAlg func() hash.Hash, iterCnt, saltSize int) {
	for i := 1; i < 13; i += 4 {
		v := int(buf[i+0])<<24 | int(buf[i+1])<<16 | int(buf[i+2])<<8 | int(buf[i+3])

		switch i {
		case 1:
			hashAlg = alg(v)
			break
		case 5:
			iterCnt = v
			break
		case 9:
			saltSize = v
			break
		}
	}

	return
}

// returns a hash function for the given key. Will panic id
// the key is not a recognised hash key.
func alg(key int) func() hash.Hash {
	switch key {
	case HashSHA256:
		return sha256.New
	case HashSHA512:
		return sha512.New
	default:
		panic(fmt.Errorf("hash: unsupported hash key: %d", key))
	}
}
