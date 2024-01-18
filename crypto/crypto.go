package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dashpay/dashd-go/btcjson"

	tmbytes "github.com/dashpay/tenderdash/libs/bytes"
)

const (
	// HashSize is the size in bytes of an AddressHash.
	HashSize = sha256.Size

	// AddressSize is the size of a pubkey address.
	AddressSize        = 20
	DefaultHashSize    = 32
	DefaultAppHashSize = DefaultHashSize
	ProTxHashSize      = DefaultHashSize
	QuorumHashSize     = DefaultHashSize
)

type KeyType int

var (
	// ErrInvalidProTxHash uses in proTxHash validation
	ErrInvalidProTxHash = errors.New("proTxHash is invalid")
)

const (
	Ed25519 KeyType = iota
	BLS12381
	Secp256k1
	KeyTypeAny
)

// Address is an address is a []byte, but hex-encoded even in JSON.
// []byte leaves us the option to change the address length.
// Use an alias so Unmarshal methods (with ptr receivers) are available too.
type Address = tmbytes.HexBytes

type ProTxHash = tmbytes.HexBytes

type QuorumHash = tmbytes.HexBytes

// AddressHash computes a truncated SHA-256 hash of bz for use as
// a peer address.
//
// See: https://docs.tendermint.com/master/spec/core/data_structures.html#address
func AddressHash(bz []byte) Address {
	h := sha256.Sum256(bz)
	return Address(h[:AddressSize])
}

// Checksum returns the SHA256 of the bz.
func Checksum(bz []byte) []byte {
	h := sha256.Sum256(bz)
	return h[:]
}

func ProTxHashFromSeedBytes(bz []byte) ProTxHash {
	return Checksum(bz)
}

func RandProTxHash() ProTxHash {
	return CRandBytes(ProTxHashSize)
}

// RandProTxHashes generates and returns a list of N random generated proTxHashes
func RandProTxHashes(n int) []ProTxHash {
	proTxHashes := make([]ProTxHash, n)
	for i := 0; i < n; i++ {
		proTxHashes[i] = RandProTxHash()
	}
	return proTxHashes
}

// ProTxHashValidate validates the proTxHash value
func ProTxHashValidate(val ProTxHash) error {
	if len(val) != ProTxHashSize {
		return fmt.Errorf(
			"incorrect size actual %d, expected %d: %w",
			len(val),
			ProTxHashSize,
			ErrInvalidProTxHash,
		)
	}
	return nil
}

func RandQuorumHash() QuorumHash {
	return CRandBytes(ProTxHashSize)
}

func SmallQuorumType() btcjson.LLMQType {
	return btcjson.LLMQType_5_60
}

type SortProTxHash []ProTxHash

func (sptxh SortProTxHash) Len() int {
	return len(sptxh)
}

func (sptxh SortProTxHash) Less(i, j int) bool {
	return bytes.Compare(sptxh[i], sptxh[j]) == -1
}

func (sptxh SortProTxHash) Swap(i, j int) {
	sptxh[i], sptxh[j] = sptxh[j], sptxh[i]
}

type QuorumKeys struct {
	PrivKey            PrivKey
	PubKey             PubKey
	ThresholdPublicKey PubKey
}

type quorumKeysJSON struct {
	PrivKey            json.RawMessage `json:"priv_key"`
	PubKey             json.RawMessage `json:"pub_key"`
	ThresholdPublicKey json.RawMessage `json:"threshold_public_key"`
}

// Validator is a validator interface
type Validator interface {
	Validate() error
}

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifySignature(msg []byte, sig []byte) bool
	VerifySignatureDigest(hash []byte, sig []byte) bool
	Equals(PubKey) bool
	Type() string

	fmt.Stringer
	HexStringer
}

type PrivKey interface {
	Bytes() []byte
	Sign(msg []byte) ([]byte, error)
	SignDigest(msg []byte) ([]byte, error)
	PubKey() PubKey
	Equals(PrivKey) bool
	Type() string
}

type Symmetric interface {
	Keygen() []byte
	Encrypt(plaintext []byte, secret []byte) (ciphertext []byte)
	Decrypt(ciphertext []byte, secret []byte) (plaintext []byte, err error)
}

// HexStringer ...
type HexStringer interface {
	HexString() string
}

// BatchVerifier If a new key type implements batch verification,
// the key type must be registered in github.com/dashpay/tenderdash/crypto/batch
type BatchVerifier interface {
	// Add appends an entry into the BatchVerifier.
	Add(key PubKey, message, signature []byte) error
	// Verify verifies all the entries in the BatchVerifier, and returns
	// if every signature in the batch is valid, and a vector of bools
	// indicating the verification status of each signature (in the order
	// that signatures were added to the batch).
	Verify() (bool, []bool)
}
