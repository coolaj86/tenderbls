package gobls

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	chiabls "github.com/chuwt/chia-bls-go"
	"github.com/dashpay/tenderdash/blsbasic"
	"github.com/dashpay/tenderdash/internal/blscore"
	bls12381 "github.com/kilic/bls12-381"

	"github.com/dashpay/tenderdash/crypto"
)

//-------------------------------------

var _ crypto.PrivKey = PrivKey{}

const (
	PrivKeyName = "tendermint/PrivKeyBLS12381"
	PubKeyName  = "tendermint/PubKeyBLS12381"
	// PubKeySize is is the size, in bytes, of public keys as used in this package.
	PubKeySize = 48
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 32
	// SignatureSize of an BLS12381 signature.
	SignatureSize = 96
	// SeedSize is the size, in bytes, of private key seeds. These are the
	// private key representations used by RFC 8032.
	SeedSize = 32

	KeyType = "bls12381"
)

var (
	errPubKeyIsEmpty     = errors.New("public key should not be empty")
	errPubKeyInvalidSize = errors.New("invalid public key size")

	emptyPubKeyVal = []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	schema = blsbasic.New()
)

// BasicScheme returns basic bls scheme
func BasicScheme() blscore.SchemeMPL {
	return schema
}

// PrivKey implements crypto.PrivKey.
type PrivKey []byte

// TypeTag satisfies the jsontypes.Tagged interface.
func (PrivKey) TypeTag() string { return PrivKeyName }

// Bytes returns the privkey byte format.
func (privKey PrivKey) Bytes() []byte {
	return privKey
}

func privKeyFromBytes(privBytes []byte) (*chiabls.PrivateKey, error) {
	if keyLen := len(privBytes); keyLen != PrivateKeySize {
		err := errInvalidPrivateKeySize(keyLen)
		return nil, err
	}

	privBigInt := &big.Int{}
	privBigInt.SetBytes(privBytes)

	q := bls12381.NewG1().Q()
	privWrap := &big.Int{}
	privWrap = privWrap.Mod(privBigInt, q)

	privBytes = privWrap.Bytes()
	privKey := chiabls.KeyFromBytes(privBytes)

	return &privKey, nil
}

// Sign produces a signature on the provided message.
// This assumes the privkey is wellformed in the golang format.
// The first 32 bytes should be random,
// corresponding to the normal bls12381 private key.
// The latter 32 bytes should be the compressed public key.
// If these conditions aren't met, Sign will panic or produce an
// incorrect signature.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	privKeyChia, err := privKeyFromBytes(privKey)
	if err != nil {
		return nil, err
	}

	sigBytes := schema.Sign(privKeyChia, msg)
	return sigBytes, nil
}

// SignDigest produces a signature on the message digest (hash).
// This assumes the privkey is well-formed in the golang format.
// The first 32 bytes should be random,
// corresponding to the normal bls12381 private key.
// The latter 32 bytes should be the compressed public key.
// If these conditions aren't met, Sign will panic or produce an
// incorrect signature.
func (privKey PrivKey) SignDigest(hash []byte) ([]byte, error) {
	sigBytes, err := privKey.Sign(hash)
	return sigBytes, err
}

// PubKey gets the corresponding public key from the private key.
//
// Panics if the private key is not initialized.
func (privKey PrivKey) PubKey() crypto.PubKey {
	blsPrivKey, err := privKeyFromBytes(privKey)
	if err != nil {
		// should probably change method sign to return an error but since
		// that's not available just panic...
		panic("bad key")
	}

	pubKey := blsPrivKey.GetPublicKey()
	pubBytes := pubKey.Bytes()
	pubIface := PubKey(pubBytes)

	return pubIface
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if otherBLS, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherBLS[:]) == 1
	}

	return false
}

func (privKey PrivKey) Type() string {
	return KeyType
}

func (privKey PrivKey) TypeValue() crypto.KeyType {
	return crypto.BLS12381
}

// GenPrivKey generates a new bls12381 private key.
// It uses OS randomness in conjunction with the current global random seed
// in tendermint/libs/common to generate the private key.
func GenPrivKey() PrivKey {
	return genPrivKey(rand.Reader)
}

// genPrivKey generates a new bls12381 private key using the provided reader.
func genPrivKey(rand io.Reader) PrivKey {
	seed := make([]byte, SeedSize)

	_, err := io.ReadFull(rand, seed)
	if err != nil {
		panic(err)
	}
	sk := chiabls.KeyGen(seed)
	skBytes := sk.Bytes()

	return skBytes
}

// GenPrivKeyFromSecret hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyFromSecret(secret []byte) PrivKey {
	seed := crypto.Checksum(secret) // Not Ripemd160 because we want 32 bytes.

	sk := chiabls.KeyGen(seed)
	skBytes := sk.Bytes()

	return skBytes
}

func ReverseProTxHashes(proTxHashes []crypto.ProTxHash) []crypto.ProTxHash {
	reversedProTxHashes := make([]crypto.ProTxHash, len(proTxHashes))
	for i := 0; i < len(proTxHashes); i++ {
		reversedProTxHashes[i] = proTxHashes[i].ReverseBytes()
	}
	return reversedProTxHashes
}

//-------------------------------------

var _ crypto.PubKey = PubKey{}

// PubKey PubKeyBLS12381 implements crypto.PubKey for the bls12381 signature scheme.
type PubKey []byte

// TypeTag satisfies the jsontypes.Tagged interface.
func (PubKey) TypeTag() string { return PubKeyName }

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKey) Address() crypto.Address {
	if len(pubKey) != PubKeySize {
		panic("pubkey is incorrect size")
	}
	return crypto.AddressHash(pubKey)
}

// Bytes returns the PubKey byte format.
func (pubKey PubKey) Bytes() []byte {
	return pubKey
}

func (pubKey PubKey) VerifySignatureDigest(hash []byte, sig []byte) bool {
	verified := pubKey.VerifySignature(hash, sig)
	return verified
}

func (pubKey PubKey) VerifySignature(msg []byte, sig []byte) bool {
	// make sure we use the same algorithm to sign
	if len(sig) == 0 {
		//  fmt.Printf("bls verifying error (signature empty) from message %X with key %X\n", msg, pubKey.Bytes())
		return false
	}

	if len(sig) != SignatureSize {
		// fmt.Printf("bls verifying error (signature size) sig %X from message %X with key %X\n", sig, msg, pubKey.Bytes())
		return false
	}

	pubKeyChia, err := chiabls.NewPublicKey(pubKey)
	if err != nil {
		panic(err)
	}

	verified := schema.Verify(&pubKeyChia, msg, sig)

	return verified
}

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyBLS12381{%X}", []byte(pubKey))
}

// HexString returns hex-string representation of pubkey
func (pubKey PubKey) HexString() string {
	return hex.EncodeToString(pubKey)
}

func (pubKey PubKey) TypeValue() crypto.KeyType {
	return crypto.BLS12381
}

func (pubKey PubKey) Type() string {
	return KeyType
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if otherBLS, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey[:], otherBLS[:])
	}

	return false
}

// Validate validates a public key value
func (pubKey PubKey) Validate() error {
	size := len(pubKey)
	if size != PubKeySize {
		return fmt.Errorf("public key has wrong size %d: %w", size, errPubKeyInvalidSize)
	}
	if bytes.Equal(pubKey, emptyPubKeyVal) {
		return errPubKeyIsEmpty
	}
	return nil
}

func errInvalidPrivateKeySize(size int) error {
	return fmt.Errorf("incorrect private key %d bytes but expected %d bytes", size, PrivateKeySize)
}
