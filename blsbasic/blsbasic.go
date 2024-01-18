package blsbasic

import (
	"bytes"
	"fmt"

	chiabls "github.com/chuwt/chia-bls-go"
	"github.com/dashpay/tenderdash/internal/blscore"
	bls12381 "github.com/kilic/bls12-381"
)

var BasicSchemeDst = blscore.DomainSeparationTag(
	"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
)

type BasicSchemeMPL struct {
	// domainSeparationValue string
}

func New() blscore.SchemeMPL {
	bsm := &BasicSchemeMPL{}

	return bsm
}

// Sign
func (bsm *BasicSchemeMPL) Sign(sk *chiabls.PrivateKey, message []byte) []byte {
	sigPoint := blscore.SignMpl(sk, message, BasicSchemeDst)
	sigBytes := bls12381.NewG2().ToCompressed(sigPoint)

	return sigBytes
}

// Verify
func (bsm *BasicSchemeMPL) Verify(pk *chiabls.PublicKey, message []byte, sig []byte) bool {
	verified := blscore.VerifyMpl(pk, message, sig, BasicSchemeDst)

	return verified
}

// Aggregate
func (bsm *BasicSchemeMPL) Aggregate(signatures ...[]byte) ([]byte, error) {
	sigBytes, err := blscore.AggregateMpl(signatures...)

	return sigBytes, err
}

// AggregateVerify
func (bsm *BasicSchemeMPL) AggregateVerify(pks [][]byte, messages [][]byte, sig []byte) (bool, error) {
	n := len(messages)
	m := 1
	for i, a := range messages {
		for j, b := range messages[m:] {
			if bytes.Equal(a, b) {
				ib := m + j
				return false, fmt.Errorf("messages at indexes %d and %d are identical", i, ib)
			}
		}
		m++
		if m >= n {
			break
		}
	}

	verified := blscore.AggregateVerify(pks, messages, sig, BasicSchemeDst)
	return verified, nil
}
