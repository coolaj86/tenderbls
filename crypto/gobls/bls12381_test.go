// nolint:lll
package gobls

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dashpay/tenderdash/crypto"
)

func TestSignAndValidateBLS12381(t *testing.T) {
	privKey := GenPrivKey()
	pubKey := privKey.PubKey()

	hash := crypto.CRandBytes(128)
	sig, err := privKey.SignDigest(hash)
	require.Nil(t, err)

	// Test the signature
	assert.True(t, pubKey.VerifySignatureDigest(hash, sig))
}

func TestBLSAddress(t *testing.T) {
	testCases := []struct {
		skB64   string
		pkB64   string
		addrHex string
	}{
		{
			skB64:   "N3CR8OcoRjvC2n1UbFO59rgd9KHMGrW/KcWQi3FRoy0=",
			pkB64:   "hiQykLvL/ZrnW97OeYGWU1AgjrXpmwTVzSTpVa2pYfjAoWLe50C+e9xsPAYTui6x",
			addrHex: "BB8F983D64252213936C9E962FDB066B3266C335",
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("test-case #%d", i+1), func(t *testing.T) {
			skBytes, err := base64.StdEncoding.DecodeString(tc.skB64)
			assert.NoError(t, err)
			pkBytes, err := base64.StdEncoding.DecodeString(tc.pkB64)
			assert.NoError(t, err)
			addrBytes, err := hex.DecodeString(tc.addrHex)
			assert.NoError(t, err)
			privKey := PrivKey(skBytes)
			pubKey := privKey.PubKey()
			assert.EqualValues(t, pkBytes, pubKey)
			assert.EqualValues(t, addrBytes, pubKey.Address())
		})
	}
}

func TestPublicKeyGeneration(t *testing.T) {
	testCases := []struct {
		sk     string
		wantPk string
	}{
		{
			sk:     "Bl1GYvRPgMpa/dpxb6gtph374TkDWoOv3OMH+jEoTWI=",
			wantPk: "pWtWZTAnU0lSZKziSOtp8XbueEzfLDlaOuyH9RYteQeWCremf9expxa57A6k33iU",
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("test-case #%d", i+1), func(t *testing.T) {
			skBytes, err := base64.StdEncoding.DecodeString(tc.sk)
			require.NoError(t, err)
			privateKey := PrivKey(skBytes)
			pkBytes := base64.StdEncoding.EncodeToString(privateKey.PubKey().Bytes())
			require.Equal(t, tc.wantPk, pkBytes)
		})
	}
}
