package main

import (
	"encoding/hex"
	"fmt"

	"github.com/dashpay/tenderdash/crypto/bls12381"
)

func main() {
	secret := []byte("it's a secret")
	priv := bls12381.GenPrivKeyFromSecret(secret)
	pub := priv.PubKey()
	privStr := hex.EncodeToString(priv)
	pubStr := hex.EncodeToString(pub.Bytes())

	fmt.Printf("Secret: %q\n", secret)
	fmt.Printf("Private: %#v\n", privStr)
	fmt.Printf("Pub: %#v\n", pubStr)
}
