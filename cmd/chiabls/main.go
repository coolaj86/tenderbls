package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	bls "github.com/chuwt/chia-bls-go"
)

func main() {
	secret := []byte("it's a secret")
	seed := sha256.Sum256(secret)
	privKey := bls.KeyGen(seed[:])
	pubKey := privKey.GetPublicKey()
	privBytes := privKey.Bytes()
	pubBytes := pubKey.Bytes()
	privStr := hex.EncodeToString(privBytes)
	pubStr := hex.EncodeToString(pubBytes)

	fmt.Printf("Secret: %q\n", secret)
	fmt.Printf("Private: %#v\n", privStr)
	fmt.Printf("Pub: %#v\n", pubStr)
}
