package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/codahale/yrgourd-go"
)

func main() {
	k, err := yrgourd.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("private key: %s\n", hex.EncodeToString(k.Bytes()))
	fmt.Printf("public key: %s\n", hex.EncodeToString(k.PublicKey().Bytes()))
}
