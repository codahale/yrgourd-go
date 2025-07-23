package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"

	"github.com/codahale/yrgourd-go"
)

var (
	addr  = flag.String("addr", "127.0.0.1:4040", "the address to connect to")
	size  = flag.Int64("size", 1024*1024*1024, "the number of bytes to write")
	isStr = flag.String("client_key", "", "the private key of the client, if any")
	rsStr = flag.String("server_key", "", "the public key of the server, if any")
)

func main() {
	flag.Parse()

	if (*isStr == "" && *rsStr != "") || (*isStr != "" && *rsStr == "") {
		log.Fatalf("must specify either both -client_key and -server_key or neither")
	}

	var is *ecdh.PrivateKey
	var rs *ecdh.PublicKey
	if *isStr != "" && *rsStr != "" {
		isB, err := hex.DecodeString(*isStr)
		if err != nil {
			log.Fatal(err)
		}

		is, err = yrgourd.NewPrivateKey(isB)
		if err != nil {
			log.Fatal(err)
		}

		rsB, err := hex.DecodeString(*rsStr)
		if err != nil {
			log.Fatal(err)
		}

		rs, err = yrgourd.NewPublicKey(rsB)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("connecting to", *addr)
	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = conn.Close()
	}()

	var rw io.ReadWriter = conn
	if is != nil && rs != nil {
		log.Println("securely connecting to", *addr)
		rw, err = yrgourd.Initiate(conn, is, rs, rand.Reader, nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	buf := make([]byte, 1024*1024)
	if _, err := io.CopyBuffer(rw, io.LimitReader(constReader{b: 0x22}, *size), buf); err != nil {
		log.Println("error writing data", err)
	}

}

type constReader struct {
	b byte
}

func (c constReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = c.b
	}
	return len(p), err
}
