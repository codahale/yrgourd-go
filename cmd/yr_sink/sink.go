package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"time"

	"github.com/codahale/yrgourd-go"
)

var (
	addr  = flag.String("addr", "127.0.0.1:4040", "the address to listen on")
	rsStr = flag.String("server_key", "", "the private key of the server, if any")
)

func main() {
	flag.Parse()

	var rs *ecdh.PrivateKey
	if *rsStr != "" {
		rsB, err := hex.DecodeString(*rsStr)
		if err != nil {
			log.Fatal(err)
		}

		rs, err = yrgourd.NewPrivateKey(rsB)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("listening for yrgourd connections")
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listening on", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("failed to accept connection", err)
			continue
		}

		go func(conn net.Conn) {
			log.Println("accepted new connection")
			defer func() {
				_ = conn.Close()
				log.Println("closed connection")
			}()

			var rw io.ReadWriter = conn
			if rs != nil {
				rw, err = yrgourd.Respond(conn, rs, rand.Reader, nil, yrgourd.AllowAllPolicy)
				if err != nil {
					log.Println("error during handshake", err)
					return
				}
			}

			start := time.Now()
			n, err := io.Copy(io.Discard, rw)
			if err != nil {
				log.Println("error reading data", err)
			}
			elapsed := time.Since(start)

			log.Printf("read %v bytes in %v (%f MiB/sec)", n, elapsed, float64(n)/1024/1024/elapsed.Seconds())
		}(conn)
	}
}
