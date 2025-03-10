package main

import (
	"context"
	"crypto/mlkem"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"

	"github.com/codahale/yrgourd-go"
)

var (
	listen  = flag.String("listen", "127.0.0.1:6060", "the address to listen on")
	connect = flag.String("connect", "127.0.0.1:5050", "the address to connect to")
	isStr   = flag.String("client_key", "", "the private key of the client")
	rsStr   = flag.String("server_key", "", "the public key of the server")
)

func main() {
	flag.Parse()

	isB, err := hex.DecodeString(*isStr)
	if err != nil {
		log.Fatal(err)
	}

	is, err := mlkem.NewDecapsulationKey768(isB)
	if err != nil {
		log.Fatal(err)
	}

	rsB, err := hex.DecodeString(*rsStr)
	if err != nil {
		log.Fatal(err)
	}

	rs, err := mlkem.NewEncapsulationKey768(rsB)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", *listen)
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

		go func() {
			log.Println("accepted new connection")
			defer conn.Close()
			defer log.Println("closed connection")

			log.Println("connecting to", *connect)
			client, err := net.Dial("tcp", *connect)
			if err != nil {
				log.Println("error connecting", err)
				return
			}
			defer client.Close()

			yrClient, err := yrgourd.Initiate(client, is, rs, nil)
			if err != nil {
				log.Println("error connecting", err)
				return
			}

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				if _, err := io.Copy(yrClient, conn); err != nil {
					log.Println("error reading from client", err)
				}
				cancel()
			}()
			go func() {
				if _, err := io.Copy(conn, yrClient); err != nil {
					log.Println("error writing to server", err)
				}
				cancel()
			}()
			<-ctx.Done()
		}()
	}
}
