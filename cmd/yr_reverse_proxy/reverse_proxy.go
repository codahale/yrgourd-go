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
	listen  = flag.String("listen", "127.0.0.1:5050", "the address to listen on")
	connect = flag.String("connect", "127.0.0.1:4040", "the address to connect to")
	rsStr   = flag.String("server_key", "", "the private key of the server")
)

func main() {
	flag.Parse()

	rsB, err := hex.DecodeString(*rsStr)
	if err != nil {
		log.Fatal(err)
	}

	rs, err := mlkem.NewDecapsulationKey768(rsB)
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
			yrConn, err := yrgourd.Respond(conn, rs, nil, yrgourd.AllowAllPolicy)
			if err != nil {
				log.Println("error responding", err)
				return
			}

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

			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				if _, err := io.Copy(client, yrConn); err != nil {
					log.Println("error reading from client", err)
				}
				cancel()
			}()
			go func() {
				if _, err := io.Copy(yrConn, client); err != nil {
					log.Println("error writing to server", err)
				}
				cancel()
			}()
			<-ctx.Done()
		}()
	}
}
