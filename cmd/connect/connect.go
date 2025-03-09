package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
)

var addr = flag.String("addr", "127.0.0.1:4040", "the address to connect to")

func main() {
	flag.Parse()

	log.Println("connecting to", *addr)
	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	close := make(chan struct{}, 2)
	go func() {
		if _, err := io.Copy(conn, os.Stdin); err != nil {
			log.Println("error reading from stdin", err)
		}
		close <- struct{}{}
	}()
	go func() {
		if _, err := io.Copy(os.Stdout, conn); err != nil {
			log.Println("error writing to stdout", err)
		}
		close <- struct{}{}
	}()
	<-close
}
