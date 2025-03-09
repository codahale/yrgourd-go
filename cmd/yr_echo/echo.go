package main

import (
	"flag"
	"log"
	"net"
)

var addr = flag.String("addr", "127.0.0.1:4040", "the address to listen on")

func main() {
	flag.Parse()

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

		go func() {
			log.Println("accepted new connection")
			defer conn.Close()
			defer log.Println("closed connection")

			for {
				buf := make([]byte, 1024)
				size, err := conn.Read(buf)
				if err != nil {
					return
				}
				data := buf[:size]
				if _, err := conn.Write(data); err != nil {
					log.Println("error writing data", err)
				}
			}
		}()
	}
}
