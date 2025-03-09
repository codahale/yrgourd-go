package main

import (
	"crypto/mlkem"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/codahale/yrgourd-go"
)

/*
   /// Run a plaintext echo server.
   Echo(EchoOpts),
   /// Run a plaintext connect client.
   Connect(ConnectOpts),
   /// Run a proxy which accepts plaintext clients and makes encrypted connections.
   Proxy(ProxyOpts),
   /// Run a proxy which accepts encrypted clients and makes plaintext connections.
   ReverseProxy(ReverseProxyOpts),
   /// Run a client which connects to an encrypted server and writes N bytes.
   Stream(StreamOpts),
   /// Run a server which accepts encrypted clients and reads everything.
   Sink(SinkOpts),
*/

func generateKey() error {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return err
	}

	fmt.Printf("private key: %s\n", hex.EncodeToString(dk.Bytes()))
	fmt.Printf("public key: %s\n", hex.EncodeToString(dk.EncapsulationKey().Bytes()))

	return nil
}

func echo(args []string) error {
	var addr string
	cmd := flag.NewFlagSet("echo", flag.ExitOnError)
	cmd.StringVar(&addr, "addr", "127.0.0.1:4040", "the address to listen on")
	if err := cmd.Parse(args); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
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

func connect(args []string) error {
	var addr string
	cmd := flag.NewFlagSet("connect", flag.ExitOnError)
	cmd.StringVar(&addr, "addr", "127.0.0.1:4040", "the address to connect to")
	if err := cmd.Parse(args); err != nil {
		return err
	}

	log.Println("connecting to", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
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

	return nil
}

func proxy(args []string) error {
	var listen, connect, isStr, rsStr string
	cmd := flag.NewFlagSet("proxy", flag.ExitOnError)
	cmd.StringVar(&listen, "listen", "127.0.0.1:6060", "the address to listen on")
	cmd.StringVar(&connect, "connect", "127.0.0.1:5050", "the address to connect to")
	cmd.StringVar(&isStr, "client_key", "", "the private key of the client")
	cmd.StringVar(&rsStr, "server_key", "", "the public key of the server")
	if err := cmd.Parse(args); err != nil {
		return err
	}

	isB, err := hex.DecodeString(isStr)
	if err != nil {
		return err
	}

	is, err := mlkem.NewDecapsulationKey768(isB)
	if err != nil {
		return err
	}

	rsB, err := hex.DecodeString(rsStr)
	if err != nil {
		return err
	}

	rs, err := mlkem.NewEncapsulationKey768(rsB)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
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

			log.Println("connecting to", connect)
			client, err := net.Dial("tcp", connect)
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

			close := make(chan struct{}, 2)
			go func() {
				if _, err := io.Copy(yrClient, conn); err != nil {
					log.Println("error reading from client", err)
				}
				close <- struct{}{}
			}()
			go func() {
				if _, err := io.Copy(conn, yrClient); err != nil {
					log.Println("error writing to server", err)
				}
				close <- struct{}{}
			}()
			<-close
		}()
	}
}

func reverseProxy(args []string) error {
	var listen, connect, rsStr string
	cmd := flag.NewFlagSet("proxy", flag.ExitOnError)
	cmd.StringVar(&listen, "listen", "127.0.0.1:5050", "the address to listen on")
	cmd.StringVar(&connect, "connect", "127.0.0.1:4040", "the address to connect to")
	cmd.StringVar(&rsStr, "server_key", "", "the private key of the server")
	if err := cmd.Parse(args); err != nil {
		return err
	}

	rsB, err := hex.DecodeString(rsStr)
	if err != nil {
		return err
	}

	rs, err := mlkem.NewDecapsulationKey768(rsB)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
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

			log.Println("connecting to", connect)
			client, err := net.Dial("tcp", connect)
			if err != nil {
				log.Println("error connecting", err)
				return
			}
			defer client.Close()

			close := make(chan struct{}, 2)
			go func() {
				if _, err := io.Copy(client, yrConn); err != nil {
					log.Println("error reading from client", err)
				}
				close <- struct{}{}
			}()
			go func() {
				if _, err := io.Copy(yrConn, client); err != nil {
					log.Println("error writing to server", err)
				}
				close <- struct{}{}
			}()
			<-close
		}()
	}
}

func stream(args []string) error {
	var addr string
	var size int64
	cmd := flag.NewFlagSet("stream", flag.ExitOnError)
	cmd.StringVar(&addr, "addr", "127.0.0.1:4040", "the address to connect to")
	cmd.Int64Var(&size, "size", 1024*1024*1024, "the number of bytes to write")
	if err := cmd.Parse(args); err != nil {
		return err
	}

	log.Println("connecting to", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := io.Copy(conn, io.LimitReader(constReader{b: 0x22}, size)); err != nil {
		log.Println("error writing data", err)
	}

	return nil
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

func sink(args []string) error {
	var addr string
	cmd := flag.NewFlagSet("sink", flag.ExitOnError)
	cmd.StringVar(&addr, "addr", "127.0.0.1:4040", "the address to listen on")
	if err := cmd.Parse(args); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
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
			defer conn.Close()
			defer log.Println("closed connection")

			start := time.Now()
			n, err := io.Copy(io.Discard, conn)
			if err != nil {
				log.Println("error reading data", err)
			}
			elapsed := time.Since(start)

			log.Printf("read %v bytes in %v (%f MiB/sec)", n, elapsed, float64(n)/1024/1024/float64(elapsed.Seconds()))
		}(conn)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		goto unknown
	}

	switch args[0] {
	case "generate-key":
		return generateKey()
	case "echo":
		return echo(args[1:])
	case "connect":
		return connect(args[1:])
	case "proxy":
		return proxy(args[1:])
	case "reverse-proxy":
		return reverseProxy(args[1:])
	case "stream":
		return stream(args[1:])
	case "sink":
		return sink(args[1:])
	default:
		goto unknown
	}

unknown:
	return fmt.Errorf("expected \"generate-key\" subcommand")
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}
