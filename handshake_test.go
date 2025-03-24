package yrgourd

import (
	"bufio"
	"bytes"
	"crypto/mlkem"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	rs, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	var serverRead, clientRead []byte

	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()

		t.Log("server responding")
		rw, err := Respond(server, rs, nil, AllowAllPolicy)
		if err != nil {
			t.Error("respond error:", err)
		}
		brw := bufio.NewReadWriter(bufio.NewReader(rw), bufio.NewWriter(rw))

		t.Log("server reading")
		message, _, err := brw.ReadLine()
		if err != nil {
			t.Errorf("server read error: %v", err)
		}
		serverRead = message

		t.Log("server writing")
		if _, err := brw.WriteString("this is the server!\n"); err != nil {
			t.Errorf("server write error: %v", err)
		}

		t.Log("server flushing")
		if err := brw.Flush(); err != nil {
			t.Errorf("server flush error: %v", err)
		}

		t.Log("server closing")
		if err := server.Close(); err != nil {
			t.Errorf("server close error: %v", err)
		}
	}()
	go func() {
		defer wg.Done()

		is, err := mlkem.GenerateKey768()
		if err != nil {
			t.Error(err)
		}

		t.Log("client initiating")
		rw, err := Initiate(client, is, rs.EncapsulationKey(), nil)
		if err != nil {
			t.Error("initiate error:", err)
		}
		brw := bufio.NewReadWriter(bufio.NewReader(rw), bufio.NewWriter(rw))

		t.Log("client writing")
		if _, err := brw.WriteString("this is the client!\n"); err != nil {
			t.Errorf("client write error: %v", err)
		}

		t.Log("client flushing")
		if err := brw.Flush(); err != nil {
			t.Errorf("client flush error: %v", err)
		}

		t.Log("client reading")
		message, _, err := brw.ReadLine()
		if err != nil {
			t.Errorf("client read error: %v", err)
		}
		clientRead = message

		t.Log("client closing")
		if err := client.Close(); err != nil {
			t.Errorf("client close error: %v", err)
		}
	}()
	wg.Wait()

	if expected, actual := []byte("this is the client!"), serverRead; !bytes.Equal(expected, actual) {
		t.Errorf("expected client to read %s but was %s", expected, actual)
	}

	if expected, actual := []byte("this is the server!"), clientRead; !bytes.Equal(expected, actual) {
		t.Errorf("expected server to read %s but was %s", expected, actual)
	}
}

func TestRatcheting(t *testing.T) {
	rs, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()

	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()

		t.Log("server responding")
		rw, err := Respond(server, rs, &Config{RatchetAfterBytes: 0, RatchetAfterTime: 0 * time.Second}, AllowAllPolicy)
		if err != nil {
			t.Error("respond error:", err)
		}

		t.Log("server writing")
		message := make([]byte, 1024)
		for i := 0; i < 100; i++ {
			if _, err := rw.Write(message); err != nil {
				t.Errorf("server write error: %v", err)
			}
		}

		t.Log("server closing")
		if err := server.Close(); err != nil {
			t.Errorf("server close error: %v", err)
		}
	}()
	go func() {
		defer wg.Done()

		is, err := mlkem.GenerateKey768()
		if err != nil {
			t.Error(err)
		}

		t.Log("client initiating")
		rw, err := Initiate(client, is, rs.EncapsulationKey(), nil)
		if err != nil {
			t.Error("initiate error:", err)
		}

		t.Log("client reading")
		_, _ = io.Copy(io.Discard, rw)

		t.Log("client closing")
		if err := client.Close(); err != nil {
			t.Errorf("client close error: %v", err)
		}
	}()
	wg.Wait()
}

func TestHandshake(t *testing.T) {
	rs, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	var clientConn, serverConn *connection

	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()

		rw, err := Respond(server, rs, nil, AllowAllPolicy)
		if err != nil {
			t.Error("respond error:", err)
		}
		serverConn = rw.(*connection)
	}()
	go func() {
		defer wg.Done()

		is, err := mlkem.GenerateKey768()
		if err != nil {
			t.Error(err)
		}

		rw, err := Initiate(client, is, rs.EncapsulationKey(), nil)
		if err != nil {
			t.Error("initiate error:", err)
		}

		clientConn = rw.(*connection)
	}()
	wg.Wait()

	defer func() {
		_ = server.Close()
		_ = client.Close()
	}()

	serverSend := serverConn.send.Derive("a", nil, 8)
	clientRecv := clientConn.recv.Derive("a", nil, 8)
	if !bytes.Equal(serverSend, clientRecv) {
		t.Errorf("expected serverSend == clientRecv, but was %v/%v", serverSend, clientRecv)
	}

	clientSend := clientConn.send.Derive("b", nil, 8)
	serverRecv := serverConn.recv.Derive("b", nil, 8)
	if !bytes.Equal(clientSend, serverRecv) {
		t.Errorf("expected clientSend == serverRecv, but was %v/%v", clientSend, serverRecv)
	}
}
