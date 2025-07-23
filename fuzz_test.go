package yrgourd_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/codahale/yrgourd-go"
)

func FuzzInitiate(f *testing.F) {
	is, err := yrgourd.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	rs, err := yrgourd.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("some garbage"))
	f.Fuzz(func(t *testing.T, a []byte) {
		b := bytes.NewBuffer(a)
		conn, err := yrgourd.Initiate(b, is, rs.PublicKey(), rand.Reader, nil)
		if err == nil {
			t.Errorf("should not have initiated but did: %v", conn)
		}
	})
}

func FuzzRespond(f *testing.F) {
	rs, err := yrgourd.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("some garbage"))
	f.Fuzz(func(t *testing.T, a []byte) {
		b := bytes.NewBuffer(a)
		conn, err := yrgourd.Respond(b, rs, rand.Reader, nil, yrgourd.AllowAllPolicy)
		if err == nil {
			t.Errorf("should not have responded but did: %v", conn)
		}
	})
}
