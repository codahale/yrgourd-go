package yrgourd_test

import (
	"bytes"
	"crypto/mlkem"
	"testing"

	"github.com/codahale/yrgourd-go"
)

func FuzzInitiate(f *testing.F) {
	is, err := mlkem.GenerateKey768()
	if err != nil {
		f.Fatal(err)
	}

	rs, err := mlkem.GenerateKey768()
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("some garbage"))
	f.Fuzz(func(t *testing.T, a []byte) {
		b := bytes.NewBuffer(a)
		conn, err := yrgourd.Initiate(b, is, rs.EncapsulationKey(), nil)
		if err == nil {
			t.Errorf("should not have initiated but did: %v", conn)
		}
	})
}

func FuzzRespond(f *testing.F) {
	rs, err := mlkem.GenerateKey768()
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("some garbage"))
	f.Fuzz(func(t *testing.T, a []byte) {
		t.Log(a)
		b := bytes.NewBuffer(a)
		conn, err := yrgourd.Respond(b, rs, nil, yrgourd.AllowAllPolicy)
		if err == nil {
			t.Errorf("should not have responded but did: %v", conn)
		}
	})
}
