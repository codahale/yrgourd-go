package yrgourd

import (
	"crypto/mlkem"
	"math"
	"testing"
	"time"

	"github.com/codahale/lockstitch-go"
)

func BenchmarkConnectionWrite(b *testing.B) {
	conn := &connection{
		rw:                &testReadWriteCloser{},
		recv:              lockstitch.NewProtocol("recv"),
		send:              lockstitch.NewProtocol("send"),
		dk:                &mlkem.DecapsulationKey768{},
		ek:                &mlkem.EncapsulationKey768{},
		sendBuf:           make([]byte, 1024*1024*10),
		lastRatchet:       time.Now(),
		ratchetAfterBytes: math.MaxInt,
		ratchetAfterTime:  10 * time.Hour,
	}
	input := make([]byte, 1024*1024)
	b.SetBytes(int64(len(input)))

	for b.Loop() {
		_, err := conn.Write(input)
		if err != nil {
			b.Fatal(b)
		}
	}
}

type testReadWriteCloser struct{}

func (testReadWriteCloser) Close() error {
	return nil
}

func (testReadWriteCloser) Read([]byte) (int, error) {
	return 0, nil
}

func (testReadWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}
