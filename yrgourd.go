package yrgourd

import (
	"crypto/mlkem"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/codahale/lockstitch-go"
)

type Config struct {
	RatchetAfterBytes int
	RatchetAfterTime  time.Duration
}

var DefaultConfig = Config{
	RatchetAfterBytes: 1024 * 1024 * 1024, // 1GiB
	RatchetAfterTime:  15 * time.Minute,
}

var (
	ErrInvalidHandshake    = errors.New("yrgourd: invalid handshake")
	ErrInitiatorNotAllowed = errors.New("yrgourd: initiator not allowed")
	AllowAllPolicy         = func(*mlkem.EncapsulationKey768) bool { return true }
)

func Initiate(rw io.ReadWriter, is *mlkem.DecapsulationKey768, rs *mlkem.EncapsulationKey768, config *Config) (io.ReadWriter, error) {
	if config == nil {
		config = &DefaultConfig
	}

	// Generate an ephemeral key pair.
	ie, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}

	// Allocate a buffer for the request.
	req := make([]byte, 0, reqLen)

	// Initialize a protocol.
	yr := lockstitch.NewProtocol("yrgourd.v1")

	// Mix the responder's static public key into the protocol.
	yr.Mix("rs", rs.Bytes())

	// Encapsulate a shared secret with the responser's static key.
	rsSS, rsCT := rs.Encapsulate()
	req = append(req, rsCT...)

	// Mix the ciphertext and shared secret into the protocol.
	yr.Mix("rs_ct", rsCT)
	yr.Mix("rs_ss", rsSS)

	// Encrypt the initiator's static public key.
	req = yr.Encrypt("is", req, is.EncapsulationKey().Bytes())

	// Seal the initiator's ephemeral public key.
	req = yr.Seal("ie", req, ie.EncapsulationKey().Bytes())

	// Send the request.
	if _, err := rw.Write(req); err != nil {
		return nil, err
	}

	// Allocate a buffer for the response.
	resp := make([]byte, respLen)

	// Read the response.
	if _, err := io.ReadFull(rw, resp); err != nil {
		return nil, err
	}
	isCT, ieCT := resp[:mlkem.CiphertextSize768], resp[mlkem.CiphertextSize768:]

	// Decrypt the ciphertext and decapsulate the static shared secret.
	isCT = yr.Decrypt("is_ct", isCT[:0], isCT)
	isSS, err := is.Decapsulate(isCT)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	yr.Mix("is_ss", isSS)

	// Open the ciphertext and decapsulate the ephemeral shared secret.
	ieCT, err = yr.Open("ie_ct", ieCT[:0], ieCT)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	ieSS, err := ie.Decapsulate(ieCT)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	yr.Mix("ie_ss", ieSS)

	// Fork the protocol into recv and send clones.
	recv, send := yr.Clone(), yr
	send.Mix("sender", []byte("initiator"))
	recv.Mix("sender", []byte("responder"))

	return newConnection(rw, recv, send, is, rs, config), nil
}

func Respond(rw io.ReadWriter, rs *mlkem.DecapsulationKey768, config *Config, policy func(*mlkem.EncapsulationKey768) bool) (io.ReadWriter, error) {
	if config == nil {
		config = &DefaultConfig
	}

	// Initialize a protocol.
	yr := lockstitch.NewProtocol("yrgourd.v1")

	// Mix the responder's static public key into the protocol.
	yr.Mix("rs", rs.EncapsulationKey().Bytes())

	// Read the initiator's request.
	req := make([]byte, reqLen)
	if _, err := io.ReadFull(rw, req); err != nil {
		return nil, err
	}
	rsCT, reqIS, reqIE := req[:mlkem.CiphertextSize768],
		req[mlkem.CiphertextSize768:mlkem.CiphertextSize768+mlkem.EncapsulationKeySize768],
		req[mlkem.CiphertextSize768+mlkem.EncapsulationKeySize768:]

	// Decapsulate the shared secret.
	yr.Mix("rs_ct", rsCT)
	rsSS, err := rs.Decapsulate(rsCT)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	yr.Mix("rs_ss", rsSS)

	// Decrypt and decode the initiator's static key.
	is, err := mlkem.NewEncapsulationKey768(yr.Decrypt("is", reqIS[:0], reqIS))
	if err != nil {
		return nil, err
	}

	// Check the initiator's static key against the policy.
	if !policy(is) {
		return nil, ErrInitiatorNotAllowed
	}

	// Open and decode the initiator's ephemeral key.
	reqIE, err = yr.Open("ie", reqIE[:0], reqIE)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	ie, err := mlkem.NewEncapsulationKey768(reqIE)
	if err != nil {
		return nil, ErrInvalidHandshake
	}

	// Allocate a buffer for the response.
	resp := make([]byte, 0, respLen)

	// Encapsulate a shared secret with the initiator's static key and encrypt it.
	isSS, isCT := is.Encapsulate()
	resp = yr.Encrypt("is_ct", resp, isCT)
	yr.Mix("is_ss", isSS)

	// Encapsulate a shared secret with the initiator's ephemeral key and seal it.
	ieSS, ieCT := ie.Encapsulate()
	resp = yr.Seal("ie_ct", resp, ieCT)
	yr.Mix("ie_ss", ieSS)

	// Send the response.
	if _, err := rw.Write(resp); err != nil {
		return nil, err
	}

	// Fork the protocol into recv and send clones.
	recv, send := yr.Clone(), yr
	recv.Mix("sender", []byte("initiator"))
	send.Mix("sender", []byte("responder"))

	return newConnection(rw, recv, send, rs, is, config), nil
}

type connection struct {
	rw                       io.ReadWriter
	recv                     lockstitch.Protocol
	send                     lockstitch.Protocol
	recvBuf, msgBuf, sendBuf []byte
	dk                       *mlkem.DecapsulationKey768
	ek                       *mlkem.EncapsulationKey768
	sentBytes                int
	lastRatchet              time.Time
	ratchetAfterBytes        int
	ratchetAfterTime         time.Duration
}

func newConnection(rw io.ReadWriter, recv, send lockstitch.Protocol, dk *mlkem.DecapsulationKey768, ek *mlkem.EncapsulationKey768, config *Config) io.ReadWriter {
	return &connection{
		rw:                rw,
		recv:              recv,
		send:              send,
		dk:                dk,
		ek:                ek,
		lastRatchet:       time.Now(),
		ratchetAfterBytes: config.RatchetAfterBytes,
		ratchetAfterTime:  config.RatchetAfterTime,
	}
}

func (c *connection) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}

	// If we still have buffered message contents, satisfy the read with that.
	if len(c.msgBuf) > 0 {
		n = min(len(c.msgBuf), len(p))
		copy(p, c.msgBuf[:n])
		c.msgBuf = c.msgBuf[n:]
		return
	}

	// Read and decrypt the message length.
	header := allocSlice(c.recvBuf, 4+3)
	if _, err := io.ReadFull(c.rw, header[4:]); err != nil {
		return 0, err
	}
	header = c.recv.Decrypt("header", header[:1], header[4:])
	messageLen := int(binary.BigEndian.Uint32(header))

	// If the header is all-zeroes, the message is an ML-KEM ciphertext and we need to ratchet.
	if messageLen == 0 {
		ratchetCT := allocSlice(c.recvBuf[:0], mlkem.CiphertextSize768+lockstitch.TagLen)
		if _, err := io.ReadFull(c.rw, ratchetCT); err != nil {
			return 0, err
		}
		ratchetCT, err = c.recv.Open("message", ratchetCT[:0], ratchetCT)
		if err != nil {
			return 0, err
		}

		ratchetSS, err := c.dk.Decapsulate(ratchetCT)
		if err != nil {
			return 0, err
		}
		c.send.Mix("ratchet-ss", ratchetSS)

		// Re-try the read.
		return c.Read(p)
	}

	// Read and open the message.
	message := allocSlice(c.recvBuf[:0], messageLen+lockstitch.TagLen)
	if _, err := io.ReadFull(c.rw, message); err != nil {
		return 0, err
	}
	message, err = c.recv.Open("message", message[:0], message)
	if err != nil {
		return 0, err
	}
	c.msgBuf = message

	// Satisfy the read with the buffered contents.
	return c.Read(p)
}

func (c *connection) Write(p []byte) (n int, err error) {
	if len(p) > 1<<24 {
		panic("packet too large")
	}

	// Check to see if we need to ratchet the connection state.
	c.sentBytes += len(p)
	if now := time.Now(); c.sentBytes > c.ratchetAfterBytes || now.Sub(c.lastRatchet) > c.ratchetAfterTime {
		// Reset the ratchet byte counter and timestamp.
		c.sentBytes = 0
		c.lastRatchet = now

		// Encapsulate a shared secret with the receiver's encapsulation key.
		ratchetSS, ratchetCT := c.ek.Encapsulate()

		// Encrypt and send an all-zeroes header.
		header := allocSlice(c.sendBuf[:0], 4)
		header = c.send.Encrypt("header", header[:0], header[:3])
		if _, err := c.rw.Write(header); err != nil {
			return 0, err
		}

		// Encrypt and send the encapsulated key.
		message := c.send.Seal("message", c.sendBuf[:0], ratchetCT)
		if n, err := c.rw.Write(message); err != nil {
			return n, err
		}

		// Mix the shared secret into the send protocol.
		c.send.Mix("ratchet-ss", ratchetSS)
	}

	// Encode a header with a 3-byte big endian message length.
	header := allocSlice(c.sendBuf[:0], 4)
	binary.BigEndian.PutUint32(header, uint32(len(p)))
	header = c.send.Encrypt("header", header[1:1], header[1:])
	if _, err := c.rw.Write(header); err != nil {
		return 0, err
	}

	// Seal the message and send it.
	message := c.send.Seal("message", c.sendBuf[:0], p)
	if _, err := c.rw.Write(message); err != nil {
		return 0, err
	}

	return len(p), nil
}

func allocSlice(in []byte, n int) []byte {
	var head []byte
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	return head[len(in):]
}

const (
	// rsCT + is + ie + tag
	reqLen = mlkem.CiphertextSize768 + mlkem.EncapsulationKeySize768 + mlkem.EncapsulationKeySize768 + lockstitch.TagLen
	// isCT + ieCT + tag
	respLen = mlkem.CiphertextSize768 + mlkem.CiphertextSize768 + lockstitch.TagLen
)
