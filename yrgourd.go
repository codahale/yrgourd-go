package yrgourd

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/codahale/elligator-squared-p256"
	"github.com/codahale/lockstitch-go"
)

type PrivateKey = ecdh.PrivateKey
type PublicKey = ecdh.PublicKey

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
	AllowAllPolicy         = func(key *PublicKey) bool { return true }
)

func NewPublicKey(key []byte) (*PublicKey, error) {
	return ecdh.P256().NewPublicKey(key)
}

func NewPrivateKey(key []byte) (*PrivateKey, error) {
	return ecdh.P256().NewPrivateKey(key)
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand)
}

func Initiate(rw io.ReadWriter, is *PrivateKey, rs *PublicKey, rand io.Reader, config *Config) (io.ReadWriter, error) {
	if config == nil {
		config = &DefaultConfig
	}

	// Allocate a buffer for the request.
	req := make([]byte, 0, reqLen)

	// Generate an ephemeral key pair.
	ie, err := GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	// Initialize a protocol.
	yr := lockstitch.NewProtocol("yrgourd.v1")

	// Mix the responder's static public key into the protocol.
	yr.Mix("rs", rs.Bytes())

	// Mix the initiator's encoded ephemeral public key into the protocol.
	ieEnc, err := elligator.Encode(ie.PublicKey().Bytes(), rand)
	if err != nil {
		return nil, err
	}
	req = append(req, ieEnc...)
	yr.Mix("ie", req)

	// Calculate and mix in the ephemeral-static shared secret.
	ssIERS, err := ie.ECDH(rs)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	yr.Mix("ie-rs", ssIERS)

	// Seal the initiator's static public key.
	req = yr.Seal("is", req, is.PublicKey().Bytes())

	// Send the request.
	if _, err := rw.Write(req); err != nil {
		return nil, err
	}

	// Calculate and mix in the static-static shared secret.
	ssISRS, err := is.ECDH(rs)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	yr.Mix("is-rs", ssISRS)

	// Allocate a buffer for the response.
	resp := make([]byte, respLen)

	// Read the response.
	if _, err := io.ReadFull(rw, resp); err != nil {
		fmt.Println(err)
		return nil, err
	}

	// Open the ciphertext and parse the responder's ephemeral public key.
	respRE, err := yr.Open("re", resp[:0], resp)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	re, err := NewPublicKey(respRE)
	if err != nil {
		return nil, ErrInvalidHandshake
	}

	// Calculate and mix in the static-ephemeral shared secret.
	ssISREE, err := is.ECDH(re)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	yr.Mix("is-re", ssISREE)

	// Calculate and mix in the ephemeral-ephemeral shared secret.
	ssIEREE, err := ie.ECDH(re)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	yr.Mix("ie-re", ssIEREE)

	// Fork the protocol into recv and send clones.
	recv, send := yr.Clone(), yr
	send.Mix("sender", []byte("initiator"))
	recv.Mix("sender", []byte("responder"))

	return newConnection(rw, recv, send, is, rs, rand, config), nil
}

func Respond(rw io.ReadWriter, rs *PrivateKey, rand io.Reader, config *Config, policy func(key *PublicKey) bool) (io.ReadWriter, error) {
	if config == nil {
		config = &DefaultConfig
	}

	// Initialize a protocol.
	yr := lockstitch.NewProtocol("yrgourd.v1")

	// Mix the responder's static public key into the protocol.
	yr.Mix("rs", rs.PublicKey().Bytes())

	// Read the initiator's request.
	req := make([]byte, reqLen)
	if _, err := io.ReadFull(rw, req); err != nil {
		return nil, err
	}

	// Decode the initiator's ephemeral key.
	reqIE, reqIS := req[:elligatorPointLen], req[elligatorPointLen:]
	yr.Mix("ie", reqIE)
	reqIE, err := elligator.Decode(reqIE)
	if err != nil {
		return nil, ErrInvalidHandshake
	}

	// Parse the initiator's ephemeral public key.
	ie, err := NewPublicKey(reqIE)
	if err != nil {
		panic(err) // should never happen
	}

	// Calculate and mix in the ephemeral-static shared secret.
	ssIERS, err := rs.ECDH(ie)
	if err != nil {
		return nil, err
	}
	yr.Mix("ie-rs", ssIERS)

	// Open and decode the initiator's static public key.
	reqIS, err = yr.Open("is", reqIS[:0], reqIS)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	is, err := NewPublicKey(reqIS)
	if err != nil {
		return nil, ErrInvalidHandshake
	}

	// Check the initiator's static public key against the policy.
	if !policy(is) {
		return nil, ErrInitiatorNotAllowed
	}

	// Allocate a buffer for the response.
	resp := make([]byte, 0, respLen)

	// Calculate and mix in the static-static shared secret.
	ssISRS, err := rs.ECDH(is)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	yr.Mix("is-rs", ssISRS)

	// Generate an ephemeral key pair.
	re, err := GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	// Seal the ephemeral public key.
	resp = yr.Seal("re", resp[:0], re.PublicKey().Bytes())

	// Send the response.
	if _, err := rw.Write(resp); err != nil {
		return nil, err
	}

	// Calculate and mix in the static-ephemeral shared secret.
	ssISREE, err := re.ECDH(is)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	yr.Mix("is-re", ssISREE)

	// Calculate and mix in the ephemeral-ephemeral shared secret.
	ssIEREE, err := re.ECDH(ie)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	yr.Mix("ie-re", ssIEREE)

	// Fork the protocol into recv and send clones.
	recv, send := yr.Clone(), yr
	recv.Mix("sender", []byte("initiator"))
	send.Mix("sender", []byte("responder"))

	return newConnection(rw, recv, send, rs, is, rand, config), nil
}

type connection struct {
	rw                       io.ReadWriter
	recv                     lockstitch.Protocol
	send                     lockstitch.Protocol
	recvBuf, msgBuf, sendBuf []byte
	localKey                 *PrivateKey
	remoteKey                *PublicKey
	rand                     io.Reader
	sentBytes                int
	lastRatchet              time.Time
	ratchetAfterBytes        int
	ratchetAfterTime         time.Duration
}

func newConnection(rw io.ReadWriter, recv, send lockstitch.Protocol, localKey *PrivateKey, remoteKey *PublicKey, rand io.Reader, config *Config) io.ReadWriter {
	return &connection{
		rw:                rw,
		recv:              recv,
		send:              send,
		localKey:          localKey,
		remoteKey:         remoteKey,
		rand:              rand,
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

	// Read and decrypt the header and decode the message length, if any.
	header := allocSlice(c.recvBuf, 4+3)
	if _, err := io.ReadFull(c.rw, header[4:]); err != nil {
		return 0, err
	}
	header = c.recv.Decrypt("header", header[:1], header[4:])
	messageLen := int(binary.BigEndian.Uint32(header))

	// If the header is all-zeroes, the message is an encrypted ephemeral public key and we need to ratchet.
	if messageLen == 0 {
		ratchetCT := allocSlice(c.recvBuf[:0], pointLen+lockstitch.TagLen)
		if _, err := io.ReadFull(c.rw, ratchetCT); err != nil {
			return 0, err
		}
		ratchetCT, err = c.recv.Open("message", ratchetCT[:0], ratchetCT)
		if err != nil {
			return 0, err
		}
		ephemeral, err := NewPublicKey(ratchetCT)
		if err != nil {
			return 0, err
		}
		ss, err := c.localKey.ECDH(ephemeral)
		if err != nil {
			return 0, err
		}
		c.send.Mix("ratchet-ss", ss)

		// Re-try the read.
		return c.Read(p)
	}

	// Otherwise, read and open the message.
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

		// Generate an ephemeral key pair.
		ephemeral, err := GenerateKey(c.rand)
		if err != nil {
			return 0, err
		}

		// Encrypt an all-zeroes header.
		header := allocSlice(c.sendBuf[:0], 4)
		header = c.send.Encrypt("header", header[:0], header[:3])

		// Seal the ephemeral public key, append it to the header, and send both.
		message := c.send.Seal("message", header, ephemeral.PublicKey().Bytes())
		if n, err := c.rw.Write(message); err != nil {
			return n, err
		}

		// Calculate and mix in the shared secret.
		ss, err := ephemeral.ECDH(c.remoteKey)
		if err != nil {
			return 0, err
		}
		c.send.Mix("ratchet-ss", ss)
	}

	// Encode a header with a 3-byte big endian message length and encrypt it.
	header := allocSlice(c.sendBuf[:0], 4)
	binary.BigEndian.PutUint32(header, uint32(len(p)))
	header = c.send.Encrypt("header", header[1:1], header[1:])

	// Seal the message, append it to the header, and send it.
	message := c.send.Seal("message", header, p)
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
	elligatorPointLen = 64
	pointLen          = 65

	// elligator(ie) + is + tag
	reqLen = elligatorPointLen + pointLen + lockstitch.TagLen
	// re + tag
	respLen = pointLen + lockstitch.TagLen
)
