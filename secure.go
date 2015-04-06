package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/nacl/box"
)

// A SecureReader wraps an io.Reader and a shared key
type SecureReader struct {
	r         io.Reader
	sharedKey *[32]byte
	started   bool
	available uint64
}

func (r *SecureReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	message := make([]byte, len(p))
	n, err := r.r.Read(message)
	if err != nil && err != io.EOF {
		return 0, err
	}
	message = message[:n]

	var nonce [24]byte
	copy(nonce[:], message[:24])

	if !r.started {
		var size uint64
		buf := bytes.NewReader(nonce[0:8])
		err = binary.Read(buf, binary.LittleEndian, &size)
		if err != nil {
			return 0, err
		}

		r.available = size
		r.started = true
	}

	if uint64(n) >= r.available {
		r.available = uint64(0)
	} else {
		r.available -= uint64(n)
	}

	decrypted, ok := box.OpenAfterPrecomputation(nil, message[24:], &nonce, r.sharedKey)
	if !ok {
		return 0, errors.New("unable to open the box")
	}
	copy(p, decrypted)

	return len(decrypted), err
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, pub, priv)
	return &SecureReader{r, &sharedKey, false, uint64(0)}
}

type SecureWriter struct {
	w         io.Writer
	sharedKey *[32]byte
}

func (w *SecureWriter) Write(p []byte) (int, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint64(len(p)))
	if err != nil {
		return 0, err
	}
	size := buf.Bytes()

	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return 0, err
	}

	var nonce [24]byte
	copy(nonce[0:8], size[:])
	copy(nonce[9:24], random[:])

	encrypted := box.SealAfterPrecomputation(nonce[:], p, &nonce, w.sharedKey)

	w.w.Write(encrypted)
	return len(p), nil
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, pub, priv)
	return &SecureWriter{w, &sharedKey}
}

type SecureReadWriteCloser struct {
	sr io.Reader
	sw io.Writer
	net.Conn
}

func NewSecureReadWriteCloser(conn net.Conn, priv, pub *[32]byte) io.ReadWriteCloser {
	sr := NewSecureReader(conn, priv, pub)
	sw := NewSecureWriter(conn, priv, pub)

	return &SecureReadWriteCloser{sr, sw, conn}
}

func (srwc SecureReadWriteCloser) Read(p []byte) (int, error) {
	return srwc.sr.Read(p)
}

func (srwc SecureReadWriteCloser) Write(p []byte) (int, error) {
	return srwc.sw.Write(p)
}

func GenerateKey() (publicKey, privateKey *[32]byte, err error) {
	return box.GenerateKey(rand.Reader)
}
